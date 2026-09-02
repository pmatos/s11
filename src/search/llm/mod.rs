//! LLM-assisted superoptimization (Codex Spark flow).
//!
//! See CONTEXT.md and docs/adr/0001-0003 for the design.

mod accounting;
pub mod codex;
pub mod ledger;
pub mod outcome;
pub mod prompt;

#[cfg(all(test, unix))]
mod test_support;

use std::time::{Duration, Instant};

use crate::ir::Instruction;
use crate::search::SearchAlgorithm;
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResult, SearchStatistics};
use crate::semantics::live_out::LiveOut;
use crate::validation::live_out::compute_live_in_registers;

pub use self::accounting::LlmTimings;

use self::accounting::{RunAccounting, RunEvent, RunTotals};
use self::codex::invoke_codex;
use self::ledger::UnsupportedMnemonicLedger;
use self::outcome::{IterationOutcome, classify};
use self::prompt::{OUTPUT_SCHEMA, build_prompt};

/// LLM-assisted search using the Codex CLI.
///
/// Each call to `search` invokes `codex exec` up to `LlmConfig.max_codex_calls`
/// times, sequentially, with fresh prompts. The first candidate that parses,
/// is strictly shorter than the target, and is provably equivalent (per the
/// existing fast + SMT pipeline) is returned.
#[derive(Default)]
pub struct LlmSearch {
    last_stats: SearchStatistics,
    last_ledger: UnsupportedMnemonicLedger,
    last_timings: LlmTimings,
}

impl LlmSearch {
    pub fn new() -> Self {
        Self::default()
    }

    /// The unsupported-mnemonic ledger from the most recent search.
    pub fn ledger(&self) -> &UnsupportedMnemonicLedger {
        &self.last_ledger
    }

    /// Per-phase timing breakdown for the most recent search.
    pub fn timings(&self) -> &LlmTimings {
        &self.last_timings
    }
}

// ADR-0004 decision 3 (reaffirming ADR-0003): the LLM-assisted search path is
// **AArch64-only by design**. The prompt body (src/search/llm/prompt.rs:20-46)
// names "AArch64 superoptimizer" and renders AArch64 registers directly; the
// response parser routes through `parser::parse_line` which is AArch64-only.
// When stage 2 step 17 makes `SearchAlgorithm` generic over `<I: ISA>`, this
// impl will be constrained to `SearchAlgorithm<AArch64>` so the LLM flow
// cannot accidentally be invoked for x86 / RISC-V. The trait is now generic
// (issue #73), so the constraint is explicit via the type parameter:
// `impl SearchAlgorithm<AArch64> for LlmSearch`.
impl SearchAlgorithm<crate::isa::AArch64> for LlmSearch {
    type LiveOut = LiveOut;
    type Result = SearchResult;

    fn search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOut,
        config: &SearchConfig,
    ) -> SearchResult {
        // Reset accumulators at the start of every search so a caller that
        // checks `ledger()` / `timings()` between two searches without a
        // manual `reset()` never sees stale data from the previous run.
        self.last_stats = SearchStatistics::default();
        self.last_ledger = UnsupportedMnemonicLedger::new();
        self.last_timings = LlmTimings::default();

        let mut acct = RunAccounting::new(target.len());
        let started = Instant::now();

        // Per ADR-0008: the LLM flow no longer statically refuses flag-live-out
        // targets. It relies on the same equivalence check as every other
        // generator — the verifier pins `with_flags(true)` (see `outcome.rs`),
        // so a candidate that drops a needed flag-setter is rejected by
        // equivalence rather than pre-refused. This supersedes ADR-0002.
        let live_in = compute_live_in_registers(target);
        let prompt = build_prompt(target, &live_in, live_out);
        let timeout = config.timeout.unwrap_or(Duration::from_secs(60));
        let max_calls = config.llm.max_codex_calls;

        let mut found: Option<Vec<Instruction>> = None;

        for call_idx in 0..max_calls {
            let Some(remaining) = remaining_until(started, timeout) else {
                if config.verbose {
                    eprintln!("llm-search: timeout after {} calls", call_idx);
                }
                break;
            };

            if config.verbose {
                eprintln!(
                    "llm-search: [{:>2}/{}] calling codex (elapsed {:.2}s)",
                    call_idx + 1,
                    max_calls,
                    started.elapsed().as_secs_f64()
                );
            }
            let call_start = Instant::now();
            let codex_result = invoke_codex(&config.llm, &prompt, OUTPUT_SCHEMA, remaining);
            let codex_elapsed = call_start.elapsed();
            // The seam counts a Codex `Ok` as an evaluated candidate; IO errors
            // count the call but not an evaluation.
            acct.record(RunEvent::Codex {
                elapsed: codex_elapsed,
                produced: codex_result.is_ok(),
            });
            let raw = match codex_result {
                Ok(s) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: [{:>2}/{}]   ← codex returned in {:.2}s",
                            call_idx + 1,
                            max_calls,
                            codex_elapsed.as_secs_f64()
                        );
                    }
                    s
                }
                Err(e) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: [{:>2}/{}]   ✗ codex error after {:.2}s: {}",
                            call_idx + 1,
                            max_calls,
                            codex_elapsed.as_secs_f64(),
                            e
                        );
                    }
                    continue;
                }
            };

            let Some(verify_remaining) = remaining_until(started, timeout)
                .and_then(|remaining| verification_timeout_for_remaining(config, remaining))
            else {
                if config.verbose {
                    eprintln!(
                        "llm-search: SMT disabled or budget exhausted before verifying candidate on call {}",
                        call_idx
                    );
                }
                break;
            };
            let verify_start = Instant::now();
            let (outcome, metrics) = classify(target, &raw, live_out, verify_remaining);
            let verify_elapsed = verify_start.elapsed();
            // The seam folds the verification metrics (independent of the
            // outcome variant) and the outcome itself into the accumulators.
            acct.record(RunEvent::Candidate {
                outcome: &outcome,
                metrics: metrics.as_ref(),
                elapsed: verify_elapsed,
            });
            match outcome {
                IterationOutcome::Success(seq) => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: success on call {} ({} -> {} instructions)",
                            call_idx,
                            target.len(),
                            seq.len()
                        );
                    }
                    found = Some(seq);
                    break;
                }
                IterationOutcome::ParseFail {
                    unsupported_mnemonics,
                } => {
                    if config.verbose {
                        if unsupported_mnemonics.is_empty() {
                            eprintln!(
                                "llm-search: parse-fail on call {} (operand or encoding error; \
                                 no unknown mnemonics)",
                                call_idx
                            );
                        } else {
                            eprintln!(
                                "llm-search: parse-fail on call {} ({} unsupported mnemonic{})",
                                call_idx,
                                unsupported_mnemonics.len(),
                                if unsupported_mnemonics.len() == 1 {
                                    ""
                                } else {
                                    "s"
                                }
                            );
                        }
                    }
                }
                IterationOutcome::NotShorter { candidate_len } => {
                    if config.verbose {
                        eprintln!(
                            "llm-search: not-shorter on call {} (got {} instructions)",
                            call_idx, candidate_len
                        );
                    }
                }
                IterationOutcome::EquivFail => {
                    if config.verbose {
                        eprintln!("llm-search: equiv-fail on call {}", call_idx);
                    }
                }
                IterationOutcome::EquivUnknown => {
                    if config.verbose {
                        eprintln!("llm-search: equiv-unknown on call {}", call_idx);
                    }
                }
            }
        }

        let RunTotals {
            stats,
            ledger,
            timings,
        } = acct.finish(started.elapsed());
        self.last_stats = stats.clone();
        self.last_ledger = ledger;
        self.last_timings = timings;

        match found {
            Some(seq) => SearchResult::with_optimization(target.to_vec(), seq, stats),
            None => SearchResult::no_optimization(target.to_vec(), stats),
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.last_stats.clone()
    }

    fn reset(&mut self) {
        self.last_stats = SearchStatistics::default();
        self.last_ledger = UnsupportedMnemonicLedger::new();
        self.last_timings = LlmTimings::default();
    }
}

fn remaining_until(started: Instant, timeout: Duration) -> Option<Duration> {
    let remaining = timeout.saturating_sub(started.elapsed());
    (!remaining.is_zero()).then_some(remaining)
}

fn verification_timeout_for_remaining(
    config: &SearchConfig,
    remaining: Duration,
) -> Option<Duration> {
    config.solver_timeout_with_remaining_budget(remaining)
}

#[cfg(test)]
mod tests {
    //! No-Codex unit tests of `LlmSearch::search` flow gates.
    //!
    //! These tests do NOT invoke Codex — they exercise paths that short-circuit
    //! before any candidate generation (the ADR-0002 flags-live-out refusal,
    //! and the `max_codex_calls = 0` budget exhaustion). For end-to-end LLM
    //! coverage see `tests/data/llm_demo/` and `just llm-demo`.
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::search::config::LlmConfig;
    #[cfg(unix)]
    use crate::search::llm::test_support::{
        FakeCodex, assembly_answer_writer_script, shell_single_quote, wait_until_process_gone,
    };

    #[cfg(unix)]
    fn cfg_with_fake_codex(fake: &FakeCodex, max_calls: u32) -> SearchConfig {
        SearchConfig::default()
            .with_timeout(Duration::from_secs(5))
            .with_verbose(true)
            .with_llm(
                LlmConfig::default()
                    .with_max_codex_calls(max_calls)
                    .with_model("fake-model")
                    .with_codex_bin(fake.path_string()),
            )
    }

    fn reducible_target() -> Vec<Instruction> {
        vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ]
    }

    fn constant_two_target() -> Vec<Instruction> {
        vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ]
    }

    fn live_out_x0() -> LiveOut {
        LiveOut::from_registers(vec![Register::X0])
    }

    fn cfg_no_calls() -> SearchConfig {
        SearchConfig::default().with_llm(LlmConfig::default().with_max_codex_calls(0))
    }

    #[test]
    fn llm_verification_timeout_is_capped_by_solver_timeout() {
        let config = SearchConfig::default().with_solver_timeout(Duration::from_millis(25));

        assert_eq!(
            verification_timeout_for_remaining(&config, Duration::from_secs(10)),
            Some(Duration::from_millis(25))
        );
    }

    #[test]
    fn remaining_until_returns_positive_budget_without_deadline() {
        let remaining = remaining_until(Instant::now(), Duration::MAX)
            .expect("a fresh search should retain a positive budget");

        assert!(!remaining.is_zero());
    }

    #[test]
    fn remaining_until_returns_none_for_exhausted_budget() {
        assert_eq!(remaining_until(Instant::now(), Duration::ZERO), None);

        let started = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .expect("a two-second-old instant should be representable");
        assert_eq!(remaining_until(started, Duration::from_secs(1)), None);
    }

    #[test]
    fn llm_zero_solver_timeout_skips_smt() {
        let config = SearchConfig::default().with_solver_timeout(Duration::ZERO);

        assert_eq!(
            verification_timeout_for_remaining(&config, Duration::from_secs(10)),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn flags_live_out_target_is_no_longer_refused_and_reaches_codex() {
        // Per ADR-0008 the static refusal is gone: a flag-live-out target (one
        // ending in CMP) must now be processed like any other. The fake codex
        // proposes `mov x0, x1`, which drops the flag-setter; because the LLM
        // verifier pins `with_flags(true)`, equivalence rejects it — so no
        // optimization is reported, but codex WAS invoked (the key signal that
        // the pre-refusal is gone).
        let fake = FakeCodex::new(&assembly_answer_writer_script("mov x0, x1"));
        let target = vec![
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0),
            },
        ];

        let mut search = LlmSearch::new();
        let result = search.search(&target, &live_out_x0(), &cfg_with_fake_codex(&fake, 1));

        assert!(
            !result.found_optimization,
            "a flag-dropping candidate must be rejected by equivalence"
        );
        assert_eq!(
            search.timings().codex_calls,
            1,
            "flag-live-out target must reach codex, not be statically refused"
        );
    }

    #[test]
    fn non_flags_live_out_target_proceeds_until_budget_exhausted() {
        // Same shape but ending on a register-writing instruction (no flag
        // writer at all). Should NOT be refused. With max_codex_calls=0 the
        // loop budget exhausts before any call, but the function still
        // returns a no-optimization result rather than the refusal path.
        let target = vec![
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let mut search = LlmSearch::new();
        let result = search.search(&target, &live_out_x0(), &cfg_no_calls());

        assert!(!result.found_optimization);
        let timings = search.timings();
        assert_eq!(
            timings.codex_calls, 0,
            "max_codex_calls = 0 means zero codex invocations"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_success_returns_first_equivalent_shorter_candidate() {
        let fake = FakeCodex::new(&assembly_answer_writer_script("add x0, x1, #1"));
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(result.found_optimization);
        let optimized = result
            .optimized_sequence
            .expect("success should include optimized sequence");
        assert_eq!(optimized.len(), 1);
        assert!(search.ledger().is_empty());

        let timings = search.timings();
        assert_eq!(timings.codex_calls, 1);
        assert_eq!(timings.verifications, 1);
        assert_eq!(timings.smt_calls, 1);
        assert!(timings.smt_formula_bytes_total > 0);

        let stats = search.statistics();
        assert_eq!(stats.candidates_evaluated, 1);
        assert_eq!(stats.smt_queries, 1);
        assert_eq!(stats.smt_equivalent, 1);
        assert_eq!(stats.improvements_found, 1);
        assert_eq!(stats.best_cost_found, 1);

        search.reset();
        assert_eq!(search.statistics().candidates_evaluated, 0);
        assert!(search.ledger().is_empty());
        assert_eq!(search.timings().codex_calls, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_parse_failure_records_unsupported_mnemonics() {
        // Use NEON mnemonics — memory ops were promoted to supported in
        // issue #68, so `ldr` / `str` no longer drive the unsupported path.
        let fake = FakeCodex::new(&assembly_answer_writer_script(
            "fadd v0.4s, v1.4s, v2.4s\nld1 {v3.16b}, [x4]",
        ));
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert_eq!(
            search.ledger().sorted_entries(),
            vec![("fadd".to_string(), 1), ("ld1".to_string(), 1)]
        );
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.timings().verifications, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_parse_failure_without_unknown_mnemonic_stays_unrecorded() {
        let fake = FakeCodex::new(&assembly_answer_writer_script("mov x0"));
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert!(search.ledger().is_empty());
        assert_eq!(search.timings().verifications, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_not_shorter_candidate_is_rejected_without_verification() {
        let fake = FakeCodex::new(&assembly_answer_writer_script("mov x0, x1\nadd x0, x0, #1"));
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert!(search.ledger().is_empty());
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.timings().verifications, 0);
        let stats = search.statistics();
        assert_eq!(stats.candidates_evaluated, 1);
        assert_eq!(stats.candidates_pruned_by_cost, 1);
        assert_eq!(stats.smt_queries, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_equiv_fail_counts_verification_but_not_smt_fast_path() {
        let fake = FakeCodex::new(&assembly_answer_writer_script("mov x0, #5"));
        let mut search = LlmSearch::new();

        let result = search.search(
            &constant_two_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.timings().verifications, 1);
        assert_eq!(search.timings().smt_calls, 0);
        assert_eq!(search.statistics().smt_queries, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_nonzero_exit_is_skipped() {
        let fake = FakeCodex::new("echo no candidate today >&2\nexit 9\n");
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.statistics().candidates_evaluated, 0);
    }

    #[cfg(unix)]
    #[test]
    fn zero_timeout_breaks_before_first_codex_call() {
        let fake = FakeCodex::new(&assembly_answer_writer_script("add x0, x1, #1"));
        let config = cfg_with_fake_codex(&fake, 3).with_timeout(Duration::ZERO);
        let mut search = LlmSearch::new();

        let result = search.search(&reducible_target(), &live_out_x0(), &config);

        assert!(!result.found_optimization);
        assert_eq!(search.timings().codex_calls, 0);
        assert_eq!(search.statistics().candidates_evaluated, 0);
    }

    #[cfg(unix)]
    #[test]
    fn search_timeout_kills_slow_codex_child() {
        let pid_file = tempfile::NamedTempFile::new().expect("create pid file");
        let pid_path = pid_file.path().to_path_buf();
        let script = format!(
            "printf '%s\\n' \"$$\" > {}\nsleep 2\n{}",
            shell_single_quote(&pid_path.to_string_lossy()),
            assembly_answer_writer_script("add x0, x1, #1")
        );
        let fake = FakeCodex::new(&script);
        let config = cfg_with_fake_codex(&fake, 3).with_timeout(Duration::from_millis(300));
        let mut search = LlmSearch::new();

        let started = Instant::now();
        let result = search.search(&reducible_target(), &live_out_x0(), &config);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(900),
            "search should return near its timeout instead of waiting for fake codex sleep; elapsed {elapsed:?}"
        );
        assert!(!result.found_optimization);
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.timings().verifications, 0);
        assert_eq!(search.statistics().candidates_evaluated, 0);

        let pid = std::fs::read_to_string(&pid_path)
            .expect("fake codex should record its pid")
            .trim()
            .parse::<u32>()
            .expect("fake codex pid should be numeric");
        wait_until_process_gone(pid);
    }
}

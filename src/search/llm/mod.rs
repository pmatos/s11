//! LLM-assisted superoptimization (Codex Spark flow).
//!
//! See CONTEXT.md and docs/adr/0001-0003 for the design.

pub mod codex;
pub mod ledger;
pub mod outcome;
pub mod prompt;

use std::time::{Duration, Instant};

use crate::ir::Instruction;
use crate::search::SearchAlgorithm;
use crate::search::config::SearchConfig;
use crate::search::result::{SearchResult, SearchStatistics};
use crate::semantics::live_out::LiveOut;
use crate::validation::live_out::{compute_live_in_registers, flags_live_out};

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
/// Per-phase timing breakdown for one `LlmSearch::search` run.
#[derive(Debug, Default, Clone, Copy)]
pub struct LlmTimings {
    /// Number of times `codex exec` was invoked.
    pub codex_calls: u32,
    /// Wall-clock time spent inside `codex exec` invocations.
    pub codex_time: Duration,
    /// Number of candidate verifications attempted (one per parseable response).
    pub verifications: u32,
    /// Wall-clock time spent in the verification pipeline (parse + fast-path
    /// random testing + Z3 SMT). Dominated by SMT for non-parse-fail outcomes.
    pub verify_time: Duration,
    /// Number of times the SMT solver was actually invoked (subset of
    /// verifications: parse-fail and fast-path-refutations don't reach SMT).
    pub smt_calls: u32,
    /// Sum of SMT formula sizes (bytes of SMT-LIB rendering) across all
    /// solver invocations in this search **whose result was Equivalent**.
    /// Sat / Unknown SMT outcomes do not contribute (we don't pay
    /// `solver.to_string()` on those paths). A run that hit SMT many times
    /// but never proved equivalence will read 0 here even though `smt_calls`
    /// is positive.
    pub smt_formula_bytes_total: usize,
    /// Largest SMT formula size (bytes) seen on an Equivalent SMT outcome.
    pub smt_formula_bytes_max: usize,
}

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

impl SearchAlgorithm for LlmSearch {
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

        let mut stats = SearchStatistics::new(crate::search::config::Algorithm::Llm);
        stats.original_cost = target.len() as u64;
        stats.best_cost_found = target.len() as u64;
        let mut ledger = UnsupportedMnemonicLedger::new();
        let mut timings = LlmTimings::default();
        let started = Instant::now();

        // Per ADR-0002: refuse targets where flags are live-out.
        if flags_live_out(target) {
            eprintln!(
                "llm-search: target has flags live-out (per ADR-0002 the LLM \
                 flow is not sound on this input). Refusing."
            );
            stats.elapsed_time = started.elapsed();
            self.last_stats = stats.clone();
            self.last_ledger = ledger;
            self.last_timings = timings;
            return SearchResult::no_optimization(target.to_vec(), stats);
        }

        let live_in = compute_live_in_registers(target);
        let prompt = build_prompt(target, &live_in, live_out.registers());
        let timeout = config.timeout.unwrap_or(Duration::from_secs(60));
        let max_calls = config.llm.max_codex_calls;

        let mut found: Option<Vec<Instruction>> = None;

        for call_idx in 0..max_calls {
            if started.elapsed() >= timeout {
                if config.verbose {
                    eprintln!("llm-search: timeout after {} calls", call_idx);
                }
                break;
            }

            if config.verbose {
                eprintln!(
                    "llm-search: [{:>2}/{}] calling codex (elapsed {:.2}s)",
                    call_idx + 1,
                    max_calls,
                    started.elapsed().as_secs_f64()
                );
            }
            let call_start = Instant::now();
            let codex_result = invoke_codex(&config.llm, &prompt, OUTPUT_SCHEMA);
            let codex_elapsed = call_start.elapsed();
            timings.codex_calls += 1;
            timings.codex_time += codex_elapsed;
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
                    // Codex produced a candidate; this is the moment we count
                    // it as "evaluated" — Codex IO errors above don't.
                    stats.candidates_evaluated += 1;
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

            let verify_start = Instant::now();
            let (outcome, metrics) = classify(target, &raw, live_out);
            let verify_elapsed = verify_start.elapsed();
            // Only count as a "verification" when the verifier actually ran.
            // Parse-fail and not-shorter short-circuit before the verifier.
            if let Some(m) = metrics {
                timings.verifications += 1;
                timings.verify_time += verify_elapsed;
                if m.smt_called {
                    timings.smt_calls += 1;
                    if let Some(bytes) = m.smt_formula_bytes {
                        timings.smt_formula_bytes_total += bytes;
                        if bytes > timings.smt_formula_bytes_max {
                            timings.smt_formula_bytes_max = bytes;
                        }
                    }
                }
            }
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
                    stats.smt_queries += 1;
                    stats.smt_equivalent += 1;
                    stats.candidates_passed_fast += 1;
                    stats.improvements_found += 1;
                    stats.best_cost_found = seq.len() as u64;
                    found = Some(seq);
                    break;
                }
                IterationOutcome::ParseFail {
                    unsupported_mnemonics,
                } => {
                    for m in &unsupported_mnemonics {
                        ledger.record(m);
                    }
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
                    stats.smt_queries += 1;
                    if config.verbose {
                        eprintln!("llm-search: equiv-fail on call {}", call_idx);
                    }
                }
                IterationOutcome::EquivUnknown => {
                    stats.smt_queries += 1;
                    if config.verbose {
                        eprintln!("llm-search: equiv-unknown on call {}", call_idx);
                    }
                }
            }
        }

        stats.elapsed_time = started.elapsed();
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    static FAKE_CODEX_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct FakeCodex {
        path: PathBuf,
        dir: PathBuf,
    }

    #[cfg(unix)]
    impl FakeCodex {
        fn new(body: &str) -> Self {
            use std::io::Write as _;
            use std::os::unix::fs::PermissionsExt;

            let dir = std::env::temp_dir().join(format!(
                "s11-llm-search-fake-codex-{}-{}",
                std::process::id(),
                FAKE_CODEX_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).expect("create fake codex temp dir");

            let path = dir.join("codex");
            let mut file = std::fs::File::create(&path).expect("create fake codex script");
            file.write_all(format!("#!/bin/sh\nset -eu\n{}", body).as_bytes())
                .expect("write fake codex script");
            file.sync_all().expect("sync fake codex script");
            drop(file);
            let mut permissions = std::fs::metadata(&path)
                .expect("stat fake codex script")
                .permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&path, permissions).expect("chmod fake codex script");
            std::thread::sleep(std::time::Duration::from_millis(20));

            Self { path, dir }
        }

        fn path_string(&self) -> String {
            self.path.to_string_lossy().into_owned()
        }
    }

    #[cfg(unix)]
    impl Drop for FakeCodex {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    fn answer_writer_script(assembly: &str) -> String {
        format!(
            r#"answer=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    answer="$1"
  fi
  shift || true
done
[ -n "$answer" ]
cat > "$answer" <<'JSON'
{{"assembly":{}}}
JSON
"#,
            serde_json::to_string(assembly).expect("quote assembly for fake response")
        )
    }

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
    fn flags_live_out_target_is_refused_without_calling_codex() {
        // Target ends in a flag-writer; per ADR-0002 the LLM flow refuses.
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
        let result = search.search(&target, &live_out_x0(), &cfg_no_calls());

        assert!(
            !result.found_optimization,
            "flags-live-out target must be refused, not optimized"
        );
        assert!(
            result.optimized_sequence.is_none(),
            "no optimized sequence expected on refusal"
        );

        let timings = search.timings();
        assert_eq!(
            timings.codex_calls, 0,
            "refusal must short-circuit before any codex invocation"
        );
        assert_eq!(timings.smt_calls, 0);
        assert_eq!(timings.verifications, 0);
        assert!(search.ledger().is_empty());
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
        let fake = FakeCodex::new(&answer_writer_script("add x0, x1, #1"));
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
        let fake = FakeCodex::new(&answer_writer_script("ldr x0, [x1]\nstr x2, [x3]"));
        let mut search = LlmSearch::new();

        let result = search.search(
            &reducible_target(),
            &live_out_x0(),
            &cfg_with_fake_codex(&fake, 1),
        );

        assert!(!result.found_optimization);
        assert_eq!(
            search.ledger().sorted_entries(),
            vec![("ldr".to_string(), 1), ("str".to_string(), 1)]
        );
        assert_eq!(search.timings().codex_calls, 1);
        assert_eq!(search.timings().verifications, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_parse_failure_without_unknown_mnemonic_stays_unrecorded() {
        let fake = FakeCodex::new(&answer_writer_script("mov x0"));
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
        let fake = FakeCodex::new(&answer_writer_script("mov x0, x1\nadd x0, x0, #1"));
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
    }

    #[cfg(unix)]
    #[test]
    fn fake_codex_equiv_fail_counts_verification_but_not_smt_fast_path() {
        let fake = FakeCodex::new(&answer_writer_script("mov x0, #5"));
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
        assert_eq!(search.statistics().smt_queries, 1);
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
        let fake = FakeCodex::new(&answer_writer_script("add x0, x1, #1"));
        let config = cfg_with_fake_codex(&fake, 3).with_timeout(Duration::ZERO);
        let mut search = LlmSearch::new();

        let result = search.search(&reducible_target(), &live_out_x0(), &config);

        assert!(!result.found_optimization);
        assert_eq!(search.timings().codex_calls, 0);
        assert_eq!(search.statistics().candidates_evaluated, 0);
    }
}

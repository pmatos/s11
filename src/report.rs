//! CLI report rendering — the pure text-formatting seam.
//!
//! This module concentrates the functions that turn search results, LLM timing
//! breakdowns, unsupported-mnemonic ledgers and equivalence outcomes into the
//! exact lines the CLI prints. Every function here is pure: it returns
//! `Vec<String>` (or a small report struct) and performs no I/O, so the
//! byte-for-byte CLI output can be asserted directly without capturing stdout.
//! The binary keeps the thin `print_*` wrappers that loop over these lines and
//! `println!`, matching the pure-function `capstone_bridge` precedent of
//! keeping stdout out of the library.
//!
//! Arch scope: [`format_search_statistics`], [`format_llm_timings`] and
//! [`format_unsupported_mnemonic_ledger`] are architecture-neutral, but the
//! [`build_equiv_report`] counterexample path is AArch64-specific — it re-runs
//! the diverging prefixes through the AArch64 concrete interpreter and renders
//! `Register` / vector values.

use std::time::Duration;

use crate::ir::instructions::split_terminator;
use crate::ir::{Instruction, Register};
use crate::search::llm::LlmTimings;
use crate::search::llm::ledger::UnsupportedMnemonicLedger;
use crate::search::result::SearchStatistics;
use crate::semantics::{self, LiveOut};

/// Format a byte count with a unit chosen to keep ~3 significant digits visible.
pub fn fmt_bytes(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:>7.2} MB", n as f64 / 1_048_576.0)
    } else if n >= 1_024 {
        format!("{:>7.2} kB", n as f64 / 1_024.0)
    } else {
        format!("{:>7} B ", n)
    }
}

/// Format a Duration with a unit chosen to keep ~3 significant digits visible.
pub fn fmt_dur(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{:>8.2} s ", secs)
    } else if secs >= 0.001 {
        format!("{:>8.2} ms", secs * 1_000.0)
    } else {
        format!("{:>8.1} µs", secs * 1_000_000.0)
    }
}

/// Render the per-phase LLM timing breakdown as one `String` per output line.
///
/// Pure seam: the pluralization, the conditional SMT sub-section (with its
/// average-formula-bytes computation), and the conditional share-percentage
/// section are all decided here so they can be asserted without capturing
/// stdout. The binary's `print_llm_timings` prints the lines.
pub fn format_llm_timings(timings: &LlmTimings, total: Duration) -> Vec<String> {
    let codex = timings.codex_time;
    let verify = timings.verify_time;
    let other = total.saturating_sub(codex).saturating_sub(verify);
    let mut lines = vec![
        "\nLLM phase timing:".to_string(),
        format!(
            "  Codex calls:      {}   ({} call{})",
            fmt_dur(codex),
            timings.codex_calls,
            if timings.codex_calls == 1 { "" } else { "s" }
        ),
        format!(
            "  Verification:     {}   ({} verification{}, parse + fast + SMT)",
            fmt_dur(verify),
            timings.verifications,
            if timings.verifications == 1 { "" } else { "s" }
        ),
    ];
    if timings.smt_calls > 0 {
        let avg_bytes = timings.smt_formula_bytes_total / timings.smt_calls as usize;
        lines.push(format!(
            "    SMT invoked:    {} time{}",
            timings.smt_calls,
            if timings.smt_calls == 1 { "" } else { "s" }
        ));
        lines.push(format!(
            "    SMT formula:    {}  total   ({}  avg, {}  max)",
            fmt_bytes(timings.smt_formula_bytes_total),
            fmt_bytes(avg_bytes),
            fmt_bytes(timings.smt_formula_bytes_max),
        ));
    }
    lines.push(format!("  Other:            {}", fmt_dur(other)));
    lines.push(format!("  Total:            {}", fmt_dur(total)));
    if total.as_secs_f64() > 0.0 {
        lines.push(format!(
            "  Codex share:      {:>6.2}%",
            100.0 * codex.as_secs_f64() / total.as_secs_f64()
        ));
        lines.push(format!(
            "  Verify share:     {:>6.2}%",
            100.0 * verify.as_secs_f64() / total.as_secs_f64()
        ));
    }
    lines
}

/// Render the unsupported-mnemonic ledger as one `String` per output line.
///
/// Pure seam: returns an empty `Vec` for an empty ledger (so the printer emits
/// nothing), otherwise a header plus one frequency-ranked entry line.
pub fn format_unsupported_mnemonic_ledger(ledger: &UnsupportedMnemonicLedger) -> Vec<String> {
    if ledger.is_empty() {
        return Vec::new();
    }
    let mut lines =
        vec!["\nUnsupported mnemonics emitted by the LLM (frequency-ranked):".to_string()];
    for (mnem, count) in ledger.sorted_entries() {
        lines.push(format!("  {:>5}  {}", count, mnem));
    }
    lines
}

/// Render the search-statistics report as one `String` per output line.
///
/// Pure: the seam that lets tests assert on the exact report without capturing
/// stdout. The binary's `print_search_statistics` prints the lines. Mirrors the
/// `build_equiv_report` precedent.
pub fn format_search_statistics(stats: &SearchStatistics) -> Vec<String> {
    let mut lines = vec![
        "\nSearch Statistics:".to_string(),
        format!("  Algorithm: {:?}", stats.algorithm),
        format!("  Elapsed time: {:?}", stats.elapsed_time),
        format!("  Candidates evaluated: {}", stats.candidates_evaluated),
        format!(
            "  Candidates pruned by cost: {}",
            stats.candidates_pruned_by_cost
        ),
        format!(
            "  Candidates passed fast test: {}",
            stats.candidates_passed_fast
        ),
        format!("  SMT queries: {}", stats.smt_queries),
        format!("  SMT equivalent: {}", stats.smt_equivalent),
        format!("  Improvements found: {}", stats.improvements_found),
        format!("  Original cost: {}", stats.original_cost),
        format!("  Best cost found: {}", stats.best_cost_found),
    ];
    if stats.iterations > 0 {
        lines.push(format!("  Iterations: {}", stats.iterations));
        lines.push(format!(
            "  Acceptance rate: {:.2}%",
            stats.acceptance_rate() * 100.0
        ));
    }
    lines
}

/// The presentation-and-policy outcome of an `equiv` run: the lines the CLI
/// should print and the process exit code it should return.
///
/// Produced by [`build_equiv_report`] with no stdout writes and no
/// `std::process::exit` of its own. Keeping policy (exit codes) and formatting
/// out of `run_equiv` is what makes the not-equivalent / counterexample /
/// unknown paths unit-testable — each previously called `std::process::exit`
/// inline and could only be exercised by running the whole binary.
#[derive(Debug, PartialEq, Eq)]
pub struct EquivReport {
    pub lines: Vec<String>,
    pub exit_code: i32,
}

/// Append `state`'s live-out registers to `lines`, one `    <reg> = 0x…` entry
/// each, sorted by register index for deterministic output. Shared by the
/// input / output-1 / output-2 sections of a counterexample so the three
/// previously-duplicated print loops live in one place.
fn push_live_out_registers(
    lines: &mut Vec<String>,
    state: &semantics::ConcreteMachineState,
    live_out: &LiveOut,
) {
    let mut regs: Vec<_> = live_out.iter().copied().collect();
    regs.sort_by_key(|reg| reg.sort_key());
    for reg in regs {
        match reg {
            Register::Vector(vector) => {
                lines.push(format!("    {} = 0x{:032x}", reg, state.get_vector(vector)));
            }
            _ => lines.push(format!(
                "    {} = 0x{:016x}",
                reg,
                state.get_register(reg).as_u64()
            )),
        }
    }
}

/// Turn an [`EquivalenceResult`] into the lines to print and the exit code to
/// return. Pure: no I/O, no process exit. `run_equiv` prints the lines and the
/// `equiv` CLI arm maps the code (Equivalent → 0, NotEquivalent[Fast] → 1,
/// Unknown → 2).
///
/// [`EquivalenceResult`]: semantics::EquivalenceResult
pub fn build_equiv_report(
    result: &semantics::EquivalenceResult,
    seq1: &[Instruction],
    seq2: &[Instruction],
    live_out: &LiveOut,
) -> EquivReport {
    use semantics::EquivalenceResult;

    match result {
        EquivalenceResult::Equivalent => EquivReport {
            lines: vec!["EQUIVALENT: The two sequences are semantically equivalent.".to_string()],
            exit_code: 0,
        },
        EquivalenceResult::NotEquivalent => EquivReport {
            lines: vec![
                "NOT EQUIVALENT: The two sequences produce different results (verified by SMT)."
                    .to_string(),
            ],
            exit_code: 1,
        },
        EquivalenceResult::NotEquivalentFast(input_state) => {
            // Issue #69: strip terminators before re-running on the
            // counterexample. The B1/B2 stubs panic if a branch reaches the
            // concrete interpreter; the equivalence layer already excluded the
            // terminator from its comparison via the precheck.
            let (prefix1, _) = split_terminator(seq1);
            let (prefix2, _) = split_terminator(seq2);

            let output1 = semantics::apply_sequence_concrete(input_state.clone(), prefix1);
            let output2 = semantics::apply_sequence_concrete(input_state.clone(), prefix2);

            let mut lines = vec![
                "NOT EQUIVALENT: The two sequences produce different results.".to_string(),
                "\nCounterexample found:".to_string(),
                "  Input state:".to_string(),
            ];
            push_live_out_registers(&mut lines, input_state, live_out);
            lines.push("  Output from sequence 1:".to_string());
            push_live_out_registers(&mut lines, &output1, live_out);
            lines.push("  Output from sequence 2:".to_string());
            push_live_out_registers(&mut lines, &output2, live_out);

            EquivReport {
                lines,
                exit_code: 1,
            }
        }
        EquivalenceResult::Unknown(reason) => EquivReport {
            lines: vec![
                "UNKNOWN: Could not determine equivalence.".to_string(),
                format!("  Reason: {}", reason),
            ],
            exit_code: 2,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Operand;
    use crate::search::config::Algorithm;

    #[test]
    fn fmt_bytes_and_fmt_dur_pick_human_units() {
        assert_eq!(fmt_bytes(42), "     42 B ");
        assert!(fmt_bytes(2_048).contains("kB"));
        assert!(fmt_bytes(2_097_152).contains("MB"));
        assert!(fmt_dur(Duration::from_nanos(500)).contains("µs"));
        assert!(fmt_dur(Duration::from_millis(2)).contains("ms"));
        assert!(fmt_dur(Duration::from_secs(2)).contains("s"));
    }

    #[test]
    fn format_search_statistics_emits_all_fields_and_acceptance_rate() {
        let mut stats = SearchStatistics::new(Algorithm::Stochastic);
        stats.elapsed_time = Duration::from_millis(5);
        stats.candidates_evaluated = 100;
        stats.candidates_pruned_by_cost = 3;
        stats.candidates_passed_fast = 12;
        stats.smt_queries = 4;
        stats.smt_equivalent = 1;
        stats.improvements_found = 2;
        stats.original_cost = 20;
        stats.best_cost_found = 18;
        stats.iterations = 10;
        stats.accepted_proposals = 5;

        assert_eq!(
            format_search_statistics(&stats),
            vec![
                "\nSearch Statistics:",
                "  Algorithm: Stochastic",
                "  Elapsed time: 5ms",
                "  Candidates evaluated: 100",
                "  Candidates pruned by cost: 3",
                "  Candidates passed fast test: 12",
                "  SMT queries: 4",
                "  SMT equivalent: 1",
                "  Improvements found: 2",
                "  Original cost: 20",
                "  Best cost found: 18",
                "  Iterations: 10",
                "  Acceptance rate: 50.00%",
            ],
        );
    }

    #[test]
    fn format_search_statistics_omits_iteration_lines_when_no_iterations() {
        let stats = SearchStatistics::new(Algorithm::Enumerative);
        let lines = format_search_statistics(&stats);
        assert!(!lines.iter().any(|l| l.contains("Iterations:")));
        assert!(!lines.iter().any(|l| l.contains("Acceptance rate:")));
        assert_eq!(
            lines.first().map(String::as_str),
            Some("\nSearch Statistics:")
        );
    }

    #[test]
    fn format_unsupported_mnemonic_ledger_is_empty_for_empty_ledger() {
        let ledger = UnsupportedMnemonicLedger::new();
        assert!(format_unsupported_mnemonic_ledger(&ledger).is_empty());
    }

    #[test]
    fn format_unsupported_mnemonic_ledger_ranks_entries_by_frequency() {
        let mut ledger = UnsupportedMnemonicLedger::new();
        ledger.record("ldr");
        ledger.record("ldr");
        ledger.record("adc");

        assert_eq!(
            format_unsupported_mnemonic_ledger(&ledger),
            vec![
                "\nUnsupported mnemonics emitted by the LLM (frequency-ranked):",
                "      2  ldr",
                "      1  adc",
            ],
        );
    }

    #[test]
    fn format_llm_timings_plural_with_smt_and_share_sections() {
        // codex 5ms / verify 30ms of a 50ms total → other 15ms; shares 10% / 60%.
        let timings = LlmTimings {
            codex_calls: 2,
            codex_time: Duration::from_millis(5),
            verifications: 3,
            verify_time: Duration::from_millis(30),
            smt_calls: 2,
            smt_formula_bytes_total: 2_048,
            smt_formula_bytes_max: 1_536,
        };
        let lines = format_llm_timings(&timings, Duration::from_millis(50));

        assert_eq!(
            lines.first().map(String::as_str),
            Some("\nLLM phase timing:")
        );
        // Plural suffixes on counts > 1.
        let codex_line = lines.iter().find(|l| l.contains("Codex calls:")).unwrap();
        assert!(codex_line.ends_with("(2 calls)"), "got {codex_line:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("(3 verifications, parse + fast + SMT)"))
        );
        // SMT sub-section present; "invoked" line is pure text so pin it exactly.
        assert!(lines.iter().any(|l| l == "    SMT invoked:    2 times"));
        // Average formula bytes = 2048 / 2 smt_calls = 1024 = 1.00 kB.
        assert!(
            lines.iter().any(|l| l.contains("1.00 kB  avg")),
            "avg not rendered from total/smt_calls: {lines:?}"
        );
        // Share section: codex 5/50 = 10%, verify 30/50 = 60%.
        assert!(lines.iter().any(|l| l.ends_with(" 10.00%")), "{lines:?}");
        assert!(lines.iter().any(|l| l.ends_with(" 60.00%")), "{lines:?}");
    }

    #[test]
    fn format_llm_timings_singular_suffixes() {
        let timings = LlmTimings {
            codex_calls: 1,
            codex_time: Duration::from_millis(5),
            verifications: 1,
            verify_time: Duration::from_millis(5),
            smt_calls: 1,
            smt_formula_bytes_total: 1_024,
            smt_formula_bytes_max: 1_024,
        };
        let lines = format_llm_timings(&timings, Duration::from_millis(20));
        assert!(lines.iter().any(|l| l.ends_with("(1 call)")));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("(1 verification, parse + fast + SMT)"))
        );
        assert!(lines.iter().any(|l| l == "    SMT invoked:    1 time"));
    }

    #[test]
    fn format_llm_timings_omits_smt_and_share_sections() {
        // No SMT calls → no SMT sub-section; zero total → no share section.
        let timings = LlmTimings {
            codex_calls: 1,
            codex_time: Duration::ZERO,
            verifications: 1,
            verify_time: Duration::ZERO,
            smt_calls: 0,
            smt_formula_bytes_total: 0,
            smt_formula_bytes_max: 0,
        };
        let lines = format_llm_timings(&timings, Duration::ZERO);
        assert!(!lines.iter().any(|l| l.contains("SMT invoked")));
        assert!(!lines.iter().any(|l| l.contains("SMT formula")));
        assert!(!lines.iter().any(|l| l.contains("share:")));
        // Non-share lines still present, in order.
        assert_eq!(
            lines.first().map(String::as_str),
            Some("\nLLM phase timing:")
        );
        assert!(lines.iter().any(|l| l.contains("Total:")));
    }

    // ===== `equiv` report builder (extracted seam) =====
    //
    // Before this refactor these outcomes were only reachable through the CLI:
    // the NotEquivalent/NotEquivalentFast/Unknown arms of `run_equiv` called
    // `std::process::exit` inline, so no test could observe their formatting or
    // exit codes. `build_equiv_report` is the pure seam that made them testable.

    #[test]
    fn equiv_report_equivalent_maps_to_exit_zero() {
        let report = build_equiv_report(
            &semantics::EquivalenceResult::Equivalent,
            &[],
            &[],
            &LiveOut::from_registers(vec![]),
        );
        assert_eq!(report.exit_code, 0);
        assert_eq!(
            report.lines,
            vec!["EQUIVALENT: The two sequences are semantically equivalent.".to_string()]
        );
    }

    #[test]
    fn equiv_report_not_equivalent_smt_maps_to_exit_one() {
        let report = build_equiv_report(
            &semantics::EquivalenceResult::NotEquivalent,
            &[],
            &[],
            &LiveOut::from_registers(vec![]),
        );
        assert_eq!(report.exit_code, 1);
        assert_eq!(
            report.lines,
            vec![
                "NOT EQUIVALENT: The two sequences produce different results (verified by SMT)."
                    .to_string()
            ]
        );
    }

    #[test]
    fn equiv_report_unknown_maps_to_exit_two_with_reason() {
        let report = build_equiv_report(
            &semantics::EquivalenceResult::Unknown("solver timeout".to_string()),
            &[],
            &[],
            &LiveOut::from_registers(vec![]),
        );
        assert_eq!(report.exit_code, 2);
        assert_eq!(
            report.lines,
            vec![
                "UNKNOWN: Could not determine equivalence.".to_string(),
                "  Reason: solver timeout".to_string(),
            ]
        );
    }

    #[test]
    fn equiv_report_counterexample_reruns_sequences_and_formats_live_registers() {
        // seq1 computes x0 = x1 + 1; seq2 computes x0 = x1 + 2. With x1 = 5 in
        // the counterexample input the two diverge on x0 (6 vs 7). The expected
        // hex values below are worked out by hand, independent of the concrete
        // interpreter the builder calls — so the assertion can actually disagree
        // with the code.
        let seq1 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(2),
        }];

        let mut input = semantics::ConcreteMachineState::new_zeroed();
        input.set_register(Register::X1, semantics::ConcreteValue::new(5));
        let live_out = LiveOut::from_registers(vec![Register::X0, Register::X1]);

        let report = build_equiv_report(
            &semantics::EquivalenceResult::NotEquivalentFast(input),
            &seq1,
            &seq2,
            &live_out,
        );

        assert_eq!(report.exit_code, 1);
        assert_eq!(
            report.lines,
            vec![
                "NOT EQUIVALENT: The two sequences produce different results.".to_string(),
                "\nCounterexample found:".to_string(),
                "  Input state:".to_string(),
                "    x0 = 0x0000000000000000".to_string(),
                "    x1 = 0x0000000000000005".to_string(),
                "  Output from sequence 1:".to_string(),
                "    x0 = 0x0000000000000006".to_string(),
                "    x1 = 0x0000000000000005".to_string(),
                "  Output from sequence 2:".to_string(),
                "    x0 = 0x0000000000000007".to_string(),
                "    x1 = 0x0000000000000005".to_string(),
            ]
        );
    }
}

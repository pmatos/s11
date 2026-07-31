//! Integration coverage for the extracted `s11::report` module.
//!
//! Before the CLI report-rendering cluster moved out of `main.rs` these
//! functions lived in the binary crate and were unreachable from an
//! integration test — the only way to observe their output was to run the CLI
//! and capture stdout. Extracting them into `s11::report` makes the pure
//! rendering seam testable from outside the crate. Expected strings are the
//! byte-for-byte CLI contract.

use std::time::Duration;

use s11::ir::{Instruction, Operand, Register};
use s11::report::{
    build_equiv_report, fmt_bytes, fmt_dur, format_llm_timings, format_search_statistics,
    format_unsupported_mnemonic_ledger,
};
use s11::search::config::Algorithm;
use s11::search::llm::LlmTimings;
use s11::search::llm::ledger::UnsupportedMnemonicLedger;
use s11::search::result::SearchStatistics;
use s11::semantics::{self, LiveOut};

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
fn format_llm_timings_renders_smt_and_share_sections() {
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
    assert!(lines.iter().any(|l| l == "    SMT invoked:    2 times"));
    assert!(lines.iter().any(|l| l.contains("1.00 kB  avg")));
    assert!(lines.iter().any(|l| l.ends_with(" 10.00%")));
    assert!(lines.iter().any(|l| l.ends_with(" 60.00%")));
}

#[test]
fn build_equiv_report_formats_counterexample_and_exit_codes() {
    // seq1 computes x0 = x1 + 1; seq2 computes x0 = x1 + 2. With x1 = 5 the two
    // diverge on x0 (6 vs 7). Hex values worked out by hand, independent of the
    // concrete interpreter the builder calls.
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

    let equivalent = build_equiv_report(
        &semantics::EquivalenceResult::Equivalent,
        &[],
        &[],
        &LiveOut::from_registers(vec![]),
    );
    assert_eq!(equivalent.exit_code, 0);
    assert_eq!(
        equivalent.lines,
        vec!["EQUIVALENT: The two sequences are semantically equivalent.".to_string()]
    );
}

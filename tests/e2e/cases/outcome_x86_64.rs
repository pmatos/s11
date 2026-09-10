use crate::e2e::harness::{Case, ExecutionExpectation, Window, run};

/// Known one-instruction shortening: two identical `mov rax, 5` collapse to
/// one (see `tests/x86_asm/dup_mov_imm.s` and
/// `test_opt_x86_64_known_shortening` in `tests/integration/opt_test.rs`).
#[test]
fn dup_mov_imm_collapses_to_one_instruction() {
    run(&Case {
        name: "outcome-x86-64-dup-mov-imm",
        subcommand: Some("opt"),
        fixture: Some("x86_64/dup_mov_imm"),
        arch: Some("x86-64"),
        window: Some(Window {
            start_addr: "0x401000",
            end_addr: "0x40100e",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "30"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        execution: Some(ExecutionExpectation {
            expected_exit_code: 5,
        }),
        ..Default::default()
    });
}

use crate::e2e::harness::{Case, run};

#[test]
fn help_exits_zero_with_usage() {
    run(&Case {
        name: "cli-contract-help",
        subcommand: None,
        fixture: None,
        arch: None,
        window: None,
        args: &["--help"],
        expected_exit_code: 0,
        expected_stdout_contains: Some("s11 - Superoptimizer"),
        expected_instructions: None,
        execution: None,
    });
}

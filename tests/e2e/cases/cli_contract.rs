use crate::e2e::harness::{Case, Window, run};

#[test]
fn help_exits_zero_with_usage() {
    run(&Case {
        name: "cli-contract-help",
        args: &["--help"],
        expected_exit_code: 0,
        expected_stdout_contains: Some("s11 - Superoptimizer"),
        ..Default::default()
    });
}

#[test]
fn opt_without_binary_exits_with_usage_error() {
    run(&Case {
        name: "opt-without-binary",
        subcommand: Some("opt"),
        window: Some(Window {
            start_addr: "0x1000",
            end_addr: "0x1004",
        }),
        expected_exit_code: 2,
        expected_stderr_contains: &[
            "the following required arguments were not provided",
            "<BINARY>",
        ],
        ..Default::default()
    });
}

#[test]
fn opt_without_start_addr_exits_with_usage_error() {
    run(&Case {
        name: "opt-without-start-addr",
        subcommand: Some("opt"),
        args: &["/nonexistent-input.elf", "--end-addr", "0x1004"],
        expected_exit_code: 2,
        expected_stderr_contains: &["--start-addr"],
        ..Default::default()
    });
}

#[test]
fn opt_without_end_addr_exits_with_usage_error() {
    run(&Case {
        name: "opt-without-end-addr",
        subcommand: Some("opt"),
        args: &["/nonexistent-input.elf", "--start-addr", "0x1000"],
        expected_exit_code: 2,
        expected_stderr_contains: &["--end-addr"],
        ..Default::default()
    });
}

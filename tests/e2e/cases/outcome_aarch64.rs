use crate::e2e::harness::{Case, Window, fixture_exists, run};

#[test]
fn aarch64_dup_mov_imm_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/dup_mov_imm") {
        eprintln!(
            "Skipping aarch64_dup_mov_imm_collapses_to_one_instruction: \
             aarch64/dup_mov_imm fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    run(&Case {
        name: "aarch64-outcome-dup-mov-imm",
        subcommand: Some("opt"),
        fixture: Some("aarch64/dup_mov_imm"),
        arch: Some("aarch64"),
        window: Some(Window {
            start_addr: "0x4000d4",
            end_addr: "0x4000dc",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}

#[test]
fn aarch64_mov_add_fuse_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/mov_add_fuse") {
        eprintln!(
            "Skipping aarch64_mov_add_fuse_collapses_to_one_instruction: \
             aarch64/mov_add_fuse fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    run(&Case {
        name: "aarch64-outcome-mov-add-fuse",
        subcommand: Some("opt"),
        fixture: Some("aarch64/mov_add_fuse"),
        arch: Some("aarch64"),
        window: Some(Window {
            start_addr: "0x4000d4",
            end_addr: "0x4000dc",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}

#[test]
fn aarch64_sub_via_add_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/sub_via_add") {
        eprintln!(
            "Skipping aarch64_sub_via_add_collapses_to_one_instruction: \
             aarch64/sub_via_add fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    run(&Case {
        name: "aarch64-outcome-sub-via-add",
        subcommand: Some("opt"),
        fixture: Some("aarch64/sub_via_add"),
        arch: Some("aarch64"),
        window: Some(Window {
            start_addr: "0x4000d4",
            end_addr: "0x4000dc",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}

#[test]
fn aarch64_ldr_dead_load_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/ldr_dead_load") {
        eprintln!(
            "Skipping aarch64_ldr_dead_load_collapses_to_one_instruction: \
             aarch64/ldr_dead_load fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    run(&Case {
        name: "aarch64-outcome-ldr-dead-load",
        subcommand: Some("opt"),
        fixture: Some("aarch64/ldr_dead_load"),
        arch: Some("aarch64"),
        window: Some(Window {
            start_addr: "0x4000d8",
            end_addr: "0x4000e0",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}

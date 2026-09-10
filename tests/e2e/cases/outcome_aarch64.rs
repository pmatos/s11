use crate::e2e::harness::{
    Case, ExecutionExpectation, Window, fixture_exists, qemu_aarch64_available, run,
};

#[test]
fn aarch64_dup_mov_imm_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/dup_mov_imm") {
        eprintln!(
            "Skipping aarch64_dup_mov_imm_collapses_to_one_instruction: \
             aarch64/dup_mov_imm fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    if !qemu_aarch64_available() {
        eprintln!(
            "Skipping aarch64_dup_mov_imm_collapses_to_one_instruction: \
             qemu-aarch64-static not present. Install qemu-user-static first."
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
        execution: Some(ExecutionExpectation {
            expected_exit_code: 5,
        }),
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
    if !qemu_aarch64_available() {
        eprintln!(
            "Skipping aarch64_mov_add_fuse_collapses_to_one_instruction: \
             qemu-aarch64-static not present. Install qemu-user-static first."
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
        execution: Some(ExecutionExpectation {
            expected_exit_code: 1,
        }),
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
    if !qemu_aarch64_available() {
        eprintln!(
            "Skipping aarch64_sub_via_add_collapses_to_one_instruction: \
             qemu-aarch64-static not present. Install qemu-user-static first."
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
        execution: Some(ExecutionExpectation {
            expected_exit_code: 255,
        }),
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
    if !qemu_aarch64_available() {
        eprintln!(
            "Skipping aarch64_ldr_dead_load_collapses_to_one_instruction: \
             qemu-aarch64-static not present. Install qemu-user-static first."
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
        execution: Some(ExecutionExpectation {
            expected_exit_code: 5,
        }),
        ..Default::default()
    });
}

/// Dynamically-linked PIE counterpart to `aarch64_dup_mov_imm_...`: same
/// shortening identity, but exercises qemu's `-L <sysroot>` dynamic-linker
/// path (issue #838) rather than the other cases' `-no-pie -nostdlib`
/// fixed-address layout. `main`'s address (0x7a4) was found via
/// `aarch64-linux-gnu-objdump -d tests/e2e/fixtures/aarch64/dup_mov_pie`
/// against this session's build; re-run that if a toolchain upgrade ever
/// shifts glibc's crt startup size and this window goes stale.
#[test]
fn aarch64_dup_mov_pie_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/dup_mov_pie") {
        eprintln!(
            "Skipping aarch64_dup_mov_pie_collapses_to_one_instruction: \
             aarch64/dup_mov_pie fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    if !qemu_aarch64_available() {
        eprintln!(
            "Skipping aarch64_dup_mov_pie_collapses_to_one_instruction: \
             qemu-aarch64-static not present. Install qemu-user-static first."
        );
        return;
    }
    run(&Case {
        name: "aarch64-outcome-dup-mov-pie",
        subcommand: Some("opt"),
        fixture: Some("aarch64/dup_mov_pie"),
        arch: Some("aarch64"),
        window: Some(Window {
            start_addr: "0x7a4",
            end_addr: "0x7ac",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        execution: Some(ExecutionExpectation {
            expected_exit_code: 5,
        }),
        ..Default::default()
    });
}

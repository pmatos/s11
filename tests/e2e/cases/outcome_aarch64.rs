use crate::e2e::harness::{
    Case, ExecutionExpectation, Window, aarch64_symbol_address, fixture_exists,
    qemu_aarch64_available, run,
};

/// The behavioral (execute-and-diff) check for an AArch64 case, gated on
/// `qemu-aarch64-static` alone: `None` (with a note, not a full test skip)
/// when qemu is absent, so a host without qemu still runs the rest of the
/// case — in particular `expected_instructions`, which needs no execution at
/// all — instead of skipping the whole test the way an early `return` before
/// `run()` would.
fn qemu_gated_execution(case_name: &str, expected_exit_code: i32) -> Option<ExecutionExpectation> {
    if qemu_aarch64_available() {
        Some(ExecutionExpectation { expected_exit_code })
    } else {
        eprintln!(
            "Note: qemu-aarch64-static not present, skipping the behavioral execution check \
             for {case_name} (the static instruction-count check still runs). Install \
             qemu-user-static to enable it."
        );
        None
    }
}

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
        execution: qemu_gated_execution("aarch64-outcome-dup-mov-imm", 5),
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
        execution: qemu_gated_execution("aarch64-outcome-mov-add-fuse", 1),
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
        execution: qemu_gated_execution("aarch64-outcome-sub-via-add", 255),
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
        execution: qemu_gated_execution("aarch64-outcome-ldr-dead-load", 5),
        ..Default::default()
    });
}

/// Dynamically-linked PIE counterpart to `aarch64_dup_mov_imm_...`: same
/// shortening identity, but exercises qemu's `-L <sysroot>` dynamic-linker
/// path (issue #838) rather than the other cases' `-no-pie -nostdlib`
/// fixed-address layout. Unlike those fixed-address fixtures, `main`'s
/// address here depends on glibc's crt startup code size, which varies
/// across `gcc-aarch64-linux-gnu`/glibc builds — a hardcoded address
/// derived from one toolchain build went stale immediately on a different
/// one (observed: CI's `ubuntu-24.04` apt toolchain placed `main`
/// somewhere other than a value pinned against a different build), so the
/// window is resolved fresh via `aarch64_symbol_address` instead of
/// hardcoded.
#[test]
fn aarch64_dup_mov_pie_collapses_to_one_instruction() {
    if !fixture_exists("aarch64/dup_mov_pie") {
        eprintln!(
            "Skipping aarch64_dup_mov_pie_collapses_to_one_instruction: \
             aarch64/dup_mov_pie fixture not present. Run ./build_tests.sh first."
        );
        return;
    }
    let Some(main_addr) = aarch64_symbol_address("aarch64/dup_mov_pie", "main") else {
        eprintln!(
            "Skipping aarch64_dup_mov_pie_collapses_to_one_instruction: \
             could not resolve `main`'s address via aarch64-linux-gnu-nm."
        );
        return;
    };
    run(&Case {
        name: "aarch64-outcome-dup-mov-pie",
        subcommand: Some("opt"),
        fixture: Some("aarch64/dup_mov_pie"),
        arch: Some("aarch64"),
        extra_args: vec![
            "--start-addr".to_string(),
            format!("0x{main_addr:x}"),
            "--end-addr".to_string(),
            format!("0x{:x}", main_addr + 8),
        ],
        args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        execution: qemu_gated_execution("aarch64-outcome-dup-mov-pie", 5),
        ..Default::default()
    });
}

use crate::e2e::harness::{
    Case, ExecutionExpectation, Window, aarch64_symbol_address, aarch64_sysroot, fixture_exists,
    run,
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
    // Unlike the four -no-pie -nostdlib fixtures, this one is dynamically
    // linked and its execution genuinely requires qemu's `-L <sysroot>` to
    // resolve `ld-linux-aarch64.so.1` — `build_execution_command` treats a
    // missing sysroot as best-effort and silently omits `-L`, so without this
    // gate a host with `qemu-aarch64-static` but no working cross-toolchain
    // sysroot would hard-fail here under qemu's "could not open dynamic
    // linker" error instead of skipping cleanly.
    if aarch64_sysroot().is_none() {
        eprintln!(
            "Skipping aarch64_dup_mov_pie_collapses_to_one_instruction: \
             no AArch64 cross-toolchain sysroot with a usable ld-linux-aarch64.so.1 \
             found; qemu can't resolve this dynamically-linked fixture's dynamic linker."
        );
        return;
    }
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
        execution: Some(ExecutionExpectation {
            expected_exit_code: 5,
        }),
        ..Default::default()
    });
}

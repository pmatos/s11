use std::fs;
use std::path::{Path, PathBuf};

use crate::e2e::harness::{Case, Window, run};

/// Write a header-only ELF (no sections) with the given `e_machine`/class to
/// `path`, mirroring `write_minimal_riscv_elf` in `tests/integration/opt_test.rs`
/// generalized to any machine. `ElfPatcher::new()` only calls
/// `ElfBytes::minimal_parse` to read `e_machine`, so this is enough to reach
/// every CLI-contract check exercised in this file without a real compiled
/// binary.
fn write_bare_elf(path: &Path, machine: u16, is_64_bit: bool) {
    let (class_byte, header_size, header_size_offset) = if is_64_bit {
        (elf::abi::ELFCLASS64, 64, 52)
    } else {
        (elf::abi::ELFCLASS32, 52, 40)
    };
    let mut bytes = vec![0; header_size];
    bytes[..4].copy_from_slice(&elf::abi::ELFMAGIC);
    bytes[elf::abi::EI_CLASS] = class_byte;
    bytes[elf::abi::EI_DATA] = elf::abi::ELFDATA2LSB;
    bytes[elf::abi::EI_VERSION] = elf::abi::EV_CURRENT;
    bytes[16..18].copy_from_slice(&elf::abi::ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&(elf::abi::EV_CURRENT as u32).to_le_bytes());
    bytes[header_size_offset..header_size_offset + 2]
        .copy_from_slice(&(header_size as u16).to_le_bytes());

    fs::write(path, &bytes).expect("write synthesized bare ELF header");
}

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

#[test]
fn opt_rejects_invalid_start_address_format() {
    let dir = tempfile::tempdir().expect("create fixture directory");
    let binary: PathBuf = dir.path().join("program.elf");
    write_bare_elf(&binary, elf::abi::EM_AARCH64, true);

    run(&Case {
        name: "opt-rejects-invalid-start-address-format",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(Window {
            start_addr: "zz",
            end_addr: "0x1004",
        }),
        expected_exit_code: 1,
        expected_stderr_contains: &["Error parsing start address", "Invalid hex address: zz"],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_invalid_end_address_format() {
    let dir = tempfile::tempdir().expect("create fixture directory");
    let binary: PathBuf = dir.path().join("program.elf");
    write_bare_elf(&binary, elf::abi::EM_AARCH64, true);

    run(&Case {
        name: "opt-rejects-invalid-end-address-format",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(Window {
            start_addr: "0x1000",
            end_addr: "zz",
        }),
        expected_exit_code: 1,
        expected_stderr_contains: &["Error parsing end address", "Invalid hex address: zz"],
        ..Default::default()
    });
}

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

    let parsed = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&bytes)
        .expect("generated fixture should be a valid ELF header");
    assert_eq!(parsed.ehdr.e_machine, machine);

    fs::write(path, &bytes).expect("write synthesized bare ELF header");
}

/// Create a tempdir containing a synthesized ELF for `machine`/`is_64_bit`
/// at `program.elf`. Returns the `TempDir` alongside the binary path so
/// callers that also need other paths inside the same directory (output
/// files, symlinks) can keep using `dir.path()`.
fn setup_binary(machine: u16, is_64_bit: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create fixture directory");
    let binary = dir.path().join("program.elf");
    write_bare_elf(&binary, machine, is_64_bit);
    (dir, binary)
}

/// The AArch64 fixture most CLI-contract cases in this file need.
fn setup_aarch64_binary() -> (tempfile::TempDir, PathBuf) {
    setup_binary(elf::abi::EM_AARCH64, true)
}

#[test]
fn help_exits_zero_with_usage() {
    run(&Case {
        name: "cli-contract-help",
        args: &["--help"],
        expected_exit_code: 0,
        expected_stdout_contains: &["s11 - Superoptimizer"],
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
    let (_dir, binary) = setup_aarch64_binary();

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
    let (_dir, binary) = setup_aarch64_binary();

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

#[test]
fn opt_rejects_declared_x86_64_against_aarch64_elf() {
    let (_dir, binary) = setup_aarch64_binary();

    run(&Case {
        name: "opt-rejects-declared-x86-64-against-aarch64-elf",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("x86-64"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &["Architecture mismatch: --arch x86-64 but ELF reports aarch64"],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_declared_aarch64_against_x86_64_elf() {
    let (_dir, binary) = setup_binary(elf::abi::EM_X86_64, true);

    run(&Case {
        name: "opt-rejects-declared-aarch64-against-x86-64-elf",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("aarch64"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &["Architecture mismatch: --arch aarch64 but ELF reports x86-64"],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_riscv32_target_matching_elf_machine() {
    let (_dir, binary) = setup_binary(elf::abi::EM_RISCV, false);

    run(&Case {
        name: "opt-rejects-riscv32-target-matching-elf-machine",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("riscv32"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &["RISC-V optimization is not yet supported"],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_riscv64_target_matching_elf_machine() {
    let (_dir, binary) = setup_binary(elf::abi::EM_RISCV, true);

    run(&Case {
        name: "opt-rejects-riscv64-target-matching-elf-machine",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("riscv64"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &["RISC-V optimization is not yet supported"],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_riscv32_target_mismatched_with_elf_machine() {
    let (_dir, binary) = setup_aarch64_binary();

    run(&Case {
        name: "opt-rejects-riscv32-target-mismatched-with-elf-machine",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("riscv32"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &[
            "Architecture mismatch: --arch riscv32 but ELF reports aarch64",
        ],
        ..Default::default()
    });
}

#[test]
fn opt_rejects_riscv64_target_mismatched_with_elf_machine() {
    let (_dir, binary) = setup_aarch64_binary();

    run(&Case {
        name: "opt-rejects-riscv64-target-mismatched-with-elf-machine",
        subcommand: Some("opt"),
        binary: Some(binary),
        arch: Some("riscv64"),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &[
            "Architecture mismatch: --arch riscv64 but ELF reports aarch64",
        ],
        ..Default::default()
    });
}

/// A syntactically valid window for cases that fail before any search runs,
/// so the exact bounds never matter.
fn placeholder_window() -> Window {
    Window {
        start_addr: "0x0",
        end_addr: "0x1",
    }
}

#[test]
fn opt_refuses_existing_explicit_output() {
    let (dir, binary) = setup_aarch64_binary();
    let out = dir.path().join("out.bin");
    let sentinel = b"unrelated file contents";
    fs::write(&out, sentinel).expect("seed existing output");

    run(&Case {
        name: "opt-refuses-existing-explicit-output",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        extra_args: vec!["-o".to_string(), out.to_string_lossy().into_owned()],
        expected_exit_code: 1,
        expected_stderr_contains: &["output path already exists", "--force"],
        ..Default::default()
    });

    assert_eq!(
        fs::read(&out).expect("read refused output"),
        sentinel,
        "refused output must remain unchanged"
    );
}

#[test]
fn opt_refuses_existing_derived_output() {
    let (dir, binary) = setup_aarch64_binary();
    let derived_output = dir.path().join("program_optimized.elf");
    let sentinel = b"previous optimization result";
    fs::write(&derived_output, sentinel).expect("seed derived output");

    run(&Case {
        name: "opt-refuses-existing-derived-output",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        expected_exit_code: 1,
        expected_stderr_contains: &["output path already exists", "--force"],
        ..Default::default()
    });

    assert_eq!(
        fs::read(&derived_output).expect("read refused output"),
        sentinel,
        "refused derived output must remain unchanged"
    );
}

#[test]
fn opt_rejects_missing_output_parent() {
    let (dir, binary) = setup_aarch64_binary();
    let output_path = dir.path().join("missing").join("output.elf");

    run(&Case {
        name: "opt-rejects-missing-output-parent",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        extra_args: vec!["-o".to_string(), output_path.to_string_lossy().into_owned()],
        expected_exit_code: 1,
        expected_stderr_contains: &["output parent directory", "does not exist"],
        ..Default::default()
    });

    assert!(!output_path.exists(), "bad output must not be created");
}

#[test]
fn opt_rejects_trailing_separator_output() {
    let (dir, binary) = setup_aarch64_binary();
    let mut output_arg = dir.path().join("result").into_os_string();
    output_arg.push(std::path::MAIN_SEPARATOR_STR);
    let output_path = PathBuf::from(&output_arg);

    run(&Case {
        name: "opt-rejects-trailing-separator-output",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        extra_args: vec!["-o".to_string(), output_arg.to_string_lossy().into_owned()],
        expected_exit_code: 1,
        expected_stderr_contains: &["output path", "must name a file"],
        ..Default::default()
    });

    assert!(!output_path.exists(), "bad output must not be created");
}

#[cfg(unix)]
#[test]
fn opt_rejects_unwritable_output_parent() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, binary) = setup_aarch64_binary();
    let read_only_dir = dir.path().join("read-only");
    fs::create_dir(&read_only_dir).expect("create output parent");
    fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o555))
        .expect("make output parent read-only");

    // Root ignores the 0o555 mode, so the precondition this test needs does
    // not hold there (containerized local/CI runs are commonly root). Probe
    // rather than assert a guard that cannot fire.
    let probe = read_only_dir.join(".writability-probe");
    if fs::File::create(&probe).is_ok() {
        let _ = fs::remove_file(&probe);
        eprintln!(
            "Skipping unwritable-parent opt e2e case: read-only mode not enforced (running as root?)"
        );
        return;
    }

    let output_path = read_only_dir.join("output.elf");

    run(&Case {
        name: "opt-rejects-unwritable-output-parent",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        extra_args: vec!["-o".to_string(), output_path.to_string_lossy().into_owned()],
        expected_exit_code: 1,
        expected_stderr_contains: &["output parent directory", "not writable"],
        ..Default::default()
    });

    assert!(!output_path.exists(), "bad output must not be created");
}

#[cfg(unix)]
#[test]
fn opt_refuses_symlink_output_even_with_force() {
    let (dir, binary) = setup_aarch64_binary();
    let victim = dir.path().join("unrelated.txt");
    let victim_bytes = b"unrelated file contents";
    fs::write(&victim, victim_bytes).expect("seed unrelated file");
    let link = dir.path().join("out.elf");
    std::os::unix::fs::symlink(&victim, &link).expect("create symlink output");

    run(&Case {
        name: "opt-refuses-symlink-output-even-with-force",
        subcommand: Some("opt"),
        binary: Some(binary),
        window: Some(placeholder_window()),
        extra_args: vec![
            "-o".to_string(),
            link.to_string_lossy().into_owned(),
            "--force".to_string(),
        ],
        expected_exit_code: 1,
        expected_stderr_contains: &["is a symlink", "unrelated.txt"],
        ..Default::default()
    });

    assert_eq!(
        fs::read(&victim).expect("read unrelated file"),
        victim_bytes,
        "the symlink target must be untouched"
    );
}

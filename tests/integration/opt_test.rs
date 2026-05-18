use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn check_test_binary(path: &PathBuf) {
    if !path.exists() {
        panic!(
            "Test binary not found: {:?}\nCurrent directory: {:?}\nBinaries directory contents: {:?}",
            path,
            std::env::current_dir().unwrap(),
            std::fs::read_dir("binaries")
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|_| vec![])
        );
    }
}

fn get_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_s11"))
}

fn assert_bytes_at_addr(elf_path: &Path, addr: u64, expected: &[u8], label: &str) {
    let data = std::fs::read(elf_path).expect("read ELF for byte-pattern check");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data)
        .expect("parse ELF for byte-pattern check");
    let section_headers = elf.section_headers().expect("ELF section headers");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 {
            continue;
        }
        let sec_start = section.sh_addr;
        let sec_end = sec_start + section.sh_size;
        if addr < sec_start || addr + expected.len() as u64 > sec_end {
            continue;
        }
        let offset_in_section = (addr - sec_start) as usize;
        let file_offset = section.sh_offset as usize + offset_in_section;
        let actual = &data[file_offset..file_offset + expected.len()];
        assert_eq!(
            actual, expected,
            "fixture {:?} drifted: bytes at 0x{:x} no longer match {} encoding {:02x?}; got {:02x?}",
            elf_path, addr, label, expected, actual
        );
        return;
    }
    panic!(
        "address 0x{:x} not in any executable section of {:?}",
        addr, elf_path
    );
}

fn executable_window(path: &Path, width: u64) -> (u64, u64) {
    let data = std::fs::read(path).expect("read test ELF");
    let elf =
        elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).expect("parse test ELF");
    let section_headers = elf.section_headers().expect("read section headers");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 || section.sh_size < width {
            continue;
        }

        // These opt tests use AArch64 fixture binaries, whose instructions are 4-byte aligned.
        let start = section.sh_addr.next_multiple_of(4);
        if start + width <= section.sh_addr + section.sh_size {
            return (start, start + width);
        }
    }

    panic!("no executable window of {width} bytes found in {path:?}");
}

fn assert_opt_arch_mismatch_rejected(test_elf: &Path, arch: &str) {
    let output = Command::new(get_binary_path())
        .arg("opt")
        .arg(test_elf)
        .arg("--arch")
        .arg(arch)
        .arg("--start-addr")
        .arg("0x0")
        .arg("--end-addr")
        .arg("0x4")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with mismatched --arch"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Architecture mismatch"),
        "Should reject before optimization, stderr: {}",
        stderr
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("Optimizing ELF binary") && !stdout.contains("Optimizing x86 ELF binary"),
        "Should reject before starting optimization, stdout: {}",
        stdout
    );
}

#[test]
fn test_opt_basic_functionality() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("arrays_debug");

    check_test_binary(&test_elf);

    // We do not use executable_window here because the start of .init in
    // arrays_debug is `paciasp` (an unsupported HINT), which the AArch64
    // optimization path now correctly rejects rather than silently dropping.
    let start_addr: u64 = 0x5cc;
    let end_addr: u64 = 0x5d0;
    assert_bytes_at_addr(
        &test_elf,
        start_addr,
        &[0x10, 0xe2, 0x3f, 0x91],
        "add x16, x16, #0xff8",
    );

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{end_addr:x}"))
        .output()
        .expect("Failed to execute s11");

    // Check that optimized binary was created first, before other assertions
    let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("arrays_debug_optimized");

    if !output.status.success() {
        // Clean up in case of failure and print debug info
        let _ = fs::remove_file(&optimized_path);
        panic!(
            "Command failed with status: {:?}\nstderr: {}\nstdout: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that optimization completed successfully
    assert!(
        stdout.contains("Optimization completed successfully"),
        "Should complete optimization successfully"
    );

    // Check that it shows the expected steps
    assert!(
        stdout.contains("Optimizing ELF binary"),
        "Should show optimization message"
    );
    assert!(
        stdout.contains("Address window"),
        "Should show address window"
    );
    assert!(
        stdout.contains("Window is within section"),
        "Should validate window"
    );
    assert!(
        stdout.contains("Disassembled"),
        "Should disassemble instructions"
    );
    assert!(stdout.contains("Converted"), "Should convert to IR");
    assert!(
        stdout.contains("Reassembled"),
        "Should reassemble instructions"
    );
    assert!(
        stdout.contains("Created optimized binary"),
        "Should create output file"
    );

    assert!(
        optimized_path.exists(),
        "Optimized binary should be created at: {:?}",
        optimized_path
    );

    // Clean up
    let _ = fs::remove_file(optimized_path);
}

#[test]
fn test_opt_requires_binary() {
    let binary = get_binary_path();

    let output = Command::new(binary)
        .arg("opt")
        .arg("--start-addr")
        .arg("0x1000")
        .arg("--end-addr")
        .arg("0x1004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail without binary"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: the following required arguments were not provided")
            || stderr.contains("error:"),
        "Should print error about missing arguments"
    );
}

#[test]
fn test_opt_requires_start_addr() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--end-addr")
        .arg("0x1004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail without start address"
    );
}

#[test]
fn test_opt_requires_end_addr() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg("0x1000")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail without end address"
    );
}

#[test]
fn test_opt_invalid_address_format() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg("invalid")
        .arg("--end-addr")
        .arg("0x1004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with invalid address"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error parsing"),
        "Should show parsing error"
    );
}

#[test]
fn test_opt_rejects_arch_mismatch_before_optimization() {
    let aarch64_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    check_test_binary(&aarch64_elf);
    assert_opt_arch_mismatch_rejected(&aarch64_elf, "x86-64");
    assert_opt_arch_mismatch_rejected(&aarch64_elf, "x86-32");

    let x86_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    if x86_elf.exists() {
        assert_opt_arch_mismatch_rejected(&x86_elf, "aarch64");
    } else {
        eprintln!(
            "Skipping x86-64 opt mismatch case: {:?} not present (run build_tests.sh)",
            x86_elf
        );
    }
}

#[test]
fn test_opt_address_out_of_bounds() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg("0x1000000") // Way out of bounds
        .arg("--end-addr")
        .arg("0x1000004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with out of bounds address"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not within any executable section"),
        "Should show bounds error"
    );
}

// Note: test_opt_conflicts_with_disasm removed since subcommands naturally prevent conflicts

#[test]
fn test_opt_address_alignment() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");
    let (start_addr, _) = executable_window(&test_elf, 8);

    // Test with unaligned addresses (not 4-byte aligned)
    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg(format!("0x{:x}", start_addr + 1)) // Unaligned
        .arg("--end-addr")
        .arg(format!("0x{:x}", start_addr + 5)) // Unaligned
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with unaligned addresses"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("4-byte aligned"),
        "Should show alignment error"
    );
}

#[test]
fn test_opt_rejects_unsupported_instruction_window() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&test_elf);
    assert_bytes_at_addr(
        &test_elf,
        0x59c,
        &[0xfd, 0x7b, 0xbf, 0xa9],
        "stp x29, x30, [sp, #-0x10]!",
    );

    // 0x59c in loops_debug is a `stp x29, x30, [sp, #-0x10]!` — an unsupported
    // mnemonic for the AArch64 optimization path. Targeting a 4-byte window on
    // this single instruction should abort before any output file is written.
    let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug_optimized");
    let _ = fs::remove_file(&optimized_path);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg("0x59c")
        .arg("--end-addr")
        .arg("0x5a0")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "opt must reject an AArch64 window containing an unsupported instruction.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported instruction") && stderr.contains("stp"),
        "stderr should identify the offending mnemonic; got: {stderr}",
    );
    assert!(
        stderr.contains("0x59c"),
        "stderr should report the offending address; got: {stderr}",
    );

    assert!(
        !optimized_path.exists(),
        "no optimized binary should be written when conversion fails: {:?}",
        optimized_path,
    );
}

#[test]
fn test_opt_hex_address_formats() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");
    let (start_addr, end_addr) = executable_window(&test_elf, 4);

    // Test different hex formats
    let test_cases = [
        (format!("0x{start_addr:x}"), format!("0x{end_addr:x}")), // 0x prefix
        (format!("0X{start_addr:x}"), format!("0X{end_addr:x}")), // 0X prefix
        (format!("{start_addr:x}"), format!("{end_addr:x}")),     // No prefix
    ];

    for (start, end) in test_cases {
        let output = Command::new(&binary)
            .arg("opt")
            .arg(&test_elf)
            .arg("--start-addr")
            .arg(&start)
            .arg("--end-addr")
            .arg(&end)
            .output()
            .expect("Failed to execute s11");

        // This might fail for other reasons (like unsupported instructions),
        // but should not fail due to address parsing
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("Error parsing"),
                "Should not fail address parsing for format: {}",
                start
            );
        }

        // Clean up any created files
        let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join("simple_debug_optimized");
        let _ = fs::remove_file(optimized_path);
    }
}

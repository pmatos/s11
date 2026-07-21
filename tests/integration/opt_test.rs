use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use capstone::prelude::*;
use s11::parser::{LineResult, parse_line};

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

fn write_minimal_riscv_elf(class: elf::file::Class) -> tempfile::NamedTempFile {
    let (class_byte, header_size, header_size_offset) = match class {
        elf::file::Class::ELF32 => (elf::abi::ELFCLASS32, 52, 40),
        elf::file::Class::ELF64 => (elf::abi::ELFCLASS64, 64, 52),
    };
    let mut bytes = vec![0; header_size];
    bytes[..4].copy_from_slice(&elf::abi::ELFMAGIC);
    bytes[elf::abi::EI_CLASS] = class_byte;
    bytes[elf::abi::EI_DATA] = elf::abi::ELFDATA2LSB;
    bytes[elf::abi::EI_VERSION] = elf::abi::EV_CURRENT;
    bytes[16..18].copy_from_slice(&elf::abi::ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&elf::abi::EM_RISCV.to_le_bytes());
    bytes[20..24].copy_from_slice(&(elf::abi::EV_CURRENT as u32).to_le_bytes());
    bytes[header_size_offset..header_size_offset + 2]
        .copy_from_slice(&(header_size as u16).to_le_bytes());

    let file = tempfile::NamedTempFile::new().expect("create temporary RISC-V ELF");
    fs::write(file.path(), &bytes).expect("write temporary RISC-V ELF");

    let parsed = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&bytes)
        .expect("generated fixture should be a valid ELF header");
    assert_eq!(parsed.ehdr.class, class);
    assert_eq!(parsed.ehdr.e_machine, elf::abi::EM_RISCV);

    file
}

// AArch64 only: scans at 4-byte-aligned offsets in every executable section
// of `elf_path` for a little-endian AArch64 encoding matching `expected`
// under `mask` (i.e. `bytes[i] & mask[i] == expected[i] & mask[i]` for each
// of the 4 bytes). A `mask` of all 0xff means exact match; a partial mask
// lets opt tests match any `add x16, x16, #N` PLT trampoline regardless of
// the build's GOT layout, etc.
fn find_encoding_masked(elf_path: &Path, expected: &[u8; 4], mask: &[u8; 4], label: &str) -> u64 {
    let data = std::fs::read(elf_path).expect("read ELF for pattern scan");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data)
        .expect("parse ELF for pattern scan");
    let section_headers = elf.section_headers().expect("ELF section headers");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 {
            continue;
        }
        let file_start = section.sh_offset as usize;
        let size = section.sh_size as usize;
        if size < expected.len() {
            continue;
        }
        let file_end = file_start
            .checked_add(size)
            .expect("executable section range should not overflow usize");
        let bytes = data
            .get(file_start..file_end)
            .expect("executable section range should be present in ELF data");
        for off in (0..size - expected.len() + 1).step_by(4) {
            if (0..4).all(|i| bytes[off + i] & mask[i] == expected[i] & mask[i]) {
                return section.sh_addr + off as u64;
            }
        }
    }
    panic!(
        "encoding matching {:02x?} (mask {:02x?}, {}) not found in any executable section of {:?}",
        expected, mask, label, elf_path
    );
}

fn find_supported_aarch64_instruction_window(
    elf_path: &Path,
    instruction_count: usize,
) -> (u64, u64) {
    assert!(
        instruction_count > 0,
        "instruction window must contain at least one instruction"
    );

    let data = std::fs::read(elf_path).expect("read ELF for supported-window scan");
    let elf = elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data)
        .expect("parse ELF for supported-window scan");
    let section_headers = elf.section_headers().expect("ELF section headers");
    let cs = Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .expect("create AArch64 Capstone disassembler");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 {
            continue;
        }

        let file_start = section.sh_offset as usize;
        let size = section.sh_size as usize;
        if size < instruction_count * 4 {
            continue;
        }
        let bytes = &data[file_start..file_start + size];
        let instructions = cs
            .disasm_all(bytes, section.sh_addr)
            .expect("disassemble executable section for supported-window scan");
        let instructions: Vec<_> = instructions.iter().collect();

        for window in instructions.windows(instruction_count) {
            let first = window[0].address();
            let mut next_address = first;
            let supported_straight_line = window.iter().all(|instruction| {
                if instruction.address() != next_address || instruction.bytes().len() != 4 {
                    return false;
                }
                next_address += 4;

                let mnemonic = instruction.mnemonic().unwrap_or("");
                let op_str = instruction.op_str().unwrap_or("");
                let line = if op_str.trim().is_empty() {
                    mnemonic.to_string()
                } else {
                    format!("{mnemonic} {}", op_str.trim())
                };

                match parse_line(&line) {
                    Ok(LineResult::Instruction(instruction)) => !instruction.is_terminator(),
                    Ok(LineResult::Skip) | Err(_) => false,
                }
            });

            if supported_straight_line {
                return (first, first + instruction_count as u64 * 4);
            }
        }
    }

    panic!(
        "no supported {instruction_count}-instruction AArch64 window found in any executable section of {elf_path:?}"
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

fn file_offset_for_executable_addr(path: &Path, addr: u64) -> usize {
    let data = std::fs::read(path).expect("read test ELF");
    let elf =
        elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).expect("parse test ELF");
    let section_headers = elf.section_headers().expect("read section headers");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 {
            continue;
        }

        let section_end = section
            .sh_addr
            .checked_add(section.sh_size)
            .expect("executable section address range should not overflow");
        if !(section.sh_addr..section_end).contains(&addr) {
            continue;
        }

        let file_offset = section
            .sh_offset
            .checked_add(addr - section.sh_addr)
            .expect("executable section file range should not overflow")
            as usize;
        data.get(file_offset..file_offset + 4)
            .expect("executable address should map to bytes in ELF data");
        return file_offset;
    }

    panic!("executable address 0x{addr:x} not found in {path:?}");
}

fn assert_opt_arch_mismatch_rejected(test_elf: &Path, arch: &str, detected_arch: &str) {
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
    let expected_message =
        format!("Architecture mismatch: --arch {arch} but ELF reports {detected_arch}");
    assert!(
        stderr.trim_start().starts_with(&expected_message),
        "Should reject before optimization with CLI architecture names, stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("Aarch64") && !stderr.contains("X86_64") && !stderr.contains("X86_32"),
        "Should not report Rust architecture variant names, stderr: {}",
        stderr
    );
    assert!(
        stderr.contains(&format!("--arch {arch}")),
        "Should print requested CLI arch spelling, stderr: {}",
        stderr
    );
    assert!(
        stderr.contains(&format!("ELF reports {detected_arch}")),
        "Should print detected CLI arch spelling, stderr: {}",
        stderr
    );
    assert!(
        !stderr.contains("Aarch64") && !stderr.contains("X86_64") && !stderr.contains("X86_32"),
        "Should not print Rust variant names, stderr: {}",
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

    // Avoid the unsupported .init PAC instruction while still exercising a
    // parser-supported, straight-line multi-instruction optimization window.
    let (start_addr, end_addr) = find_supported_aarch64_instruction_window(&test_elf, 4);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--algorithm")
        .arg("stochastic")
        .arg("--iterations")
        .arg("64")
        .arg("--seed")
        .arg("0")
        .arg("--timeout")
        .arg("5")
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
    assert!(
        stdout.contains("Disassembled 4 instructions"),
        "Should disassemble a multi-instruction window; stdout: {stdout}"
    );
    assert!(stdout.contains("Converted"), "Should convert to IR");
    assert!(
        stdout.contains("Converted 4 instructions"),
        "Should convert a multi-instruction window to IR; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Running stochastic (MCMC) search"),
        "Should run the bounded stochastic search path; stdout: {stdout}"
    );
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
    assert_opt_arch_mismatch_rejected(&aarch64_elf, "x86-64", "aarch64");
    assert_opt_arch_mismatch_rejected(&aarch64_elf, "x86-32", "aarch64");

    let x86_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    if x86_elf.exists() {
        assert_opt_arch_mismatch_rejected(&x86_elf, "aarch64", "x86-64");
    } else {
        eprintln!(
            "Skipping x86-64 opt mismatch case: {:?} not present (run build_tests.sh)",
            x86_elf
        );
    }
}

#[test]
fn test_opt_matching_riscv_arch_reports_unsupported() {
    const UNSUPPORTED_MESSAGE: &str =
        "RISC-V optimization is not yet supported (ISA traits available but not integrated)";

    for (arch, class) in [
        ("riscv32", elf::file::Class::ELF32),
        ("riscv64", elf::file::Class::ELF64),
    ] {
        let test_elf = write_minimal_riscv_elf(class);
        let output = Command::new(get_binary_path())
            .arg("opt")
            .arg(test_elf.path())
            .arg("--arch")
            .arg(arch)
            .arg("--start-addr")
            .arg("0x0")
            .arg("--end-addr")
            .arg("0x4")
            .output()
            .expect("execute s11 opt");

        assert!(!output.status.success(), "{arch} optimization should fail");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            format!("{UNSUPPORTED_MESSAGE}\n"),
            "{arch} should report the RISC-V support boundary"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("Error reading ELF"),
            "{arch} should not expose an ELF-reading error"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("Optimizing ELF binary")
                && !stdout.contains("Optimizing x86 ELF binary"),
            "{arch} should be rejected before optimization starts, stdout: {stdout}"
        );
    }
}

#[test]
fn test_opt_mismatched_riscv_arch_reports_arch_mismatch() {
    let aarch64_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");
    check_test_binary(&aarch64_elf);

    let output = Command::new(get_binary_path())
        .arg("opt")
        .arg(&aarch64_elf)
        .arg("--arch")
        .arg("riscv64")
        .arg("--start-addr")
        .arg("0x0")
        .arg("--end-addr")
        .arg("0x4")
        .output()
        .expect("execute s11 opt");

    assert!(
        !output.status.success(),
        "mismatched --arch riscv64 should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("Architecture mismatch: --arch riscv64 but ELF reports aarch64"),
        "an AArch64 ELF requested as riscv64 should report the mismatch, not the RISC-V \
         support boundary; stderr: {stderr}"
    );
}

#[test]
fn test_opt_riscv_arch_with_missing_file_reports_io_error() {
    let output = Command::new(get_binary_path())
        .arg("opt")
        .arg("/nonexistent/path/does-not-exist.elf")
        .arg("--arch")
        .arg("riscv64")
        .arg("--start-addr")
        .arg("0x0")
        .arg("--end-addr")
        .arg("0x4")
        .output()
        .expect("execute s11 opt");

    assert!(
        !output.status.success(),
        "a missing file requested as riscv64 should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("Error reading ELF"),
        "a missing file should report the I/O error, not the RISC-V support boundary; \
         stderr: {stderr}"
    );
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
fn test_opt_rejects_partially_decoded_window_with_first_bad_address() {
    let binary = get_binary_path();
    let source_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&source_elf);

    let (start_addr, end_addr) = executable_window(&source_elf, 8);
    let first_bad_addr = start_addr + 4;

    let tmp_dir = tempfile::tempdir().expect("create temp fixture dir");
    let test_elf = tmp_dir.path().join("loops_debug");
    fs::copy(&source_elf, &test_elf).expect("copy ELF fixture to tmp");

    let bad_offset = file_offset_for_executable_addr(&test_elf, first_bad_addr);
    let mut data = fs::read(&test_elf).expect("read temp ELF");
    data[bad_offset..bad_offset + 4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    fs::write(&test_elf, data).expect("write corrupted temp ELF");

    let optimized_path = tmp_dir.path().join("loops_debug_optimized");
    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{end_addr:x}"))
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "opt must reject an AArch64 window Capstone only partially decoded.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not fully decoded"),
        "stderr should report the byte-coverage failure; got: {stderr}",
    );
    assert!(
        stderr.contains(&format!("0x{first_bad_addr:x}")),
        "stderr should report the first undecoded address 0x{first_bad_addr:x}; got: {stderr}",
    );
    assert!(
        !optimized_path.exists(),
        "no optimized binary should be written when decode coverage fails: {:?}",
        optimized_path,
    );
}

#[test]
fn test_opt_rejects_unsupported_instruction_window() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&test_elf);

    // Scan loops_debug for the first `paciasp` — pointer authentication is
    // unsupported by the AArch64 optimization path. (Memory ops moved to
    // supported in issue #68, so the old `stp` fixture became valid; see
    // ADR-0007.) Targeting a 4-byte window on this instruction must abort
    // before any output file is written.
    let start_addr = find_encoding_masked(
        &test_elf,
        &[0x3f, 0x23, 0x03, 0xd5],
        &[0xff, 0xff, 0xff, 0xff],
        "paciasp",
    );
    let end_addr = start_addr + 4;

    let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug_optimized");
    let _ = fs::remove_file(&optimized_path);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{end_addr:x}"))
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
        stderr.contains("unsupported instruction") && stderr.contains("paciasp"),
        "stderr should identify the offending mnemonic; got: {stderr}",
    );
    assert!(
        stderr.contains(&format!("0x{start_addr:x}")),
        "stderr should report the offending address 0x{start_addr:x}; got: {stderr}",
    );
    assert!(
        !stderr.contains("cannot optimize"),
        "stderr should avoid redundant optimization framing; got: {stderr}",
    );

    assert!(
        !optimized_path.exists(),
        "no optimized binary should be written when conversion fails: {:?}",
        optimized_path,
    );
}

/// Helper for memory-op integration tests: assert that `s11 opt` on the
/// given single-instruction window succeeds.
///
/// Each test copies the source ELF to a unique tempdir so concurrent
/// `cargo test` runs don't collide on the `<input>_optimized` artifact
/// the binary always writes alongside its input. The tempdir is cleaned
/// up automatically when the helper returns or panics.
fn assert_opt_succeeds_on_window(source_elf: &Path, start_addr: u64) {
    let binary = get_binary_path();
    let end_addr = start_addr + 4;

    let tmp_dir = tempfile::tempdir().expect("create temp fixture dir");
    let test_elf = tmp_dir.path().join("loops_debug");
    fs::copy(source_elf, &test_elf).expect("copy ELF fixture to tmp");
    let optimized_path = tmp_dir.path().join("loops_debug_optimized");

    let output = Command::new(&binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{end_addr:x}"))
        .output()
        .expect("Failed to execute s11");

    if !output.status.success() {
        panic!(
            "opt failed on memory-op window 0x{start_addr:x}.\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ok = stdout.contains("Optimization completed successfully");
    let optimized_exists = optimized_path.exists();

    assert!(
        ok,
        "memory-op window must round-trip end-to-end; stdout: {stdout}",
    );
    assert!(
        optimized_exists,
        "optimized binary must be created at {:?}",
        optimized_path,
    );
}

#[test]
fn test_opt_accepts_stp_writeback_window() {
    // STP pre-index `stp x29, x30, [sp, #-16]!` — the standard AArch64
    // function-prologue spill. Issue #68 moves this from "unsupported" to
    // "supported"; this test pins that decision at the CLI boundary.
    let source_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&source_elf);
    let start_addr = find_encoding_masked(
        &source_elf,
        &[0xfd, 0x7b, 0xbf, 0xa9],
        &[0xff, 0xff, 0xff, 0xff],
        "stp x29, x30, [sp, #-16]!",
    );
    assert_opt_succeeds_on_window(&source_elf, start_addr);
}

#[test]
fn test_opt_accepts_ldp_postindex_window() {
    // LDP post-index `ldp x29, x30, [sp], #16` — function-epilogue
    // restore. Verifies the post-index addressing mode runs cleanly
    // through disasm → IR → SMT → reassemble.
    let source_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&source_elf);
    let start_addr = find_encoding_masked(
        &source_elf,
        &[0xfd, 0x7b, 0xc1, 0xa8],
        &[0xff, 0xff, 0xff, 0xff],
        "ldp x29, x30, [sp], #16",
    );
    assert_opt_succeeds_on_window(&source_elf, start_addr);
}

#[test]
fn test_opt_accepts_ldr_positive_offset_window() {
    // LDR X-form unsigned-offset family `ldr xN, [xM{, #imm}]` — covers
    // the RefOffset / Uscaled encoding path (vs the LDUR Sbits path tested
    // at the assembler unit-test layer). The exact (Rt, Rn, imm) tuple
    // varies across `loops_debug` rebuilds (PLT layout depends on the
    // toolchain), so the mask wildcards them and pins only the class bits:
    // byte 3 = 11111001 (size=11, V=1, class=001, opc=01); byte 2 top
    // bits 7-6 = 01 (LDR unsigned-offset variant).
    let source_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("loops_debug");
    check_test_binary(&source_elf);
    let start_addr = find_encoding_masked(
        &source_elf,
        &[0x00, 0x00, 0x40, 0xf9],
        &[0x00, 0x00, 0xc0, 0xff],
        "ldr xN, [xM{, #imm}]",
    );
    assert_opt_succeeds_on_window(&source_elf, start_addr);
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

// ============================================================================
// x86 algorithm dispatch smoke tests (issue #73 Phase F)
// ============================================================================

/// First executable byte address in an x86 binary. Mirrors
/// `executable_window` above but takes the first byte of the first
/// executable section since x86 has variable-length instructions.
fn x86_first_executable_address(path: &Path) -> u64 {
    let data = std::fs::read(path).expect("read test ELF");
    let elf =
        elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).expect("parse test ELF");
    let section_headers = elf.section_headers().expect("read section headers");
    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 != 0 && section.sh_size > 0 {
            return section.sh_addr;
        }
    }
    panic!("no executable section in {path:?}");
}

#[test]
fn test_opt_x86_hybrid_still_rejected() {
    // Hybrid remains AArch64-only after issue #73: the parallel
    // coordinator hasn't been genericised yet (#77 stage 2 step 12
    // deferral). The CLI must still reject hybrid for x86 with a
    // clear message naming hybrid+llm.
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    check_test_binary(&test_elf);
    let start_addr = x86_first_executable_address(&test_elf);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--arch")
        .arg("x86-64")
        .arg("--algorithm")
        .arg("hybrid")
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{:x}", start_addr + 4))
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "x86 hybrid should still be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hybrid") || stderr.contains("AArch64-only"),
        "rejection message should mention hybrid/llm; got: {}",
        stderr
    );
}

#[test]
fn test_opt_x86_llm_still_rejected() {
    // LLM remains AArch64-only per ADR-0004 decision 3.
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    check_test_binary(&test_elf);
    let start_addr = x86_first_executable_address(&test_elf);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--arch")
        .arg("x86-64")
        .arg("--algorithm")
        .arg("llm")
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{:x}", start_addr + 4))
        .output()
        .expect("Failed to execute s11");

    assert!(!output.status.success(), "x86 llm should still be rejected");
}

#[test]
fn test_opt_x86_stochastic_is_no_longer_rejected_at_cli() {
    // Regression: before issue #73 the CLI rejected
    // `--arch x86-64 --algorithm stochastic` with
    // "x86 only supports --algorithm enumerative in this release; ...".
    // After this PR, the rejection message must not appear; the
    // command may exit non-zero for other reasons (e.g. address
    // alignment, no optimization found) but the specific x86-only
    // rejection text must be gone.
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    check_test_binary(&test_elf);
    let start_addr = x86_first_executable_address(&test_elf);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--arch")
        .arg("x86-64")
        .arg("--algorithm")
        .arg("stochastic")
        .arg("--iterations")
        .arg("50")
        .arg("--timeout")
        .arg("10")
        .arg("--seed")
        .arg("42")
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{:x}", start_addr + 4))
        .output()
        .expect("Failed to execute s11");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("x86 only supports --algorithm enumerative"),
        "old x86-only-enumerative rejection text must be gone; stderr was: {}",
        stderr
    );

    // Clean up any optimized binary that might have been created
    let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug_optimized");
    let _ = fs::remove_file(optimized_path);
}

/// Scan every executable section of `path` for the first occurrence of the
/// raw byte sequence `needle`, returning its virtual address. Used by the x86
/// end-to-end opt test to locate a known instruction window by its exact
/// encoding so the test survives toolchain layout drift.
fn x86_find_byte_sequence(path: &Path, needle: &[u8]) -> u64 {
    let data = std::fs::read(path).expect("read test ELF");
    let elf =
        elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data).expect("parse test ELF");
    let section_headers = elf.section_headers().expect("read section headers");

    for section in section_headers.iter() {
        if section.sh_flags & elf::abi::SHF_EXECINSTR as u64 == 0 {
            continue;
        }
        let start = section.sh_offset as usize;
        let size = section.sh_size as usize;
        if size < needle.len() {
            continue;
        }
        let bytes = &data[start..start + size];
        if let Some(off) = bytes.windows(needle.len()).position(|w| w == needle) {
            return section.sh_addr + off as u64;
        }
    }

    panic!("byte sequence {needle:02x?} not found in any executable section of {path:?}");
}

/// End-to-end x86-64 opt test (issue #91): run the `s11 opt` CLI on a real
/// x86-64 ELF and assert a *known* one-instruction shortening is found and
/// reported.
///
/// The `binaries/x86_64/dup_mov_imm` fixture (assembled from
/// `tests/x86_asm/dup_mov_imm.s` by `build_tests.sh`) contains two identical
/// `mov rax, 5` instructions. Only RAX is live-out and neither MOV touches
/// EFLAGS, so the enumerative (deterministic) search collapses the redundant
/// pair to a single `mov rax, 5`. The window is located by its exact encoding
/// (`48 c7 c0 05 00 00 00` twice) so the assertion is stable across rebuilds.
///
/// Mirrors `test_opt_basic_functionality` (AArch64) but pins the *result*: the
/// opt path must report "Optimized to 1 instructions" and complete, not merely
/// run. If the fixture is absent (e.g. no host x86-64 gcc), the test skips
/// rather than failing, matching the other x86 opt tests here.
#[test]
fn test_opt_x86_64_known_shortening() {
    let binary = get_binary_path();
    let source_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("dup_mov_imm");
    if !source_elf.exists() {
        eprintln!(
            "Skipping x86-64 known-shortening opt test: {:?} not present (run build_tests.sh)",
            source_elf
        );
        return;
    }

    // `mov rax, 5` == 48 c7 c0 05 00 00 00; find the first of the redundant
    // pair and take a 14-byte (two-instruction) window over both.
    let mov_rax_5: [u8; 7] = [0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00];
    let pair: Vec<u8> = mov_rax_5.iter().chain(mov_rax_5.iter()).copied().collect();
    let start_addr = x86_find_byte_sequence(&source_elf, &pair);
    let end_addr = start_addr + pair.len() as u64;

    // Copy to a unique tempdir so concurrent `cargo test` runs don't collide
    // on the `<input>_optimized` artifact the binary always writes.
    let tmp_dir = tempfile::tempdir().expect("create temp fixture dir");
    let test_elf = tmp_dir.path().join("dup_mov_imm");
    fs::copy(&source_elf, &test_elf).expect("copy x86-64 fixture to tmp");
    let optimized_path = tmp_dir.path().join("dup_mov_imm_optimized");

    let output = Command::new(&binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--arch")
        .arg("x86-64")
        .arg("--algorithm")
        .arg("enumerative")
        .arg("--timeout")
        .arg("30")
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{end_addr:x}"))
        .output()
        .expect("Failed to execute s11");

    assert!(
        output.status.success(),
        "x86-64 opt should succeed.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Detected: X86_64"),
        "should run the x86-64 opt path; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Disassembled 2 instructions"),
        "should disassemble the two-instruction window; stdout: {stdout}"
    );
    // The known shortening: 2 instructions collapse to 1.
    assert!(
        stdout.contains("Optimized to 1 instructions"),
        "x86-64 opt must find the one-instruction shortening; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Created optimized binary"),
        "should write the optimized binary; stdout: {stdout}"
    );
    assert!(
        stdout.contains("Optimization completed successfully"),
        "should complete the optimization; stdout: {stdout}"
    );
    assert!(
        optimized_path.exists(),
        "optimized binary should be created at {:?}",
        optimized_path,
    );
}

#[test]
fn test_opt_x86_symbolic_is_no_longer_rejected_at_cli() {
    // Companion to the stochastic regression test: symbolic must
    // also be accepted now.
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug");
    check_test_binary(&test_elf);
    let start_addr = x86_first_executable_address(&test_elf);

    let output = Command::new(binary)
        .arg("opt")
        .arg(&test_elf)
        .arg("--arch")
        .arg("x86-64")
        .arg("--algorithm")
        .arg("symbolic")
        .arg("--timeout")
        .arg("5")
        .arg("--solver-timeout")
        .arg("2")
        .arg("--start-addr")
        .arg(format!("0x{start_addr:x}"))
        .arg("--end-addr")
        .arg(format!("0x{:x}", start_addr + 4))
        .output()
        .expect("Failed to execute s11");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("x86 only supports --algorithm enumerative"),
        "old x86-only-enumerative rejection text must be gone; stderr was: {}",
        stderr
    );

    let optimized_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("x86_64")
        .join("simple_debug_optimized");
    let _ = fs::remove_file(optimized_path);
}

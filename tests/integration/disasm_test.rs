use std::path::PathBuf;
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
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("s11");
    path
}

#[test]
fn test_disasm_simple_binary() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    check_test_binary(&test_elf);

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--disasm")
        .output()
        .expect("Failed to execute s11");

    assert!(
        output.status.success(),
        "Command failed with status: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that output contains hex addresses
    assert!(stdout.contains("0x"), "Output should contain hex addresses");

    // Check that output contains instruction bytes (8 hex chars for AArch64)
    assert!(
        stdout.lines().any(|line| {
            line.contains(':')
                && line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim().split_whitespace().next())
                    .and_then(|s| s)
                    .map(|s| s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()))
                    .unwrap_or(false)
        }),
        "Output should contain 8-character hex instruction bytes"
    );

    // Check for common AArch64 instructions
    assert!(
        stdout.contains("mov")
            || stdout.contains("add")
            || stdout.contains("sub")
            || stdout.contains("ret")
            || stdout.contains("stp")
            || stdout.contains("ldp"),
        "Output should contain AArch64 instructions"
    );
}

#[test]
fn test_disasm_optimized_binary() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_opt3");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--disasm")
        .output()
        .expect("Failed to execute s11");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have clean output without extra headers in disasm mode
    assert!(
        !stdout.contains("s11 - AArch64 Optimizer"),
        "Disasm mode should not print header"
    );
    assert!(
        !stdout.contains("ELF Header:"),
        "Disasm mode should not print ELF header info"
    );
    assert!(
        !stdout.contains("Text sections:"),
        "Disasm mode should not print section headers"
    );
}

#[test]
fn test_disasm_arrays_binary() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("arrays_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--disasm")
        .output()
        .expect("Failed to execute s11");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Arrays code should have load/store instructions
    assert!(
        stdout.contains("ldr")
            || stdout.contains("str")
            || stdout.contains("ldp")
            || stdout.contains("stp"),
        "Arrays binary should contain load/store instructions"
    );
}

#[test]
fn test_disasm_functions_binary() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("functions_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--disasm")
        .output()
        .expect("Failed to execute s11");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Functions should have call/return instructions
    assert!(
        stdout.contains("bl") || stdout.contains("ret") || stdout.contains("blr"),
        "Functions binary should contain branch/return instructions"
    );
}

#[test]
fn test_disasm_requires_binary() {
    let binary = get_binary_path();

    let output = Command::new(binary)
        .arg("--disasm")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail without binary"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--disasm requires --binary"),
        "Should print error about missing binary"
    );
}


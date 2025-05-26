use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_binary_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("s11");
    path
}

#[test]
fn test_opt_basic_functionality() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("arrays_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
        .arg("--start-addr")
        .arg("0x5c8")
        .arg("--end-addr")
        .arg("0x5cc")
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
        .arg("--opt")
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
        stderr.contains("--opt requires --binary"),
        "Should print error about missing binary"
    );
}

#[test]
fn test_opt_requires_start_addr() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
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
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
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
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
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
fn test_opt_address_out_of_bounds() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
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

#[test]
fn test_opt_conflicts_with_demo() {
    let binary = get_binary_path();

    let output = Command::new(binary)
        .arg("--opt")
        .arg("--demo")
        .arg("--start-addr")
        .arg("0x1000")
        .arg("--end-addr")
        .arg("0x1004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with conflicting flags"
    );
}

#[test]
fn test_opt_conflicts_with_disasm() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
        .arg("--disasm")
        .arg("--start-addr")
        .arg("0x1000")
        .arg("--end-addr")
        .arg("0x1004")
        .output()
        .expect("Failed to execute s11");

    assert!(
        !output.status.success(),
        "Command should fail with conflicting flags"
    );
}

#[test]
fn test_opt_address_alignment() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    // Test with unaligned addresses (not 4-byte aligned)
    let output = Command::new(binary)
        .arg("--binary")
        .arg(&test_elf)
        .arg("--opt")
        .arg("--start-addr")
        .arg("0x5c9") // Unaligned
        .arg("--end-addr")
        .arg("0x5cd") // Unaligned
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
fn test_opt_hex_address_formats() {
    let binary = get_binary_path();
    let test_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("simple_debug");

    // Test different hex formats
    let test_cases = vec![
        ("0x5c8", "0x5cc"), // 0x prefix
        ("0X5c8", "0X5cc"), // 0X prefix
        ("5c8", "5cc"),     // No prefix
    ];

    for (start, end) in test_cases {
        let output = Command::new(&binary)
            .arg("--binary")
            .arg(&test_elf)
            .arg("--opt")
            .arg("--start-addr")
            .arg(start)
            .arg("--end-addr")
            .arg(end)
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

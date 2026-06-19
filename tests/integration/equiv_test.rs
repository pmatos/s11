use std::process::{Command, Output};

const FAST_ONLY_MEMORY_WARNING: &str =
    "[s11] warning: --fast-only disabled for memory-bearing window (see ADR-0007)";

fn get_binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_s11"))
}

fn run_equiv(seq1_text: &str, seq2_text: &str, fast_only: bool) -> Output {
    let dir = tempfile::tempdir().expect("create temp dir for equiv fixtures");
    let seq1 = dir.path().join("seq1.s");
    let seq2 = dir.path().join("seq2.s");
    std::fs::write(&seq1, seq1_text).expect("write first sequence");
    std::fs::write(&seq2, seq2_text).expect("write second sequence");

    let mut command = Command::new(get_binary_path());
    command.arg("equiv").arg(&seq1).arg(&seq2);
    if fast_only {
        command.arg("--fast-only");
    }
    command
        .arg("--live-out")
        .arg("x0")
        .arg("--timeout")
        .arg("5");
    command.output().expect("execute s11 equiv")
}

fn run_equiv_fast_only(seq1_text: &str, seq2_text: &str) -> Output {
    run_equiv(seq1_text, seq2_text, true)
}

fn run_equiv_without_fast_only(seq1_text: &str, seq2_text: &str) -> Output {
    run_equiv(seq1_text, seq2_text, false)
}

#[test]
fn equiv_fast_only_memory_window_warns_when_overridden() {
    let output = run_equiv_fast_only("ldr x0, [x1]\n", "ldr x0, [x1]\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "s11 equiv should succeed, status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("EQUIVALENT"),
        "stdout should report equivalence, stdout:\n{}",
        stdout
    );
    assert_eq!(
        stderr.matches(FAST_ONLY_MEMORY_WARNING).count(),
        1,
        "stderr should contain the ADR-0007 fast-only override warning exactly once, stderr:\n{}",
        stderr
    );
}

#[test]
fn equiv_memory_window_without_fast_only_does_not_warn() {
    let output = run_equiv_without_fast_only("ldr x0, [x1]\n", "ldr x0, [x1]\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "s11 equiv should succeed, status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("EQUIVALENT"),
        "stdout should report equivalence, stdout:\n{}",
        stdout
    );
    assert!(
        !stderr.contains(FAST_ONLY_MEMORY_WARNING),
        "stderr should not contain the memory fast-only override warning, stderr:\n{}",
        stderr
    );
}

#[test]
fn equiv_fast_only_register_window_does_not_warn() {
    let output = run_equiv_fast_only("mov x0, x1\n", "mov x0, x1\n");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "s11 equiv should succeed, status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert!(
        stdout.contains("EQUIVALENT"),
        "stdout should report equivalence, stdout:\n{}",
        stdout
    );
    assert!(
        !stderr.contains(FAST_ONLY_MEMORY_WARNING),
        "stderr should not contain the memory fast-only override warning, stderr:\n{}",
        stderr
    );
}

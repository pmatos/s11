use std::process::{Command, Output};

fn get_binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_s11"))
}

fn run_equiv_with_live_out(live_out: &str) -> Output {
    let dir = tempfile::tempdir().expect("create temp dir for equiv fixtures");
    let seq1 = dir.path().join("seq1.s");
    let seq2 = dir.path().join("seq2.s");
    std::fs::write(&seq1, "mov x0, x1\n").expect("write first sequence");
    std::fs::write(&seq2, "mov x0, x1\n").expect("write second sequence");

    Command::new(get_binary_path())
        .arg("equiv")
        .arg(&seq1)
        .arg(&seq2)
        .arg("--fast-only")
        .arg("--live-out")
        .arg(live_out)
        .arg("--timeout")
        .arg("5")
        .output()
        .expect("execute s11 equiv")
}

fn run_llm_opt_with_live_out(live_out: &str) -> Output {
    let dir = tempfile::tempdir().expect("create temp dir for llm-opt fixture");
    let target = dir.path().join("target.s");
    std::fs::write(&target, "mov x0, x1\n").expect("write target sequence");

    Command::new(get_binary_path())
        .arg("llm-opt")
        .arg("--asm")
        .arg(&target)
        .arg("--live-out")
        .arg(live_out)
        .arg("--max-calls")
        .arg("0")
        .arg("--timeout")
        .arg("0")
        .output()
        .expect("execute s11 llm-opt")
}

#[test]
fn equiv_invalid_live_out_reports_full_user_facing_error() {
    let output = run_equiv_with_live_out("foo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "s11 equiv should reject invalid live-out, status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert_eq!("", stdout);
    assert_eq!(
        "Error: invalid live-out: invalid register name: 'foo'\n",
        stderr
    );
}

#[test]
fn llm_opt_invalid_live_out_reports_full_user_facing_error() {
    let output = run_llm_opt_with_live_out("foo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "s11 llm-opt should reject invalid live-out, status: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );
    assert_eq!("", stdout);
    assert_eq!(
        "llm-opt: invalid live-out: invalid register name: 'foo'\n",
        stderr
    );
}

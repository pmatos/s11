use std::path::{Path, PathBuf};
use std::process::Command;

/// An `--start-addr`/`--end-addr` window into a fixture binary.
#[derive(Default)]
pub(crate) struct Window {
    pub start_addr: &'static str,
    pub end_addr: &'static str,
}

/// Post-optimization behavioral check: run input and output and compare.
/// Unimplemented — `run()` panics if a case sets this (Phase 3, #834-#836).
#[derive(Default)]
pub(crate) struct ExecutionExpectation {
    pub expected_exit_code: i32,
}

/// A declarative e2e test case. Construct with `Case { name: ..., ..Default::default() }`
/// and hand it to [`run`].
#[derive(Default)]
pub(crate) struct Case {
    pub name: &'static str,
    /// Subcommand token (e.g. `"opt"`, `"disasm"`), placed first in argv.
    /// `None` for top-level flags like `--help`.
    pub subcommand: Option<&'static str>,
    /// Fixture path, relative to `tests/e2e/fixtures/`. Passed as the first
    /// positional argument after the subcommand, when present.
    pub fixture: Option<&'static str>,
    pub arch: Option<&'static str>,
    pub window: Option<Window>,
    /// Remaining CLI arguments, appended after any fixture/arch/window flags.
    pub args: &'static [&'static str],
    pub expected_exit_code: i32,
    pub expected_stdout_contains: Option<&'static str>,
    /// Instruction count (before, after) a successful optimization must report.
    pub expected_instructions: Option<(usize, usize)>,
    pub execution: Option<ExecutionExpectation>,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures")
}

pub(crate) fn s11_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_s11"))
}

fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// Parses the instruction count following `prefix` (e.g. `"Disassembled "`,
/// `"Optimized to "`) out of `s11 opt`'s stdout report lines.
fn extract_reported_count(stdout: &str, prefix: &str) -> Option<usize> {
    let start = stdout.find(prefix)? + prefix.len();
    stdout[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()
}

/// The exact, copy-pasteable shell command a human can re-run standalone.
pub(crate) fn reproducer_command(binary: &Path, argv: &[String]) -> String {
    let mut parts = vec![shell_quote(&binary.to_string_lossy())];
    parts.extend(argv.iter().map(|a| shell_quote(a)));
    parts.join(" ")
}

fn build_argv(case: &Case) -> Vec<String> {
    let mut argv = Vec::new();

    if let Some(subcommand) = case.subcommand {
        argv.push(subcommand.to_string());
    }

    if let Some(fixture) = case.fixture {
        assert!(
            !Path::new(fixture).is_absolute(),
            "e2e case {:?}: fixture must be relative to tests/e2e/fixtures/, got absolute path {:?}",
            case.name,
            fixture
        );
        let path = fixture_dir().join(fixture);
        assert!(
            path.exists(),
            "e2e case {:?}: fixture not found: {:?}",
            case.name,
            path
        );
        argv.push(path.to_string_lossy().into_owned());
    }

    if let Some(arch) = case.arch {
        argv.push("--arch".to_string());
        argv.push(arch.to_string());
    }

    if let Some(window) = &case.window {
        argv.push("--start-addr".to_string());
        argv.push(window.start_addr.to_string());
        argv.push("--end-addr".to_string());
        argv.push(window.end_addr.to_string());
    }

    argv.extend(case.args.iter().map(|a| a.to_string()));
    argv
}

/// Run a declarative e2e [`Case`] against the real `s11` binary.
///
/// Panics with the exact reproducer command on any exit-code/stdout/instruction-count
/// mismatch, so a human can copy-paste it to reproduce the failure standalone. A case
/// using an unimplemented field (`execution`) panics before the reproducer is built,
/// naming the tracking issue instead.
pub(crate) fn run(case: &Case) {
    if let Some(execution) = &case.execution {
        panic!(
            "e2e case {:?}: execution expectations are not implemented by this harness yet \
             (Phase 3, see issues #834-#836); wanted post-execution exit code {}",
            case.name, execution.expected_exit_code
        );
    }

    let argv = build_argv(case);
    let binary = s11_binary_path();
    let reproducer = reproducer_command(&binary, &argv);

    let output = Command::new(&binary)
        .args(&argv)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "e2e case {:?}: failed to execute:\nreproducer: {reproducer}\nerror: {err}",
                case.name
            )
        });

    let actual_exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        actual_exit_code == case.expected_exit_code,
        "e2e case {:?}: exited with {actual_exit_code} (expected {})\n\
         reproducer: {reproducer}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        case.name,
        case.expected_exit_code,
    );

    if let Some(expected) = case.expected_stdout_contains {
        assert!(
            stdout.contains(expected),
            "e2e case {:?}: stdout did not contain {expected:?}\n\
             reproducer: {reproducer}\nstdout:\n{stdout}",
            case.name,
        );
    }

    if let Some((before, after)) = case.expected_instructions {
        let actual_before = extract_reported_count(&stdout, "Disassembled ").unwrap_or_else(|| {
            panic!(
                "e2e case {:?}: could not find \"Disassembled N instructions:\" in stdout\n\
                     reproducer: {reproducer}\nstdout:\n{stdout}",
                case.name
            )
        });
        let actual_after = extract_reported_count(&stdout, "Optimized to ").unwrap_or_else(|| {
            panic!(
                "e2e case {:?}: could not find \"Optimized to N instructions:\" in stdout \
                 (the search may not have found the expected shortening)\n\
                 reproducer: {reproducer}\nstdout:\n{stdout}",
                case.name
            )
        });
        assert_eq!(
            (actual_before, actual_after),
            (before, after),
            "e2e case {:?}: instruction count before->after mismatch\n\
             reproducer: {reproducer}\nstdout:\n{stdout}",
            case.name
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_reported_count_parses_before_and_after() {
        let stdout = "Disassembled 2 instructions:\n...\nOptimized to 1 instructions:\n";
        assert_eq!(extract_reported_count(stdout, "Disassembled "), Some(2));
        assert_eq!(extract_reported_count(stdout, "Optimized to "), Some(1));
    }

    #[test]
    fn extract_reported_count_returns_none_when_prefix_missing() {
        let stdout = "Disassembled 2 instructions:";
        assert_eq!(extract_reported_count(stdout, "Optimized to "), None);
    }

    #[test]
    fn reproducer_command_is_pasteable() {
        let binary = PathBuf::from("/path/to/s11");
        let argv = vec![
            "opt".to_string(),
            "some file.elf".to_string(),
            "--arch".to_string(),
        ];
        let command = reproducer_command(&binary, &argv);
        assert_eq!(command, "/path/to/s11 opt 'some file.elf' --arch");
    }

    /// Acceptance criterion: a deliberately-failing case must print a
    /// reproducer command a human can copy-paste. This exercises the real
    /// failure path in `run()` (not just the formatter) while keeping the
    /// suite green.
    #[test]
    fn deliberately_failing_case_prints_a_reproducer() {
        let case = Case {
            name: "reproducer-smoke",
            args: &["--help"],
            expected_exit_code: 42, // s11 --help actually exits 0; this must fail.
            ..Default::default()
        };

        // Deliberately does not touch the global panic hook: cargo test runs
        // tests within this binary concurrently by default, and a process-wide
        // hook swap would risk swallowing a genuinely-panicking sibling test's
        // message. The default hook printing to stderr during this expected
        // failure is harmless.
        let result = std::panic::catch_unwind(|| run(&case));

        let payload = result.expect_err("a case with a wrong expected_exit_code must panic");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .expect("panic payload should be a string message");

        let expected_reproducer = reproducer_command(&s11_binary_path(), &["--help".to_string()]);
        assert!(
            message.contains(&expected_reproducer),
            "panic message did not include the reproducer command:\n{message}"
        );
    }
}

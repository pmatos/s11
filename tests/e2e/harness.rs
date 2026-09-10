use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

/// An `--start-addr`/`--end-addr` window into a fixture binary, consumed by
/// [`Case::expected_instructions`].
#[derive(Default)]
pub(crate) struct Window {
    pub start_addr: &'static str,
    pub end_addr: &'static str,
}

/// Post-optimization behavioral check: `run()` natively executes both the
/// unpatched input and the `-o`-patched output and compares exit code +
/// stdout via [`diff_execution`], catching a miscompile the SMT model
/// misses because it observes real execution rather than static bytes.
#[derive(Default)]
pub(crate) struct ExecutionExpectation {
    /// The exit code both the input fixture and the patched output must
    /// produce when run with no arguments/stdin.
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
    /// positional argument after the subcommand, when present. Check
    /// [`fixture_exists`] before setting this so a missing toolchain-built
    /// fixture skips the case instead of hitting `build_argv`'s hard panic.
    pub fixture: Option<&'static str>,
    /// A positional input path computed at test time (e.g. a synthesized
    /// ELF written to a tempdir). Mutually exclusive with `fixture`.
    pub binary: Option<PathBuf>,
    pub arch: Option<&'static str>,
    pub window: Option<Window>,
    /// Remaining CLI arguments, appended after any fixture/arch/window flags.
    pub args: &'static [&'static str],
    /// Owned, dynamically-computed argv pieces (e.g. `-o <tempdir path>`),
    /// appended after `args`.
    pub extra_args: Vec<String>,
    pub expected_exit_code: i32,
    /// Substring checks against stdout; every entry must be present.
    pub expected_stdout_contains: &'static [&'static str],
    /// Substring checks against stderr; every entry must be present.
    pub expected_stderr_contains: &'static [&'static str],
    /// Instruction count (before, after) a successful optimization must report,
    /// checked against the `Disassembled N instructions:`/`Optimized to N
    /// instructions:` markers `src/elf_optimizer/mod.rs` prints on success.
    pub expected_instructions: Option<(usize, usize)>,
    /// Behavioral (execute-and-diff) check, requires subcommand `"opt"`.
    /// See [`ExecutionExpectation`].
    pub execution: Option<ExecutionExpectation>,
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/e2e/fixtures")
}

/// Whether a fixture, relative to `tests/e2e/fixtures/`, exists. Lets a case
/// check for its fixture and skip cleanly before `build_argv`'s hard
/// `assert!(path.exists())`, which panics (fails, doesn't skip) instead.
pub(crate) fn fixture_exists(relative: &str) -> bool {
    fixture_dir().join(relative).exists()
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

/// The exact, copy-pasteable shell command a human can re-run standalone.
pub(crate) fn reproducer_command(binary: &Path, argv: &[String]) -> String {
    let mut parts = vec![shell_quote(&binary.to_string_lossy())];
    parts.extend(argv.iter().map(|a| shell_quote(a)));
    parts.join(" ")
}

/// Checks stdout for the exact `println!` markers `src/elf_optimizer/mod.rs`
/// emits on a successful optimization run.
fn stdout_reports_instructions(stdout: &str, before: usize, after: usize) -> bool {
    stdout.contains(&format!("Disassembled {before} instructions:"))
        && stdout.contains(&format!("Optimized to {after} instructions:"))
}

/// Resolve a case's positional input path: `fixture`, joined against the
/// fixtures dir, or an explicit `binary` computed at test time. Shared by
/// [`build_argv`] (which validates and passes it as `s11`'s argv) and the
/// execution-diff step in [`run`], so the two can't silently resolve
/// different paths for what is meant to be the same input.
fn resolve_input_path(case: &Case) -> PathBuf {
    match case.fixture {
        Some(fixture) => fixture_dir().join(fixture),
        None => case.binary.clone().unwrap_or_else(|| {
            panic!(
                "e2e case {:?}: needs a fixture or binary as its positional input",
                case.name
            )
        }),
    }
}

fn build_argv(case: &Case) -> Vec<String> {
    let mut argv = Vec::new();

    if let Some(subcommand) = case.subcommand {
        argv.push(subcommand.to_string());
    }

    assert!(
        case.fixture.is_none() || case.binary.is_none(),
        "e2e case {:?}: fixture and binary are mutually exclusive positional inputs, got both",
        case.name
    );

    if let Some(fixture) = case.fixture {
        assert!(
            !Path::new(fixture).is_absolute(),
            "e2e case {:?}: fixture must be relative to tests/e2e/fixtures/, got absolute path {:?}",
            case.name,
            fixture
        );
        let path = resolve_input_path(case);
        assert!(
            path.exists(),
            "e2e case {:?}: fixture not found: {:?}",
            case.name,
            path
        );
        argv.push(path.to_string_lossy().into_owned());
    }

    if let Some(binary) = &case.binary {
        argv.push(binary.to_string_lossy().into_owned());
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
    argv.extend(case.extra_args.iter().cloned());
    argv
}

/// Run a declarative e2e [`Case`] against the real `s11` binary.
///
/// Panics with the exact reproducer command on any exit-code/stdout mismatch,
/// so a human can copy-paste it to reproduce the failure standalone. A case
/// setting `execution` additionally runs the behavioral tier: natively
/// executing the unpatched input and the `-o`-patched output and diffing
/// them via [`diff_execution`].
pub(crate) fn run(case: &Case) {
    // Cases asserting `expected_instructions` and/or `execution` write their
    // optimized output here rather than relying on `s11 opt`'s default
    // derived-sibling path, so runs never leave stray files next to the
    // (gitignored) fixture. The directory is persisted (not auto-cleaned via
    // `TempDir`'s `Drop`) so that on failure the reproducer command printed
    // below still points at an on-disk `-o` path a human can inspect or
    // re-run standalone; it is removed explicitly at the end of this
    // function on the success path.
    let output_path =
        (case.expected_instructions.is_some() || case.execution.is_some()).then(|| {
            assert!(
                case.subcommand == Some("opt"),
                "e2e case {:?}: expected_instructions/execution requires subcommand \"opt\" \
                 (the only subcommand accepting -o/--output), got {:?}",
                case.name,
                case.subcommand
            );
            tempfile::tempdir()
                .expect("create e2e case output tempdir")
                .keep()
                .join(format!("{}-optimized", case.name))
        });

    let mut argv = build_argv(case);
    if let Some(path) = &output_path {
        argv.push("-o".to_string());
        argv.push(path.to_string_lossy().into_owned());
    }

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

    for expected in case.expected_stdout_contains {
        assert!(
            stdout.contains(expected),
            "e2e case {:?}: stdout did not contain {expected:?}\n\
             reproducer: {reproducer}\nstdout:\n{stdout}",
            case.name,
        );
    }

    for expected in case.expected_stderr_contains {
        assert!(
            stderr.contains(expected),
            "e2e case {:?}: stderr did not contain {expected:?}\n\
             reproducer: {reproducer}\nstderr:\n{stderr}",
            case.name,
        );
    }

    if let Some((before, after)) = case.expected_instructions {
        assert!(
            stdout_reports_instructions(&stdout, before, after),
            "e2e case {:?}: stdout did not report {before} -> {after} instructions\n\
             reproducer: {reproducer}\nstdout:\n{stdout}",
            case.name,
        );
        let path = output_path
            .as_deref()
            .expect("expected_instructions implies -o was set");
        assert!(
            path.exists(),
            "e2e case {:?}: reported instructions but never wrote -o output {:?}\n\
             reproducer: {reproducer}\nstdout:\n{stdout}",
            case.name,
            path,
        );
    }

    if let Some(execution) = &case.execution {
        let path = output_path
            .as_deref()
            .expect("execution implies -o was set");
        diff_execution(
            case.name,
            &resolve_input_path(case),
            path,
            execution,
            &reproducer,
        );
    }

    // Only reached on success (every failure path above panics first), so the
    // tempdir is still on disk for anyone inspecting a panic from this run;
    // clean it up now that it's no longer needed.
    if let Some(path) = output_path {
        let dir = path
            .parent()
            .expect("tempdir-derived output path always has a parent");
        let _ = fs::remove_dir_all(dir);
    }
}

/// Generous bound for a fixture's native execution: healthy fixtures exit in
/// milliseconds, but a genuinely miscompiled/looping patched binary must
/// still be killed rather than hang `cargo test` forever.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of running a binary to completion: its exit code and captured
/// stdout.
#[derive(Debug)]
struct ExecutionOutcome {
    exit_code: i32,
    stdout: Vec<u8>,
}

/// Spawn `binary` with no arguments/stdin, wait up to `timeout`, and capture
/// its exit code and stdout. Panics naming `binary` and `timeout` if the
/// process is still running when the timeout elapses (after killing it, so
/// no orphan survives the test run).
fn run_to_completion(binary: &Path, timeout: Duration) -> ExecutionOutcome {
    let mut child = Command::new(binary)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to execute {binary:?}: {err}"));

    let status = match child
        .wait_timeout(timeout)
        .unwrap_or_else(|err| panic!("failed to wait on {binary:?}: {err}"))
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("execution of {binary:?} did not complete within {timeout:?} (timeout)");
        }
    };

    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout was piped")
        .read_to_end(&mut stdout)
        .unwrap_or_else(|err| panic!("failed to read stdout of {binary:?}: {err}"));

    ExecutionOutcome {
        exit_code: status.code().unwrap_or(-1),
        stdout,
    }
}

/// Run `input_binary` and `output_binary` and compare exit code + stdout,
/// per `expectation`. Three separate assertions, each carrying distinct
/// debugging value: the input's own exit code (fixture/expectation
/// misconfigured, not the optimizer's fault), the output's exit code versus
/// the input's (a miscompile signal), and stdout (a second miscompile
/// signal axis). All three panic messages include `reproducer` so a human
/// can copy-paste the failing case's `s11` invocation.
///
/// Stdout is read only after the child has exited, not concurrently — fine
/// for these fixtures' empty/few-byte output, well under the pipe buffer,
/// but not a fully general solution for a binary that emits enough stdout to
/// fill the pipe before exiting.
fn diff_execution(
    case_name: &str,
    input_binary: &Path,
    output_binary: &Path,
    expectation: &ExecutionExpectation,
    reproducer: &str,
) {
    let input = run_to_completion(input_binary, EXECUTION_TIMEOUT);
    assert!(
        input.exit_code == expectation.expected_exit_code,
        "e2e case {case_name:?}: unpatched input {input_binary:?} exited {} (expected {}) — \
         fixture or expectation is misconfigured, not an optimizer bug\n\
         reproducer: {reproducer}",
        input.exit_code,
        expectation.expected_exit_code,
    );

    let output = run_to_completion(output_binary, EXECUTION_TIMEOUT);
    assert!(
        output.exit_code == input.exit_code,
        "e2e case {case_name:?}: patched output {output_binary:?} exited {} but input \
         {input_binary:?} exited {} — likely miscompile\nreproducer: {reproducer}",
        output.exit_code,
        input.exit_code,
    );

    assert!(
        output.stdout == input.stdout,
        "e2e case {case_name:?}: patched output {output_binary:?} stdout {:?} diverged from \
         input {input_binary:?} stdout {:?} — likely miscompile\nreproducer: {reproducer}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&input.stdout),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    /// Extract the human-readable message from a `catch_unwind` panic
    /// payload, which is a `String` or `&str` depending on how the panic
    /// was raised.
    fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
        payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .expect("panic payload should be a string message")
    }

    /// Write an executable `#!/bin/sh` script to `dir/name`, for cheaply
    /// exercising [`run_to_completion`]/[`diff_execution`] without a real
    /// fixture or toolchain.
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
        let mut perms = fs::metadata(&path).expect("stat script").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod script");
        path
    }

    #[test]
    fn stdout_diff_panics_on_divergent_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let input = write_script(dir.path(), "input.sh", "exit 0");
        let output = write_script(dir.path(), "output.sh", "echo foo\nexit 0");

        let result = std::panic::catch_unwind(|| {
            diff_execution(
                "stdout-diff-smoke",
                &input,
                &output,
                &ExecutionExpectation {
                    expected_exit_code: 0,
                },
                "repro-command",
            )
        });

        let payload = result.expect_err("divergent stdout must panic");
        let message = panic_message(&*payload);
        assert!(
            message.contains(&input.to_string_lossy().into_owned())
                && message.contains(&output.to_string_lossy().into_owned()),
            "panic message did not name both binaries:\n{message}"
        );
        assert!(
            message.contains("foo"),
            "panic message did not quote the differing stdout:\n{message}"
        );
    }

    #[test]
    fn exit_code_diff_panics_when_input_and_output_diverge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let input = write_script(dir.path(), "input.sh", "exit 5");
        let output = write_script(dir.path(), "output.sh", "exit 6");

        let result = std::panic::catch_unwind(|| {
            diff_execution(
                "exit-code-diff-smoke",
                &input,
                &output,
                &ExecutionExpectation {
                    expected_exit_code: 5,
                },
                "repro-command",
            )
        });

        let payload = result.expect_err("divergent exit codes must panic");
        let message = panic_message(&*payload);
        assert!(
            message.contains('5') && message.contains('6'),
            "panic message did not name both exit codes:\n{message}"
        );
    }

    #[test]
    fn run_to_completion_kills_a_hung_process_after_timeout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hung = write_script(dir.path(), "hung.sh", "sleep 5");

        let start = std::time::Instant::now();
        let result =
            std::panic::catch_unwind(|| run_to_completion(&hung, Duration::from_millis(200)));
        let elapsed = start.elapsed();

        let payload = result.expect_err("a hung process must panic on timeout");
        let message = panic_message(&*payload);
        assert!(
            message.contains("timeout") || message.contains("did not complete"),
            "panic message did not describe a timeout:\n{message}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "run_to_completion did not honor the timeout; took {elapsed:?}"
        );
    }

    #[test]
    fn stdout_reports_instructions_matches_exact_counts() {
        let stdout = "Disassembled 2 instructions:\n  mov eax, 5\n  mov eax, 5\n\
                       Optimized to 1 instructions:\n  mov eax, 5\n";
        assert!(stdout_reports_instructions(stdout, 2, 1));
    }

    #[test]
    fn stdout_reports_instructions_rejects_wrong_count() {
        let stdout = "Disassembled 2 instructions:\n\
                       Optimized to 1 instructions:\n";
        assert!(!stdout_reports_instructions(stdout, 2, 2));
        assert!(!stdout_reports_instructions(stdout, 3, 1));
    }

    #[test]
    fn fixture_exists_finds_known_file() {
        assert!(fixture_exists("README.md"));
        assert!(!fixture_exists("does-not-exist"));
    }

    #[test]
    #[should_panic(expected = "mutually exclusive")]
    fn build_argv_rejects_fixture_and_binary_both_set() {
        let case = Case {
            name: "fixture-and-binary-both-set",
            fixture: Some("some-fixture.elf"),
            binary: Some(PathBuf::from("/tmp/some-binary.elf")),
            ..Default::default()
        };
        build_argv(&case);
    }

    #[test]
    fn build_argv_appends_extra_args_after_static_args() {
        let case = Case {
            name: "extra-args-ordering",
            args: &["--static-flag"],
            extra_args: vec!["-o".to_string(), "/tmp/out.elf".to_string()],
            ..Default::default()
        };
        let argv = build_argv(&case);
        assert_eq!(
            argv,
            vec![
                "--static-flag".to_string(),
                "-o".to_string(),
                "/tmp/out.elf".to_string(),
            ]
        );
    }

    #[test]
    fn deliberately_missing_stderr_needle_panics_naming_it() {
        let case = Case {
            name: "stderr-needle-smoke",
            args: &["--help"],
            expected_exit_code: 0,
            expected_stderr_contains: &["this substring never appears in --help output"],
            ..Default::default()
        };

        let result = std::panic::catch_unwind(|| run(&case));

        let payload = result.expect_err("a missing stderr needle must panic");
        let message = panic_message(&*payload);

        assert!(
            message.contains("this substring never appears in --help output"),
            "panic message did not name the missing needle:\n{message}"
        );
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
        let message = panic_message(&*payload);

        let expected_reproducer = reproducer_command(&s11_binary_path(), &["--help".to_string()]);
        assert!(
            message.contains(&expected_reproducer),
            "panic message did not include the reproducer command:\n{message}"
        );
    }
}

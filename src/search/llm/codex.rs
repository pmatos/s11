//! Codex CLI invocation and response parsing.

use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::search::config::LlmConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidJson,
    MissingAssemblyField,
    EmptyAssembly,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::InvalidJson => f.write_str("envelope is not valid JSON"),
            EnvelopeError::MissingAssemblyField => {
                f.write_str("envelope is missing the `assembly` field")
            }
            EnvelopeError::EmptyAssembly => {
                f.write_str("envelope `assembly` field is empty or whitespace-only")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Debug)]
pub enum CodexError {
    Io(String),
    TimedOut { timeout: Duration },
    NonZeroExit { status: i32, stderr: String },
    Envelope(EnvelopeError),
}

impl std::fmt::Display for CodexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodexError::Io(e) => write!(f, "codex io error: {}", e),
            CodexError::TimedOut { timeout } => {
                write!(f, "codex timed out after {:.3}s", timeout.as_secs_f64())
            }
            CodexError::NonZeroExit { status, stderr } => {
                write!(f, "codex exited with status {}: {}", status, stderr)
            }
            CodexError::Envelope(e) => write!(f, "codex envelope parse error: {}", e),
        }
    }
}

impl std::error::Error for CodexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CodexError::Envelope(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct Envelope {
    assembly: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    owner_uid: u32,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
        }
    }

    fn is_same_file(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

/// Parse the Codex `--output-schema` envelope into the assembly string.
///
/// Returns `EmptyAssembly` for an envelope whose `assembly` field is the empty
/// string — the LLM essentially saying "no candidate" — so the caller can
/// treat it as a non-candidate iteration without burning a verifier slot.
pub fn parse_codex_envelope(json: &str) -> Result<String, EnvelopeError> {
    let env: Envelope = serde_json::from_str(json).map_err(|_| EnvelopeError::InvalidJson)?;
    let asm = env.assembly.ok_or(EnvelopeError::MissingAssemblyField)?;
    if asm.trim().is_empty() {
        return Err(EnvelopeError::EmptyAssembly);
    }
    Ok(asm)
}

/// Invoke `codex exec` with the given prompt and schema, return the asm string.
///
/// Uses an ephemeral, read-only Codex run with subscription auth (no API key needed).
/// Subprocess files live in an unpredictable private temporary directory. The
/// answer file is pre-created with owner-only permissions on Unix and read
/// through its retained descriptor after Codex exits.
pub fn invoke_codex(
    config: &LlmConfig,
    prompt: &str,
    schema: &str,
    timeout: Duration,
) -> Result<String, CodexError> {
    let workspace = create_temp_workspace()
        .map_err(|e| CodexError::Io(format!("creating temporary workspace: {e}")))?;
    let schema_path = workspace.path().join("schema.json");
    let answer_path = workspace.path().join("answer.json");
    let stderr_path = workspace.path().join("stderr.txt");

    write_file(&schema_path, schema)
        .map_err(|e| CodexError::Io(format!("writing schema file: {e}")))?;
    let mut answer_file = create_file(&answer_path)
        .map_err(|e| CodexError::Io(format!("creating answer file: {e}")))?;
    #[cfg(unix)]
    let answer_identity = FileIdentity::from_metadata(
        &answer_file
            .metadata()
            .map_err(|e| CodexError::Io(format!("recording answer file identity: {e}")))?,
    );
    let stderr_file = create_file(&stderr_path)
        .map_err(|e| CodexError::Io(format!("creating stderr file: {e}")))?;
    let mut stderr_reader = stderr_file
        .try_clone()
        .map_err(|e| CodexError::Io(format!("retaining stderr file: {e}")))?;

    let mut child = Command::new(&config.codex_bin)
        .arg("exec")
        .arg("-m")
        .arg(&config.model)
        .arg("-s")
        .arg("read-only")
        .arg("--ephemeral")
        .arg("--skip-git-repo-check")
        .arg("--output-schema")
        .arg(&schema_path)
        .arg("-o")
        .arg(&answer_path)
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|e| CodexError::Io(e.to_string()))?;
    let status = wait_for_child(&mut child, timeout)?;

    if !status.success() {
        let stderr = read_file_from_start(&mut stderr_reader)
            .unwrap_or_else(|e| format!("<failed to read codex stderr: {}>", e));
        return Err(CodexError::NonZeroExit {
            status: status.code().unwrap_or(-1),
            stderr,
        });
    }

    let answer_path_metadata = std::fs::symlink_metadata(&answer_path)
        .map_err(|e| CodexError::Io(format!("validating answer path: {e}")))?;
    if !answer_path_metadata.file_type().is_file() {
        return Err(CodexError::Io(
            "answer path is not a regular file after codex invocation".to_string(),
        ));
    }
    #[cfg(unix)]
    validate_answer_metadata(answer_identity, &answer_path_metadata, &answer_file)
        .map_err(CodexError::Io)?;
    let json = read_file_from_start(&mut answer_file)
        .map_err(|e| CodexError::Io(format!("reading answer file: {e}")))?;
    if json.is_empty() {
        return Err(CodexError::Io(
            "answer file is empty after successful codex invocation".to_string(),
        ));
    }

    parse_codex_envelope(&json).map_err(CodexError::Envelope)
}

fn read_file_from_start(file: &mut File) -> std::io::Result<String> {
    file.rewind()?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

#[cfg(unix)]
fn validate_answer_metadata(
    expected: FileIdentity,
    path_metadata: &std::fs::Metadata,
    file: &File,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let path_identity = FileIdentity::from_metadata(path_metadata);
    let open_metadata = file
        .metadata()
        .map_err(|e| format!("reading retained answer file identity: {e}"))?;
    let open_identity = FileIdentity::from_metadata(&open_metadata);
    if !path_identity.is_same_file(expected) || !open_identity.is_same_file(expected) {
        return Err("answer file identity changed after codex invocation".to_string());
    }
    if path_identity.owner_uid != expected.owner_uid
        || open_identity.owner_uid != expected.owner_uid
    {
        return Err("answer file ownership changed after codex invocation".to_string());
    }
    if path_metadata.mode() & 0o077 != 0 || open_metadata.mode() & 0o077 != 0 {
        return Err("answer file permissions changed after codex invocation".to_string());
    }
    Ok(())
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus, CodexError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| CodexError::Io(format!("waiting for codex: {}", e)))?
        {
            return Ok(status);
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            if let Err(kill_error) = child.kill() {
                if child
                    .try_wait()
                    .map_err(|e| CodexError::Io(format!("checking timed-out codex: {}", e)))?
                    .is_none()
                {
                    return Err(CodexError::Io(format!(
                        "killing timed-out codex: {}",
                        kill_error
                    )));
                }
            } else {
                child
                    .wait()
                    .map_err(|e| CodexError::Io(format!("reaping timed-out codex: {}", e)))?;
            }
            return Err(CodexError::TimedOut { timeout });
        }

        let remaining = timeout.saturating_sub(elapsed);
        std::thread::sleep(std::cmp::min(remaining, Duration::from_millis(10)));
    }
}

fn create_temp_workspace() -> Result<tempfile::TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("s11-codex-");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }

    builder.tempdir().map_err(|e| e.to_string())
}

/// Create a new file with owner-only (`0o600`) permissions on Unix; falls
/// back to default permissions on non-Unix platforms (the LLM flow is only
/// tested on Linux). The schema file is dull but the answer file briefly
/// contains the model's response — we don't want to leak it to other users
/// on a multi-user host during the (small) window before the RAII guard
/// removes the file.
fn write_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut f = create_file(path)?;
    f.write_all(content.as_bytes())
}

fn create_file(path: &Path) -> std::io::Result<File> {
    use std::fs::OpenOptions;
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::search::llm::test_support::{
        FakeCodex, envelope_answer_writer_script, shell_single_quote, wait_until_process_gone,
    };
    use std::error::Error;

    #[cfg(unix)]
    fn generous_timeout() -> Duration {
        Duration::from_secs(5)
    }

    #[cfg(unix)]
    fn answer_path_script(body: &str) -> String {
        format!(
            r#"answer=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      answer="$1"
      ;;
  esac
  shift || true
done
[ -n "$answer" ]
{body}
"#
        )
    }

    #[test]
    fn parses_basic_envelope() {
        let json = r#"{"assembly":"mov x0, x1"}"#;
        assert_eq!(parse_codex_envelope(json), Ok("mov x0, x1".to_string()));
    }

    #[test]
    fn rejects_empty_assembly() {
        let json = r#"{"assembly":""}"#;
        assert_eq!(
            parse_codex_envelope(json),
            Err(EnvelopeError::EmptyAssembly)
        );
    }

    #[test]
    fn rejects_whitespace_only_assembly() {
        let json = r#"{"assembly":"   \n\t  "}"#;
        assert_eq!(
            parse_codex_envelope(json),
            Err(EnvelopeError::EmptyAssembly)
        );
    }

    #[test]
    fn rejects_invalid_json() {
        assert_eq!(parse_codex_envelope("{"), Err(EnvelopeError::InvalidJson));
    }

    #[test]
    fn rejects_missing_assembly_field() {
        let json = r#"{"foo":"bar"}"#;
        assert_eq!(
            parse_codex_envelope(json),
            Err(EnvelopeError::MissingAssemblyField)
        );
    }

    #[test]
    fn ignores_extra_fields() {
        let json = r#"{"assembly":"mov x0, x1", "rationale":"shorter"}"#;
        assert_eq!(parse_codex_envelope(json), Ok("mov x0, x1".to_string()));
    }

    #[test]
    fn error_display_and_source_are_covered() {
        assert_eq!(
            EnvelopeError::InvalidJson.to_string(),
            "envelope is not valid JSON"
        );
        assert_eq!(
            EnvelopeError::MissingAssemblyField.to_string(),
            "envelope is missing the `assembly` field"
        );
        assert_eq!(
            EnvelopeError::EmptyAssembly.to_string(),
            "envelope `assembly` field is empty or whitespace-only"
        );

        let io = CodexError::Io("spawn failed".to_string());
        assert_eq!(io.to_string(), "codex io error: spawn failed");
        assert!(io.source().is_none());

        let timed_out = CodexError::TimedOut {
            timeout: Duration::from_millis(25),
        };
        assert_eq!(timed_out.to_string(), "codex timed out after 0.025s");
        assert!(timed_out.source().is_none());

        let nonzero = CodexError::NonZeroExit {
            status: 7,
            stderr: "bad prompt".to_string(),
        };
        assert_eq!(
            nonzero.to_string(),
            "codex exited with status 7: bad prompt"
        );
        assert!(nonzero.source().is_none());

        let envelope = CodexError::Envelope(EnvelopeError::EmptyAssembly);
        assert_eq!(
            envelope.to_string(),
            "codex envelope parse error: envelope `assembly` field is empty or whitespace-only"
        );
        assert!(envelope.source().is_some());
    }

    #[test]
    fn create_file_refuses_to_replace_existing_contents() {
        let dir = tempfile::tempdir().expect("create test tempdir");
        let path = dir.path().join("answer.json");
        std::fs::write(&path, "original").expect("seed existing file");

        let err = create_file(&path).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(path).expect("read preserved file"),
            "original"
        );
    }

    #[test]
    fn temp_workspaces_are_private_and_unpredictable() {
        let first = create_temp_workspace().expect("create first temp workspace");
        let second = create_temp_workspace().expect("create second temp workspace");

        assert_ne!(first.path(), second.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = first
                .path()
                .metadata()
                .expect("stat temp workspace")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "workspace must be owner-only");
        }
    }

    #[cfg(unix)]
    #[test]
    fn answer_validation_rejects_owner_mismatch() {
        let dir = tempfile::tempdir().expect("create test tempdir");
        let path = dir.path().join("answer.json");
        let file = create_file(&path).expect("create answer file");
        let metadata = std::fs::symlink_metadata(&path).expect("stat answer path");
        let mut expected = FileIdentity::from_metadata(&metadata);
        expected.owner_uid ^= 1;

        let err = validate_answer_metadata(expected, &metadata, &file).unwrap_err();

        assert!(err.contains("answer file ownership changed"));
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_reads_answer_file_from_fake_cli() {
        let fake = FakeCodex::new(&envelope_answer_writer_script(
            r#"{"assembly":"mov x0, x1"}"#,
        ));
        let config = LlmConfig::default()
            .with_model("fake-model")
            .with_codex_bin(fake.path_string());

        let asm = invoke_codex(
            &config,
            "try a candidate",
            r#"{"type":"object"}"#,
            generous_timeout(),
        )
        .expect("fake codex should produce an answer");

        assert_eq!(asm, "mov x0, x1");
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_reports_nonzero_exit() {
        let fake = FakeCodex::new("echo fake failure >&2\nexit 7\n");
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::NonZeroExit { status, stderr } => {
                assert_eq!(status, 7);
                assert!(stderr.contains("fake failure"));
            }
            other => panic!("expected nonzero exit, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_rejects_untouched_answer_file() {
        let fake = FakeCodex::new("exit 0\n");
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::Io(message) => assert!(message.contains("answer file is empty")),
            other => panic!("expected answer-file IO error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_rejects_deleted_answer_path() {
        let fake = FakeCodex::new(&answer_path_script("rm -f \"$answer\""));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::Io(message) => assert!(message.contains("validating answer path")),
            other => panic!("expected answer-validation IO error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_rejects_replaced_answer_file() {
        let fake = FakeCodex::new(&answer_path_script(
            "rm -f \"$answer\"\nprintf '%s' '{\"assembly\":\"stale\"}' > \"$answer\"",
        ));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::Io(message) => assert!(message.contains("answer file identity changed")),
            other => panic!("expected answer-identity IO error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_rejects_symlinked_answer_path() {
        let fake = FakeCodex::new(&answer_path_script(
            "printf '%s' '{\"assembly\":\"stale\"}' > \"$answer.stale\"\nrm -f \"$answer\"\nln -s \"$answer.stale\" \"$answer\"",
        ));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::Io(message) => {
                assert!(message.contains("answer path is not a regular file"))
            }
            other => panic!("expected answer-file-type IO error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_rejects_answer_with_group_or_other_permissions() {
        let fake = FakeCodex::new(&answer_path_script(
            "printf '%s' '{\"assembly\":\"mov x0, x1\"}' > \"$answer\"\nchmod 0644 \"$answer\"",
        ));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        match err {
            CodexError::Io(message) => assert!(message.contains("answer file permissions changed")),
            other => panic!("expected answer-permissions IO error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_reports_envelope_errors() {
        let fake = FakeCodex::new(&envelope_answer_writer_script(r#"{"assembly":"   "}"#));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let err = invoke_codex(&config, "try a candidate", "{}", generous_timeout()).unwrap_err();

        assert!(matches!(
            err,
            CodexError::Envelope(EnvelopeError::EmptyAssembly)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn invoke_codex_times_out_and_reaps_slow_child() {
        let pid_file = tempfile::NamedTempFile::new().expect("create pid file");
        let pid_path = pid_file.path().to_path_buf();
        let fake = FakeCodex::new(&format!(
            "printf '%s\\n' \"$$\" > {}\nsleep 2\n",
            shell_single_quote(&pid_path.to_string_lossy())
        ));
        let config = LlmConfig::default().with_codex_bin(fake.path_string());

        let started = Instant::now();
        let err =
            invoke_codex(&config, "try a candidate", "{}", Duration::from_millis(300)).unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(900),
            "invoke_codex should return near its timeout; elapsed {elapsed:?}"
        );
        assert!(matches!(err, CodexError::TimedOut { .. }));

        let pid = std::fs::read_to_string(&pid_path)
            .expect("fake codex should record its pid")
            .trim()
            .parse::<u32>()
            .expect("fake codex pid should be numeric");
        wait_until_process_gone(pid);
    }
}

//! Codex CLI invocation and response parsing.

use serde::Deserialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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
    NonZeroExit { status: i32, stderr: String },
    Envelope(EnvelopeError),
}

impl std::fmt::Display for CodexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodexError::Io(e) => write!(f, "codex io error: {}", e),
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

/// Per-process monotonic counter ensuring temp-file paths are unique across
/// concurrent and sequential `invoke_codex` calls within a single process.
/// Combined with the PID, this avoids cross-process collisions too.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// RAII guard that removes a path on drop. Survives early returns / panics.
struct TempPath(PathBuf);

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl TempPath {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Invoke `codex exec` with the given prompt and schema, return the asm string.
///
/// Uses an ephemeral, read-only Codex run with subscription auth (no API key needed).
/// Schema and answer files are written under the system temp dir with PID +
/// monotonic-counter naming and removed via RAII guards before this function
/// returns (success, error, or panic).
pub fn invoke_codex(config: &LlmConfig, prompt: &str, schema: &str) -> Result<String, CodexError> {
    let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let tmp = std::env::temp_dir();
    let schema_path = TempPath(tmp.join(format!("s11-codex-schema-{}-{}.json", pid, id)));
    let answer_path = TempPath(tmp.join(format!("s11-codex-answer-{}-{}.json", pid, id)));

    write_file(schema_path.as_path(), schema).map_err(CodexError::Io)?;

    let output = Command::new(&config.codex_bin)
        .arg("exec")
        .arg("-m")
        .arg(&config.model)
        .arg("-s")
        .arg("read-only")
        .arg("--ephemeral")
        .arg("--skip-git-repo-check")
        .arg("--output-schema")
        .arg(schema_path.as_path())
        .arg("-o")
        .arg(answer_path.as_path())
        .arg(prompt)
        .output()
        .map_err(|e| CodexError::Io(e.to_string()))?;

    if !output.status.success() {
        return Err(CodexError::NonZeroExit {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let json = std::fs::read_to_string(answer_path.as_path())
        .map_err(|e| CodexError::Io(format!("reading answer file: {}", e)))?;

    parse_codex_envelope(&json).map_err(CodexError::Envelope)
}

/// Create a new file with owner-only (`0o600`) permissions on Unix; falls
/// back to default permissions on non-Unix platforms (the LLM flow is only
/// tested on Linux). The schema file is dull but the answer file briefly
/// contains the model's response — we don't want to leak it to other users
/// on a multi-user host during the (small) window before the RAII guard
/// removes the file.
fn write_file(path: &Path, content: &str) -> Result<(), String> {
    use std::fs::OpenOptions;

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    f.write_all(content.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

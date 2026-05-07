//! Codex CLI invocation and response parsing.

use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::search::config::LlmConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidJson,
    MissingAssemblyField,
}

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
            CodexError::Envelope(e) => write!(f, "codex envelope parse error: {:?}", e),
        }
    }
}

#[derive(Deserialize)]
struct Envelope {
    assembly: Option<String>,
}

/// Parse the Codex `--output-schema` envelope into the assembly string.
pub fn parse_codex_envelope(json: &str) -> Result<String, EnvelopeError> {
    let env: Envelope = serde_json::from_str(json).map_err(|_| EnvelopeError::InvalidJson)?;
    env.assembly.ok_or(EnvelopeError::MissingAssemblyField)
}

/// Invoke `codex exec` with the given prompt and schema, return the asm string.
///
/// Uses an ephemeral, read-only Codex run with subscription auth (no API key needed).
/// Schema and answer files are written under the system temp dir.
pub fn invoke_codex(config: &LlmConfig, prompt: &str, schema: &str) -> Result<String, CodexError> {
    let tmp = std::env::temp_dir();
    let schema_path = tmp.join(format!("s11-codex-schema-{}.json", std::process::id()));
    let answer_path = tmp.join(format!("s11-codex-answer-{}.json", std::process::id()));

    write_file(&schema_path, schema).map_err(CodexError::Io)?;
    // Pre-clear any stale answer file.
    let _ = std::fs::remove_file(&answer_path);

    let output = Command::new(&config.codex_bin)
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
        .output()
        .map_err(|e| CodexError::Io(e.to_string()))?;

    if !output.status.success() {
        return Err(CodexError::NonZeroExit {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let json = std::fs::read_to_string(&answer_path)
        .map_err(|e| CodexError::Io(format!("reading answer file: {}", e)))?;

    parse_codex_envelope(&json).map_err(CodexError::Envelope)
}

fn write_file(path: &Path, content: &str) -> Result<(), String> {
    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;
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
    fn parses_empty_assembly() {
        let json = r#"{"assembly":""}"#;
        assert_eq!(parse_codex_envelope(json), Ok(String::new()));
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

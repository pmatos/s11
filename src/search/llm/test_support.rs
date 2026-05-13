#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static FAKE_CODEX_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
pub(crate) struct FakeCodex {
    path: PathBuf,
    dir: PathBuf,
}

#[cfg(unix)]
impl FakeCodex {
    pub(crate) fn new(body: &str) -> Self {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "s11-fake-codex-{}-{}",
            std::process::id(),
            FAKE_CODEX_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).expect("create fake codex temp dir");

        let path = dir.join("codex");
        let mut file = std::fs::File::create(&path).expect("create fake codex script");
        file.write_all(
            format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = \"__s11_ready_probe\" ]; then exit 0; fi\nset -eu\n{}",
                body
            )
            .as_bytes(),
        )
        .expect("write fake codex script");
        file.sync_all().expect("sync fake codex script");
        drop(file);
        let mut permissions = std::fs::metadata(&path)
            .expect("stat fake codex script")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("chmod fake codex script");
        wait_until_executable_ready(&path);

        Self { path, dir }
    }

    pub(crate) fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

#[cfg(unix)]
impl Drop for FakeCodex {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn wait_until_executable_ready(path: &Path) {
    for _ in 0..100 {
        match std::process::Command::new(path)
            .arg("__s11_ready_probe")
            .status()
        {
            Ok(status) if status.success() => return,
            Ok(status) => panic!("fake codex readiness probe exited with {status}"),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(1))
            }
            Err(e) => panic!("fake codex readiness probe failed: {e}"),
        }
    }
    panic!("fake codex executable was still busy after readiness probes");
}

#[cfg(unix)]
pub(crate) fn envelope_answer_writer_script(envelope: &str) -> String {
    answer_writer_script(envelope)
}

#[cfg(unix)]
pub(crate) fn assembly_answer_writer_script(assembly: &str) -> String {
    let envelope = format!(
        r#"{{"assembly":{}}}"#,
        serde_json::to_string(assembly).expect("quote assembly for fake response")
    );
    answer_writer_script(&envelope)
}

#[cfg(unix)]
fn answer_writer_script(envelope: &str) -> String {
    let envelope = shell_single_quote(envelope);
    format!(
        r#"answer=""
schema=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-schema)
      shift
      schema="$1"
      ;;
    -o)
      shift
      answer="$1"
      ;;
  esac
  shift || true
done
if [ -n "$schema" ]; then
  [ -s "$schema" ]
fi
[ -n "$answer" ]
printf '%s' {} > "$answer"
"#,
        envelope
    )
}

#[cfg(unix)]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

//! Output-path resolution — the seam deciding and enforcing where `opt` writes.
//!
//! `s11 opt` never rewrites the input binary in place: with no explicit
//! `-o/--output` it derives a `<stem>_optimized.<ext>` sibling. Existing explicit
//! or derived targets are refused unless `--force` was passed, but force never
//! permits an output that aliases the input. Parent existence and writability
//! are checked before search so a bad target fails cheaply.
//!
//! Any existing output that is not a regular file is refused outright, with or
//! without `--force`: this includes symlinks, directories, sockets, FIFOs, and
//! device nodes. See `validate_existing_output_kind` for the non-opening check.
//!
//! [`resolve_output_path`] returns a [`ResolvedOutput`] that carries the policy
//! into the final write, which repeats it: the preflight runs before a
//! potentially long search, so it cannot be the last word. Writes are staged in
//! a private directory under the destination, inherit the input's ordinary
//! access permissions, and are then published without exposing a partial
//! result. Deriving a sibling remains fallible for stem-less or non-UTF-8 input
//! names. See the `CONTEXT.md` glossary for the domain term.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use same_file::Handle;

/// A validated `opt` output target together with its overwrite policy.
///
/// Callers resolve this once before starting a potentially long search, then
/// pass it to the ELF writer, whose write re-applies the policy against the
/// state of the filesystem at the end of that search.
#[derive(Debug)]
pub struct ResolvedOutput {
    input: PathBuf,
    path: PathBuf,
    overwrite: bool,
}

impl ResolvedOutput {
    /// The path where the result will be materialized.
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let input_handle = Handle::from_path(&self.input).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot open input '{}': {error}", self.input.display()),
            )
        })?;
        self.write_from_input(bytes, &input_handle)
    }

    pub(crate) fn write_from_input(&self, bytes: &[u8], input: &Handle) -> io::Result<()> {
        let input_permissions = input
            .as_file()
            .metadata()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot read permissions from input '{}': {error}",
                        self.input.display()
                    ),
                )
            })?
            .permissions();
        // Build the complete result in a mode-0700 staging directory under the
        // destination. Another user with write access to the shared parent
        // cannot replace the named staging inode before publication, while the
        // nested location still guarantees a same-filesystem rename.
        let parent = output_parent(&self.path);
        let (staging_dir, mut staged) =
            create_staged_output(parent).map_err(|error| self.write_error(&error))?;
        staged
            .write_all(bytes)
            .map_err(|error| self.write_error(&error))?;
        staged
            .as_file()
            .set_permissions(sanitize_output_permissions(input_permissions))
            .map_err(|error| self.write_error(&error))?;

        if self.overwrite {
            return self.publish_forced(staging_dir, staged, input);
        }

        staged
            .persist_noclobber(&self.path)
            .map(|_| ())
            .map_err(|error| self.persist_error(&error.error))
    }

    /// Publish with one atomic exchange, then validate the entry displaced into
    /// the protected staging directory. This binds validation to replacement:
    /// no pathname race can substitute an input alias or special file between
    /// the two operations because they are the same filesystem operation.
    fn publish_forced(
        &self,
        mut staging_dir: tempfile::TempDir,
        mut staged: tempfile::NamedTempFile,
        input: &Handle,
    ) -> io::Result<()> {
        // Creation needs no replacement primitive. Trying no-clobber first
        // lets `--force` remain portable when the target is absent, while an
        // AlreadyExists result returns ownership of the staged file so the
        // atomic replacement path below can still handle a raced entry.
        match staged.persist_noclobber(&self.path) {
            Ok(_) => return Ok(()),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                staged = error.file;
            }
            Err(error) => return Err(self.write_error(&error.error)),
        }

        match exchange_paths(staged.path(), &self.path) {
            Ok(()) => match self.validate_displaced_target(staged.path(), input) {
                Ok(()) => {
                    // `staged` now names the safe, displaced old output. Its
                    // cleanup removes that inode; the open file it owns is the
                    // newly published output and remains at `self.path`.
                    drop(staged);
                    drop(staging_dir);
                    Ok(())
                }
                Err(refusal) => match exchange_paths(staged.path(), &self.path) {
                    Ok(()) => Err(refusal),
                    Err(rollback) => {
                        // A hostile shared-directory writer may remove the new
                        // output before rollback. Never let cleanup then unlink
                        // the displaced original: leave it at a reported,
                        // mode-0700 recovery path.
                        let recovery = staged.path().to_path_buf();
                        staged.disable_cleanup(true);
                        staging_dir.disable_cleanup(true);
                        Err(io::Error::new(
                            rollback.kind(),
                            format!(
                                "{refusal}; rollback failed: {rollback}; displaced entry preserved at '{}'",
                                recovery.display()
                            ),
                        ))
                    }
                },
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => staged
                .persist_noclobber(&self.path)
                .map(|_| ())
                .map_err(|persist| self.write_error(&persist.error)),
            Err(error) => Err(self.write_error(&error)),
        }
    }

    fn validate_displaced_target(&self, displaced: &Path, input: &Handle) -> io::Result<()> {
        let existing =
            std::fs::symlink_metadata(displaced).map_err(|error| self.write_error(&error))?;
        validate_existing_output_kind_at(displaced, &self.path, &existing)
            .map_err(|message| io::Error::new(io::ErrorKind::PermissionDenied, message))?;

        if path_points_to_handle(displaced, input) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                in_place_refusal(&self.path),
            ));
        }
        Ok(())
    }

    fn persist_error(&self, error: &io::Error) -> io::Error {
        if !self.overwrite && error.kind() == io::ErrorKind::AlreadyExists {
            io::Error::new(
                error.kind(),
                format!(
                    "output path '{}' appeared while the search was running; refusing to replace it (pass --force to replace it)",
                    self.path.display()
                ),
            )
        } else {
            self.write_error(error)
        }
    }

    fn write_error(&self, error: &io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!(
                "cannot write output path '{}': {error}",
                self.path.display()
            ),
        )
    }
}

/// Whether `path` currently identifies the exact input inode held open by the
/// optimizer, independent of what now exists at the original input pathname.
#[cfg(unix)]
fn path_points_to_handle(path: &Path, handle: &Handle) -> bool {
    same_file_ids(handle.as_file().metadata(), std::fs::metadata(path))
}

/// Whether `path` currently identifies the exact input file held open by the
/// optimizer, independent of what now exists at the original input pathname.
#[cfg(not(unix))]
fn path_points_to_handle(path: &Path, handle: &Handle) -> bool {
    matches!(Handle::from_path(path), Ok(path_handle) if &path_handle == handle)
}

/// Resolve where an `opt` run writes its result.
///
/// With no explicit `-o/--output`, derive the
/// `<stem>_optimized.<ext>` sibling. Unless `force` is true, an existing regular
/// file at the target is rejected; even with force, an output resolving to the
/// input binary — or to any non-regular filesystem entry — is always rejected.
/// The parent directory must already exist and be writable. A stem-less or
/// non-UTF-8 input name yields an error instead of panicking.
pub fn resolve_output_path(
    input: &Path,
    output: Option<&Path>,
    force: bool,
) -> Result<ResolvedOutput, String> {
    let output = match output {
        Some(out) => out.to_path_buf(),
        None => optimized_output_path(input)?,
    };

    validate_output_file_path(&output)?;

    if paths_point_to_same_file(input, &output) {
        return Err(in_place_refusal(&output));
    }

    // One stat decides the whole existing-target policy; the branches below
    // must not re-derive it, or the diagnostic and the check can disagree.
    match std::fs::symlink_metadata(&output) {
        Ok(existing) => validate_existing_output(&output, &existing, force)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => validate_output_parent(&output)?,
        Err(error) => {
            return Err(format!(
                "cannot inspect output path '{}': {error}",
                output.display()
            ));
        }
    }

    Ok(ResolvedOutput {
        input: input.to_path_buf(),
        path: output,
        overwrite: force,
    })
}

/// Decide whether an already-present `output` may become the result file.
///
/// Non-regular filesystem entries are refused with or without `--force`:
/// opening a symlink for writing truncates its *target*, a path the user never
/// named; opening a FIFO can block; and devices must not become output sinks.
/// None may advertise `--force` as the way forward.
fn validate_existing_output(
    output: &Path,
    existing: &std::fs::Metadata,
    force: bool,
) -> Result<(), String> {
    validate_existing_output_kind(output, existing)?;
    if !force {
        return Err(format!(
            "output path already exists: '{}' (pass --force to replace it)",
            output.display()
        ));
    }
    // Atomic replacement renames a new inode into the directory; the old
    // inode's mode is irrelevant, while parent publication permission is
    // essential and must fail before search.
    validate_output_parent(output)?;
    validate_sticky_replacement(output, existing)?;
    validate_atomic_replacement(output)
}

/// Reject every existing target that cannot safely become a regular result.
///
/// This check only inspects directory-entry metadata; it never opens the path,
/// so special files such as FIFOs cannot block preflight and device nodes can
/// never become output sinks.
fn validate_existing_output_kind(
    output: &Path,
    existing: &std::fs::Metadata,
) -> Result<(), String> {
    validate_existing_output_kind_at(output, output, existing)
}

/// Validate metadata read at `actual`, while diagnostics consistently name the
/// user-selected `display` path. They differ after an atomic exchange, when the
/// displaced entry is protected under the private staging directory.
fn validate_existing_output_kind_at(
    actual: &Path,
    display: &Path,
    existing: &std::fs::Metadata,
) -> Result<(), String> {
    let file_type = existing.file_type();
    if file_type.is_symlink() {
        return Err(match std::fs::read_link(actual) {
            Ok(target) => format!(
                "output path '{}' is a symlink to '{}'; refusing to write through it (pass -o '{}' or remove the link)",
                display.display(),
                target.display(),
                target.display()
            ),
            Err(_) => format!(
                "output path '{}' is a symlink; refusing to write through it (remove the link or choose a different -o/--output)",
                display.display()
            ),
        });
    }
    if file_type.is_dir() {
        return Err(format!(
            "output path '{}' is an existing directory; choose a file path with -o/--output",
            display.display()
        ));
    }
    if !file_type.is_file() {
        return Err(format!(
            "output path '{}' is not a regular file; choose a regular file path with -o/--output",
            display.display()
        ));
    }
    Ok(())
}

fn output_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_staged_output(parent: &Path) -> io::Result<(tempfile::TempDir, tempfile::NamedTempFile)> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".s11-output-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Apply this at creation time, not with a later chmod: no other user
        // may get a window in which they can enter the staging directory.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let staging_dir = builder.tempdir_in(parent)?;
    let staged = tempfile::NamedTempFile::new_in(staging_dir.path())?;
    Ok((staging_dir, staged))
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn exchange_paths(a: &Path, b: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        a,
        rustix::fs::CWD,
        b,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn exchange_paths(_a: &Path, _b: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform does not provide atomic pathname exchange",
    ))
}

/// Probe the exact cross-directory atomic exchange used for forced
/// publication. The destination-side probe file is owned by this process, so
/// the operation is non-destructive; sticky-directory ownership is checked
/// separately for the real existing target.
fn validate_atomic_replacement(output: &Path) -> Result<(), String> {
    let parent = output_parent(output);
    let (_staging_dir, staged) = create_staged_output(parent).map_err(|error| {
        format!(
            "output parent directory '{}' is not writable: {error}",
            parent.display()
        )
    })?;
    let peer = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "output parent directory '{}' is not writable: {error}",
            parent.display()
        )
    })?;
    exchange_paths(staged.path(), peer.path()).map_err(|error| {
        format!(
            "output parent directory '{}' cannot atomically replace '{}': {error}",
            parent.display(),
            output.display()
        )
    })
}

#[cfg(unix)]
fn validate_sticky_replacement(output: &Path, existing: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let parent = output_parent(output);
    let parent_metadata = std::fs::metadata(parent).map_err(|error| {
        format!(
            "cannot inspect output parent directory '{}': {error}",
            parent.display()
        )
    })?;
    if parent_metadata.mode() & 0o1000 == 0 {
        return Ok(());
    }

    let effective_uid = rustix::process::geteuid().as_raw();
    if sticky_directory_allows_replacement(parent_metadata.uid(), existing.uid(), effective_uid) {
        Ok(())
    } else {
        Err(format!(
            "cannot replace output path '{}' in sticky directory '{}': output is owned by uid {}, current effective uid is {}",
            output.display(),
            parent.display(),
            existing.uid(),
            effective_uid
        ))
    }
}

#[cfg(not(unix))]
fn validate_sticky_replacement(
    _output: &Path,
    _existing: &std::fs::Metadata,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn sticky_directory_allows_replacement(
    parent_uid: u32,
    output_uid: u32,
    effective_uid: u32,
) -> bool {
    effective_uid == 0 || effective_uid == parent_uid || effective_uid == output_uid
}

#[cfg(unix)]
fn sanitize_output_permissions(input: std::fs::Permissions) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    // The staged inode belongs to the current user, which may differ from the
    // input owner. Copy only ordinary access bits so a privileged invocation
    // can never manufacture a setuid/setgid executable owned by itself.
    std::fs::Permissions::from_mode(input.mode() & 0o777)
}

#[cfg(not(unix))]
fn sanitize_output_permissions(input: std::fs::Permissions) -> std::fs::Permissions {
    input
}

fn validate_output_parent(output: &Path) -> Result<(), String> {
    let parent = output_parent(output);
    // One stat answers both questions; `Path::exists` and `Path::is_dir` are
    // each a `metadata` call, so asking in turn would stat the same path twice.
    match std::fs::metadata(parent) {
        Err(_) => {
            return Err(format!(
                "output parent directory '{}' does not exist",
                parent.display()
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "output parent path '{}' is not a directory",
                parent.display()
            ));
        }
        Ok(_) => {}
    }
    // Exercise the exact directory-and-file creation used by publication. This
    // proves parent writability without depending on the mode of an old target
    // inode, which atomic replacement never opens.
    create_staged_output(parent).map_err(|error| {
        format!(
            "output parent directory '{}' is not writable: {error}",
            parent.display()
        )
    })?;
    Ok(())
}

/// Reject path spellings that cannot denote a regular output file.
///
/// Inspect the raw OS string: [`Path`] accessors intentionally normalize away
/// a trailing separator, which is precisely the distinction this preflight
/// must preserve so the final create cannot fail only after search.
fn validate_output_file_path(output: &Path) -> Result<(), String> {
    if output.as_os_str().is_empty() || output_path_ends_with_separator(output) {
        return Err(format!(
            "output path '{}' must name a file, not an empty or separator-terminated path",
            output.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn output_path_ends_with_separator(output: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    output.as_os_str().as_bytes().last() == Some(&b'/')
}

#[cfg(windows)]
fn output_path_ends_with_separator(output: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    matches!(
        output.as_os_str().encode_wide().next_back(),
        Some(last) if last == b'/' as u16 || last == b'\\' as u16
    )
}

#[cfg(not(any(unix, windows)))]
fn output_path_ends_with_separator(output: &Path) -> bool {
    output
        .to_string_lossy()
        .ends_with(std::path::MAIN_SEPARATOR)
}

/// Derive the default `<stem>_optimized.<ext>` sibling for `path`.
///
/// Fallible on purpose: `path` originates from the CLI, so it may have no file
/// stem (`..`, `/`) or a non-UTF-8 name (arbitrary bytes on Linux). Rather than
/// `unwrap` those away — which panicked the driver — surface an error the
/// caller turns into a clean message pointing at `-o/--output`.
fn optimized_output_path(path: &Path) -> Result<PathBuf, String> {
    let mut new_path = path.to_path_buf();
    let stem = new_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            format!(
                "cannot derive an output path from input '{}': it has no usable (UTF-8) file name (pass an explicit -o/--output)",
                path.display()
            )
        })?;
    let extension = match new_path.extension() {
        Some(ext) => Some(ext.to_str().ok_or_else(|| {
            format!(
                "cannot derive an output path from input '{}': its extension is not valid UTF-8 (pass an explicit -o/--output)",
                path.display()
            )
        })?),
        None => None,
    };

    let new_name = if let Some(ext) = extension {
        format!("{}_optimized.{}", stem, ext)
    } else {
        format!("{}_optimized", stem)
    };

    new_path.set_file_name(new_name);
    Ok(new_path)
}

/// Whether `a` and `b` are the same file on disk.
///
/// Comparing the `(device, inode)` pair is the only check that catches a **hard
/// link**: two hard links to one inode are distinct directory entries with
/// distinct canonical paths, so a canonical-path comparison would miss them and
/// let an `-o` hard link to the input slip through the in-place guard and get
/// truncated by `create_patched_copy`. `metadata` follows symlinks and requires
/// the path to exist, so it subsumes the symlink and `./bin` vs `bin` cases too.
#[cfg(unix)]
fn paths_point_to_same_file(a: &Path, b: &Path) -> bool {
    same_file_ids(std::fs::metadata(a), std::fs::metadata(b))
}

/// Whether `a` and `b` are the same file on disk.
///
/// Without `(device, inode)` this compares canonical paths, then literal paths
/// when canonicalization fails — which only happens for a not-yet-created
/// output, which therefore cannot be the input.
#[cfg(not(unix))]
fn paths_point_to_same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// The single `(device, inode)` identity rule, shared by the preflight guard
/// and the write-time recheck so the two can never drift apart.
///
/// Takes the `Result`s rather than the metadata so the "a failed stat means
/// *different*" half of the rule is shared too: a `-o` target that does not
/// exist yet cannot alias the already-present input.
#[cfg(unix)]
fn same_file_ids(a: io::Result<std::fs::Metadata>, b: io::Result<std::fs::Metadata>) -> bool {
    use std::os::unix::fs::MetadataExt;
    matches!((a, b), (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino())
}

/// The one wording for "this output is the input binary", shared by the
/// preflight guard and the write-time recheck that enforce the same rule.
fn in_place_refusal(output: &Path) -> String {
    format!(
        "output path '{}' resolves to the input binary; refusing to optimize in place (choose a different -o/--output)",
        output.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TempFile;

    #[test]
    fn resolve_output_path_falls_back_to_derived_path() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("prog.elf");
        assert_eq!(
            resolve_output_path(&input, None, false).unwrap().path(),
            dir.path().join("prog_optimized.elf")
        );
    }

    #[test]
    fn resolve_output_path_honors_explicit_output() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("prog.elf");
        let out = dir.path().join("out.bin");
        assert_eq!(
            resolve_output_path(&input, Some(&out), false)
                .unwrap()
                .path(),
            out
        );
    }

    #[test]
    fn resolve_output_path_rejects_explicit_output_without_a_file_name() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("prog.elf");
        let mut trailing_separator = dir.path().join("result").into_os_string();
        trailing_separator.push(std::path::MAIN_SEPARATOR_STR);

        for output in [PathBuf::new(), PathBuf::from(trailing_separator)] {
            let err = resolve_output_path(&input, Some(&output), false)
                .expect_err("explicit output must name a file");
            assert!(
                err.contains("output path") && err.contains("must name a file"),
                "unexpected error for {output:?}: {err}"
            );
            assert!(
                !err.contains("--force"),
                "force cannot make an unusable file path valid: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_reports_metadata_errors_before_search() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("prog.elf");
        let output = dir.path().join("x".repeat(256));

        let err = resolve_output_path(&input, Some(&output), false)
            .expect_err("an invalid final component must fail during preflight");

        assert!(
            err.contains("cannot inspect output path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_output_path_rejects_in_place_output() {
        // The same existing file addressed two ways (a `.` component): on Unix
        // the guard fires via the (dev, ino) identity check, off-Unix via
        // canonicalization — either way, not literal string comparison.
        let input = TempFile::new_bytes("s11-resolve-inplace", "elf", &[0u8; 4]);
        let aliased = input
            .path()
            .parent()
            .unwrap()
            .join(".")
            .join(input.path().file_name().unwrap());
        for force in [false, true] {
            let err = resolve_output_path(input.path(), Some(&aliased), force)
                .expect_err("output resolving to the input binary must be rejected");
            assert!(
                err.contains("refusing to optimize in place"),
                "unexpected error with force={force}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_rejects_hard_link_to_input() {
        // A hard link shares the input's inode but has a distinct canonical
        // path, so only a (dev, ino) comparison — not canonicalize — catches it.
        let input = TempFile::new_bytes("s11-resolve-hardlink", "elf", &[0u8; 8]);
        let link = input.path().with_extension("hardlink");
        std::fs::hard_link(input.path(), &link).expect("create hard link to input");
        for force in [false, true] {
            let err = resolve_output_path(input.path(), Some(&link), force)
                .expect_err("a hard link to the input binary must be rejected");
            assert!(
                err.contains("refusing to optimize in place"),
                "unexpected error with force={force}: {err}"
            );
        }
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn resolve_output_path_errors_on_stem_less_input() {
        // `..` / `/` have no file stem; the derived-name step must surface an
        // error the driver can report, not panic on an `unwrap`.
        for input in [Path::new(".."), Path::new("/")] {
            let err = resolve_output_path(input, None, false)
                .expect_err("an input path with no file stem must yield an error, not a panic");
            assert!(
                err.contains("output path"),
                "unexpected error for {input:?}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_errors_on_non_utf8_input() {
        // Linux filenames are arbitrary bytes; a non-UTF-8 name must not panic
        // when the driver derives `<stem>_optimized`.
        use std::os::unix::ffi::OsStrExt;
        let input = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"bin\xffname"));
        let err = resolve_output_path(&input, None, false)
            .expect_err("a non-UTF-8 input path must yield an error, not a panic");
        assert!(err.contains("output path"), "unexpected error: {err}");
    }

    #[test]
    fn resolved_output_refuses_target_created_after_preflight() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("output.elf");
        std::fs::write(&input, b"original input binary").expect("seed input");
        let resolved = resolve_output_path(&input, Some(&output), false)
            .expect("missing output should pass preflight");
        let sentinel = b"file created while optimization was running";
        std::fs::write(&output, sentinel).expect("create racing output");

        let error = resolved
            .write(b"optimized ELF")
            .expect_err("default writer must refuse the racing output");

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            error.to_string().contains("output.elf") && error.to_string().contains("--force"),
            "racing-output diagnostic must name the path and the override: {error}"
        );
        assert_eq!(
            std::fs::read(&output).expect("read racing output"),
            sentinel,
            "racing output must remain unchanged"
        );
    }

    #[test]
    fn forced_write_creates_a_missing_output_without_replacement() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("output.elf");
        std::fs::write(&input, b"original input binary").expect("seed input");

        let resolved = resolve_output_path(&input, Some(&output), true)
            .expect("force must not require replacement support for a missing target");
        resolved
            .write(b"optimized ELF")
            .expect("force should create a missing output with no-clobber publication");

        assert_eq!(
            std::fs::read(output).expect("read created output"),
            b"optimized ELF"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolved_output_preserves_access_permissions_without_privilege_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("output.elf");
        std::fs::write(&input, b"original input binary").expect("seed input");
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o6751))
            .expect("set executable input mode with privilege bits");

        let resolved = resolve_output_path(&input, Some(&output), false)
            .expect("missing output should pass preflight");
        resolved.write(b"optimized ELF").expect("write output");

        let output_mode = std::fs::metadata(&output)
            .expect("stat output")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            output_mode, 0o751,
            "output must inherit access bits without becoming setuid or setgid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn forced_write_refuses_hard_link_to_input_created_after_preflight() {
        // The write-time identity recheck is the only thing standing between a
        // `--force` run and a truncated input when a hard link appears at the
        // output path during the search.
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("output.elf");
        let input_bytes = b"original input binary";
        std::fs::write(&input, input_bytes).expect("seed input");
        std::fs::write(&output, b"stale output").expect("seed output");

        let resolved =
            resolve_output_path(&input, Some(&output), true).expect("forced output resolves");

        std::fs::remove_file(&output).expect("remove resolved output");
        std::fs::hard_link(&input, &output).expect("race a hard link into the output path");

        let error = resolved
            .write(b"optimized ELF")
            .expect_err("forced writer must refuse a hard link to the input");

        assert!(
            error.to_string().contains("refusing to optimize in place"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(&input).expect("read input"),
            input_bytes,
            "input binary must survive the refused forced write"
        );
        assert!(
            paths_point_to_same_file(&input, &output),
            "atomic refusal must restore the raced input link at the output path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn forced_write_refuses_symlink_created_after_preflight() {
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("output.elf");
        std::fs::write(&input, b"original input binary").expect("seed input");
        std::fs::write(&output, b"stale output").expect("seed output");

        let resolved =
            resolve_output_path(&input, Some(&output), true).expect("forced output resolves");

        let victim = dir.path().join("unrelated.txt");
        let victim_bytes = b"unrelated file contents";
        std::fs::write(&victim, victim_bytes).expect("seed unrelated file");
        std::fs::remove_file(&output).expect("remove resolved output");
        std::os::unix::fs::symlink(&victim, &output).expect("race a symlink into the output path");

        let error = resolved
            .write(b"optimized ELF")
            .expect_err("forced writer must refuse a raced symlink");

        assert!(
            error.to_string().contains("is a symlink"),
            "unexpected error: {error}"
        );
        assert_eq!(
            std::fs::read(&victim).expect("read unrelated file"),
            victim_bytes,
            "forced publication must not follow the raced symlink"
        );
        assert_eq!(
            std::fs::read_link(&output).expect("raced symlink should be restored"),
            victim,
            "atomic refusal must restore the unsafe output entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_refuses_symlink_output_even_with_force() {
        // Opening a symlink for writing truncates its target — a path the user
        // never named — so neither the default nor the forced policy may follow
        // one. Regression for the clobber this seam exists to prevent.
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        std::fs::write(&input, b"input").expect("seed input");
        let victim = dir.path().join("unrelated.txt");
        let victim_bytes = b"unrelated file contents";
        std::fs::write(&victim, victim_bytes).expect("seed unrelated file");
        let link = dir.path().join("out.elf");
        std::os::unix::fs::symlink(&victim, &link).expect("create symlink output");

        for force in [false, true] {
            let err = resolve_output_path(&input, Some(&link), force)
                .expect_err("a symlink output must be rejected");
            assert!(
                err.contains("is a symlink") && err.contains("unrelated.txt"),
                "diagnostic should name the symlink target with force={force}: {err}"
            );
        }
        assert_eq!(
            std::fs::read(&victim).expect("read unrelated file"),
            victim_bytes,
            "the symlink target must be untouched"
        );
    }

    #[test]
    fn resolve_output_path_refuses_directory_output_without_advertising_force() {
        // `--force` can never turn a directory into the result file, so the
        // diagnostic must not send the user down that dead end.
        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        std::fs::write(&input, b"input").expect("seed input");
        let output_dir = dir.path().join("out.d");
        std::fs::create_dir(&output_dir).expect("create directory output");

        for force in [false, true] {
            let err = resolve_output_path(&input, Some(&output_dir), force)
                .expect_err("a directory output must be rejected");
            assert!(
                err.contains("is an existing directory"),
                "unexpected error with force={force}: {err}"
            );
            assert!(
                !err.contains("--force"),
                "directory diagnostic must not advertise --force: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_refuses_non_regular_output_without_opening_it() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().expect("create output directory");
        let input = dir.path().join("input.elf");
        std::fs::write(&input, b"input").expect("seed input");
        let socket = dir.path().join("out.sock");
        let _listener = UnixListener::bind(&socket).expect("bind output socket");

        for force in [false, true] {
            let err = resolve_output_path(&input, Some(&socket), force)
                .expect_err("a non-regular output must be rejected");
            assert!(
                err.contains("is not a regular file"),
                "unexpected error with force={force}: {err}"
            );
            assert!(
                !err.contains("--force"),
                "non-regular output diagnostic must not advertise --force: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_forced_output_requires_writable_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create fixture directory");
        let input = dir.path().join("input.elf");
        std::fs::write(&input, b"input").expect("seed input");
        let parent = dir.path().join("read-only");
        std::fs::create_dir(&parent).expect("create output parent");
        let output = parent.join("output.elf");
        std::fs::write(&output, b"stale output").expect("seed existing output");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555))
            .expect("make output parent read-only");

        if tempfile::tempfile_in(&parent).is_ok() {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
                .expect("restore output parent permissions");
            eprintln!(
                "Skipping forced-parent test: read-only mode not enforced (running as root?)"
            );
            return;
        }

        let result = resolve_output_path(&input, Some(&output), true);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("restore output parent permissions");
        let err = result.expect_err("forced replacement requires writable parent directory");
        assert!(
            err.contains("output parent directory") && err.contains("not writable"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_forced_output_does_not_require_old_inode_writability() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create fixture directory");
        let input = dir.path().join("input.elf");
        let output = dir.path().join("read-only-output.elf");
        std::fs::write(&input, b"input").expect("seed input");
        std::fs::write(&output, b"stale output").expect("seed existing output");
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o444))
            .expect("make old output inode read-only");

        if std::fs::OpenOptions::new()
            .write(true)
            .open(&output)
            .is_ok()
        {
            eprintln!("Skipping read-only-inode test: mode not enforced (running as root?)");
            return;
        }

        resolve_output_path(&input, Some(&output), true)
            .expect("atomic replacement should depend on parent, not old inode, writability");
    }

    #[cfg(unix)]
    #[test]
    fn sticky_directory_replacement_policy_checks_ownership() {
        assert!(sticky_directory_allows_replacement(10, 20, 0));
        assert!(sticky_directory_allows_replacement(10, 20, 10));
        assert!(sticky_directory_allows_replacement(10, 20, 20));
        assert!(
            !sticky_directory_allows_replacement(10, 20, 30),
            "an unrelated user cannot replace another users file in a sticky directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_output_is_nested_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("create output parent");
        let (staging_dir, staged) =
            create_staged_output(parent.path()).expect("create staged output");

        assert_eq!(
            staging_dir.path().parent(),
            Some(parent.path()),
            "staging directory must share the destination filesystem"
        );
        assert_eq!(
            staged.path().parent(),
            Some(staging_dir.path()),
            "named staging file must not be exposed directly in a shared parent"
        );
        let staging_mode = std::fs::metadata(staging_dir.path())
            .expect("stat staging directory")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            staging_mode, 0o700,
            "other users must not be able to replace the staged inode"
        );
    }
}

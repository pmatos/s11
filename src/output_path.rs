//! Output-path resolution — the seam deciding and enforcing where `opt` writes.
//!
//! `s11 opt` never rewrites the input binary in place: with no explicit
//! `-o/--output` it derives a `<stem>_optimized.<ext>` sibling. Existing explicit
//! or derived targets are refused unless `--force` was passed, but force never
//! permits an output that aliases the input. Parent existence and writability
//! are checked before search so a bad target fails cheaply.
//!
//! An output that already exists as a **symlink** or a **directory** is refused
//! outright, with or without `--force` — see `validate_existing_output` for why
//! `--force` cannot help in either case.
//!
//! [`resolve_output_path`] returns a [`ResolvedOutput`] that carries the policy
//! into the final write, which repeats it: the preflight runs before a
//! potentially long search, so it cannot be the last word. Deriving a sibling
//! remains fallible for stem-less or non-UTF-8 input names. See the
//! `CONTEXT.md` glossary for the domain term.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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

    pub(crate) fn write(&self, bytes: &[u8]) -> io::Result<()> {
        // `create_new` wins over `create` when both are set, so the two flags
        // are the whole policy: exclusive creation by default, open-or-create
        // under `--force`.
        let mut file = OpenOptions::new()
            .write(true)
            .create(self.overwrite)
            .create_new(!self.overwrite)
            .open(&self.path)
            .map_err(|error| {
                // The search that produced `bytes` may have run for hours, so an
                // open failure here has to name the path and the way out — the
                // bare `File exists (os error 17)` an unwrapped `create_new`
                // yields tells the user neither.
                let context = if error.kind() == io::ErrorKind::AlreadyExists {
                    format!(
                        "output path '{}' appeared while the search was running; refusing to replace it (pass --force to replace it)",
                        self.path.display()
                    )
                } else {
                    format!("cannot write output path '{}': {error}", self.path.display())
                };
                io::Error::new(error.kind(), context)
            })?;

        // Unconditional, though it can only fire under `--force`: the default
        // path just created this file exclusively, so it cannot already share
        // the input's inode. Stating the guard once beats gating it on the same
        // flag the open mode already encodes.
        if self.opened_target_aliases_input(&file) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                in_place_refusal(&self.path),
            ));
        }
        // Also a no-op on the default path: a freshly created file is empty.
        file.set_len(0)?;
        file.write_all(bytes)
    }

    /// Whether the file just opened at [`Self::path`] is the input binary.
    ///
    /// Re-checked at write time because the preflight identity guard in
    /// [`resolve_output_path`] runs before a potentially long search: a hard
    /// link to the input can appear at the output path in between.
    #[cfg(unix)]
    fn opened_target_aliases_input(&self, file: &File) -> bool {
        same_file_ids(file.metadata(), std::fs::metadata(&self.input))
    }

    #[cfg(not(unix))]
    fn opened_target_aliases_input(&self, _file: &File) -> bool {
        paths_point_to_same_file(&self.input, &self.path)
    }
}

/// Resolve where an `opt` run writes its result.
///
/// With no explicit `-o/--output`, derive the
/// `<stem>_optimized.<ext>` sibling. Unless `force` is true, an existing regular
/// file at the target is rejected; even with force, an output resolving to the
/// input binary — or to a symlink or directory — is always rejected. The parent
/// directory must already exist and be writable. A stem-less or non-UTF-8 input
/// name yields an error instead of panicking.
pub fn resolve_output_path(
    input: &Path,
    output: Option<&Path>,
    force: bool,
) -> Result<ResolvedOutput, String> {
    let output = match output {
        Some(out) => out.to_path_buf(),
        None => optimized_output_path(input)?,
    };

    if paths_point_to_same_file(input, &output) {
        return Err(in_place_refusal(&output));
    }

    // One stat decides the whole existing-target policy; the branches below
    // must not re-derive it, or the diagnostic and the check can disagree.
    match std::fs::symlink_metadata(&output) {
        Ok(existing) => validate_existing_output(&output, &existing, force)?,
        Err(_) => validate_output_parent(&output)?,
    }

    Ok(ResolvedOutput {
        input: input.to_path_buf(),
        path: output,
        overwrite: force,
    })
}

/// Decide whether an already-present `output` may become the result file.
///
/// Symlinks and directories are refused with or without `--force`: opening a
/// symlink for writing truncates its *target*, a path the user never named, and
/// a directory can never be replaced by a file — so neither may advertise
/// `--force` as the way forward.
fn validate_existing_output(
    output: &Path,
    existing: &std::fs::Metadata,
    force: bool,
) -> Result<(), String> {
    let file_type = existing.file_type();
    if file_type.is_symlink() {
        return Err(match std::fs::read_link(output) {
            Ok(target) => format!(
                "output path '{}' is a symlink to '{}'; refusing to write through it (pass -o '{}' or remove the link)",
                output.display(),
                target.display(),
                target.display()
            ),
            Err(_) => format!(
                "output path '{}' is a symlink; refusing to write through it (remove the link or choose a different -o/--output)",
                output.display()
            ),
        });
    }
    if file_type.is_dir() {
        return Err(format!(
            "output path '{}' is an existing directory; choose a file path with -o/--output",
            output.display()
        ));
    }
    if !force {
        return Err(format!(
            "output path already exists: '{}' (pass --force to replace it)",
            output.display()
        ));
    }
    OpenOptions::new()
        .write(true)
        .open(output)
        .map_err(|error| {
            format!(
                "output path '{}' is not writable: {error}",
                output.display()
            )
        })?;
    Ok(())
}

fn validate_output_parent(output: &Path) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
    tempfile::tempfile_in(parent).map_err(|error| {
        format!(
            "output parent directory '{}' is not writable: {error}",
            parent.display()
        )
    })?;
    Ok(())
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
}

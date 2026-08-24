//! Output-path resolution — the seam deciding and enforcing where `opt` writes.
//!
//! `s11 opt` never rewrites the input binary in place: with no explicit
//! `-o/--output` it derives a `<stem>_optimized.<ext>` sibling. Existing explicit
//! or derived targets are refused unless `--force` was passed, but force never
//! permits an output that aliases the input. Parent existence and writability
//! are checked before search so a bad target fails cheaply.
//!
//! [`resolve_output_path`] returns a [`ResolvedOutput`] that carries the policy
//! into the final write. Default writes use exclusive creation, closing the
//! race where another file appears during a long search; forced writes reopen
//! without truncation, recheck the input identity, and only then replace the
//! target. Deriving a sibling remains fallible for stem-less or non-UTF-8 input
//! names. See the `CONTEXT.md` glossary for the domain term.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A validated `opt` output target together with its overwrite policy.
///
/// Callers resolve this once before starting a potentially long search, then
/// pass it to the ELF writer. The final write repeats the safety policy:
/// default writes use exclusive creation, while forced writes may truncate a
/// distinct existing target but still refuse an alias of the input binary.
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
        let mut options = OpenOptions::new();
        options.write(true);
        if self.overwrite {
            options.create(true);
        } else {
            options.create_new(true);
        }

        let mut file = options.open(&self.path)?;
        if self.overwrite {
            if opened_file_points_to_path(&file, &self.input, &self.path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "output path '{}' resolves to the input binary; refusing to optimize in place",
                        self.path.display()
                    ),
                ));
            }
            file.set_len(0)?;
        }
        file.write_all(bytes)
    }
}

/// Resolve where an `opt` run writes its result.
///
/// With no explicit `-o/--output`, derive the
/// `<stem>_optimized.<ext>` sibling. Unless `force` is true, any existing target
/// is rejected; even with force, an output resolving to the input binary is
/// always rejected. The parent directory must already exist and be writable.
/// A stem-less or non-UTF-8 input name yields an error instead of panicking.
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
        Err(format!(
            "output path '{}' resolves to the input binary; refusing to optimize in place (choose a different -o/--output)",
            output.display()
        ))
    } else if std::fs::symlink_metadata(&output).is_ok() && !force {
        Err(format!(
            "output path already exists: '{}' (pass --force to replace it)",
            output.display()
        ))
    } else {
        validate_output_writable(&output)?;
        Ok(ResolvedOutput {
            input: input.to_path_buf(),
            path: output,
            overwrite: force,
        })
    }
}

#[cfg(unix)]
fn opened_file_points_to_path(file: &File, input: &Path, _output: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (file.metadata(), std::fs::metadata(input)) {
        (Ok(output), Ok(input)) => output.dev() == input.dev() && output.ino() == input.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn opened_file_points_to_path(_file: &File, input: &Path, output: &Path) -> bool {
    paths_point_to_same_file(input, output)
}

fn validate_output_writable(output: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(output).is_ok() {
        std::fs::OpenOptions::new()
            .write(true)
            .open(output)
            .map_err(|error| {
                format!(
                    "output path '{}' is not writable: {error}",
                    output.display()
                )
            })?;
        Ok(())
    } else {
        validate_output_parent(output)
    }
}

fn validate_output_parent(output: &Path) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return Err(format!(
            "output parent directory '{}' does not exist",
            parent.display()
        ));
    }
    if !parent.is_dir() {
        return Err(format!(
            "output parent path '{}' is not a directory",
            parent.display()
        ));
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
/// On Unix this compares the `(device, inode)` pair, the only check that catches
/// a **hard link**: two hard links to one inode are distinct directory entries
/// with distinct canonical paths, so a canonical-path comparison would miss them
/// and let an `-o` hard link to the input slip through the in-place guard and get
/// truncated by `create_patched_copy`. `metadata` follows symlinks and requires
/// the path to exist, so it subsumes the symlink and `./bin` vs `bin` cases too;
/// a `-o` target that does not exist yet cannot alias the already-present input,
/// so a failed stat means "different". Off Unix, fall back to comparing canonical
/// paths (then literal paths when canonicalization fails, which only happens for
/// a not-yet-created output that therefore cannot be the input).
fn paths_point_to_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    fn same_file(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::metadata(a), std::fs::metadata(b)) {
            (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    fn same_file(a: &Path, b: &Path) -> bool {
        match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(ca), Ok(cb)) => ca == cb,
            _ => a == b,
        }
    }
    same_file(a, b)
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
        assert_eq!(
            std::fs::read(&output).expect("read racing output"),
            sentinel,
            "racing output must remain unchanged"
        );
    }
}

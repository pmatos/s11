//! Output-path resolution — the pure seam deciding where an `opt` run writes.
//!
//! `s11 opt` never rewrites the input binary in place: with no explicit
//! `-o/--output` it writes a derived `<stem>_optimized.<ext>` sibling, and an
//! explicit output that resolves to the input itself is rejected rather than
//! silently clobbering the source. Those rules — deriving the sibling name and
//! the in-place guard (including the hard-link identity check that a
//! canonical-path comparison would miss) — used to live inline in the driver
//! (`main`'s `opt` arm), a shallow arrangement where the only way to exercise
//! "a hard link to the input is refused" or "a stem-less input yields an error"
//! was to drive the whole command.
//!
//! This module lifts those rules into a pure seam: paths in, a resolved
//! `PathBuf` or an error message out, with a single public entry point
//! ([`resolve_output_path`]). The derive step is fallible — a caller-supplied
//! path with no usable (UTF-8) file name yields an `Err` the driver reports,
//! never a panic. The two helpers behind the seam
//! (`optimized_output_path`, `paths_point_to_same_file`) stay private because
//! the whole point of the module is that callers only need the one decision.
//! See the `CONTEXT.md` glossary for the domain terms.

use std::path::{Path, PathBuf};

/// Resolve where an `opt` run writes its result.
///
/// With no explicit `-o/--output` the derived `<stem>_optimized.<ext>` sibling
/// is preserved verbatim (the pre-#616 single-window behaviour). An explicit
/// output is honoured, except when it resolves to the input binary itself: the
/// driver never rewrites the input in place, so that request is rejected rather
/// than silently clobbering the source. A `None` output over an input with no
/// usable file name (a stem-less or non-UTF-8 path) yields an error instead of
/// panicking, so the driver can report it and exit cleanly.
pub fn resolve_output_path(input: &Path, output: Option<&Path>) -> Result<PathBuf, String> {
    match output {
        Some(out) => {
            if paths_point_to_same_file(input, out) {
                Err(format!(
                    "output path '{}' resolves to the input binary; refusing to optimize in place (choose a different -o/--output)",
                    out.display()
                ))
            } else {
                Ok(out.to_path_buf())
            }
        }
        None => optimized_output_path(input),
    }
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
        let input = Path::new("/some/dir/prog.elf");
        assert_eq!(
            resolve_output_path(input, None).unwrap(),
            optimized_output_path(input).unwrap()
        );
    }

    #[test]
    fn resolve_output_path_honors_explicit_output() {
        let input = Path::new("/some/dir/prog.elf");
        let out = Path::new("/other/place/out.bin");
        assert_eq!(
            resolve_output_path(input, Some(out)).unwrap(),
            out.to_path_buf()
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
        let err = resolve_output_path(input.path(), Some(&aliased))
            .expect_err("output resolving to the input binary must be rejected");
        assert!(
            err.contains("refusing to optimize in place"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_output_path_rejects_hard_link_to_input() {
        // A hard link shares the input's inode but has a distinct canonical
        // path, so only a (dev, ino) comparison — not canonicalize — catches it.
        let input = TempFile::new_bytes("s11-resolve-hardlink", "elf", &[0u8; 8]);
        let link = input.path().with_extension("hardlink");
        std::fs::hard_link(input.path(), &link).expect("create hard link to input");
        let result = resolve_output_path(input.path(), Some(&link));
        let _ = std::fs::remove_file(&link);
        let err = result.expect_err("a hard link to the input binary must be rejected");
        assert!(
            err.contains("refusing to optimize in place"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_output_path_errors_on_stem_less_input() {
        // `..` / `/` have no file stem; the derived-name step must surface an
        // error the driver can report, not panic on an `unwrap`.
        for input in [Path::new(".."), Path::new("/")] {
            let err = resolve_output_path(input, None)
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
        let err = resolve_output_path(&input, None)
            .expect_err("a non-UTF-8 input path must yield an error, not a panic");
        assert!(err.contains("output path"), "unexpected error: {err}");
    }
}

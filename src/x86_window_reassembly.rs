//! Reassembly of a single optimized x86 window into patch bytes.
//!
//! Once x86 search returns an optimized Candidate for a window, the driver must
//! turn it back into bytes that can be spliced into the ELF at the window's
//! original address *without moving the window's fixed terminator*. On x86 the
//! only held-fixed terminator is a trailing `Jcc` (see [`split_terminator_x86`],
//! ADR-0009 whole-binary driver, and the `CONTEXT.md` Target/Candidate/Live-out
//! glossary). Its rel8/rel32 displacement is encoded relative to the byte that
//! follows it, so the terminator must stay at the exact byte offset it occupied
//! in the source window. This module owns that byte-offset invariant behind one
//! pure seam:
//!
//! * [`reassemble_optimized_x86_window`] — the deep entry point: library types
//!   in (the optimized IR, the original IR, the original terminator's raw bytes,
//!   the window byte length, and the arch), patch bytes out. It refuses to patch
//!   when the optimized sequence's terminator disagrees with the original's,
//!   derives the prefix's original byte room, re-encodes only the straight-line
//!   prefix, and NOP-pads the shrink so the pinned `Jcc` bytes land back at their
//!   original offset.
//!
//! This logic used to live inline in the binary's `ElfOptimizationBackend`
//! implementation for x86 in `main.rs`, interleaved with Capstone access — a
//! shallow arrangement where the only way to exercise "an optimized prefix that
//! shrinks must NOP-pad so the Jcc keeps its offset" or "a mismatched terminator
//! is refused" was to drive a whole ELF optimization. Lifting it into a pure
//! seam (no Capstone, no ELF I/O) makes each rule a fixture-free unit test and
//! leaves the driver a thin adapter that only pulls the pinned terminator's raw
//! bytes out of Capstone and hands them across the seam. This mirrors
//! [`x86_search_inputs`](crate::x86_search_inputs) and
//! [`aarch64_search_inputs`](crate::aarch64_search_inputs).

use crate::assembler::x86::X86Assembler;
use crate::elf_patcher::DetectedArch;
use crate::ir::instructions::split_terminator_x86;
use crate::isa::x86::X86Instruction;

/// Reassemble an optimized x86 window into patch bytes, preserving the original
/// `Jcc` terminator's byte offset.
///
/// * `final_ir` — the optimized Candidate for the whole window (prefix, plus the
///   held-fixed `Jcc` terminator if the window had one).
/// * `original_ir` — the window's original Target. Only its terminator is
///   consulted: it must equal `final_ir`'s terminator, otherwise the search
///   returned a sequence that transfers control differently and the window is
///   refused rather than incorrectly patched.
/// * `pinned_terminator_bytes` — the raw bytes of the original `Jcc` as they were
///   encoded in the source binary. `Some` iff the original window ended in a
///   terminator; the caller (a Capstone adapter) supplies them because
///   re-encoding the `Jcc` here would emit a placeholder zero displacement.
/// * `original_window_byte_len` — the byte length of the whole original window
///   (prefix + terminator), used to recover the prefix's original byte room.
/// * `arch` — selects the 32- vs 64-bit encoder and NOP filler.
///
/// Returns `Err` when the terminators disagree, when a terminator is present but
/// its bytes were not supplied, when the optimized prefix is larger than the
/// original prefix's byte room (shifting the `Jcc` earlier would corrupt its
/// displacement), or when the arch is not an x86 mode.
pub fn reassemble_optimized_x86_window(
    final_ir: &[X86Instruction],
    original_ir: &[X86Instruction],
    pinned_terminator_bytes: Option<&[u8]>,
    original_window_byte_len: usize,
    arch: DetectedArch,
) -> Result<Vec<u8>, String> {
    let (final_prefix_ir, final_terminator) = split_terminator_x86(final_ir);
    let (_, original_terminator) = split_terminator_x86(original_ir);

    // A search that changes the terminator changes where control transfers.
    // Splicing the original `Jcc` bytes behind such a prefix would silently
    // patch the wrong branch, so refuse rather than patch incorrectly.
    if final_terminator != original_terminator {
        return Err(format!(
            "search returned a terminator ({final_terminator:?}) that does not match \
             the original window's terminator ({original_terminator:?}); refusing to patch"
        ));
    }

    // The original terminator's IR is the source of truth for whether a `Jcc`
    // must be spliced; its raw bytes come from the caller (a Capstone adapter),
    // since re-encoding the `Jcc` here would emit a placeholder displacement.
    let pinned_terminator_bytes = if original_terminator.is_some() {
        match pinned_terminator_bytes {
            Some(bytes) => Some(bytes),
            None => {
                return Err(
                    "original window ends in a terminator but its pinned bytes were \
                     not supplied; cannot preserve the Jcc"
                        .to_string(),
                );
            }
        }
    } else {
        None
    };

    let original_prefix_byte_size =
        original_window_byte_len - pinned_terminator_bytes.map_or(0, <[u8]>::len);

    reassemble_prefix_with_pinned_terminator(
        final_prefix_ir,
        arch,
        pinned_terminator_bytes,
        original_prefix_byte_size,
    )
}

fn select_x86_assembler(arch: DetectedArch) -> Result<X86Assembler, String> {
    match arch {
        DetectedArch::X86_64 => Ok(X86Assembler::new_64()),
        DetectedArch::X86_32 => Ok(X86Assembler::new_32()),
        DetectedArch::Aarch64 => {
            Err("x86 window reassembly requires an x86 arch; got AArch64".to_string())
        }
    }
}

/// Assemble an x86 prefix and splice an ORIGINAL pinned `Jcc` terminator back at
/// its original byte offset. Re-encoding the `Jcc` via dynasm would emit a
/// placeholder zero displacement and overwrite the real branch target.
///
/// `pinned_terminator` is `None` when the source window had no trailing `Jcc`;
/// in that case the function returns the assembled prefix verbatim. When
/// `Some(jcc_bytes)`, the returned vector is exactly
/// `original_prefix_byte_size + jcc_bytes.len()` long, with NOP padding inserted
/// between the new prefix and the `Jcc` so the `Jcc` lands at its original
/// offset (preserving its rel8 / rel32 displacement).
///
/// Returns `Err` if the optimized prefix encodes to more bytes than the original
/// prefix occupied — shifting the `Jcc` earlier would change the branch target.
fn reassemble_prefix_with_pinned_terminator(
    final_prefix_ir: &[X86Instruction],
    arch: DetectedArch,
    pinned_terminator: Option<&[u8]>,
    original_prefix_byte_size: usize,
) -> Result<Vec<u8>, String> {
    let mut asm = select_x86_assembler(arch)?;
    let mut out = asm.assemble_instructions(final_prefix_ir)?;

    let Some(jcc_bytes) = pinned_terminator else {
        return Ok(out);
    };

    if out.len() > original_prefix_byte_size {
        return Err(format!(
            "optimized prefix ({} bytes) is larger than original prefix \
             ({} bytes); cannot preserve the pinned Jcc terminator's \
             displacement",
            out.len(),
            original_prefix_byte_size
        ));
    }

    let gap = original_prefix_byte_size - out.len();
    append_nop_padding(&mut out, gap, arch, |remaining| {
        arch.nop_sequence(remaining)
    })?;
    out.extend_from_slice(jcc_bytes);
    Ok(out)
}

fn append_nop_padding<F>(
    out: &mut Vec<u8>,
    gap: usize,
    arch: DetectedArch,
    mut nop_sequence: F,
) -> Result<(), String>
where
    F: FnMut(usize) -> &'static [u8],
{
    // Pad NOPs so the `Jcc` lands at the same offset as in the original window.
    // `nop_sequence` may return fewer than the requested bytes; loop until the
    // gap is filled. Return Err on an empty NOP slice (debug-assert alone would
    // let release builds spin forever).
    let mut padded = 0;
    while padded < gap {
        let remaining = gap - padded;
        let nop = nop_sequence(remaining);
        if nop.is_empty() {
            return Err(format!(
                "nop_sequence returned an empty slice while padding {} bytes \
                 for arch {:?}; refusing to spin forever",
                remaining, arch
            ));
        }
        let take = nop.len().min(remaining);
        out.extend_from_slice(&nop[..take]);
        padded += take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::{X86Condition, X86Instruction, X86Register};

    fn mov_rax_rbx() -> X86Instruction {
        X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }
    }

    #[test]
    fn rejects_when_optimized_terminator_differs_from_original() {
        // Original window ends in `je`; the optimized sequence ends in `jne`.
        // Splicing the original `je` bytes behind a prefix that logically ends
        // in `jne` would patch the wrong branch, so the seam must refuse.
        let original_ir = [
            mov_rax_rbx(),
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let final_ir = [
            mov_rax_rbx(),
            X86Instruction::Jcc {
                cond: X86Condition::NE,
            },
        ];
        let err = reassemble_optimized_x86_window(
            &final_ir,
            &original_ir,
            Some(&[0x74u8, 0x10]),
            5,
            DetectedArch::X86_64,
        )
        .expect_err("a mismatched terminator must be refused");
        assert!(
            err.contains("does not match") || err.contains("terminator"),
            "expected a terminator-mismatch error, got: {err}"
        );
    }

    #[test]
    fn preserves_pinned_terminator_offset_when_prefix_shrinks() {
        // Original window: 7-byte prefix + 2-byte `je` = 9 bytes, `je` at
        // offset 7. The optimized prefix shrinks to a 3-byte `mov rax, rbx`.
        // The seam must NOP-pad 4 bytes so the original `je` bytes land back at
        // offset 7, keeping their rel8 displacement valid.
        let original_jcc_bytes = [0x74u8, 0x20];
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let final_ir = [mov_rax_rbx(), jcc];
        let original_ir = [mov_rax_rbx(), jcc];
        let out = reassemble_optimized_x86_window(
            &final_ir,
            &original_ir,
            Some(&original_jcc_bytes),
            9,
            DetectedArch::X86_64,
        )
        .expect("reassemble succeeds");
        assert_eq!(
            out.len(),
            9,
            "patched window must match the original length"
        );
        assert_eq!(
            &out[7..9],
            &original_jcc_bytes,
            "pinned Jcc bytes must sit at the original offset"
        );
        assert_ne!(
            &out[3..7],
            &[0u8; 4],
            "the shrink gap must be NOP padding, not a zeroed branch displacement"
        );
    }

    #[test]
    fn rejects_when_terminator_present_but_pinned_bytes_missing() {
        // Defensive guard: the original window ends in a `Jcc` but no pinned
        // bytes were supplied. The seam cannot re-encode the branch, so it
        // refuses rather than emit a prefix with a dropped terminator.
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let final_ir = [mov_rax_rbx(), jcc];
        let original_ir = [mov_rax_rbx(), jcc];
        let err =
            reassemble_optimized_x86_window(&final_ir, &original_ir, None, 5, DetectedArch::X86_64)
                .expect_err("missing pinned bytes must be refused");
        assert!(
            err.contains("pinned bytes") || err.contains("terminator"),
            "expected a missing-pinned-bytes error, got: {err}"
        );
    }

    // --- x86 Jcc-byte preservation across reassembly (relocated from main.rs,
    // now targeting the private `reassemble_prefix_with_pinned_terminator`
    // helper directly through a library seam rather than the binary crate) ---

    #[test]
    fn reassemble_x86_no_terminator_returns_assembled_bytes_unchanged() {
        let final_ir = [mov_rax_rbx()];
        let bytes =
            reassemble_prefix_with_pinned_terminator(&final_ir, DetectedArch::X86_64, None, 3)
                .expect("reassemble succeeds");
        // No splice, no padding: just the assembled prefix.
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn reassemble_x86_splices_original_terminator_bytes_at_original_offset() {
        // Original window: [3-byte mov rax,rbx] [2-byte je 0x10] = 5 bytes total,
        // jcc at offset 3.
        // Optimized prefix: same 3-byte mov. Should produce: [mov, je] = 5 bytes,
        // jcc still at offset 3 (no NOP padding needed since prefix didn't shrink).
        let original_jcc_bytes = [0x74u8, 0x10]; // je rel8=0x10
        let final_ir = [mov_rax_rbx()];
        let out = reassemble_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            3,
        )
        .expect("reassemble succeeds");
        // Original Jcc bytes must be the LAST 2 bytes, unchanged.
        assert_eq!(&out[out.len() - 2..], &original_jcc_bytes);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn reassemble_x86_pads_with_nops_when_optimized_prefix_shrinks() {
        // Original window: 7-byte prefix + 2-byte jcc = 9 bytes, jcc at offset 7.
        // Optimized prefix shrinks to 3 bytes. We must NOP-pad 4 bytes so the
        // Jcc still lands at offset 7 (preserving its rel8 displacement).
        let original_jcc_bytes = [0x75u8, 0x20]; // jne rel8=0x20
        let final_ir = [mov_rax_rbx()];
        let out = reassemble_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            7,
        )
        .expect("reassemble succeeds");
        // Total length matches the original window.
        assert_eq!(out.len(), 9);
        // Jcc bytes are at the original offset (7).
        assert_eq!(&out[7..9], &original_jcc_bytes);
        // First 3 bytes are the new prefix; bytes [3..7] are NOP padding.
        // We don't assert specific NOP encodings here — `nop_sequence` is
        // covered separately. We just assert they aren't zero (which would
        // be the buggy `je BYTE 0` overwrite the reviewer flagged).
        assert_ne!(&out[3..7], &[0u8; 4]);
    }

    #[test]
    fn reassemble_x86_32_splices_and_pads_correctly() {
        // Mirrors the x86-64 pad-with-NOPs test for the x86-32 mode.
        // The x86-32 nop_sequence returns single-byte 0x90 NOPs, so the
        // padding loop must iterate `gap` times rather than once.
        let original_jcc_bytes = [0x74u8, 0x05]; // je rel8=5
        let final_ir = [mov_rax_rbx()];
        // Original prefix was 5 bytes; optimized prefix encodes to 2
        // bytes (`mov eax, ebx` on x86-32). NOP-pad 3 bytes then the
        // 2-byte je at offset 5 — total 7 bytes.
        let out = reassemble_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_32,
            Some(&original_jcc_bytes),
            5,
        )
        .expect("x86-32 reassemble succeeds");
        assert_eq!(out.len(), 7);
        assert_eq!(&out[5..7], &original_jcc_bytes);
        // Bytes [2..5] are NOP-padding; x86-32 nop_sequence emits 0x90.
        assert_eq!(&out[2..5], &[0x90u8; 3]);
    }

    #[test]
    fn append_nop_padding_clamps_overlong_nop_provider() {
        let mut out = vec![0xcc];

        append_nop_padding(&mut out, 3, DetectedArch::X86_64, |_| {
            &[0x90, 0x90, 0x90, 0x90]
        })
        .expect("padding succeeds");

        assert_eq!(out.len(), 4, "padding must not overshoot the requested gap");
        assert_eq!(&out[1..], &[0x90, 0x90, 0x90]);
    }

    #[test]
    fn reassemble_x86_rejects_optimized_prefix_larger_than_original() {
        // Pathological case: optimized prefix is LARGER than the original
        // prefix room. Cannot pad backwards. Must surface as an error
        // instead of silently corrupting the Jcc displacement.
        let original_jcc_bytes = [0x74u8, 0x10];
        // 3-byte assembled prefix — but we claim original prefix room was 1.
        let final_ir = [mov_rax_rbx()];
        let err = reassemble_prefix_with_pinned_terminator(
            &final_ir,
            DetectedArch::X86_64,
            Some(&original_jcc_bytes),
            1,
        )
        .expect_err("should reject");
        assert!(
            err.contains("larger") || err.contains("preserve"),
            "expected explanatory error, got: {}",
            err
        );
    }
}

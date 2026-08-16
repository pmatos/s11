//! Search inputs for a single x86 optimization window.
//!
//! [`candidate_windows`](crate::candidate_windows) *selects* which address
//! ranges of a binary are rewritable. This module answers the next question for
//! one already-selected window: given its Target (the window's instructions),
//! what does x86 search see, and is the window even admissible? Four pure
//! functions make up that seam:
//!
//! * [`registers_from_target`] — the Candidate register pool search may write.
//! * [`enumerative_immediates_from_target`] — the Candidate immediate pool the
//!   enumerative path draws from.
//! * [`live_out_for_optimization`] — the per-window Live-out contract, including
//!   the conditional-branch soundness veto on register narrowing.
//! * [`validate_terminator_placement`] — the admissibility gate that rejects a
//!   window the optimizer cannot soundly rewrite (a non-terminal `Jcc`).
//!
//! These rules used to live inline in the `run_x86_*` drivers in the binary's
//! `main.rs`, interleaved with CLI parsing, ELF I/O, and Capstone bridging — a
//! shallow arrangement where the only way to exercise "RSP/RBP are excluded from
//! the pool" or "a trailing terminator vetoes narrowing" was to drive a whole
//! search. Lifting them into a **pure seam** (library types in, library types
//! out; no CLI, ELF, or Capstone) makes each rule a fixture-free unit test and
//! keeps the drivers as a thin adapter. See the `CONTEXT.md` glossary for the
//! domain terms used above (Target, Candidate, Live-out, Observable state); the
//! narrowing/flags issue references live on the individual functions below.

use crate::isa::x86::{X86Instruction, X86Register, default_x86_registers};
use crate::semantics::live_out::{RegisterSet, X86LiveOut};
use crate::validation::live_out::x86_live_out_from_target;

/// Reject any non-terminal `Jcc` in an x86 optimization window. The optimizer
/// only special-cases a trailing `Jcc` (peeled by `split_terminator_x86`,
/// displacement preserved by `reassemble_x86_prefix_with_pinned_terminator`). A
/// `Jcc` anywhere else in the window would be modelled as a data-state no-op by
/// both the concrete and SMT executors, so the equivalence check could accept a
/// rewrite that silently drops or rewrites the branch.
pub fn validate_terminator_placement(ir: &[X86Instruction]) -> Result<(), String> {
    for (idx, instr) in ir.iter().enumerate() {
        if matches!(instr, X86Instruction::Jcc { .. }) && idx != ir.len() - 1 {
            return Err(format!(
                "x86 window contains a non-terminal conditional branch at position {} \
                 (last position is {}). The optimizer only supports Jcc as the trailing \
                 terminator of a window. Narrow --start-addr/--end-addr to exclude the \
                 mid-window branch.",
                idx,
                ir.len() - 1
            ));
        }
    }
    Ok(())
}

/// Candidate register pool for x86 search, drawn from the target's original
/// destinations. The trait refactor regressed coverage by defaulting to the
/// fixed `default_x86_registers()` pool, so a window over R10-R15 had no
/// representable rewrite. Source-only registers are deliberately excluded: the
/// single candidate pool can place registers in writable positions, while
/// live-out tracking only makes original destinations plus EFLAGS observable.
/// `RSP` and `RBP` are also excluded so search never synthesizes stack/frame
/// writes. Falls back to the default pool only for an empty target; a non-empty
/// target with no usable destinations returns an empty pool so search does not
/// introduce unrelated writable registers.
pub fn registers_from_target(target: &[X86Instruction]) -> Vec<X86Register> {
    let mut pool: Vec<X86Register> = Vec::new();
    let referenced = target
        .iter()
        .filter_map(|instr| instr.destination_operand());
    for reg in referenced {
        if matches!(reg.canonical(), X86Register::RSP | X86Register::RBP) {
            continue;
        }
        if !pool.contains(&reg) {
            pool.push(reg);
        }
    }
    if target.is_empty() {
        return default_x86_registers();
    }
    pool
}

/// Candidate immediate pool for the x86 enumerative path: the target's own
/// immediates plus `0`, `1`, and `-1`. The fixed `default_x86_immediates()`
/// pool holds no negatives, so the trait refactor lost rewrites like
/// `mov rax, -1; mov rax, -1` → `mov rax, -1`.
pub fn enumerative_immediates_from_target(target: &[X86Instruction]) -> Vec<i64> {
    let mut imms = vec![0i64, 1, -1];
    let referenced = target.iter().filter_map(|instr| match instr {
        X86Instruction::MovImm { imm, .. }
        | X86Instruction::AddImm { imm, .. }
        | X86Instruction::SubImm { imm, .. }
        | X86Instruction::AndImm { imm, .. }
        | X86Instruction::OrImm { imm, .. }
        | X86Instruction::XorImm { imm, .. }
        | X86Instruction::CmpImm { imm, .. } => Some(*imm),
        _ => None,
    });
    for imm in referenced {
        if !imms.contains(&imm) {
            imms.push(imm);
        }
    }
    imms
}

/// Build the per-window x86 live-out contract.
///
/// EFLAGS liveness folds in the downstream flags scan (pre-existing). For
/// registers (issue #621): when `downstream_live` is `Some(set)`, the
/// window-written live-out set is narrowed to that proven-live subset;
/// when `None` every written register stays live (the pre-#621 default).
///
/// **Conditional/branch soundness gate (defense in depth).** Like the AArch64
/// builder, register narrowing applies only when the window has no terminator:
/// the downstream scan follows only the linear fall-through successor, so a
/// trailing Jcc (with its unscanned branch-taken target) vetoes narrowing.
/// The backend already withholds the narrowed set in that case; this is a
/// second, local guard so the function is sound regardless of caller.
pub fn live_out_for_optimization(
    target: &[X86Instruction],
    downstream_flags_live: bool,
    downstream_live: Option<&RegisterSet<X86Register>>,
) -> X86LiveOut {
    let live_out = x86_live_out_from_target(target);
    let flags_live = live_out.flags_live() || downstream_flags_live;
    let has_terminator = target.last().is_some_and(|i| i.is_terminator());
    let narrowing = if has_terminator {
        None
    } else {
        downstream_live
    };
    let narrowed = match narrowing {
        Some(live) => RegisterSet::from_registers(live.iter().copied().collect()),
        None => live_out,
    };
    narrowed.with_flags(flags_live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::X86Condition;

    // ===== enumerative_immediates_from_target (new coverage) =====

    #[test]
    fn enumerative_immediates_are_seeded_with_zero_one_minus_one() {
        // No target immediates: the pool is exactly the fixed seeds.
        assert_eq!(enumerative_immediates_from_target(&[]), vec![0, 1, -1]);
    }

    #[test]
    fn enumerative_immediates_append_novel_target_immediates_in_order() {
        // 42 and -5 are novel, so they follow the seeds in first-seen order.
        let target = [
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 42,
            },
            X86Instruction::AddImm {
                rd: X86Register::RBX,
                imm: -5,
            },
        ];
        assert_eq!(
            enumerative_immediates_from_target(&target),
            vec![0, 1, -1, 42, -5]
        );
    }

    #[test]
    fn enumerative_immediates_dedupe_against_seeds_and_repeats() {
        // 1 duplicates a seed; the second 7 duplicates the first — neither repeats.
        let target = [
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 1,
            },
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 7,
            },
            X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 7,
            },
        ];
        assert_eq!(
            enumerative_immediates_from_target(&target),
            vec![0, 1, -1, 7]
        );
    }

    #[test]
    fn enumerative_immediates_ignore_register_only_instructions() {
        // A register-to-register move carries no immediate to harvest.
        let target = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        assert_eq!(enumerative_immediates_from_target(&target), vec![0, 1, -1]);
    }

    // ===== registers_from_target (carried from main.rs) =====

    #[test]
    fn register_pool_is_destination_derived_and_empty_falls_back() {
        let target = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RSP,
                rs: X86Register::R11,
            },
            X86Instruction::CmpReg {
                rn: X86Register::RBP,
                rs: X86Register::R12,
            },
            X86Instruction::MovReg {
                rd: X86Register::R11,
                rs: X86Register::R10,
            },
            X86Instruction::AddReg {
                rd: X86Register::R12,
                rs: X86Register::RSP,
            },
        ];

        assert_eq!(
            registers_from_target(&target),
            vec![X86Register::R11, X86Register::R12]
        );
        assert_eq!(registers_from_target(&[]), default_x86_registers());
        assert_eq!(
            registers_from_target(&[
                X86Instruction::CmpImm {
                    rn: X86Register::R10,
                    imm: 1,
                },
                X86Instruction::CmpImm {
                    rn: X86Register::R10,
                    imm: 1,
                },
            ]),
            Vec::<X86Register>::new()
        );
        assert_eq!(
            registers_from_target(&[
                X86Instruction::CmpImm {
                    rn: X86Register::RSP,
                    imm: 1,
                },
                X86Instruction::CmpReg {
                    rn: X86Register::RBP,
                    rs: X86Register::RBP,
                },
            ]),
            Vec::<X86Register>::new()
        );
    }

    // ===== validate_terminator_placement (carried from main.rs) =====

    #[test]
    fn validate_rejects_mid_window_jcc() {
        let ir = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
        ];
        let err = validate_terminator_placement(&ir).expect_err("mid-window Jcc must be rejected");
        assert!(
            err.contains("non-terminal conditional branch") && err.contains("position 1"),
            "unhelpful error: {}",
            err
        );
    }

    #[test]
    fn validate_accepts_trailing_jcc() {
        let ir = vec![
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        validate_terminator_placement(&ir).expect("trailing Jcc must be accepted");
    }

    #[test]
    fn validate_accepts_no_jcc() {
        let ir = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        validate_terminator_placement(&ir).expect("Jcc-free window must be accepted");
    }

    // ===== live_out_for_optimization (carried from main.rs) =====

    #[test]
    fn live_out_includes_downstream_flags() {
        let mov_only = [X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];

        assert!(!live_out_for_optimization(&mov_only, false, None).flags_live());
        assert!(live_out_for_optimization(&mov_only, true, None).flags_live());

        let flag_writer = [X86Instruction::XorReg {
            rd: X86Register::RAX,
            rs: X86Register::RAX,
        }];
        assert!(live_out_for_optimization(&flag_writer, false, None).flags_live());
    }

    #[test]
    fn live_out_narrows_to_downstream_live_regs() {
        // Window writes RAX and RBX.
        let window = [
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::MovImm {
                rd: X86Register::RBX,
                imm: 0,
            },
        ];

        // Default (no downstream analysis): both written registers stay live.
        let default = live_out_for_optimization(&window, false, None);
        assert!(default.contains(X86Register::RAX));
        assert!(default.contains(X86Register::RBX));

        // Downstream scan proved only RBX live (RAX dead). The contract must
        // drop RAX and pin RBX.
        let downstream_live = RegisterSet::from_registers(vec![X86Register::RBX]);
        let narrowed = live_out_for_optimization(&window, false, Some(&downstream_live));
        assert!(
            !narrowed.contains(X86Register::RAX),
            "a provably-dead window register must be dropped from live-out"
        );
        assert!(
            narrowed.contains(X86Register::RBX),
            "a downstream-read window register must stay pinned"
        );
    }

    /// x86 sibling of the conditional-terminator soundness gate: a target
    /// ending in a Jcc must not narrow even if the proven-live set excludes a
    /// written register.
    #[test]
    fn live_out_does_not_narrow_with_trailing_jcc() {
        let target = [
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 7,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        // Pretend the fall-through scan proved RAX dead (empty set).
        let dead = RegisterSet::<X86Register>::empty();
        let live_out = live_out_for_optimization(&target, false, Some(&dead));
        assert!(
            live_out.contains(X86Register::RAX),
            "RAX must stay live: a trailing Jcc has an unscanned branch-taken successor, \
             so register narrowing must not apply"
        );
    }
}

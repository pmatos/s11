//! Search inputs for a single AArch64 optimization window.
//!
//! [`candidate_windows`](crate::candidate_windows) *selects* which address
//! ranges of a binary are rewritable. This module answers the next question for
//! one already-selected AArch64 window: given its Target (the window's
//! instructions) and the downstream liveness scan, what does the search see, and
//! is the window even admissible? Three pure functions make up that seam:
//!
//! * [`aarch64_search_registers`] — the Candidate register pool the search may
//!   write (the base general-purpose set plus every vector register the Target
//!   already names).
//! * [`live_out_for_optimization_prefix`] — the per-window Live-out contract,
//!   including the terminator soundness veto on register narrowing.
//! * [`validate_basic_block`] — the admissibility gate that rejects a window the
//!   optimizer cannot soundly rewrite (a branch anywhere but the final slot,
//!   issue #69 scope).
//!
//! These rules used to live inline in `run_optimization` and the AArch64 backend
//! in the binary's `main.rs`, interleaved with CLI parsing, ELF I/O, and
//! Capstone bridging — a shallow arrangement where the only way to exercise
//! "a held-fixed terminator vetoes narrowing" or "a mid-block branch is
//! rejected" was to drive a whole search. Lifting them into a **pure seam**
//! (library types in, library types out; no CLI, ELF, or Capstone) makes each
//! rule a fixture-free unit test and keeps the driver a thin adapter. This is
//! the AArch64 mirror of [`x86_search_inputs`](crate::x86_search_inputs); see
//! the `CONTEXT.md` glossary for the domain terms (Target, Candidate, Live-out).

use crate::ir::{Instruction, Register};
use crate::semantics::LiveOut;
use crate::semantics::live_out::RegisterSet;

/// The Live-out contract for an AArch64 optimization window.
///
/// A held-fixed terminator vetoes register narrowing: its other successor is
/// never scanned, so a register the fall-through path proved dead may still be
/// read on the taken path. Without a terminator, an available downstream-live
/// set narrows live-out to (written ∩ proven-live); otherwise every
/// window-written register stays live. A terminator's own source registers are
/// always re-pinned so it can be reattached bit-identically, and a terminator
/// keeps NZCV live for the same reason.
pub fn live_out_for_optimization_prefix(
    prefix: &[Instruction],
    terminator: Option<&Instruction>,
    downstream_flags_live: bool,
    downstream_live: Option<&RegisterSet<Register>>,
) -> LiveOut {
    // A terminator vetoes register narrowing (its other successor is unscanned).
    let narrowing = if terminator.is_some() {
        None
    } else {
        downstream_live
    };

    let mut live_registers: Vec<Register> = match narrowing {
        // Narrow to (written ∩ proven-live). The downstream set is already a
        // subset of the window-written registers (it is computed from exactly
        // that candidate set), so iterating it is sufficient.
        Some(live) => live.iter().copied().collect(),
        // No downstream analysis (or vetoed by a terminator): keep every
        // written register live.
        None => prefix
            .iter()
            .flat_map(|instr| instr.destinations())
            .collect(),
    };

    if let Some(terminator) = terminator {
        live_registers.extend(terminator.source_registers());
    }

    let flags_live = if terminator.is_some() {
        true
    } else {
        downstream_flags_live
    };

    LiveOut::from_registers(live_registers).with_flags(flags_live)
}

/// The Candidate register pool AArch64 search may write for `target`.
///
/// The base general-purpose set (x0..x7) is always available; every vector
/// register the Target already reads or writes joins the pool so a rewrite can
/// reuse it. The pool is sorted for deterministic search behaviour.
pub fn aarch64_search_registers(target: &[Instruction]) -> Vec<Register> {
    let mut registers = vec![
        Register::X0,
        Register::X1,
        Register::X2,
        Register::X3,
        Register::X4,
        Register::X5,
        Register::X6,
        Register::X7,
    ];

    for register in target
        .iter()
        .flat_map(|instruction| instruction.source_registers().into_iter())
        .chain(
            target
                .iter()
                .flat_map(|instruction| instruction.destinations().into_iter()),
        )
        .filter(|register| register.vector().is_some())
    {
        if !registers.contains(&register) {
            registers.push(register);
        }
    }
    registers.sort_by_key(|register| register.sort_key());
    registers
}

/// Reject any window that is not a single basic block ending in a terminator.
///
/// Issue #69 only supports rewriting the straight-line prefix of a window whose
/// sole control-flow instruction (if any) is its last: a branch anywhere else
/// would be modelled as a data-state no-op and the equivalence check could
/// accept a rewrite that silently drops or reorders the branch.
///
/// Accepted shapes: `[]`, `[i1, ..., ik]` (no branch), `[t]` (terminator
/// only), `[i1, ..., ik, t]` (prefix + terminator).
pub fn validate_basic_block(ir: &[Instruction]) -> Result<(), String> {
    let last_idx = ir.len().saturating_sub(1);
    for (i, instr) in ir.iter().enumerate() {
        if i < last_idx && instr.is_terminator() {
            return Err(format!(
                "Region contains a branch at position {} ({}); only single basic blocks ending in a terminator are supported (issue #69 scope)",
                i, instr
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{self, Operand};
    use crate::semantics;

    // ===== Issue #69: validate_basic_block =====

    #[test]
    fn validate_basic_block_accepts_empty_sequence() {
        assert!(validate_basic_block(&[]).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_prefix_only_no_terminator() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(2),
            },
        ];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_terminator_only() {
        let seq = vec![Instruction::Ret { rn: Register::X30 }];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn validate_basic_block_accepts_prefix_plus_terminator() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Ret { rn: Register::X30 },
        ];
        assert!(validate_basic_block(&seq).is_ok());
    }

    #[test]
    fn validate_basic_block_rejects_branch_mid_block() {
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::B {
                target: ir::LabelId(0x1000),
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(2),
            },
        ];
        let err = validate_basic_block(&seq).expect_err("branch at position 1 must be rejected");
        assert!(
            err.contains("position 1") && err.contains("issue #69"),
            "unexpected error: {}",
            err
        );
    }

    // ===== aarch64_search_registers =====

    #[test]
    fn aarch64_search_registers_include_vectors_used_by_target() {
        let target = [
            Instruction::VectorAdd {
                vd: ir::VectorRegister::V0,
                vn: ir::VectorRegister::V1,
                vm: ir::VectorRegister::V2,
                arrangement: ir::VectorArrangement::TwoD,
            },
            Instruction::MovFromVectorLane {
                rd: Register::X0,
                vn: ir::VectorRegister::V0,
                lane: 0,
            },
        ];

        let registers = aarch64_search_registers(&target);

        assert!(registers.contains(&Register::Vector(ir::VectorRegister::V0)));
        assert!(registers.contains(&Register::Vector(ir::VectorRegister::V1)));
        assert!(registers.contains(&Register::Vector(ir::VectorRegister::V2)));
        assert_eq!(
            registers
                .iter()
                .filter(|reg| reg.vector().is_some())
                .count(),
            3
        );
    }

    // ===== live_out_for_optimization_prefix =====

    #[test]
    fn live_out_for_optimization_prefix_narrows_to_downstream_live_regs() {
        // Prefix writes x0 and x1.
        let prefix = [
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 0,
            },
        ];

        // Default (no downstream analysis): both written registers stay live.
        let default = live_out_for_optimization_prefix(&prefix, None, false, None);
        assert!(default.contains(Register::X0));
        assert!(default.contains(Register::X1));

        // Downstream scan proved only x1 live (x0 dead): drop x0, pin x1.
        let downstream_live = semantics::live_out::RegisterSet::from_registers(vec![Register::X1]);
        let narrowed =
            live_out_for_optimization_prefix(&prefix, None, false, Some(&downstream_live));
        assert!(
            !narrowed.contains(Register::X0),
            "a provably-dead window register must be dropped from live-out"
        );
        assert!(
            narrowed.contains(Register::X1),
            "a downstream-live window register must stay pinned"
        );
    }

    /// Soundness regression: a window whose held-fixed terminator is a
    /// CONDITIONAL branch must NOT narrow window-written registers, even if the
    /// linear fall-through suffix proved one dead. The downstream-regs scan only
    /// follows the fall-through successor; the branch-TAKEN successor is never
    /// inspected and may read the register's window value.
    ///
    /// Counterexample being guarded against:
    ///   window:       mov x0, #7 ; b.eq TARGET
    ///   fall-through: mov x0, #0 ; ret           (kills x0 -> scan says Dead)
    ///   elsewhere:    TARGET: add x9, x0, #1     (READS x0 on the taken path)
    /// If x0 were narrowed to dead, `mov x0, #7` could be deleted and the
    /// b.eq-taken path would read a stale x0. `BCond::source_registers()` is
    /// empty, so the terminator does not re-pin x0 either — the only correct
    /// fix is to not narrow at all when a terminator is present.
    #[test]
    fn live_out_for_optimization_prefix_does_not_narrow_with_conditional_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X0,
            imm: 7,
        }];
        let b_eq = Instruction::BCond {
            target: ir::LabelId(0x2000),
            cond: ir::Condition::EQ,
        };

        // The fall-through scan "proved" x0 dead (empty proven-live set).
        let downstream_live_fall_through = semantics::live_out::RegisterSet::<Register>::empty();

        let live_out = live_out_for_optimization_prefix(
            &prefix,
            Some(&b_eq),
            false,
            Some(&downstream_live_fall_through),
        );

        assert!(
            live_out.contains(Register::X0),
            "x0 must stay live: a conditional terminator has a branch-taken successor \
             the fall-through scan never inspected, so register narrowing must not apply"
        );
    }

    /// Same soundness gate for unconditional terminators: the instruction at
    /// `end_addr` is not the real/only successor, so narrowing must not apply.
    #[test]
    fn live_out_for_optimization_prefix_does_not_narrow_with_unconditional_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X0,
            imm: 7,
        }];
        let cases = [
            Instruction::B {
                target: ir::LabelId(0x2000),
            },
            Instruction::Ret { rn: Register::X30 },
        ];
        let dead = semantics::live_out::RegisterSet::<Register>::empty();
        for terminator in cases {
            let live_out =
                live_out_for_optimization_prefix(&prefix, Some(&terminator), false, Some(&dead));
            assert!(
                live_out.contains(Register::X0),
                "x0 must stay live with a {:?} terminator: narrowing must not apply",
                terminator
            );
        }
    }

    #[test]
    fn live_out_for_optimization_prefix_includes_registers_read_by_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];
        let cases = [
            (
                Instruction::Cbz {
                    rn: Register::X0,
                    target: ir::LabelId(0x1000),
                },
                Register::X0,
            ),
            (
                Instruction::Tbz {
                    rt: Register::X2,
                    bit: 5,
                    target: ir::LabelId(0x1000),
                },
                Register::X2,
            ),
            (Instruction::Br { rn: Register::X16 }, Register::X16),
            (Instruction::Ret { rn: Register::X30 }, Register::X30),
        ];

        for (terminator, source) in cases {
            let live_out =
                live_out_for_optimization_prefix(&prefix, Some(&terminator), false, None);
            assert!(live_out.contains_register(Register::X1));
            assert!(
                live_out.contains_register(source),
                "{:?} must keep {:?} live for the reattached terminator",
                terminator,
                source
            );
        }
    }

    #[test]
    fn live_out_for_optimization_prefix_uses_downstream_flags_without_terminator() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];

        let flags_dead = live_out_for_optimization_prefix(&prefix, None, false, None);
        assert!(!flags_dead.flags_live());

        let flags_live = live_out_for_optimization_prefix(&prefix, None, true, None);
        assert!(flags_live.flags_live());
    }

    #[test]
    fn live_out_for_optimization_prefix_keeps_flags_live_for_terminators() {
        let prefix = [Instruction::MovImm {
            rd: Register::X1,
            imm: 1,
        }];

        let b_cond = Instruction::BCond {
            target: ir::LabelId(0x1000),
            cond: ir::Condition::EQ,
        };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&b_cond), false, None);
        assert!(live_out.flags_live());

        let ret = Instruction::Ret { rn: Register::X30 };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&ret), false, None);
        assert!(live_out.flags_live());
    }
}

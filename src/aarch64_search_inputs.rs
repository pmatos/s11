//! Search inputs for a single AArch64 optimization window.
//!
//! [`plan_candidate_windows`](crate::candidate_windows) *selects* which address
//! ranges of a binary are rewritable. This module answers the next question for
//! one already-selected window: given its Target (the window's instructions),
//! what does AArch64 search see, and is the window even admissible? Four pure
//! functions make up that seam:
//!
//! * [`registers_from_target`] — the Candidate register pool search may write.
//! * [`default_immediates`] — the fixed Candidate immediate pool every AArch64
//!   algorithm draws from.
//! * [`live_out_for_optimization_prefix`] — the per-window Live-out contract,
//!   including the terminator soundness veto on register narrowing.
//! * [`validate_basic_block`] — the admissibility gate that rejects a window the
//!   optimizer cannot soundly rewrite (a non-terminal terminator, issue #69).
//!
//! These rules used to live inline in the `run_optimization` driver in the
//! binary's `main.rs`, interleaved with CLI parsing, ELF I/O, and Capstone
//! bridging — a shallow arrangement where the only way to exercise "X0..X7 plus
//! the target's vector registers" or "a held-fixed terminator vetoes narrowing"
//! was to drive a whole search. Lifting them into a **pure seam** (library types
//! in, library types out; no CLI, ELF, or Capstone) makes each rule a
//! fixture-free unit test and keeps the driver a thin adapter. This mirrors
//! [`x86_search_inputs`](crate::x86_search_inputs), extracted for the x86 path
//! in #752. See the `CONTEXT.md` glossary for the domain terms used above
//! (Target, Candidate, Live-out, Observable state).

use crate::ir::{Instruction, Register};
use crate::semantics::{LiveOut, RegisterSet};

/// Build the AArch64 search register pool, preserving the historical X0..X7
/// scalar policy while adding every vector register referenced by the target.
/// A target-local vector pool avoids the 32^3 candidate explosion of enabling
/// the entire SIMD register file for small enumerative searches.
pub fn registers_from_target(target: &[Instruction]) -> Vec<Register> {
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

/// The fixed AArch64 Candidate immediate pool every algorithm draws from: small
/// constants, powers of two and their neighbours, and encodable masks. Unlike
/// the x86 pool it is not target-derived — it is a shared default handed to
/// every AArch64 builder (stochastic/enumerative/hybrid/symbolic/LLM) via
/// `run_optimization`.
pub fn default_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

/// Build the per-window AArch64 Live-out contract over the window `prefix`.
///
/// Register liveness: when `downstream_live` is `Some(set)` *and* there is no
/// held-fixed terminator, the window-written live-out set is narrowed to that
/// proven-live subset; otherwise every written register stays live. Any
/// register the reattached `terminator` reads is then pinned live. NZCV
/// liveness comes from the terminator (always live) or the downstream
/// fall-through scan.
///
/// **Terminator soundness veto.** A held-fixed terminator has an unscanned
/// second successor (the branch-taken target), so its downstream register scan
/// only covers the fall-through path. Register narrowing is therefore vetoed
/// whenever a terminator is present, so a register live only on the taken path
/// is never dropped. Mirrors the same guard in
/// [`x86_search_inputs::live_out_for_optimization`](crate::x86_search_inputs::live_out_for_optimization).
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

/// Admissibility gate for an AArch64 optimization window (issue #69): reject any
/// window that contains a terminator anywhere but its final position. The
/// optimizer only supports a single basic block whose trailing terminator is
/// held fixed and reattached bit-identical; a mid-window branch would be modeled
/// as a data-state no-op, so the equivalence check could accept a rewrite that
/// silently drops it.
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
    use crate::ir::{Condition, LabelId, Operand, VectorArrangement, VectorRegister};

    // ===== default_immediates (new coverage) =====

    #[test]
    fn default_immediates_is_the_fixed_search_pool() {
        // The AArch64 immediate pool is a fixed set of small constants and
        // encodable masks. It used to be an untested literal inline in
        // `run_optimization`; pinning it here guards silent edits to the pool.
        assert_eq!(
            default_immediates(),
            vec![
                0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095
            ]
        );
    }

    #[test]
    fn default_immediates_span_zero_to_the_imm12_ceiling() {
        let imms = default_immediates();
        assert!(imms.contains(&0));
        assert!(imms.contains(&1));
        // 4095 = 0xFFF is the largest value an unshifted imm12 can encode; the
        // pool must reach it (cf. #720's imm12 sampling contract) and never
        // exceed it, since a larger literal is not directly encodable.
        assert_eq!(imms.iter().copied().max(), Some(4095));
        assert!(imms.iter().all(|&imm| (0..=4095).contains(&imm)));
    }

    // ===== registers_from_target (new coverage + carried from main.rs) =====

    #[test]
    fn registers_from_target_does_not_admit_scalar_registers_beyond_x7() {
        // Deliberate policy: a scalar register the target references above X7 is
        // NOT added — only the fixed X0..X7 scalars plus target vector registers
        // seed the pool. Pin it so it does not read as an omission bug.
        let target = [Instruction::MovImm {
            rd: Register::X9,
            imm: 0,
        }];
        let pool = registers_from_target(&target);
        assert!(!pool.contains(&Register::X9));
        assert_eq!(pool.len(), 8);
    }

    #[test]
    fn registers_from_target_seeds_scalar_x0_through_x7_sorted() {
        // With no vector registers referenced, the pool is exactly the
        // historical X0..X7 scalar seed, in sort_key order.
        let target = [Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        assert_eq!(
            registers_from_target(&target),
            vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
                Register::X6,
                Register::X7,
            ]
        );
        // No stray vector registers when the target is purely scalar.
        assert!(
            registers_from_target(&target)
                .iter()
                .all(|reg| reg.vector().is_none())
        );
    }

    #[test]
    fn registers_from_target_include_vectors_used_by_target() {
        let target = [
            Instruction::VectorAdd {
                vd: VectorRegister::V0,
                vn: VectorRegister::V1,
                vm: VectorRegister::V2,
                arrangement: VectorArrangement::TwoD,
            },
            Instruction::MovFromVectorLane {
                rd: Register::X0,
                vn: VectorRegister::V0,
                lane: 0,
            },
        ];

        let registers = registers_from_target(&target);

        assert!(registers.contains(&Register::Vector(VectorRegister::V0)));
        assert!(registers.contains(&Register::Vector(VectorRegister::V1)));
        assert!(registers.contains(&Register::Vector(VectorRegister::V2)));
        assert_eq!(
            registers
                .iter()
                .filter(|reg| reg.vector().is_some())
                .count(),
            3
        );
    }

    // ===== live_out_for_optimization_prefix (carried from main.rs) =====

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
        let downstream_live = RegisterSet::from_registers(vec![Register::X1]);
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
            target: LabelId(0x2000),
            cond: Condition::EQ,
        };

        // The fall-through scan "proved" x0 dead (empty proven-live set).
        let downstream_live_fall_through = RegisterSet::<Register>::empty();

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
                target: LabelId(0x2000),
            },
            Instruction::Ret { rn: Register::X30 },
        ];
        let dead = RegisterSet::<Register>::empty();
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
                    target: LabelId(0x1000),
                },
                Register::X0,
            ),
            (
                Instruction::Tbz {
                    rt: Register::X2,
                    bit: 5,
                    target: LabelId(0x1000),
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
            target: LabelId(0x1000),
            cond: Condition::EQ,
        };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&b_cond), false, None);
        assert!(live_out.flags_live());

        let ret = Instruction::Ret { rn: Register::X30 };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&ret), false, None);
        assert!(live_out.flags_live());
    }

    // ===== validate_basic_block (carried from main.rs, issue #69) =====

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
                target: LabelId(0x1000),
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
}

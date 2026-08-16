//! Per-target search-input derivation for the AArch64 optimization driver.
//!
//! Before a search runs it needs three things derived from the *target* (see
//! `CONTEXT.md`): the **register pool** and **immediate pool** candidates may be
//! drawn from, and the **live-out contract** a candidate must preserve. Those
//! rules are policy, not plumbing:
//!
//! * the historical X0..X7 scalar pool, widened only by the target's own vector
//!   registers, keeps small enumerative searches from exploding over the full
//!   SIMD register file;
//! * the live-out contract narrows to a proven-live downstream set **only when no
//!   held-fixed terminator is present** — a terminator has an unscanned
//!   branch-taken successor, so narrowing there would be unsound (ADR-0006 /
//!   ADR-0008).
//!
//! These functions used to live inline in the 6,417-line binary crate
//! (`src/main.rs`), where the only way to exercise them was through the binary's
//! own `cli_helper_tests`. Lifting them into this library module — the
//! search-input analogue of [`crate::candidate_windows`] — makes every rule a
//! fixture-free unit test at a public seam, and lets `main.rs` shrink toward a
//! thin adapter. The x86 sibling of this module is
//! [`crate::x86_search_inputs`].

use crate::ir::{Instruction, Register};
use crate::semantics::LiveOut;
use crate::semantics::live_out::RegisterSet;

/// Build the per-window AArch64 live-out contract over the optimized prefix.
///
/// A held-fixed terminator vetoes register narrowing: the downstream-regs scan
/// follows only the linear fall-through successor, so a terminator's unscanned
/// branch-taken successor may read a register the scan "proved" dead. When a
/// terminator is present every written register stays live and its source
/// registers are pinned; NZCV is forced live. Without a terminator the contract
/// narrows to the proven-live downstream set (when supplied) and inherits the
/// downstream flag liveness. See ADR-0006 / ADR-0008.
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

/// Build the AArch64 search register pool, preserving the historical X0..X7
/// scalar policy while adding every vector register referenced by the target.
/// A target-local vector pool avoids the 32^3 candidate explosion of enabling
/// the entire SIMD register file for small enumerative searches.
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

/// The default AArch64 candidate immediate pool. A small, hand-picked set that
/// covers common small constants, power-of-two boundaries, and `4095` — the
/// largest value an unshifted imm12 field can encode. Mirrors
/// [`crate::x86_search_inputs::enumerative_immediates_from_target`]'s role for
/// the x86 path (which additionally seeds from the target); the AArch64 pool
/// is target-independent.
pub fn aarch64_search_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use crate::ir::{Instruction, Register, VectorArrangement, VectorRegister};

    #[test]
    fn aarch64_pool_is_exactly_x0_through_x7_for_a_scalar_target() {
        // A purely scalar window contributes no vector registers, so the pool is
        // the historical X0..X7 scalar policy and nothing else.
        let target = [Instruction::Add {
            rd: Register::X2,
            rn: Register::X1,
            rm: crate::ir::Operand::Register(Register::X0),
        }];
        assert_eq!(
            aarch64_search_registers(&target),
            vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
                Register::X6,
                Register::X7,
            ],
        );
    }

    #[test]
    fn aarch64_pool_does_not_admit_scalar_registers_beyond_x7() {
        // Deliberate policy: a scalar register the target references above X7 is
        // NOT added — only the fixed X0..X7 scalars plus target vector registers
        // seed the pool. Pin it so it does not read as an omission bug.
        let target = [Instruction::MovImm {
            rd: Register::X9,
            imm: 0,
        }];
        let pool = aarch64_search_registers(&target);
        assert!(!pool.contains(&Register::X9));
        assert_eq!(pool.len(), 8);
    }

    #[test]
    fn aarch64_pool_appends_target_vector_registers_sorted_after_scalars() {
        // A NEON window touching V1 widens the pool by exactly that vector
        // register, ordered after the scalars by `sort_key` (V1 -> 65).
        let target = [Instruction::VectorAdd {
            vd: VectorRegister::V1,
            vn: VectorRegister::V1,
            vm: VectorRegister::V1,
            arrangement: VectorArrangement::TwoD,
        }];
        assert_eq!(
            aarch64_search_registers(&target),
            vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
                Register::X6,
                Register::X7,
                Register::Vector(VectorRegister::V1),
            ],
        );
    }

    #[test]
    fn aarch64_immediate_pool_spans_zero_to_the_imm12_ceiling() {
        let imms = aarch64_search_immediates();
        assert!(imms.contains(&0));
        assert!(imms.contains(&1));
        // 4095 = 0xFFF is the largest value an unshifted imm12 can encode; the
        // pool must reach it (cf. #720's imm12 sampling contract) and never
        // exceed it, since a larger literal is not directly encodable.
        assert_eq!(imms.iter().copied().max(), Some(4095));
        assert!(imms.iter().all(|&imm| (0..=4095).contains(&imm)));
    }

    // --- Live-out contract regressions (relocated intact from the binary's
    // cli_helper_tests; ADR-0006 / ADR-0008 soundness gates). ---

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
            target: crate::ir::LabelId(0x2000),
            cond: crate::ir::Condition::EQ,
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
                target: crate::ir::LabelId(0x2000),
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
    fn aarch64_search_registers_include_vectors_used_by_target() {
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

        let registers = aarch64_search_registers(&target);

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
                    target: crate::ir::LabelId(0x1000),
                },
                Register::X0,
            ),
            (
                Instruction::Tbz {
                    rt: Register::X2,
                    bit: 5,
                    target: crate::ir::LabelId(0x1000),
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
            target: crate::ir::LabelId(0x1000),
            cond: crate::ir::Condition::EQ,
        };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&b_cond), false, None);
        assert!(live_out.flags_live());

        let ret = Instruction::Ret { rn: Register::X30 };
        let live_out = live_out_for_optimization_prefix(&prefix, Some(&ret), false, None);
        assert!(live_out.flags_live());
    }
}

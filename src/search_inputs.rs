//! Per-target search-input derivation — a pure seam shared by the AArch64 and
//! x86 optimization drivers.
//!
//! Before a search runs it needs three things derived from the *target* (see
//! `CONTEXT.md`): the **register pool** and **immediate pool** candidates may be
//! drawn from, and the **live-out contract** a candidate must preserve. Those
//! rules are policy, not plumbing:
//!
//! * the historical X0..X7 scalar pool, widened only by the target's own vector
//!   registers, keeps small enumerative searches from exploding over the full
//!   SIMD register file;
//! * the x86 pool excludes the stack pointer / frame pointer and falls back to a
//!   default pool for an empty target;
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
//! thin adapter.

use crate::ir::{Instruction, Register};
use crate::semantics::LiveOut;
use crate::semantics::live_out::{RegisterSet, X86LiveOut};

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

/// Build the per-window x86 live-out contract.
///
/// EFLAGS liveness folds in the downstream flags scan. For registers: when
/// `downstream_live` is `Some(set)`, the window-written live-out set is narrowed
/// to that proven-live subset; when `None` every written register stays live.
///
/// **Conditional/branch soundness gate (defense in depth).** Like the AArch64
/// builder, register narrowing applies only when the window has no terminator:
/// the downstream scan follows only the linear fall-through successor, so a
/// trailing Jcc (with its unscanned branch-taken target) vetoes narrowing.
pub fn x86_live_out_for_optimization(
    target: &[crate::isa::x86::X86Instruction],
    downstream_flags_live: bool,
    downstream_live: Option<&RegisterSet<crate::isa::x86::X86Register>>,
) -> X86LiveOut {
    let live_out = crate::validation::live_out::x86_live_out_from_target(target);
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
/// [`x86_enumerative_immediates_from_target`]'s role for the x86 path (which
/// additionally seeds from the target); the AArch64 pool is target-independent.
pub fn aarch64_search_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

/// Build the x86 search register pool from the target's own destination
/// registers, excluding the stack and frame pointers. An *empty* target falls
/// back to the default pool; a *non-empty* target whose instructions have no
/// destination operands (e.g. only `cmp`s) deliberately yields an **empty**
/// pool — the empty-target check runs after the derivation loop, so it does not
/// fire here.
pub fn x86_registers_from_target(
    target: &[crate::isa::x86::X86Instruction],
) -> Vec<crate::isa::x86::X86Register> {
    use crate::isa::x86::X86Register;
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
        return crate::isa::x86::default_x86_registers();
    }
    pool
}

/// Candidate immediate pool for the x86 enumerative path: the target's own
/// immediates plus `0`, `1`, and `-1`. The fixed `default_x86_immediates()`
/// pool holds no negatives, so the trait refactor lost rewrites like
/// `mov rax, -1; mov rax, -1` → `mov rax, -1`.
pub fn x86_enumerative_immediates_from_target(
    target: &[crate::isa::x86::X86Instruction],
) -> Vec<i64> {
    use crate::isa::x86::X86Instruction;
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

    use crate::isa::x86::{X86Instruction, X86Register, default_x86_registers};

    #[test]
    fn x86_pool_excludes_a_narrow_stack_pointer_view() {
        // ESP is the dword view of the stack pointer (reg 4). The filter checks
        // `canonical()`, so the narrow view is excluded just like RSP. (Broader
        // destination-derivation and empty-fallback behaviour is pinned by the
        // relocated `x86_register_pool_is_destination_derived_and_empty_falls_back`
        // regression below.)
        let target = [X86Instruction::MovImm {
            rd: X86Register::ESP,
            imm: 0,
        }];
        let pool = x86_registers_from_target(&target);
        assert!(!pool.contains(&X86Register::ESP));
        assert!(!pool.contains(&X86Register::RSP));
    }

    #[test]
    fn x86_enumerative_immediates_always_seed_zero_one_and_minus_one() {
        assert_eq!(x86_enumerative_immediates_from_target(&[]), vec![0, 1, -1]);
    }

    #[test]
    fn x86_enumerative_immediates_dedup_a_target_value_already_in_the_seed() {
        // The doc-comment regression: `mov rax, -1; mov rax, -1`. -1 is already a
        // seed, so it must not be appended twice.
        let target = [
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: -1,
            },
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: -1,
            },
        ];
        assert_eq!(
            x86_enumerative_immediates_from_target(&target),
            vec![0, 1, -1],
        );
    }

    #[test]
    fn x86_enumerative_immediates_append_novel_target_values_after_the_seed() {
        let target = [X86Instruction::AddImm {
            rd: X86Register::RAX,
            imm: 42,
        }];
        assert_eq!(
            x86_enumerative_immediates_from_target(&target),
            vec![0, 1, -1, 42],
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
    fn x86_live_out_for_optimization_includes_downstream_flags() {
        let mov_only = [X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];

        assert!(!x86_live_out_for_optimization(&mov_only, false, None).flags_live());
        assert!(x86_live_out_for_optimization(&mov_only, true, None).flags_live());

        let flag_writer = [X86Instruction::XorReg {
            rd: X86Register::RAX,
            rs: X86Register::RAX,
        }];
        assert!(x86_live_out_for_optimization(&flag_writer, false, None).flags_live());
    }

    #[test]
    fn x86_live_out_for_optimization_narrows_to_downstream_live_regs() {
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
        let default = x86_live_out_for_optimization(&window, false, None);
        assert!(default.contains(X86Register::RAX));
        assert!(default.contains(X86Register::RBX));

        // Downstream scan proved only RBX live (RAX dead). The contract must
        // drop RAX and pin RBX.
        let downstream_live = RegisterSet::from_registers(vec![X86Register::RBX]);
        let narrowed = x86_live_out_for_optimization(&window, false, Some(&downstream_live));
        assert!(
            !narrowed.contains(X86Register::RAX),
            "a provably-dead window register must be dropped from live-out"
        );
        assert!(
            narrowed.contains(X86Register::RBX),
            "a downstream-read window register must stay pinned"
        );
    }

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

    /// x86 sibling of the conditional-terminator soundness gate: a target
    /// ending in a Jcc must not narrow even if the proven-live set excludes a
    /// written register.
    #[test]
    fn x86_live_out_for_optimization_does_not_narrow_with_trailing_jcc() {
        use crate::isa::x86::X86Condition;
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
        let live_out = x86_live_out_for_optimization(&target, false, Some(&dead));
        assert!(
            live_out.contains(X86Register::RAX),
            "RAX must stay live: a trailing Jcc has an unscanned branch-taken successor, \
             so register narrowing must not apply"
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
    fn x86_register_pool_is_destination_derived_and_empty_falls_back() {
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
            x86_registers_from_target(&target),
            vec![X86Register::R11, X86Register::R12]
        );
        assert_eq!(x86_registers_from_target(&[]), default_x86_registers());
        assert_eq!(
            x86_registers_from_target(&[
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
            x86_registers_from_target(&[
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

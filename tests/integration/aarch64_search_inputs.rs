//! Integration coverage for the extracted `s11::aarch64_search_inputs` module.
//!
//! Before the AArch64 per-window search-inputs cluster moved out of `main.rs`
//! these functions lived in the binary crate and were unreachable from an
//! integration test — the only way to exercise the register-narrowing veto or
//! the single-basic-block gate was to drive a whole optimization run. Extracting
//! them into `s11::aarch64_search_inputs` makes the pure seam testable from
//! outside the crate, mirroring the `s11::x86_search_inputs` sibling (#752).
//!
//! Expected values are the known-good literals from the seam's own unit tests.

use s11::aarch64_search_inputs::{
    aarch64_search_registers, live_out_for_optimization_prefix, validate_basic_block,
};
use s11::ir::{
    Condition, Instruction, LabelId, Operand, Register, VectorArrangement, VectorRegister,
};
use s11::semantics::live_out::RegisterSet;

#[test]
fn live_out_narrows_to_the_downstream_live_registers() {
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

    // No downstream analysis: every written register stays live.
    let default = live_out_for_optimization_prefix(&prefix, None, false, None);
    assert!(default.contains(Register::X0));
    assert!(default.contains(Register::X1));

    // Downstream scan proved only x1 live: x0 is dropped, x1 is pinned.
    let downstream_live = RegisterSet::from_registers(vec![Register::X1]);
    let narrowed = live_out_for_optimization_prefix(&prefix, None, false, Some(&downstream_live));
    assert!(!narrowed.contains(Register::X0));
    assert!(narrowed.contains(Register::X1));
}

#[test]
fn live_out_does_not_narrow_when_a_terminator_is_held_fixed() {
    // Soundness gate: a held-fixed conditional terminator has a branch-taken
    // successor the fall-through scan never inspects, so narrowing must not
    // apply even when the fall-through "proved" the register dead.
    let prefix = [Instruction::MovImm {
        rd: Register::X0,
        imm: 7,
    }];
    let b_eq = Instruction::BCond {
        target: LabelId(0x2000),
        cond: Condition::EQ,
    };
    let dead = RegisterSet::<Register>::empty();

    let live_out = live_out_for_optimization_prefix(&prefix, Some(&b_eq), false, Some(&dead));
    assert!(
        live_out.contains(Register::X0),
        "a held-fixed terminator vetoes register narrowing"
    );
    assert!(
        live_out.flags_live(),
        "a held-fixed terminator keeps NZCV live for reattachment"
    );
}

#[test]
fn validate_basic_block_rejects_a_mid_block_branch() {
    let seq = [
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

    let err = validate_basic_block(&seq).expect_err("a branch mid-block is out of #69 scope");
    assert!(
        err.contains("position 1") && err.contains("issue #69"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_basic_block_accepts_a_prefix_ending_in_a_terminator() {
    let seq = [
        Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        },
        Instruction::Ret { rn: Register::X30 },
    ];
    assert!(validate_basic_block(&seq).is_ok());
}

#[test]
fn aarch64_search_registers_expose_base_gprs_and_target_vectors() {
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

    // The base general-purpose pool (x0..x7) is always available.
    assert!(registers.contains(&Register::X0));
    assert!(registers.contains(&Register::X7));
    // Every vector register named by the target joins the pool.
    assert!(registers.contains(&Register::Vector(VectorRegister::V0)));
    assert!(registers.contains(&Register::Vector(VectorRegister::V1)));
    assert!(registers.contains(&Register::Vector(VectorRegister::V2)));
}

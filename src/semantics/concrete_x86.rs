//! Concrete (non-symbolic) interpreter for the x86 backend.
//!
//! Mirrors `semantics::concrete::apply_instruction_concrete` but over
//! ## Deletion gate
//!
//! Issue #77 keeps this file as the x86 instruction interpreter while the
//! public search/equivalence callers route through the ISA trait surface.
//!
//! `X86Instruction` and `X86ConcreteMachineState`. Operand widths follow
//! `state.width()` — writes to registers are already masked by the
//! state, and flag computation receives the correct width.

use crate::isa::x86::X86Instruction;
use crate::semantics::live_out::X86LiveOut;
use crate::semantics::state::{ConcreteValue, Eflags, X86ConcreteMachineState};

/// Apply a single x86 instruction to a concrete machine state.
pub fn apply_instruction_concrete_x86(
    mut state: X86ConcreteMachineState,
    instruction: &X86Instruction,
) -> X86ConcreteMachineState {
    match instruction {
        X86Instruction::MovReg { rd, rs } => {
            let value = state.get_register(*rs);
            state.set_register(*rd, value);
        }
        X86Instruction::MovImm { rd, imm } => {
            state.set_register(*rd, ConcreteValue::from_i64(*imm));
        }
        X86Instruction::AddReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Add),
        X86Instruction::AddImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Add),
        X86Instruction::SubReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Sub),
        X86Instruction::SubImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Sub),
        X86Instruction::AndReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::And),
        X86Instruction::AndImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::And),
        X86Instruction::OrReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Or),
        X86Instruction::OrImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Or),
        X86Instruction::XorReg { rd, rs } => apply_binop_reg(&mut state, *rd, *rs, Binop::Xor),
        X86Instruction::XorImm { rd, imm } => apply_binop_imm(&mut state, *rd, *imm, Binop::Xor),
        X86Instruction::CmpReg { rn, rs } => apply_cmp_reg(&mut state, *rn, *rs),
        X86Instruction::CmpImm { rn, imm } => apply_cmp_imm(&mut state, *rn, *imm),
        X86Instruction::TestReg { rn, rs } => apply_test_reg(&mut state, *rn, *rs),
        X86Instruction::TestImm { rn, imm } => apply_test_imm(&mut state, *rn, *imm),
        X86Instruction::Neg { rd } => apply_neg(&mut state, *rd),
        X86Instruction::Not { rd } => apply_not(&mut state, *rd),
        X86Instruction::Inc { rd } => apply_inc(&mut state, *rd),
        X86Instruction::Dec { rd } => apply_dec(&mut state, *rd),
        X86Instruction::Cmov { rd, rs, cond } => {
            if state.get_flags().evaluate(*cond) {
                let v = state.get_register(*rs);
                state.set_register(*rd, v);
            }
            // CMOV does not write EFLAGS regardless of the branch taken.
        }
        // Jcc transfers control; PC is unmodelled and the search peels
        // it off via `split_terminator_x86`. Treat as a no-op for
        // safety if a stray Jcc reaches the concrete executor.
        X86Instruction::Jcc { .. } => {}
    }
    state
}

fn apply_cmp_reg(
    state: &mut X86ConcreteMachineState,
    rn: crate::isa::x86::X86Register,
    rs: crate::isa::x86::X86Register,
) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = state.get_register(rs).as_u64();
    let result = lhs.wrapping_sub(rhs);
    state.set_flags(Eflags::from_sub(lhs, rhs, result, state.width()));
}

fn apply_cmp_imm(state: &mut X86ConcreteMachineState, rn: crate::isa::x86::X86Register, imm: i64) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = imm as u64;
    let result = lhs.wrapping_sub(rhs);
    state.set_flags(Eflags::from_sub(lhs, rhs, result, state.width()));
}

// TEST is the non-destructive sibling of AND: it computes `rn & rhs`, sets
// flags from the result via the logical path (CF=OF=0, SF/ZF/PF from result),
// and writes no register — just as CMP discards a SUB result.
fn apply_test_reg(
    state: &mut X86ConcreteMachineState,
    rn: crate::isa::x86::X86Register,
    rs: crate::isa::x86::X86Register,
) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = state.get_register(rs).as_u64();
    let result = lhs & rhs;
    state.set_flags(Eflags::from_logical(result, state.width()));
}

fn apply_test_imm(state: &mut X86ConcreteMachineState, rn: crate::isa::x86::X86Register, imm: i64) {
    let lhs = state.get_register(rn).as_u64();
    let rhs = imm as u64;
    let result = lhs & rhs;
    state.set_flags(Eflags::from_logical(result, state.width()));
}

// NEG computes `rd = -rd` (two's complement) and sets EFLAGS as if computing
// `0 - rd`: CF = (rd != 0), with OF/SF/ZF/PF from the SUB result. We reuse the
// SUB flag path with lhs = 0, rhs = old_rd so the carry/overflow semantics
// match `sub` exactly.
fn apply_neg(state: &mut X86ConcreteMachineState, rd: crate::isa::x86::X86Register) {
    let old = state.get_register(rd).as_u64();
    let result = 0u64.wrapping_sub(old);
    state.set_register(rd, ConcreteValue::new(result));
    state.set_flags(Eflags::from_sub(0, old, result, state.width()));
}

// NOT computes `rd = !rd` (bitwise complement). It affects NO flags — EFLAGS
// is left exactly as it was, like MOV.
fn apply_not(state: &mut X86ConcreteMachineState, rd: crate::isa::x86::X86Register) {
    let old = state.get_register(rd).as_u64();
    state.set_register(rd, ConcreteValue::new(!old));
}

// INC computes `rd = rd + 1`. It sets OF/SF/ZF/PF exactly as `add rd, 1` would,
// but — the load-bearing subtlety — it leaves CF UNCHANGED (the incoming carry
// flows through untouched). We capture the prior CF FIRST, compute the ADD flag
// path for `rd + 1`, then override CF back to the captured value.
fn apply_inc(state: &mut X86ConcreteMachineState, rd: crate::isa::x86::X86Register) {
    let prev_cf = state.get_flags().cf;
    let old = state.get_register(rd).as_u64();
    let result = old.wrapping_add(1);
    state.set_register(rd, ConcreteValue::new(result));
    let mut flags = Eflags::from_add(old, 1, result, state.width());
    flags.cf = prev_cf;
    state.set_flags(flags);
}

// DEC computes `rd = rd - 1`. Like INC it sets OF/SF/ZF/PF as `sub rd, 1` would
// while leaving CF UNCHANGED. Capture the prior CF first, derive flags from the
// SUB path for `rd - 1`, then restore CF.
fn apply_dec(state: &mut X86ConcreteMachineState, rd: crate::isa::x86::X86Register) {
    let prev_cf = state.get_flags().cf;
    let old = state.get_register(rd).as_u64();
    let result = old.wrapping_sub(1);
    state.set_register(rd, ConcreteValue::new(result));
    let mut flags = Eflags::from_sub(old, 1, result, state.width());
    flags.cf = prev_cf;
    state.set_flags(flags);
}

#[derive(Clone, Copy)]
enum Binop {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

fn apply_binop_reg(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    rs: crate::isa::x86::X86Register,
    op: Binop,
) {
    let lhs = state.get_register(rd).as_u64();
    let rhs = state.get_register(rs).as_u64();
    apply_binop(state, rd, lhs, rhs, op);
}

fn apply_binop_imm(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    op: Binop,
) {
    let lhs = state.get_register(rd).as_u64();
    let rhs = imm as u64;
    apply_binop(state, rd, lhs, rhs, op);
}

fn apply_binop(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    lhs: u64,
    rhs: u64,
    op: Binop,
) {
    let width = state.width();
    let (result, flags) = match op {
        Binop::Add => {
            let r = lhs.wrapping_add(rhs);
            (r, Eflags::from_add(lhs, rhs, r, width))
        }
        Binop::Sub => {
            let r = lhs.wrapping_sub(rhs);
            (r, Eflags::from_sub(lhs, rhs, r, width))
        }
        Binop::And => {
            let r = lhs & rhs;
            (r, Eflags::from_logical(r, width))
        }
        Binop::Or => {
            let r = lhs | rhs;
            (r, Eflags::from_logical(r, width))
        }
        Binop::Xor => {
            let r = lhs ^ rhs;
            (r, Eflags::from_logical(r, width))
        }
    };
    state.set_register(rd, ConcreteValue::new(result));
    state.set_flags(flags);
}

/// Apply a sequence of x86 instructions to a concrete machine state.
/// Mirrors `apply_sequence_concrete` for AArch64; used by
/// stochastic/symbolic search to evaluate a candidate against a test
/// input.
pub fn apply_sequence_concrete_x86(
    state: crate::semantics::state::X86ConcreteMachineState,
    sequence: &[X86Instruction],
) -> crate::semantics::state::X86ConcreteMachineState {
    let mut s = state;
    for instr in sequence {
        s = apply_instruction_concrete_x86(s, instr);
    }
    s
}

/// Compare two x86 concrete states over the registers (and, when
/// `mask.flags_live()`, the EFLAGS) declared live-out by `mask`.
pub fn states_equal_for_live_out_x86(
    state1: &crate::semantics::state::X86ConcreteMachineState,
    state2: &crate::semantics::state::X86ConcreteMachineState,
    mask: &X86LiveOut,
) -> bool {
    for reg in mask.iter() {
        if state1.get_register(*reg) != state2.get_register(*reg) {
            return false;
        }
    }
    if mask.flags_live() && state1.get_flags() != state2.get_flags() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::x86::X86Register;

    #[test]
    fn cmpreg_sets_eflags_without_writing_register() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(5));
        state.set_register(X86Register::RBX, ConcreteValue::new(5));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        // Equal operands -> ZF set, no borrow.
        let flags = after.get_flags();
        assert!(flags.zf);
        assert!(!flags.cf);
        // Operand registers must be unchanged.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 5);
        assert_eq!(after.get_register(X86Register::RBX).as_u64(), 5);
    }

    #[test]
    fn testreg_zero_result_sets_zf_clears_cf_of_without_writing_register() {
        // rax & rbx == 0 -> ZF set; TEST writes no register and always
        // clears CF/OF (logical-flag semantics).
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xf0));
        state.set_register(X86Register::RBX, ConcreteValue::new(0x0f));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let flags = after.get_flags();
        assert!(flags.zf, "0xf0 & 0x0f == 0 -> ZF set");
        assert!(!flags.cf, "TEST always clears CF");
        assert!(!flags.of, "TEST always clears OF");
        assert!(!flags.sf);
        // Operands are untouched.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xf0);
        assert_eq!(after.get_register(X86Register::RBX).as_u64(), 0x0f);
    }

    #[test]
    fn testreg_nonzero_result_clears_zf_keeps_cf_of_clear() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xff));
        state.set_register(X86Register::RBX, ConcreteValue::new(0x0f));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let flags = after.get_flags();
        assert!(!flags.zf, "0xff & 0x0f == 0x0f != 0 -> ZF clear");
        assert!(!flags.cf);
        assert!(!flags.of);
    }

    #[test]
    fn testimm_masks_and_sets_flags_without_writing_register() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x80));
        // 0x80 & 0x80 = 0x80 (top bit of low byte set) -> nonzero.
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 0x80,
            },
        );
        let flags = after.get_flags();
        assert!(!flags.zf);
        assert!(!flags.cf);
        assert!(!flags.of);
        // rn untouched.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x80);

        // 0x80 & 0x7f == 0 -> ZF set.
        let mut state2 = X86ConcreteMachineState::new_zeroed(64);
        state2.set_register(X86Register::RAX, ConcreteValue::new(0x80));
        let after2 = apply_instruction_concrete_x86(
            state2,
            &X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 0x7f,
            },
        );
        assert!(after2.get_flags().zf);
        assert!(!after2.get_flags().cf);
        assert!(!after2.get_flags().of);
    }

    #[test]
    fn neg_of_zero_yields_zero_with_zf_set_and_cf_clear() {
        // NEG 0 -> 0; flags from `0 - 0`: ZF set, CF clear (rd == 0).
        let state = X86ConcreteMachineState::new_zeroed(64);
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Neg {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        let flags = after.get_flags();
        assert!(flags.zf, "neg 0 -> result 0 -> ZF set");
        assert!(!flags.cf, "neg 0 -> CF clear (operand was zero)");
        assert!(!flags.sf);
        assert!(!flags.of);
    }

    #[test]
    fn neg_of_nonzero_sets_cf_and_computes_twos_complement() {
        // NEG 1 -> -1 (all ones); CF set because operand != 0.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(1));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Neg {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(
            after.get_register(X86Register::RAX).as_u64(),
            0u64.wrapping_sub(1)
        );
        let flags = after.get_flags();
        assert!(flags.cf, "neg of nonzero sets CF");
        assert!(!flags.zf);
        assert!(flags.sf, "result -1 has top bit set");
    }

    #[test]
    fn not_flips_bits_and_leaves_flags_unchanged() {
        // NOT flips every bit and must NOT touch EFLAGS. Pre-set a flag
        // pattern, run NOT, and assert the flags are byte-for-byte identical.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x0f0f));
        // Establish a non-trivial incoming flag state via a CMP.
        state.set_register(X86Register::RBX, ConcreteValue::new(5));
        let state = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpImm {
                rn: X86Register::RBX,
                imm: 9,
            },
        );
        let flags_before = state.get_flags();
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Not {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), !0x0f0fu64);
        assert_eq!(
            after.get_flags(),
            flags_before,
            "NOT must leave EFLAGS unchanged"
        );
    }

    #[test]
    fn inc_adds_one_and_sets_zf_sf_pf_of() {
        // INC 0xFF -> 0x100: result nonzero, ZF clear, SF clear, no signed
        // overflow.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xFF));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Inc {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x100);
        let flags = after.get_flags();
        assert!(!flags.zf);
        assert!(!flags.sf);
        assert!(!flags.of);

        // INC of -1 (all ones) wraps to 0: ZF set.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(u64::MAX));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Inc {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        assert!(after.get_flags().zf, "INC of -1 wraps to 0 -> ZF set");
    }

    #[test]
    fn dec_subtracts_one_and_sets_zf_sf() {
        // DEC 1 -> 0: ZF set.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(1));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Dec {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        assert!(after.get_flags().zf, "dec 1 -> 0 -> ZF set");

        // DEC 0 -> -1 (all ones): SF set, ZF clear.
        let state = X86ConcreteMachineState::new_zeroed(64);
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Dec {
                rd: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), u64::MAX);
        let flags = after.get_flags();
        assert!(flags.sf, "dec 0 -> -1 -> SF set");
        assert!(!flags.zf);
    }

    // The load-bearing INC/DEC subtlety: CF is preserved across the operation,
    // unlike ADD/SUB which derive CF from the arithmetic. We assert this in
    // both directions (CF=1 stays 1, CF=0 stays 0) for both INC and DEC.
    #[test]
    fn inc_dec_preserve_carry_flag() {
        for instr in [
            X86Instruction::Inc {
                rd: X86Register::RAX,
            },
            X86Instruction::Dec {
                rd: X86Register::RAX,
            },
        ] {
            for cf_in in [true, false] {
                let mut state = X86ConcreteMachineState::new_zeroed(64);
                // Use a value where ADD/SUB by 1 would *change* CF if it were
                // derived (e.g. u64::MAX: add 1 carries; sub 1 from 0 borrows),
                // so a preserved CF is genuinely distinguishable.
                state.set_register(X86Register::RAX, ConcreteValue::new(u64::MAX));
                let mut flags = state.get_flags();
                flags.cf = cf_in;
                state.set_flags(flags);
                let after = apply_instruction_concrete_x86(state, &instr);
                assert_eq!(
                    after.get_flags().cf,
                    cf_in,
                    "{instr:?} must preserve CF (incoming CF = {cf_in})"
                );
            }
        }
    }

    #[test]
    fn cmpimm_less_than_sets_cf_and_sf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 5,
            },
        );
        assert!(after.get_flags().cf, "3 < 5 -> borrow");
        assert!(after.get_flags().sf);
        // rn must be untouched.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 3);
    }

    #[test]
    fn xorreg_self_clears_register_and_sets_zf() {
        // The canonical x86 zeroing idiom: `xor rax, rax`.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x42));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        let flags = after.get_flags();
        assert!(flags.zf, "zero flag set");
        assert!(!flags.cf, "CF cleared by logical");
        assert!(!flags.of, "OF cleared by logical");
        assert!(!flags.sf);
        assert!(flags.pf, "zero has even parity");
    }

    #[test]
    fn andimm_masks_register() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xff_ff));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm: 0xff,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xff);
        assert!(!after.get_flags().cf);
        assert!(!after.get_flags().of);
    }

    #[test]
    fn orreg_combines_bits() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xf0));
        state.set_register(X86Register::RBX, ConcreteValue::new(0x0f));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::OrReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xff);
        assert!(!after.get_flags().zf);
    }

    #[test]
    fn addreg_writes_sum_and_sets_eflags() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        state.set_register(X86Register::RBX, ConcreteValue::new(4));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 7);
        let flags = after.get_flags();
        assert!(!flags.cf);
        assert!(!flags.zf);
        assert!(!flags.sf);
        assert!(!flags.of);
    }

    #[test]
    fn addimm_carries_set_cf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(u64::MAX));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        assert!(after.get_flags().cf, "carry expected");
        assert!(after.get_flags().zf, "result is zero");
    }

    #[test]
    fn subreg_writes_difference_and_sets_eflags() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(10));
        state.set_register(X86Register::RBX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::SubReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 7);
        assert!(!after.get_flags().cf, "no borrow");
        assert!(!after.get_flags().zf);
    }

    #[test]
    fn subimm_borrow_sets_cf_and_sf() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(3));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 5,
            },
        );
        // 3 - 5 = -2 → 0xff..fe.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), u64::MAX - 1);
        assert!(after.get_flags().cf, "borrow");
        assert!(after.get_flags().sf, "negative");
    }

    #[test]
    fn movreg_copies_source_to_destination() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(0xcafebabe));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xcafebabe);
        // Source unchanged.
        assert_eq!(after.get_register(X86Register::RBX).as_u64(), 0xcafebabe);
        // MOV does not change EFLAGS.
        assert_eq!(after.get_flags(), Eflags::default());
    }

    #[test]
    fn movimm_loads_immediate() {
        let state = X86ConcreteMachineState::new_zeroed(64);
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 42,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 42);
        assert_eq!(after.get_flags(), Eflags::default());
    }

    #[test]
    fn movimm_in_32bit_state_truncates_to_low_32() {
        let state = X86ConcreteMachineState::new_zeroed(32);
        // i64 with high bits set; the 32-bit state must truncate.
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0x1_0000_0042i64,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x0000_0042);
    }

    // ---- apply_sequence_concrete_x86 + states_equal_for_live_out_x86 ----

    #[test]
    fn apply_sequence_concrete_x86_threads_state_left_to_right() {
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState};

        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(7));
        let seq = vec![
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 3,
            },
        ];
        let after = apply_sequence_concrete_x86(state, &seq);
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 10);
    }

    #[test]
    fn states_equal_for_live_out_x86_ignores_non_live_registers() {
        use crate::semantics::live_out::RegisterSet;
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState};

        let mut a = X86ConcreteMachineState::new_zeroed(64);
        let mut b = X86ConcreteMachineState::new_zeroed(64);
        a.set_register(X86Register::RAX, ConcreteValue::new(42));
        b.set_register(X86Register::RAX, ConcreteValue::new(42));
        a.set_register(X86Register::RCX, ConcreteValue::new(1));
        b.set_register(X86Register::RCX, ConcreteValue::new(99)); // differs

        // Only RAX live-out: equal.
        let mask = RegisterSet::from_registers(vec![X86Register::RAX]);
        assert!(states_equal_for_live_out_x86(&a, &b, &mask));

        // RCX live-out too: unequal.
        let mask = RegisterSet::from_registers(vec![X86Register::RAX, X86Register::RCX]);
        assert!(!states_equal_for_live_out_x86(&a, &b, &mask));
    }

    #[test]
    fn states_equal_for_live_out_x86_honours_flags_live() {
        use crate::semantics::live_out::RegisterSet;
        use crate::semantics::state::{ConcreteValue, Eflags, X86ConcreteMachineState};

        let mut a = X86ConcreteMachineState::new_zeroed(64);
        let mut b = X86ConcreteMachineState::new_zeroed(64);
        a.set_register(X86Register::RAX, ConcreteValue::new(0));
        b.set_register(X86Register::RAX, ConcreteValue::new(0));
        let mut flags_set = Eflags::new();
        flags_set.zf = true;
        a.set_flags(flags_set);
        // b keeps default (zf = false).

        let no_flags = RegisterSet::from_registers(vec![X86Register::RAX]);
        assert!(states_equal_for_live_out_x86(&a, &b, &no_flags));

        let with_flags = no_flags.with_flags(true);
        assert!(!states_equal_for_live_out_x86(&a, &b, &with_flags));
    }

    // --- CMOVcc concrete semantics ---

    #[test]
    fn cmov_when_condition_true_writes_source() {
        use crate::isa::x86::X86Condition;
        // ZF=1, so CMOVE rax, rbx should copy rbx into rax.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xaa));
        state.set_register(X86Register::RBX, ConcreteValue::new(0xbb));
        let mut flags = Eflags::new();
        flags.zf = true;
        state.set_flags(flags);

        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xbb);
        // CMOV does not modify flags.
        assert!(after.get_flags().zf);
    }

    #[test]
    fn cmov_when_condition_false_preserves_dest() {
        use crate::isa::x86::X86Condition;
        // ZF=0, so CMOVE rax, rbx must NOT update rax.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xaa));
        state.set_register(X86Register::RBX, ConcreteValue::new(0xbb));
        // zf stays false.

        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xaa);
    }
}

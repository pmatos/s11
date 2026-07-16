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
use crate::semantics::state::{ConcreteValue, Eflags, X86ConcreteMachineState, mask_to_width};

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
        X86Instruction::Movzx { rd, rs, src_width } => {
            assert!(
                matches!(src_width, 8 | 16),
                "MOVZX source width must be 8 or 16 bits"
            );
            let narrow = mask_to_width(state.get_register(*rs).as_u64(), *src_width);
            state.set_register(*rd, ConcreteValue::new(narrow));
        }
        X86Instruction::Movsx { rd, rs, src_width } => {
            assert!(
                matches!(src_width, 8 | 16),
                "MOVSX source width must be 8 or 16 bits"
            );
            let narrow = mask_to_width(state.get_register(*rs).as_u64(), *src_width);
            let sign_bit = 1u64 << (*src_width - 1);
            let extended = if narrow & sign_bit == 0 {
                narrow
            } else {
                narrow | !mask_to_width(u64::MAX, *src_width)
            };
            state.set_register(*rd, ConcreteValue::new(extended));
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
        X86Instruction::Shl { rd, imm } => apply_shift(&mut state, *rd, *imm, ShiftKind::Shl),
        X86Instruction::Shr { rd, imm } => apply_shift(&mut state, *rd, *imm, ShiftKind::Shr),
        X86Instruction::Sar { rd, imm } => apply_shift(&mut state, *rd, *imm, ShiftKind::Sar),
        X86Instruction::Rol { rd, imm } => apply_rotate(&mut state, *rd, *imm, RotateKind::Rol),
        X86Instruction::Ror { rd, imm } => apply_rotate(&mut state, *rd, *imm, RotateKind::Ror),
        X86Instruction::ImulReg { rd, rs } => {
            let lhs = state.get_register(*rd).as_u64();
            let rhs = state.get_register(*rs).as_u64();
            apply_imul(&mut state, *rd, lhs, rhs);
        }
        X86Instruction::ImulRegImm { rd, rs, imm } => {
            let lhs = state.get_register(*rs).as_u64();
            let rhs = *imm as u64;
            apply_imul(&mut state, *rd, lhs, rhs);
        }
        // LEA computes `rd = base + disp` (wrapping at width) and writes NO
        // flags — pure address arithmetic, like MovReg. `set_register` masks
        // the result to the state width.
        X86Instruction::Lea { rd, base, disp } => {
            let base = state.get_register(*base).as_u64();
            let result = base.wrapping_add(*disp as u64);
            state.set_register(*rd, ConcreteValue::new(result));
        }
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

// Sign-extend the low `width` bits of `value` to a full i128 (so a width-`width`
// signed multiply cannot overflow the i128 product).
fn sign_extend_to_i128(value: u64, width: u32) -> i128 {
    let masked = mask_width(value, width);
    // Shift the sign bit up to bit 127, then arithmetic-shift back down.
    let shift = 128 - width;
    ((masked as i128) << shift) >> shift
}

// IMUL (signed multiply) — shared by both the 2-operand (`rd = rd * rs`) and
// 3-operand (`rd = rs * imm`) forms. `lhs`/`rhs` are the raw register/immediate
// bit patterns; this function sign-extends each from the operand width, takes
// the FULL signed product, and writes the low `width` bits to `rd`.
//
// FLAG MODEL (Intel SDM): for IMUL only CF and OF are architecturally defined;
// SF/ZF/PF/AF are UNDEFINED. CF = OF = 1 iff the full signed product does NOT
// fit the truncated `width`-bit destination (i.e. signed overflow), else 0.
//
// SF/ZF/PF are Intel-undefined. We model them DETERMINISTICALLY from the
// truncated result (the `from_logical` SF/ZF/PF path: SF = MSB, ZF = result==0,
// PF = parity of the low byte) and AF per the existing convention (false). This
// is documented as deterministic-undefined: because the target and candidate
// sequences share this exact lowering (concrete here, SMT in `smt_x86`),
// equivalence checking stays internally consistent and conservative — it never
// accepts a rewrite that changes a flag a legitimate program could rely on,
// since legitimate programs do not read IMUL's undefined flags.
fn apply_imul(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    lhs: u64,
    rhs: u64,
) {
    let width = state.width();
    let full = sign_extend_to_i128(lhs, width) * sign_extend_to_i128(rhs, width);
    let result = mask_width(full as u64, width);

    // CF = OF = signed overflow: the full product does not equal the
    // sign-extension of the truncated result.
    let overflow = full != sign_extend_to_i128(result, width);

    state.set_register(rd, ConcreteValue::new(result));
    // SF/ZF/PF from the truncated result (Intel-undefined; modelled
    // deterministically — see the function comment). CF/OF then overridden.
    let mut flags = Eflags::from_logical(result, width);
    flags.cf = overflow;
    flags.of = overflow;
    state.set_flags(flags);
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Sar,
}

// Mask a value to the operand width (low `width` bits).
fn mask_width(value: u64, width: u32) -> u64 {
    match width {
        64 => value,
        32 => value & 0xffff_ffff,
        16 => value & 0xffff,
        8 => value & 0xff,
        _ => unreachable!("unsupported width: {}", width),
    }
}

// Top (sign) bit of a width-`width` value.
fn msb(value: u64, width: u32) -> bool {
    (mask_width(value, width) >> (width - 1)) & 1 == 1
}

// Immediate-count shift. The count is a concrete compile-time value, so we
// branch on it directly rather than modelling a symbolic count.
//
// x86 masks the count to `width-1` (0x1f at width 32, 0x3f at width 64). A
// masked count of 0 is the load-bearing case: the result and ALL flags are
// left completely unchanged (a shift by 0 touches nothing). For a nonzero
// count, SF/ZF/PF come from the result; CF is the last bit shifted out; OF is
// architecturally defined only for count 1.
//
// OF for count > 1 is UNDEFINED on real hardware. We deliberately model it
// with the SAME formula as count == 1 — a fixed, deterministic value. Since
// both the target and candidate sequences go through this identical lowering,
// equivalence checking stays internally consistent; downstream consumers must
// not rely on OF after a count > 1 shift because the architecture leaves it
// undefined.
fn apply_shift(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    kind: ShiftKind,
) {
    let width = state.width();
    let mask = u64::from(width - 1);
    let eff = (imm as u64) & mask;
    let old = mask_width(state.get_register(rd).as_u64(), width);

    // Count masks to 0: leave rd and every flag untouched.
    if eff == 0 {
        return;
    }

    let result = match kind {
        ShiftKind::Shl => old << eff,
        ShiftKind::Shr => old >> eff,
        // Arithmetic right shift: sign-extend within the operand width.
        ShiftKind::Sar => {
            let sign = msb(old, width);
            let logical = old >> eff;
            if sign {
                // Set the top `eff` bits that the logical shift cleared.
                let fill = mask_width(!0u64 << (width as u64 - eff), width);
                logical | fill
            } else {
                logical
            }
        }
    };
    let result = mask_width(result, width);

    // CF is the last bit shifted out of the source.
    let cf = match kind {
        // SHL: the bit at index `width - eff` of the original operand.
        ShiftKind::Shl => (old >> (width as u64 - eff)) & 1 == 1,
        // SHR / SAR: the bit at index `eff - 1` of the original operand.
        ShiftKind::Shr | ShiftKind::Sar => (old >> (eff - 1)) & 1 == 1,
    };

    // OF: defined for count == 1 only; we reuse the count-1 formula for all
    // nonzero counts (see the function comment).
    let of = match kind {
        ShiftKind::Shl => msb(result, width) ^ cf,
        ShiftKind::Shr => msb(old, width),
        ShiftKind::Sar => false,
    };

    state.set_register(rd, ConcreteValue::new(result));
    let mut flags = Eflags::from_logical(result, width);
    flags.cf = cf;
    flags.of = of;
    state.set_flags(flags);
}

#[derive(Clone, Copy)]
enum RotateKind {
    Rol,
    Ror,
}

// Immediate-count rotate. Like the shifts the count is a concrete compile-time
// value masked to `width-1` (`eff`). The CRUCIAL difference from the shifts is
// the flag model: rotates touch ONLY CF (plus OF for count 1). SF/ZF/PF/AF are
// PRESERVED — this is a PARTIAL flag update, so we read the prior flags and keep
// SF/ZF/PF/AF, overriding only CF (and OF when count == 1).
//
// * `eff == 0`: the rotate is a complete no-op — leave `rd` and every flag
//   untouched.
// * `eff != 0`:
//   - ROL: `result = rotate_left(rd, eff)`; CF = bit 0 of the result (the bit
//     rotated from the MSB into the LSB). OF (count 1 only) = `MSB(result) XOR
//     CF`.
//   - ROR: `result = rotate_right(rd, eff)`; CF = the MSB (bit `width-1`) of the
//     result. OF (count 1 only) = `MSB(result) XOR (bit width-2 of result)` (the
//     XOR of the result's two most-significant bits).
//   - For count != 1 OF is architecturally UNDEFINED, so we PRESERVE the
//     incoming OF (deterministic and internally consistent: target and candidate
//     share this lowering).
fn apply_rotate(
    state: &mut X86ConcreteMachineState,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    kind: RotateKind,
) {
    let width = state.width();
    let mask = u64::from(width - 1);
    let eff = (imm as u64) & mask;

    // Count masks to 0: leave rd and every flag untouched.
    if eff == 0 {
        return;
    }

    let old = mask_width(state.get_register(rd).as_u64(), width);
    let eff_u32 = eff as u32;

    // `(old << eff) | (old >>u (width - eff))` for ROL (and the mirror for ROR),
    // masked back to the operand width.
    let result = match kind {
        RotateKind::Rol => (old << eff_u32) | (old >> (width - eff_u32)),
        RotateKind::Ror => (old >> eff_u32) | (old << (width - eff_u32)),
    };
    let result = mask_width(result, width);

    let cf = match kind {
        // ROL: CF = bit 0 of the result.
        RotateKind::Rol => result & 1 == 1,
        // ROR: CF = the MSB (bit width-1) of the result.
        RotateKind::Ror => msb(result, width),
    };

    // Start from the PRIOR flags so SF/ZF/PF/AF are preserved, then override CF.
    let mut flags = state.get_flags();
    flags.cf = cf;
    // OF is defined for count == 1 only. For any other count it is undefined, so
    // we keep the prior OF (already carried over by cloning the flags above).
    if eff == 1 {
        flags.of = match kind {
            RotateKind::Rol => msb(result, width) ^ cf,
            // XOR of the result's two most-significant bits.
            RotateKind::Ror => msb(result, width) ^ ((result >> (width - 2)) & 1 == 1),
        };
    }

    state.set_register(rd, ConcreteValue::new(result));
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
    fn shl_shifts_left_and_sets_zf_sf() {
        // shl rax, 4 of 0x0F00_0000_0000_0000 -> 0xF000_0000_0000_0000:
        // SF set (MSB), ZF clear.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x0F00_0000_0000_0000));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 4,
            },
        );
        assert_eq!(
            after.get_register(X86Register::RAX).as_u64(),
            0xF000_0000_0000_0000
        );
        let flags = after.get_flags();
        assert!(flags.sf, "shl result MSB set -> SF");
        assert!(!flags.zf);

        // shl that shifts every bit out -> 0: ZF set.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(1u64 << 60));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 8,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        assert!(after.get_flags().zf, "all bits shifted out -> ZF set");
    }

    // Known-concrete CF case from the DoD: `shr rax, 1` of an odd value sets
    // CF = 1 (the low bit shifted out).
    #[test]
    fn shr_odd_value_sets_carry_from_low_bit() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0b1011));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Shr {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0b101);
        assert!(
            after.get_flags().cf,
            "shr of an odd value shifts a 1 out -> CF set"
        );

        // Even value: low bit is 0, so CF clear.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0b1010));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Shr {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0b101);
        assert!(!after.get_flags().cf, "shr of an even value -> CF clear");
    }

    #[test]
    fn sar_preserves_sign_and_sets_carry() {
        // sar of a negative value sign-extends; CF = original bit (eff-1).
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x8000_0000_0000_0001));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Sar {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        // 0x8000_0000_0000_0001 >>s 1 = 0xC000_0000_0000_0000.
        assert_eq!(
            after.get_register(X86Register::RAX).as_u64(),
            0xC000_0000_0000_0000
        );
        let flags = after.get_flags();
        assert!(flags.sf, "sar of a negative value keeps the sign -> SF");
        assert!(flags.cf, "sar shifts the set low bit out -> CF set");
    }

    // The load-bearing eff == 0 case: a shift by 0 (after masking) leaves the
    // register AND every flag untouched. We seed distinctive flag values and
    // assert they survive unchanged for shl/shr/sar.
    #[test]
    fn shift_by_zero_preserves_register_and_all_flags() {
        for instr in [
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Shr {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Sar {
                rd: X86Register::RAX,
                imm: 0,
            },
            // A count of 64 masks to 0 at width 64 (mask = 0x3f), so it is also
            // a no-op even though the raw count is nonzero.
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 64,
            },
        ] {
            let mut state = X86ConcreteMachineState::new_zeroed(64);
            state.set_register(X86Register::RAX, ConcreteValue::new(0xDEAD_BEEF));
            let seeded = Eflags {
                cf: true,
                pf: true,
                af: true,
                zf: true,
                sf: true,
                of: true,
            };
            state.set_flags(seeded);
            let after = apply_instruction_concrete_x86(state, &instr);
            assert_eq!(
                after.get_register(X86Register::RAX).as_u64(),
                0xDEAD_BEEF,
                "{instr:?} (eff==0) must leave rd unchanged"
            );
            assert_eq!(
                after.get_flags(),
                seeded,
                "{instr:?} (eff==0) must preserve ALL flags"
            );
        }
    }

    #[test]
    fn rol_rotates_left_and_sets_carry_from_lsb() {
        // rol rax, 1 of MSB-set value: 0x8000... -> 0x0000...0001. CF = bit 0
        // of the result = 1.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x8000_0000_0000_0000));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 1);
        assert!(
            after.get_flags().cf,
            "rol moved the MSB into bit 0 -> CF set"
        );
        // OF (count 1) = MSB(result) XOR CF = 0 XOR 1 = 1.
        assert!(after.get_flags().of, "rol count 1: OF = MSB(result) XOR CF");

        // rol of a value whose MSB is 0: CF = 0.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x1));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0b10);
        assert!(!after.get_flags().cf, "rol of bit 0 only -> CF clear");
    }

    #[test]
    fn ror_rotates_right_and_sets_carry_from_msb() {
        // ror rax, 1 of an odd value: bit 0 wraps to the MSB and becomes CF.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0x1));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(
            after.get_register(X86Register::RAX).as_u64(),
            0x8000_0000_0000_0000
        );
        assert!(
            after.get_flags().cf,
            "ror wrapped bit 0 into the MSB -> CF = result MSB = 1"
        );

        // ror of an even value: result MSB is 0, so CF clear.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0b10));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0b1);
        assert!(!after.get_flags().cf, "ror of an even value -> CF clear");
    }

    // The load-bearing rotate distinction: SF/ZF/PF/AF are PRESERVED across a
    // rotate (only CF and, for count 1, OF change). Seed distinctive SF/ZF/PF/AF
    // and assert they survive.
    #[test]
    fn rotate_preserves_sf_zf_pf_af() {
        for instr in [
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 3,
            },
            X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 3,
            },
        ] {
            let mut state = X86ConcreteMachineState::new_zeroed(64);
            // A nonzero, non-zero-result value so the "natural" SF/ZF/PF would
            // differ from the seeded ones if the rotate (wrongly) recomputed
            // them.
            state.set_register(X86Register::RAX, ConcreteValue::new(0x1));
            let seeded = Eflags {
                cf: false,
                pf: true,
                af: true,
                zf: true,
                sf: true,
                of: false,
            };
            state.set_flags(seeded);
            let after = apply_instruction_concrete_x86(state, &instr);
            let flags = after.get_flags();
            assert_eq!(flags.sf, seeded.sf, "{instr:?} must preserve SF");
            assert_eq!(flags.zf, seeded.zf, "{instr:?} must preserve ZF");
            assert_eq!(flags.pf, seeded.pf, "{instr:?} must preserve PF");
            assert_eq!(flags.af, seeded.af, "{instr:?} must preserve AF");
            // count == 3 (!= 1): OF is undefined, so the model preserves it.
            assert_eq!(
                flags.of, seeded.of,
                "{instr:?} count != 1 must preserve incoming OF"
            );
        }
    }

    // A masked count of 0 is a complete no-op: register AND every flag, including
    // CF and OF, are left untouched.
    #[test]
    fn rotate_by_zero_preserves_register_and_all_flags() {
        for instr in [
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 0,
            },
            // A count of 64 masks to 0 at width 64 (mask = 0x3f), so it is also a
            // no-op even though the raw count is nonzero.
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 64,
            },
        ] {
            let mut state = X86ConcreteMachineState::new_zeroed(64);
            state.set_register(X86Register::RAX, ConcreteValue::new(0xDEAD_BEEF));
            let seeded = Eflags {
                cf: true,
                pf: true,
                af: true,
                zf: true,
                sf: true,
                of: true,
            };
            state.set_flags(seeded);
            let after = apply_instruction_concrete_x86(state, &instr);
            assert_eq!(
                after.get_register(X86Register::RAX).as_u64(),
                0xDEAD_BEEF,
                "{instr:?} (eff==0) must leave rd unchanged"
            );
            assert_eq!(
                after.get_flags(),
                seeded,
                "{instr:?} (eff==0) must preserve ALL flags"
            );
        }
    }

    // Cross-check the rotate result against the shift-construction identity from
    // the DoD: `rol rd, 1` == `(rd << 1) | (rd >>u (width-1))`.
    #[test]
    fn rol_by_one_matches_shift_construction() {
        for value in [0x1u64, 0x8000_0000_0000_0000, 0xDEAD_BEEF, u64::MAX, 0x5555] {
            let mut state = X86ConcreteMachineState::new_zeroed(64);
            state.set_register(X86Register::RAX, ConcreteValue::new(value));
            let after = apply_instruction_concrete_x86(
                state,
                &X86Instruction::Rol {
                    rd: X86Register::RAX,
                    imm: 1,
                },
            );
            // The DoD cross-check is precisely that `rol rd, 1` equals this
            // hand-written shift construction, so spell it out rather than
            // collapsing it into `rotate_left` (which would make the test
            // tautological).
            #[allow(clippy::manual_rotate)]
            let expected = (value << 1) | (value >> 63);
            assert_eq!(
                after.get_register(X86Register::RAX).as_u64(),
                expected,
                "rol {value:#x}, 1 must equal (v << 1) | (v >>u 63)"
            );
        }
    }

    #[test]
    fn imul_reg_multiplies_and_clears_cf_of_when_product_fits() {
        // imul rax, rbx with small operands: 6 * 7 = 42 fits the 64-bit
        // destination, so CF = OF = 0.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(6));
        state.set_register(X86Register::RBX, ConcreteValue::new(7));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 42);
        let flags = after.get_flags();
        assert!(!flags.cf, "product fits -> CF clear");
        assert!(!flags.of, "product fits -> OF clear");
        // SF/ZF modelled deterministically from the truncated result.
        assert!(!flags.zf);
        assert!(!flags.sf);
    }

    #[test]
    fn imul_reg_signed_negative_product() {
        // imul of (-3) * 4 = -12: the truncated 64-bit result is -12 and the
        // full product still fits, so CF = OF = 0 and SF (modelled) is set.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new((-3i64) as u64));
        state.set_register(X86Register::RBX, ConcreteValue::new(4));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(
            after.get_register(X86Register::RAX).as_u64(),
            (-12i64) as u64
        );
        let flags = after.get_flags();
        assert!(!flags.cf, "(-3)*4 fits -> CF clear");
        assert!(!flags.of);
        assert!(flags.sf, "negative result -> SF set (deterministic model)");
    }

    #[test]
    fn imul_reg_overflow_sets_cf_and_of() {
        // imul rax, rbx where the full signed product overflows 64 bits:
        // (1<<40) * (1<<40) = 1<<80, which does NOT fit -> CF = OF = 1.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(1u64 << 40));
        state.set_register(X86Register::RBX, ConcreteValue::new(1u64 << 40));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        // Low 64 bits of 1<<80 are 0.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0);
        let flags = after.get_flags();
        assert!(flags.cf, "product overflows -> CF set");
        assert!(flags.of, "product overflows -> OF set");
    }

    #[test]
    fn imul_reg_imm_writes_rs_times_imm() {
        // imul rax, rbx, 4: rax = rbx * 4 (rax is purely written, NOT read).
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RAX, ConcreteValue::new(0xdead));
        state.set_register(X86Register::RBX, ConcreteValue::new(5));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::ImulRegImm {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                imm: 4,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 20);
        let flags = after.get_flags();
        assert!(!flags.cf);
        assert!(!flags.of);
    }

    // The DoD result identity, concrete form: `imul rd, rs, 4` produces the
    // same truncated value as `rs << 2` (multiply by a power of two).
    #[test]
    fn imul_reg_imm_by_power_of_two_matches_shift_construction() {
        for value in [0u64, 1, 5, 0xdead_beef, u64::MAX, 1u64 << 62] {
            let mut state = X86ConcreteMachineState::new_zeroed(64);
            state.set_register(X86Register::RBX, ConcreteValue::new(value));
            let after = apply_instruction_concrete_x86(
                state,
                &X86Instruction::ImulRegImm {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    imm: 4,
                },
            );
            assert_eq!(
                after.get_register(X86Register::RAX).as_u64(),
                value.wrapping_shl(2),
                "imul {value:#x}, 4 must equal value << 2 (truncated)"
            );
        }
    }

    // The 32-bit overflow boundary differs from 64-bit: 0x10000 * 0x10000 =
    // 0x1_0000_0000 overflows a 32-bit destination (CF=OF=1) but fits a 64-bit
    // one. Pin both widths to guard width-awareness.
    #[test]
    fn imul_overflow_is_width_aware() {
        // width 32: 0x10000 * 0x10000 overflows.
        let mut s32 = X86ConcreteMachineState::new_zeroed(32);
        s32.set_register(X86Register::RAX, ConcreteValue::new(0x10000));
        s32.set_register(X86Register::RBX, ConcreteValue::new(0x10000));
        let after32 = apply_instruction_concrete_x86(
            s32,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert!(after32.get_flags().cf, "32-bit product overflows -> CF set");
        assert!(after32.get_flags().of);

        // width 64: the same operands fit.
        let mut s64 = X86ConcreteMachineState::new_zeroed(64);
        s64.set_register(X86Register::RAX, ConcreteValue::new(0x10000));
        s64.set_register(X86Register::RBX, ConcreteValue::new(0x10000));
        let after64 = apply_instruction_concrete_x86(
            s64,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        assert_eq!(
            after64.get_register(X86Register::RAX).as_u64(),
            0x1_0000_0000
        );
        assert!(!after64.get_flags().cf, "64-bit product fits -> CF clear");
        assert!(!after64.get_flags().of);
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
    fn movzx_zero_extends_low_source_bits_and_preserves_flags() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(0xfeed_face_cafe_80a5));
        state.set_register(X86Register::RAX, ConcreteValue::new(u64::MAX));
        let mut flags = Eflags::new();
        flags.cf = true;
        flags.zf = true;
        state.set_flags(flags);

        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 8,
            },
        );

        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0xa5);
        assert_eq!(
            after.get_register(X86Register::RBX).as_u64(),
            0xfeed_face_cafe_80a5
        );
        assert_eq!(after.get_flags(), flags);
    }

    #[test]
    fn movsx_sign_extends_byte_and_word_sources_to_the_machine_width() {
        for (machine_width, src_width, source, expected) in [
            (64, 8, 0x017f, 0x7f),
            (64, 8, 0x0180, 0xffff_ffff_ffff_ff80),
            (64, 16, 0x17fff, 0x7fff),
            (64, 16, 0x18001, 0xffff_ffff_ffff_8001),
            (32, 8, 0x017f, 0x7f),
            (32, 8, 0x0180, 0xffff_ff80),
            (32, 16, 0x17fff, 0x7fff),
            (32, 16, 0x18001, 0xffff_8001),
        ] {
            let mut state = X86ConcreteMachineState::new_zeroed(machine_width);
            state.set_register(X86Register::RBX, ConcreteValue::new(source));
            let mut flags = Eflags::new();
            flags.of = true;
            state.set_flags(flags);

            let after = apply_instruction_concrete_x86(
                state,
                &X86Instruction::Movsx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width,
                },
            );

            assert_eq!(
                after.get_register(X86Register::RAX).as_u64(),
                expected,
                "machine width {machine_width}, source width {src_width}"
            );
            assert_eq!(after.get_flags(), flags);
        }
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

    #[test]
    fn lea_computes_base_plus_disp_and_leaves_flags_unchanged() {
        // LEA writes `rd = base + disp` (wrapping at width) and must NOT touch
        // EFLAGS. Establish a non-trivial incoming flag state, then assert it
        // survives the LEA byte-for-byte while rd takes the address value.
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(0x1000));
        state.set_register(X86Register::RCX, ConcreteValue::new(5));
        let state = apply_instruction_concrete_x86(
            state,
            &X86Instruction::CmpImm {
                rn: X86Register::RCX,
                imm: 9,
            },
        );
        let flags_before = state.get_flags();

        // Positive displacement.
        let after = apply_instruction_concrete_x86(
            state.clone(),
            &X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0x20,
            },
        );
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x1020);
        assert_eq!(
            after.get_flags(),
            flags_before,
            "LEA must leave EFLAGS unchanged"
        );

        // Negative displacement wraps via two's complement add.
        let after_neg = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: -0x10,
            },
        );
        assert_eq!(after_neg.get_register(X86Register::RAX).as_u64(), 0x0ff0);
    }

    #[test]
    fn lea_wraps_at_width_32() {
        // At width 32 the result is masked to the low 32 bits.
        let mut state = X86ConcreteMachineState::new_zeroed(32);
        state.set_register(X86Register::RBX, ConcreteValue::new(0xffff_fff8));
        let after = apply_instruction_concrete_x86(
            state,
            &X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0x10,
            },
        );
        // 0xffff_fff8 + 0x10 = 0x1_0000_0008, masked to 32 bits = 0x8.
        assert_eq!(after.get_register(X86Register::RAX).as_u64(), 0x8);
    }
}

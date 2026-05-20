//! Concrete interpreter for fast validation of instruction sequences

use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
use crate::ir::{Condition, Instruction, Operand, Register, ShiftKind};
use crate::semantics::live_out::RegisterSet;
use crate::semantics::state::{ConcreteMachineState, ConcreteValue, ConditionFlags};

/// Evaluate an operand to get its concrete value
fn eval_operand(state: &ConcreteMachineState, operand: &Operand) -> ConcreteValue {
    match operand {
        Operand::Register(reg) => state.get_register(*reg),
        Operand::Immediate(imm) => ConcreteValue::from_i64(*imm),
        Operand::ShiftedRegister { reg, kind, amount } => {
            let value = state.get_register(*reg).as_u64();
            let shifted = match kind {
                ShiftKind::Lsl => value << amount,
                ShiftKind::Lsr => value >> amount,
                ShiftKind::Asr => ((value as i64) >> amount) as u64,
                ShiftKind::Ror => value.rotate_right(*amount as u32),
            };
            ConcreteValue::new(shifted)
        }
        // Issue #60: extract low N bits, sign/zero-extend to 64, then shl.
        Operand::ExtendedRegister { reg, kind, shift } => {
            let value = state.get_register(*reg).as_u64();
            let extended = match kind {
                crate::ir::ExtendKind::Uxtb => value & 0xFF,
                crate::ir::ExtendKind::Uxth => value & 0xFFFF,
                crate::ir::ExtendKind::Uxtw => value & 0xFFFF_FFFF,
                crate::ir::ExtendKind::Uxtx => value,
                crate::ir::ExtendKind::Sxtb => (value as i8) as i64 as u64,
                crate::ir::ExtendKind::Sxth => (value as i16) as i64 as u64,
                crate::ir::ExtendKind::Sxtw => (value as i32) as i64 as u64,
                crate::ir::ExtendKind::Sxtx => value,
            };
            ConcreteValue::new(extended.wrapping_shl(*shift as u32))
        }
    }
}

/// Apply a single instruction to a concrete machine state
pub fn apply_instruction_concrete(
    mut state: ConcreteMachineState,
    instruction: &Instruction,
) -> ConcreteMachineState {
    match instruction {
        Instruction::MovReg { rd, rn } => {
            let value = state.get_register(*rn);
            state.set_register(*rd, value);
        }
        Instruction::MovImm { rd, imm } => {
            let value = ConcreteValue::from_i64(*imm);
            state.set_register(*rd, value);
        }
        Instruction::Add { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs.wrapping_add(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Sub { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs.wrapping_sub(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::And { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs & rhs;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Orr { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs | rhs;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Eor { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs ^ rhs;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Lsl { rd, rn, shift } => {
            let value = state.get_register(*rn).as_u64();
            let shift_amount = eval_operand(&state, shift).as_u64() & 63;
            let result = value << shift_amount;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Lsr { rd, rn, shift } => {
            let value = state.get_register(*rn).as_u64();
            let shift_amount = eval_operand(&state, shift).as_u64() & 63;
            let result = value >> shift_amount;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Asr { rd, rn, shift } => {
            let value = state.get_register(*rn).as_i64();
            let shift_amount = eval_operand(&state, shift).as_u64() & 63;
            let result = value >> shift_amount;
            state.set_register(*rd, ConcreteValue::from_i64(result));
        }
        Instruction::Mul { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = state.get_register(*rm).as_u64();
            let result = lhs.wrapping_mul(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Sdiv { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_i64();
            let rhs = state.get_register(*rm).as_i64();
            let result = if rhs == 0 {
                0 // Division by zero returns 0 in AArch64
            } else {
                lhs.checked_div(rhs).unwrap_or(i64::MIN) // Overflow case returns dividend
            };
            state.set_register(*rd, ConcreteValue::from_i64(result));
        }
        Instruction::Udiv { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = state.get_register(*rm).as_u64();
            let result = lhs.checked_div(rhs).unwrap_or(0); // Division by zero returns 0 in AArch64
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Madd { rd, rn, rm, ra } => {
            let a = state.get_register(*rn).as_u64();
            let b = state.get_register(*rm).as_u64();
            let c = state.get_register(*ra).as_u64();
            let result = c.wrapping_add(a.wrapping_mul(b));
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Msub { rd, rn, rm, ra } => {
            let a = state.get_register(*rn).as_u64();
            let b = state.get_register(*rm).as_u64();
            let c = state.get_register(*ra).as_u64();
            let result = c.wrapping_sub(a.wrapping_mul(b));
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Mneg { rd, rn, rm } => {
            let a = state.get_register(*rn).as_u64();
            let b = state.get_register(*rm).as_u64();
            let result = 0u64.wrapping_sub(a.wrapping_mul(b));
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Smulh { rd, rn, rm } => {
            let a = state.get_register(*rn).as_i64() as i128;
            let b = state.get_register(*rm).as_i64() as i128;
            // wrapping_mul for i128 is sufficient: a×b fits in 128 bits when
            // |a|,|b| ≤ i64::MAX, except for i64::MIN×i64::MIN which still
            // fits in i128 since i64::MIN as i128 is -2^63.
            let result = (a.wrapping_mul(b) >> 64) as i64;
            state.set_register(*rd, ConcreteValue::from_i64(result));
        }
        Instruction::Umulh { rd, rn, rm } => {
            let a = state.get_register(*rn).as_u64() as u128;
            let b = state.get_register(*rm).as_u64() as u128;
            let result = ((a * b) >> 64) as u64;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // CMP: Compare (subtract and set flags, discard result)
        Instruction::Cmp { rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let flags = ConditionFlags::from_sub(lhs, rhs, lhs.wrapping_sub(rhs));
            state.set_flags(flags);
        }
        // CMN: Compare negative (add and set flags, discard result)
        Instruction::Cmn { rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let flags = ConditionFlags::from_add(lhs, rhs, lhs.wrapping_add(rhs));
            state.set_flags(flags);
        }
        // TST: Test (AND and set flags, discard result)
        Instruction::Tst { rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs & rhs;
            // TST sets N and Z based on result, clears C and V
            let flags = ConditionFlags {
                n: (result as i64) < 0,
                z: result == 0,
                c: false,
                v: false,
            };
            state.set_flags(flags);
        }
        // CCMP: conditional compare (subtract). If `cond` holds at runtime,
        // set NZCV from `rn - operand(rm)` exactly like CMP; otherwise force
        // NZCV to the 4-bit immediate.
        Instruction::Ccmp { rn, rm, nzcv, cond } => {
            let flags = if evaluate_condition(&state, *cond) {
                let lhs = state.get_register(*rn).as_u64();
                let rhs = eval_operand(&state, rm).as_u64();
                ConditionFlags::from_sub(lhs, rhs, lhs.wrapping_sub(rhs))
            } else {
                unpack_nzcv(*nzcv)
            };
            state.set_flags(flags);
        }
        // CCMN: conditional compare negative (add). Same as CCMP but with
        // addition for the true branch.
        Instruction::Ccmn { rn, rm, nzcv, cond } => {
            let flags = if evaluate_condition(&state, *cond) {
                let lhs = state.get_register(*rn).as_u64();
                let rhs = eval_operand(&state, rm).as_u64();
                ConditionFlags::from_add(lhs, rhs, lhs.wrapping_add(rhs))
            } else {
                unpack_nzcv(*nzcv)
            };
            state.set_flags(flags);
        }
        // CSEL: Conditional select
        Instruction::Csel { rd, rn, rm, cond } => {
            let cond_true = evaluate_condition(&state, *cond);
            let result = if cond_true {
                state.get_register(*rn)
            } else {
                state.get_register(*rm)
            };
            state.set_register(*rd, result);
        }
        // CSINC: Conditional select increment
        Instruction::Csinc { rd, rn, rm, cond } => {
            let cond_true = evaluate_condition(&state, *cond);
            let result = if cond_true {
                state.get_register(*rn)
            } else {
                ConcreteValue::new(state.get_register(*rm).as_u64().wrapping_add(1))
            };
            state.set_register(*rd, result);
        }
        // CSINV: Conditional select invert
        Instruction::Csinv { rd, rn, rm, cond } => {
            let cond_true = evaluate_condition(&state, *cond);
            let result = if cond_true {
                state.get_register(*rn)
            } else {
                ConcreteValue::new(!state.get_register(*rm).as_u64())
            };
            state.set_register(*rd, result);
        }
        // CSNEG: Conditional select negate
        Instruction::Csneg { rd, rn, rm, cond } => {
            let cond_true = evaluate_condition(&state, *cond);
            let result = if cond_true {
                state.get_register(*rn)
            } else {
                // `wrapping_neg` mirrors AArch64 two's-complement semantics:
                // negating `i64::MIN` yields `i64::MIN`, matching the sibling
                // NEG handler below. Plain `-x` would panic in debug builds.
                ConcreteValue::from_i64(state.get_register(*rm).as_i64().wrapping_neg())
            };
            state.set_register(*rd, result);
        }
        // MVN: bitwise NOT (rd = !rm)
        Instruction::Mvn { rd, rm } => {
            let result = !state.get_register(*rm).as_u64();
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // NEG: two's-complement negation (rd = -rm)
        Instruction::Neg { rd, rm } => {
            let result = state.get_register(*rm).as_i64().wrapping_neg();
            state.set_register(*rd, ConcreteValue::from_i64(result));
        }
        // NEGS: NEG with flag side-effect, same as `SUBS rd, XZR, rm`
        Instruction::Negs { rd, rm } => {
            let rhs = state.get_register(*rm).as_u64();
            let result = 0_u64.wrapping_sub(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
            let flags = ConditionFlags::from_sub(0, rhs, result);
            state.set_flags(flags);
        }
        // MOVN: rd = !((imm as u64) << shift)
        Instruction::MovN { rd, imm, shift } => {
            let value = !((*imm as u64) << (*shift as u32));
            state.set_register(*rd, ConcreteValue::new(value));
        }
        // MOVZ: rd = (imm as u64) << shift (other lanes cleared to zero)
        Instruction::MovZ { rd, imm, shift } => {
            let value = (*imm as u64) << (*shift as u32);
            state.set_register(*rd, ConcreteValue::new(value));
        }
        // MOVK: write one 16-bit chunk of rd, preserving the others.
        Instruction::MovK { rd, imm, shift } => {
            let prev = state.get_register(*rd).as_u64();
            let mask = !(0xFFFF_u64 << (*shift as u32));
            let value = (prev & mask) | ((*imm as u64) << (*shift as u32));
            state.set_register(*rd, ConcreteValue::new(value));
        }
        // BIC: rd = rn & !rm
        Instruction::Bic { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            state.set_register(*rd, ConcreteValue::new(lhs & !rhs));
        }
        // BICS: BIC with flag side-effect via from_logical
        Instruction::Bics { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs & !rhs;
            state.set_register(*rd, ConcreteValue::new(result));
            state.set_flags(ConditionFlags::from_logical(result));
        }
        // ORN: rd = rn | !rm
        Instruction::Orn { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            state.set_register(*rd, ConcreteValue::new(lhs | !rhs));
        }
        // EON: rd = rn ^ !rm
        Instruction::Eon { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            state.set_register(*rd, ConcreteValue::new(lhs ^ !rhs));
        }
        // Flag-setting arithmetic / logical
        Instruction::Adds { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs.wrapping_add(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
            state.set_flags(ConditionFlags::from_add(lhs, rhs, result));
        }
        Instruction::Subs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs.wrapping_sub(rhs);
            state.set_register(*rd, ConcreteValue::new(result));
            state.set_flags(ConditionFlags::from_sub(lhs, rhs, result));
        }
        Instruction::Ands { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = eval_operand(&state, rm).as_u64();
            let result = lhs & rhs;
            state.set_register(*rd, ConcreteValue::new(result));
            state.set_flags(ConditionFlags::from_logical(result));
        }
        // CSET / CSETM: AArch64-spec defines them as aliases of CSINC/CSINV
        // with XZR sources and inverted condition. The observable result is
        // simply "if cond holds then 1/-1 else 0". Note: `evaluate_condition`
        // at concrete.rs:177-197 has an NV=true quirk that disagrees with
        // state.rs:84 (NV=false); is_encodable_aarch64 rejects NV so this
        // path is unreachable for NV at runtime.
        Instruction::Cset { rd, cond } => {
            let result = if evaluate_condition(&state, *cond) {
                1
            } else {
                0
            };
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Csetm { rd, cond } => {
            let result: u64 = if evaluate_condition(&state, *cond) {
                u64::MAX
            } else {
                0
            };
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // ROR: imm form rotates by `imm`; reg form rotates by `rm & 63`
        // (hardware uses low 6 bits).
        Instruction::Ror { rd, rn, shift } => {
            let value = state.get_register(*rn).as_u64();
            let amount = (eval_operand(&state, shift).as_u64() & 63) as u32;
            state.set_register(*rd, ConcreteValue::new(value.rotate_right(amount)));
        }
        // CLZ: count leading zero bits (returns 64 for input 0).
        Instruction::Clz { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            state.set_register(*rd, ConcreteValue::new(value.leading_zeros() as u64));
        }
        // CLS: count leading bits that match the sign bit, excluding the sign
        // bit itself. Equivalent to `clz(x ^ (x asr 63)) - 1`; for input 0 or
        // all-ones the result is 63.
        Instruction::Cls { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let folded = value ^ ((value as i64 >> 63) as u64);
            // After the sign-fold `x ^ (x ASR 63)`, bit 63 of `folded` is
            // always 0, so `leading_zeros(folded) >= 1` and the subtraction
            // cannot underflow.
            let result = folded.leading_zeros() as u64 - 1;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // RBIT: reverse the bit order of the 64-bit value.
        Instruction::Rbit { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            state.set_register(*rd, ConcreteValue::new(value.reverse_bits()));
        }
        // REV: reverse the byte order of the 64-bit value.
        Instruction::Rev { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            state.set_register(*rd, ConcreteValue::new(value.swap_bytes()));
        }
        // REV32: byte-reverse within each 32-bit half (independently).
        Instruction::Rev32 { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let lo = (value as u32).swap_bytes() as u64;
            let hi = ((value >> 32) as u32).swap_bytes() as u64;
            state.set_register(*rd, ConcreteValue::new(lo | (hi << 32)));
        }
        // REV16: byte-reverse within each 16-bit half (four halves).
        Instruction::Rev16 { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let result =
                ((value & 0xFF00_FF00_FF00_FF00) >> 8) | ((value & 0x00FF_00FF_00FF_00FF) << 8);
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // SXTB/SXTH/SXTW: extract low N bits, sign-extend to 64. Issue #60.
        Instruction::Sxtb { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let result = (value as i8) as i64 as u64;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Sxth { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let result = (value as i16) as i64 as u64;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        Instruction::Sxtw { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            let result = (value as i32) as i64 as u64;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // UXTB/UXTH: extract low N bits, zero-extend to 64. Issue #60.
        Instruction::Uxtb { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            state.set_register(*rd, ConcreteValue::new(value & 0xFF));
        }
        Instruction::Uxth { rd, rn } => {
            let value = state.get_register(*rn).as_u64();
            state.set_register(*rd, ConcreteValue::new(value & 0xFFFF));
        }
        // UBFX rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // zero-extend the result into rd. width=64 must use u64::MAX as the
        // low-bits mask to avoid the `1u64 << 64` UB.
        Instruction::Ubfx { rd, rn, lsb, width } => {
            let value = state.get_register(*rn).as_u64();
            let low_mask = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let extracted = (value >> *lsb) & low_mask;
            state.set_register(*rd, ConcreteValue::new(extracted));
        }
        // SBFX rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // sign-extend the result into rd. width=64 is the no-op identity.
        Instruction::Sbfx { rd, rn, lsb, width } => {
            let value = state.get_register(*rn).as_u64();
            // Shift left then arithmetic-right by the same amount, computed on
            // i64, to sign-extend the field MSB across the upper bits.
            // Widen lsb/width to u32 before the sum so we never narrowly wrap
            // through u8 when the caller passes unvalidated immediates
            // (validated paths are bounded by is_encodable_aarch64).
            let shift_left = 64 - ((*lsb as u32) + (*width as u32));
            let intermediate = (value << shift_left) as i64;
            // Right shift by (64 - width) sign-extends from bit (width-1).
            let result = (intermediate >> (64 - *width as u32)) as u64;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // BFI rd, rn, #lsb, #width: insert low `width` bits of rn at position
        // lsb of rd, preserving the other bits of rd.
        Instruction::Bfi { rd, rn, lsb, width } => {
            let dest = state.get_register(*rd).as_u64();
            let src = state.get_register(*rn).as_u64();
            let low_mask = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let shifted_mask = low_mask << *lsb;
            let inserted = (src & low_mask) << *lsb;
            let result = (dest & !shifted_mask) | inserted;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // BFXIL rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // place at [width-1:0] of rd, preserve rd[63:width].
        Instruction::Bfxil { rd, rn, lsb, width } => {
            let dest = state.get_register(*rd).as_u64();
            let src = state.get_register(*rn).as_u64();
            let low_mask = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let extracted = (src >> *lsb) & low_mask;
            let result = (dest & !low_mask) | extracted;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // UBFIZ rd, rn, #lsb, #width: take low `width` bits of rn, zero-extend
        // to 64, shift left by lsb → rd (other bits zero).
        Instruction::Ubfiz { rd, rn, lsb, width } => {
            let value = state.get_register(*rn).as_u64();
            let low_mask = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let inserted = (value & low_mask) << *lsb;
            state.set_register(*rd, ConcreteValue::new(inserted));
        }
        // SBFIZ rd, rn, #lsb, #width: low `width` bits of rn, sign-extended
        // across bits [63:width], then shifted left by lsb → rd.
        Instruction::Sbfiz { rd, rn, lsb, width } => {
            let value = state.get_register(*rn).as_u64();
            // Sign-extend the low `width` bits to 64.
            let shift_left = 64 - *width as u32;
            let sign_extended = ((value << shift_left) as i64 >> shift_left) as u64;
            // Then shift left by lsb.
            let result = sign_extended << *lsb;
            state.set_register(*rd, ConcreteValue::new(result));
        }
        // Branches / terminators: callers must strip terminators before
        // apply_sequence_concrete. The equivalence layer handles them via
        // identity-check, not by execution.
        Instruction::B { .. }
        | Instruction::BCond { .. }
        | Instruction::Ret { .. }
        | Instruction::Cbz { .. }
        | Instruction::Cbnz { .. }
        | Instruction::Tbz { .. }
        | Instruction::Tbnz { .. }
        | Instruction::Bl { .. }
        | Instruction::Br { .. } => unreachable!(
            "Branches are terminators; strip them before apply_sequence_concrete. Reached: {:?}",
            instruction
        ),
        // Memory ops (issue #68). Concrete semantics for LDR-family land in
        // step 6; until the memory model is plumbed onto ConcreteMachineState
        // there is no way to evaluate these and callers should not synthesise
        // them yet.
        Instruction::Ldr { rt, addr, width } => {
            let (effective, writeback) = compute_address(&state, addr);
            let raw = state.read_bytes(effective, *width);
            let value = zero_extend_load(raw, *width);
            state.set_register(*rt, ConcreteValue::new(value));
            if let Some((base, new_base)) = writeback {
                state.set_register(base, ConcreteValue::new(new_base));
            }
        }
        Instruction::Ldrs { rt, addr, width } => {
            let (effective, writeback) = compute_address(&state, addr);
            let raw = state.read_bytes(effective, *width);
            let value = sign_extend_load(raw, *width);
            state.set_register(*rt, ConcreteValue::new(value));
            if let Some((base, new_base)) = writeback {
                state.set_register(base, ConcreteValue::new(new_base));
            }
        }
        Instruction::Str { rt, addr, width } => {
            let (effective, writeback) = compute_address(&state, addr);
            let value = state.get_register(*rt).as_u64();
            state.write_bytes(effective, value, *width);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, ConcreteValue::new(new_base));
            }
        }
        Instruction::Ldp {
            rt1,
            rt2,
            addr,
            width,
            signed,
        } => {
            let (effective, writeback) = compute_address(&state, addr);
            let bytes = width.bytes() as u64;
            let raw1 = state.read_bytes(effective, *width);
            let raw2 = state.read_bytes(effective.wrapping_add(bytes), *width);
            let (v1, v2) = if *signed {
                (
                    sign_extend_load(raw1, *width),
                    sign_extend_load(raw2, *width),
                )
            } else {
                (
                    zero_extend_load(raw1, *width),
                    zero_extend_load(raw2, *width),
                )
            };
            state.set_register(*rt1, ConcreteValue::new(v1));
            state.set_register(*rt2, ConcreteValue::new(v2));
            if let Some((base, new_base)) = writeback {
                state.set_register(base, ConcreteValue::new(new_base));
            }
        }
        Instruction::Stp {
            rt1,
            rt2,
            addr,
            width,
        } => {
            let (effective, writeback) = compute_address(&state, addr);
            let bytes = width.bytes() as u64;
            let v1 = state.get_register(*rt1).as_u64();
            let v2 = state.get_register(*rt2).as_u64();
            state.write_bytes(effective, v1, *width);
            state.write_bytes(effective.wrapping_add(bytes), v2, *width);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, ConcreteValue::new(new_base));
            }
        }
    }
    state
}

/// Compute the effective address used by a memory access, together with
/// any writeback `(base, new_base_value)` that must be committed to the
/// register file. PreIndex updates the base *before* the access; the new
/// value is also the effective address. PostIndex uses the original base
/// as the effective address and updates afterwards.
fn compute_address(
    state: &ConcreteMachineState,
    addr: &AddressOperand,
) -> (u64, Option<(Register, u64)>) {
    match addr {
        AddressOperand::Imm { base, offset, mode } => {
            let base_val = state.get_register(*base).as_u64();
            let updated = base_val.wrapping_add(*offset as u64);
            match mode {
                IndexMode::Offset => (updated, None),
                IndexMode::PreIndex => (updated, Some((*base, updated))),
                IndexMode::PostIndex => (base_val, Some((*base, updated))),
            }
        }
        AddressOperand::Reg { base, idx, shift } => {
            let base_val = state.get_register(*base).as_u64();
            let idx_val = state.get_register(*idx).as_u64();
            (base_val.wrapping_add(idx_val << *shift), None)
        }
        AddressOperand::Ext {
            base,
            idx,
            kind,
            shift,
        } => {
            let base_val = state.get_register(*base).as_u64();
            let idx_val = state.get_register(*idx).as_u64();
            let extended = match kind {
                crate::ir::ExtendKind::Uxtw => idx_val & 0xFFFF_FFFF,
                crate::ir::ExtendKind::Sxtw => (idx_val as i32) as i64 as u64,
                crate::ir::ExtendKind::Uxtx => idx_val,
                crate::ir::ExtendKind::Sxtx => idx_val,
                // Byte/half kinds are rejected by is_encodable for memory
                // operands; treat as zero-extend to keep the eval total.
                crate::ir::ExtendKind::Uxtb => idx_val & 0xFF,
                crate::ir::ExtendKind::Uxth => idx_val & 0xFFFF,
                crate::ir::ExtendKind::Sxtb => (idx_val as i8) as i64 as u64,
                crate::ir::ExtendKind::Sxth => (idx_val as i16) as i64 as u64,
            };
            (base_val.wrapping_add(extended << *shift), None)
        }
    }
}

/// Zero-extend the low `width.bytes() * 8` bits of `raw` to u64.
fn zero_extend_load(raw: u64, width: AccessWidth) -> u64 {
    match width {
        AccessWidth::Byte => raw & 0xFF,
        AccessWidth::Half => raw & 0xFFFF,
        AccessWidth::Word => raw & 0xFFFF_FFFF,
        AccessWidth::Extended => raw,
    }
}

/// Sign-extend the low `width.bytes() * 8` bits of `raw` to u64.
fn sign_extend_load(raw: u64, width: AccessWidth) -> u64 {
    match width {
        AccessWidth::Byte => (raw as i8) as i64 as u64,
        AccessWidth::Half => (raw as i16) as i64 as u64,
        AccessWidth::Word => (raw as i32) as i64 as u64,
        AccessWidth::Extended => raw,
    }
}

/// Evaluate a condition code against the current flags
/// Unpack a 4-bit NZCV literal (CCMP/CCMN false-branch flag value) into the
/// `ConditionFlags` struct. Layout per ARM ARM: bit3 = N, bit2 = Z, bit1 = C,
/// bit0 = V.
fn unpack_nzcv(byte: u8) -> ConditionFlags {
    ConditionFlags {
        n: (byte >> 3) & 1 == 1,
        z: (byte >> 2) & 1 == 1,
        c: (byte >> 1) & 1 == 1,
        v: byte & 1 == 1,
    }
}

fn evaluate_condition(state: &ConcreteMachineState, cond: Condition) -> bool {
    let flags = state.get_flags();
    match cond {
        Condition::EQ => flags.z,                          // Equal (Z=1)
        Condition::NE => !flags.z,                         // Not equal (Z=0)
        Condition::CS => flags.c,                          // Carry set (C=1)
        Condition::CC => !flags.c,                         // Carry clear (C=0)
        Condition::MI => flags.n,                          // Minus/negative (N=1)
        Condition::PL => !flags.n,                         // Plus/positive or zero (N=0)
        Condition::VS => flags.v,                          // Overflow (V=1)
        Condition::VC => !flags.v,                         // No overflow (V=0)
        Condition::HI => flags.c && !flags.z,              // Unsigned higher (C=1 && Z=0)
        Condition::LS => !flags.c || flags.z,              // Unsigned lower or same (C=0 || Z=1)
        Condition::GE => flags.n == flags.v,               // Signed greater or equal (N=V)
        Condition::LT => flags.n != flags.v,               // Signed less than (N!=V)
        Condition::GT => !flags.z && (flags.n == flags.v), // Signed greater than (Z=0 && N=V)
        Condition::LE => flags.z || (flags.n != flags.v),  // Signed less or equal (Z=1 || N!=V)
        Condition::AL => true,                             // Always
        Condition::NV => true, // Never (but executes as always on AArch64)
    }
}

/// Apply a sequence of instructions to a concrete machine state
pub fn apply_sequence_concrete(
    mut state: ConcreteMachineState,
    instructions: &[Instruction],
) -> ConcreteMachineState {
    for instruction in instructions {
        state = apply_instruction_concrete(state, instruction);
    }
    state
}

/// Check if two concrete states are equal for the specified live-out registers,
/// optionally including the NZCV condition flags and the whole memory map.
///
/// `memory_live` is derived automatically by callers from whether either
/// sequence touches memory (see ADR-0007). When set, every memory cell
/// must agree between the two states — equivalently, the two `BTreeMap`s
/// must be structurally equal (prune-on-write guarantees structural ==
/// semantic equality).
///
/// TODO(#282): The explicit `flags_live` parameter is now redundant with
/// `live_out.flags_live()` for every caller except the stochastic backend
/// (which deliberately passes `false`). Tracked for cleanup in issue #282.
pub fn states_equal_for_live_out(
    state1: &ConcreteMachineState,
    state2: &ConcreteMachineState,
    live_out: &RegisterSet<Register>,
    flags_live: bool,
    memory_live: bool,
) -> bool {
    for reg in live_out.iter() {
        if state1.get_register(*reg) != state2.get_register(*reg) {
            return false;
        }
    }
    if flags_live && state1.get_flags() != state2.get_flags() {
        return false;
    }
    if memory_live && state1.memory() != state2.memory() {
        return false;
    }
    true
}

/// Find the first differing register between two states for live-out registers.
/// Flag divergence (when `flags_live` is set) is reported via the `XZR`
/// sentinel since the function signature is register-typed.
///
/// TODO(#282): see `states_equal_for_live_out` — the same `flags_live`
/// redundancy applies here. Tracked for follow-up cleanup.
pub fn find_first_difference(
    state1: &ConcreteMachineState,
    state2: &ConcreteMachineState,
    live_out: &RegisterSet<Register>,
    flags_live: bool,
) -> Option<(Register, ConcreteValue, ConcreteValue)> {
    for reg in live_out.iter() {
        let v1 = state1.get_register(*reg);
        let v2 = state2.get_register(*reg);
        if v1 != v2 {
            return Some((*reg, v1, v2));
        }
    }
    if flags_live {
        let f1 = state1.get_flags();
        let f2 = state2.get_flags();
        if f1 != f2 {
            // Pack each flag set into a ConcreteValue so the return type stays
            // (Register, ConcreteValue, ConcreteValue). Layout: N<<3 | Z<<2 | C<<1 | V.
            // The XZR register slot signals "this difference is a flag, not a register."
            let pack = |f: crate::semantics::state::ConditionFlags| -> ConcreteValue {
                ConcreteValue(
                    ((f.n as u64) << 3) | ((f.z as u64) << 2) | ((f.c as u64) << 1) | (f.v as u64),
                )
            };
            return Some((Register::XZR, pack(f1), pack(f2)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn state_with(values: Vec<(Register, u64)>) -> ConcreteMachineState {
        let map: HashMap<Register, u64> = values.into_iter().collect();
        ConcreteMachineState::from_values(map)
    }

    #[test]
    fn test_mov_reg() {
        let state = state_with(vec![(Register::X1, 42)]);
        let instr = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 42);
    }

    #[test]
    fn test_mov_imm() {
        let state = ConcreteMachineState::new_zeroed();
        let instr = Instruction::MovImm {
            rd: Register::X0,
            imm: 100,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 100);
    }

    #[test]
    fn test_mov_imm_negative() {
        let state = ConcreteMachineState::new_zeroed();
        let instr = Instruction::MovImm {
            rd: Register::X0,
            imm: -1,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn test_add_registers() {
        let state = state_with(vec![(Register::X1, 10), (Register::X2, 20)]);
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 30);
    }

    #[test]
    fn test_add_immediate() {
        let state = state_with(vec![(Register::X1, 10)]);
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 15);
    }

    #[test]
    fn test_sub_shifted_register_lsr() {
        // x1 - (x2 >> 4) — LSR is logical shift right (zero-fill).
        let state = state_with(vec![(Register::X1, 100), (Register::X2, 0xF0)]);
        let instr = Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Lsr,
                amount: 4,
            },
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // 100 - (0xF0 >> 4) == 100 - 15 == 85
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 85);
    }

    #[test]
    fn test_orr_shifted_register_asr() {
        // ASR preserves sign — -8 (0xFFFFFFFFFFFFFFF8) >> 1 == -4.
        let state = state_with(vec![(Register::X1, 0), (Register::X2, (-8i64) as u64)]);
        let instr = Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Asr,
                amount: 1,
            },
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(
            new_state.get_register(Register::X0).as_u64(),
            (-4i64) as u64
        );
    }

    #[test]
    fn test_and_shifted_register_ror() {
        // ROR by 4 of 0x...0F brings the low nibble into the high nibble.
        let state = state_with(vec![(Register::X1, u64::MAX), (Register::X2, 0x0F)]);
        let instr = Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Ror,
                amount: 4,
            },
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // 0xF rotated right by 4 in 64 bits == 0xF000_0000_0000_0000
        assert_eq!(
            new_state.get_register(Register::X0).as_u64(),
            0xF000_0000_0000_0000u64
        );
    }

    #[test]
    fn test_add_shifted_register_lsl() {
        let state = state_with(vec![(Register::X1, 10), (Register::X2, 4)]);
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Lsl,
                amount: 3,
            },
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // 10 + (4 << 3) == 10 + 32 == 42
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 42);
    }

    #[test]
    fn test_add_wrapping() {
        let state = state_with(vec![(Register::X1, u64::MAX)]);
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
    }

    #[test]
    fn test_sub() {
        let state = state_with(vec![(Register::X1, 100)]);
        let instr = Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(30),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 70);
    }

    #[test]
    fn test_sub_wrapping() {
        let state = state_with(vec![(Register::X1, 0)]);
        let instr = Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn test_and() {
        let state = state_with(vec![(Register::X1, 0xFF00), (Register::X2, 0x0FF0)]);
        let instr = Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0x0F00);
    }

    #[test]
    fn test_orr() {
        let state = state_with(vec![(Register::X1, 0xF0), (Register::X2, 0x0F)]);
        let instr = Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0xFF);
    }

    #[test]
    fn test_eor() {
        let state = state_with(vec![(Register::X1, 0xFF), (Register::X2, 0x0F)]);
        let instr = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0xF0);
    }

    #[test]
    fn test_eor_self_clears() {
        let state = state_with(vec![(Register::X0, 12345)]);
        let instr = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
    }

    #[test]
    fn test_lsl() {
        let state = state_with(vec![(Register::X1, 1)]);
        let instr = Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(4),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 16);
    }

    #[test]
    fn test_lsl_large_shift() {
        let state = state_with(vec![(Register::X1, 1)]);
        let instr = Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(100),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(
            new_state.get_register(Register::X0).as_u64(),
            1 << (100 & 63)
        );
    }

    #[test]
    fn test_lsr() {
        let state = state_with(vec![(Register::X1, 0x100)]);
        let instr = Instruction::Lsr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(4),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0x10);
    }

    #[test]
    fn test_asr_positive() {
        let state = state_with(vec![(Register::X1, 0x100)]);
        let instr = Instruction::Asr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(4),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0x10);
    }

    #[test]
    fn test_asr_negative() {
        let state = state_with(vec![(Register::X1, (-16i64) as u64)]);
        let instr = Instruction::Asr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_i64(), -4);
    }

    #[test]
    fn test_xzr_reads_zero() {
        let state = ConcreteMachineState::new_zeroed();
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::XZR,
            rm: Operand::Immediate(10),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 10);
    }

    #[test]
    fn test_xzr_writes_ignored() {
        let state = ConcreteMachineState::new_zeroed();
        let instr = Instruction::MovImm {
            rd: Register::XZR,
            imm: 100,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::XZR).as_u64(), 0);
    }

    #[test]
    fn test_apply_sequence() {
        let state = ConcreteMachineState::new_zeroed();
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 10,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
        ];
        let new_state = apply_sequence_concrete(state, &seq);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 15);
        assert_eq!(new_state.get_register(Register::X1).as_u64(), 10);
    }

    #[test]
    fn test_states_equal_for_live_out_equal() {
        let state1 = state_with(vec![(Register::X0, 42), (Register::X1, 100)]);
        let state2 = state_with(vec![(Register::X0, 42), (Register::X1, 999)]);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        assert!(states_equal_for_live_out(
            &state1, &state2, &live_out, false, false
        ));
    }

    #[test]
    fn test_states_equal_for_live_out_different() {
        let state1 = state_with(vec![(Register::X0, 42)]);
        let state2 = state_with(vec![(Register::X0, 43)]);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        assert!(!states_equal_for_live_out(
            &state1, &state2, &live_out, false, false
        ));
    }

    #[test]
    fn test_find_first_difference() {
        let state1 = state_with(vec![(Register::X0, 42), (Register::X1, 100)]);
        let state2 = state_with(vec![(Register::X0, 42), (Register::X1, 200)]);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0, Register::X1]);
        let diff = find_first_difference(&state1, &state2, &live_out, false);
        assert!(diff.is_some());
        let (reg, v1, v2) = diff.unwrap();
        assert_eq!(reg, Register::X1);
        assert_eq!(v1.as_u64(), 100);
        assert_eq!(v2.as_u64(), 200);
    }

    #[test]
    fn test_find_first_difference_none() {
        let state1 = state_with(vec![(Register::X0, 42)]);
        let state2 = state_with(vec![(Register::X0, 42)]);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        let diff = find_first_difference(&state1, &state2, &live_out, false);
        assert!(diff.is_none());
    }

    #[test]
    fn test_mov_zero_eor_equivalence() {
        let state = state_with(vec![(Register::X0, 12345)]);

        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let state1 = apply_sequence_concrete(state.clone(), &seq1);

        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        let state2 = apply_sequence_concrete(state, &seq2);

        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);
        assert!(states_equal_for_live_out(
            &state1, &state2, &live_out, false, false
        ));
    }

    #[test]
    fn test_mul() {
        let state = state_with(vec![(Register::X1, 6), (Register::X2, 7)]);
        let instr = Instruction::Mul {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 42);
    }

    #[test]
    fn test_mul_wrapping() {
        let state = state_with(vec![(Register::X1, u64::MAX), (Register::X2, 2)]);
        let instr = Instruction::Mul {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // u64::MAX * 2 wraps around
        assert_eq!(
            new_state.get_register(Register::X0).as_u64(),
            u64::MAX.wrapping_mul(2)
        );
    }

    /// Issue #56 acceptance: UMULH must match Rust's u128 high-half product
    /// across edge cases (boundaries, identity, max×max).
    #[test]
    fn test_umulh_matches_rust_u128() {
        let cases: [(u64, u64); 16] = [
            (0, 0),
            (0, 12345),
            (1, u64::MAX),
            (u64::MAX, u64::MAX),
            (u64::MAX, 1),
            (u64::MAX, 2),
            (1 << 32, 1 << 32),
            (1 << 32, (1 << 32) - 1),
            (0xDEAD_BEEF, 0x1234_5678),
            (0xFFFF_FFFF_FFFF_FFFE, 2),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (0xCAFE_F00D, 0xBABE_BEEF),
            ((1u64 << 63) - 1, (1u64 << 63) - 1),
            (u64::MAX - 1, u64::MAX - 1),
            (0xFFFF_FFFF, 0xFFFF_FFFF),
        ];

        for (a, b) in cases {
            let state = state_with(vec![(Register::X1, a), (Register::X2, b)]);
            let instr = Instruction::Umulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            let expected = (((a as u128) * (b as u128)) >> 64) as u64;
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                expected,
                "umulh(0x{:x}, 0x{:x})",
                a,
                b
            );
        }
    }

    /// Issue #56 acceptance: SMULH must match Rust's i128 high-half product
    /// across edge cases (signed boundaries, zero, identity, MIN×-1).
    #[test]
    fn test_smulh_matches_rust_i128() {
        let cases: [(i64, i64); 16] = [
            (0, 0),
            (0, 12345),
            (1, i64::MAX),
            (-1, i64::MIN),
            (i64::MAX, i64::MAX),
            (i64::MIN, i64::MIN),
            (i64::MIN, -1),
            (i64::MIN, 1),
            (i64::MAX, -1),
            (123456789, -987654321),
            (-1, -1),
            (2, i64::MAX),
            (-2, i64::MIN),
            (1 << 32, 1 << 32),
            (-(1 << 32), 1 << 32),
            (0xDEAD_BEEF, 0x1234_5678),
        ];

        for (a, b) in cases {
            let state = state_with(vec![(Register::X1, a as u64), (Register::X2, b as u64)]);
            let instr = Instruction::Smulh {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            let expected = ((a as i128).wrapping_mul(b as i128) >> 64) as i64;
            assert_eq!(
                new_state.get_register(Register::X0).as_i64(),
                expected,
                "smulh(0x{:x}, 0x{:x})",
                a,
                b
            );
        }
    }

    #[test]
    fn test_sdiv() {
        let state = state_with(vec![(Register::X1, 42), (Register::X2, 7)]);
        let instr = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 6);
    }

    #[test]
    fn test_sdiv_negative() {
        let state = state_with(vec![(Register::X1, (-42i64) as u64), (Register::X2, 7)]);
        let instr = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_i64(), -6);
    }

    #[test]
    fn test_sdiv_by_zero() {
        let state = state_with(vec![(Register::X1, 42), (Register::X2, 0)]);
        let instr = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // AArch64: Division by zero returns 0
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
    }

    #[test]
    fn test_sdiv_overflow() {
        let state = state_with(vec![
            (Register::X1, i64::MIN as u64),
            (Register::X2, (-1i64) as u64),
        ]);
        let instr = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // AArch64: MIN / -1 overflow returns MIN (the dividend)
        assert_eq!(new_state.get_register(Register::X0).as_i64(), i64::MIN);
    }

    #[test]
    fn test_udiv() {
        let state = state_with(vec![(Register::X1, 42), (Register::X2, 7)]);
        let instr = Instruction::Udiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 6);
    }

    #[test]
    fn test_udiv_by_zero() {
        let state = state_with(vec![(Register::X1, 42), (Register::X2, 0)]);
        let instr = Instruction::Udiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // AArch64: Division by zero returns 0
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
    }

    #[test]
    fn test_udiv_large() {
        let state = state_with(vec![(Register::X1, u64::MAX), (Register::X2, 3)]);
        let instr = Instruction::Udiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), u64::MAX / 3);
    }

    #[test]
    fn test_ror_imm_matches_rotate_right() {
        // ROR rd, rn, #imm — match against u64::rotate_right
        for shift in [0u64, 1, 4, 16, 63] {
            let input: u64 = 0xDEAD_BEEF_DEAD_BEEF;
            let state = state_with(vec![(Register::X1, input)]);
            let instr = Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(shift as i64),
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                input.rotate_right(shift as u32),
                "ROR(#{:#x}, #{}) wrong",
                input,
                shift
            );
        }
    }

    #[test]
    fn test_ror_reg_masks_amount_to_low_6_bits() {
        // ROR rd, rn, rm uses rm[5:0]; rotate by 64 ≡ rotate by 0
        let input: u64 = 0x1234_5678_9ABC_DEF0;
        let state = state_with(vec![(Register::X1, input), (Register::X2, 64)]);
        let instr = Instruction::Ror {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // ROR by 64 wraps to ROR by 0 → input unchanged
        assert_eq!(new_state.get_register(Register::X0).as_u64(), input);
    }

    #[test]
    fn test_cset_writes_1_when_cond_true_0_otherwise() {
        // Set Z=1 via CMP X1, X1 (rn == rm)
        let pre = state_with(vec![(Register::X1, 5)]);
        let after_cmp = apply_instruction_concrete(
            pre,
            &Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X1),
            },
        );
        let after_cset = apply_instruction_concrete(
            after_cmp,
            &Instruction::Cset {
                rd: Register::X0,
                cond: Condition::EQ,
            },
        );
        assert_eq!(after_cset.get_register(Register::X0).as_u64(), 1);

        // Set Z=0 via CMP X1, X2 with X1=5, X2=6
        let pre = state_with(vec![(Register::X1, 5), (Register::X2, 6)]);
        let after_cmp = apply_instruction_concrete(
            pre,
            &Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
        );
        let after_cset = apply_instruction_concrete(
            after_cmp,
            &Instruction::Cset {
                rd: Register::X0,
                cond: Condition::EQ,
            },
        );
        assert_eq!(after_cset.get_register(Register::X0).as_u64(), 0);
    }

    #[test]
    fn test_csetm_writes_all_ones_when_cond_true() {
        let pre = state_with(vec![(Register::X1, 5)]);
        let after_cmp = apply_instruction_concrete(
            pre,
            &Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X1),
            },
        );
        let after_csetm = apply_instruction_concrete(
            after_cmp,
            &Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::EQ,
            },
        );
        assert_eq!(after_csetm.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn test_cset_rejects_al_and_nv() {
        // CSET with AL or NV is nonsensical; is_encodable_aarch64 must refuse.
        assert!(
            !Instruction::Cset {
                rd: Register::X0,
                cond: Condition::AL,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Cset {
                rd: Register::X0,
                cond: Condition::NV,
            }
            .is_encodable_aarch64()
        );
        assert!(
            !Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::AL,
            }
            .is_encodable_aarch64()
        );
    }

    #[test]
    fn test_adds_overflow_sets_v_flag() {
        // ADDS(i64::MAX, 1) overflows: result wraps to INT_MIN; V=1, N=1
        let state = state_with(vec![(Register::X1, i64::MAX as u64), (Register::X2, 1)]);
        let instr = Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_i64(), i64::MIN);
        let f = new_state.get_flags();
        assert!(f.n, "ADDS overflow: N should be 1");
        assert!(!f.z, "ADDS overflow: Z should be 0");
        assert!(f.v, "ADDS overflow: V should be 1");
    }

    #[test]
    fn test_subs_carry_is_no_borrow() {
        // SUBS(rn, rm): C=1 when no borrow (rn >= rm unsigned)
        let state = state_with(vec![(Register::X1, 5), (Register::X2, 5)]);
        let instr = Instruction::Subs {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
        let f = new_state.get_flags();
        assert_eq!((f.n, f.z, f.c, f.v), (false, true, true, false));

        // SUBS where rn < rm unsigned → C=0 (borrow occurred)
        let state = state_with(vec![(Register::X1, 3), (Register::X2, 5)]);
        let instr = Instruction::Subs {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        let f = new_state.get_flags();
        assert!(!f.c, "SUBS(3, 5): C=0 (borrow)");
    }

    #[test]
    fn test_ands_clears_c_and_v() {
        let state = state_with(vec![(Register::X1, 0), (Register::X2, 0xFF)]);
        let instr = Instruction::Ands {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
        let f = new_state.get_flags();
        // Logical ops: N from result, Z from result, C=0, V=0
        assert_eq!((f.n, f.z, f.c, f.v), (false, true, false, false));
    }

    #[test]
    fn test_orn_or_with_inverted_rm() {
        // ORN x, x = !0 (all ones)
        let state = state_with(vec![(Register::X1, 0xDEAD_BEEF)]);
        let instr = Instruction::Orn {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X1),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn test_eon_xor_with_inverted_rm() {
        // EON x, x = !0 (all ones)
        let state = state_with(vec![(Register::X1, 0xDEAD_BEEF)]);
        let instr = Instruction::Eon {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X1),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn test_bics_clears_bits_and_sets_flags() {
        // BICS: rd = rn & !rm; flags via from_logical (Z=result==0, N=high bit, C=V=0).
        // Case 1: result is zero → Z=1
        let state = state_with(vec![
            (Register::X1, 0xFF),
            (Register::X2, 0xFF), // mask off all of rn → 0
        ]);
        let instr = Instruction::Bics {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0);
        let f = new_state.get_flags();
        assert_eq!((f.n, f.z, f.c, f.v), (false, true, false, false));
    }

    #[test]
    fn test_bic_clears_bits_set_in_rm() {
        // BIC rd, rn, rm  →  rd = rn & !rm
        let state = state_with(vec![
            (Register::X1, 0b1111_1010),
            (Register::X2, 0b0000_1100),
        ]);
        let instr = Instruction::Bic {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let new_state = apply_instruction_concrete(state, &instr);
        // 0b11111010 & ~0b00001100 = 0b11111010 & 0b...11110011 = 0b11110010
        assert_eq!(new_state.get_register(Register::X0).as_u64(), 0b1111_0010);
    }

    #[test]
    fn test_movn_inverts_shifted_immediate() {
        // MOVN rd, #imm, lsl #shift → rd = !((imm as u64) << shift)
        struct Case {
            imm: u16,
            shift: u8,
            expected: u64,
        }
        let cases = [
            Case {
                imm: 0,
                shift: 0,
                expected: u64::MAX,
            }, // !(0<<0) = all ones
            Case {
                imm: 0xFFFF,
                shift: 0,
                expected: !0xFFFF_u64,
            }, // 0xFFFF_FFFF_FFFF_0000
            Case {
                imm: 1,
                shift: 16,
                expected: !(1_u64 << 16),
            }, // 0xFFFF_FFFF_FFFE_FFFF
            Case {
                imm: 0xFFFF,
                shift: 48,
                expected: !(0xFFFF_u64 << 48),
            }, // 0x0000_FFFF_FFFF_FFFF
        ];
        for case in &cases {
            let state = ConcreteMachineState::new_zeroed();
            let instr = Instruction::MovN {
                rd: Register::X0,
                imm: case.imm,
                shift: case.shift,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                case.expected,
                "MOVN(#{:#x}, lsl #{}) should be {:#x}",
                case.imm,
                case.shift,
                case.expected
            );
        }
    }

    #[test]
    fn test_movz_concrete_lifts_imm_into_shifted_chunk() {
        let cases: [(u16, u8, u64); 4] = [
            (0xABCD, 0, 0xABCD),
            (0x1234, 16, 0x1234_0000),
            (0x5678, 32, 0x5678_0000_0000),
            (0xFFFF, 48, 0xFFFF_0000_0000_0000),
        ];
        for (imm, shift, expected) in cases {
            let state = ConcreteMachineState::new_zeroed();
            let instr = Instruction::MovZ {
                rd: Register::X0,
                imm,
                shift,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                expected,
                "MOVZ(#{:#x}, lsl #{}) should be {:#x}",
                imm,
                shift,
                expected
            );
        }
    }

    #[test]
    fn test_movk_concrete_preserves_unwritten_lanes() {
        // Pre-seed x0 with a known full 64-bit pattern; MOVK should rewrite
        // exactly one 16-bit lane and leave the others untouched.
        let mut state = ConcreteMachineState::new_zeroed();
        state.set_register(
            Register::X0,
            crate::semantics::state::ConcreteValue::new(0x1111_2222_3333_4444),
        );
        let cases: [(u16, u8, u64); 4] = [
            (0xAAAA, 0, 0x1111_2222_3333_AAAA),
            (0xBBBB, 16, 0x1111_2222_BBBB_4444),
            (0xCCCC, 32, 0x1111_CCCC_3333_4444),
            (0xDDDD, 48, 0xDDDD_2222_3333_4444),
        ];
        for (imm, shift, expected) in cases {
            let instr = Instruction::MovK {
                rd: Register::X0,
                imm,
                shift,
            };
            let new_state = apply_instruction_concrete(state.clone(), &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                expected,
                "MOVK(#{:#x}, lsl #{}) should be {:#x}",
                imm,
                shift,
                expected
            );
        }
    }

    #[test]
    fn test_negs_sets_flags_and_value() {
        // NEGS = SUBS rd, XZR, rm — so flag rule is `from_sub(0, rm, result)`.
        // - NEGS(0)        → result=0,        Z=1, N=0, C=1 (no borrow: 0>=0), V=0
        // - NEGS(1)        → result=-1,       Z=0, N=1, C=0 (borrow),         V=0
        // - NEGS(INT64_MIN)→ result=INT64_MIN, Z=0, N=1, C=0,                  V=1 (signed overflow)
        struct Case {
            input: i64,
            expected_result: i64,
            n: bool,
            z: bool,
            c: bool,
            v: bool,
        }
        let cases = [
            Case {
                input: 0,
                expected_result: 0,
                n: false,
                z: true,
                c: true,
                v: false,
            },
            Case {
                input: 1,
                expected_result: -1,
                n: true,
                z: false,
                c: false,
                v: false,
            },
            Case {
                input: i64::MIN,
                expected_result: i64::MIN,
                n: true,
                z: false,
                c: false,
                v: true,
            },
        ];
        for case in &cases {
            let state = state_with(vec![(Register::X1, case.input as u64)]);
            let instr = Instruction::Negs {
                rd: Register::X0,
                rm: Register::X1,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_i64(),
                case.expected_result,
                "NEGS({}) value wrong",
                case.input
            );
            let f = new_state.get_flags();
            assert_eq!(
                (f.n, f.z, f.c, f.v),
                (case.n, case.z, case.c, case.v),
                "NEGS({}) flags wrong: got NZCV={:?}, expected NZCV={:?}",
                case.input,
                (f.n, f.z, f.c, f.v),
                (case.n, case.z, case.c, case.v)
            );
        }
    }

    #[test]
    fn test_neg_two_complement() {
        let cases: &[(i64, i64)] = &[
            (0, 0),
            (1, -1),
            (-1, 1),
            (i64::MIN, i64::MIN), // wraps
            (42, -42),
            (-42, 42),
        ];
        for (input, expected) in cases {
            let state = state_with(vec![(Register::X1, *input as u64)]);
            let instr = Instruction::Neg {
                rd: Register::X0,
                rm: Register::X1,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_i64(),
                *expected,
                "NEG({}) should be {}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_mvn_inverts_bits() {
        // MVN x0, x1 sets x0 = !x1 (bitwise NOT)
        let cases: &[(u64, u64)] = &[
            (0, u64::MAX),
            (u64::MAX, 0),
            (0xFF, !0xFF_u64),
            (0xDEAD_BEEF_DEAD_BEEF, !0xDEAD_BEEF_DEAD_BEEF_u64),
        ];
        for (input, expected) in cases {
            let state = state_with(vec![(Register::X1, *input)]);
            let instr = Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            };
            let new_state = apply_instruction_concrete(state, &instr);
            assert_eq!(
                new_state.get_register(Register::X0).as_u64(),
                *expected,
                "MVN({:#x}) should be {:#x}",
                input,
                expected
            );
        }
    }

    fn apply_unary(instr: Instruction, input: u64) -> u64 {
        let state = state_with(vec![(Register::X1, input)]);
        apply_instruction_concrete(state, &instr)
            .get_register(Register::X0)
            .as_u64()
    }

    #[test]
    fn test_clz_matches_leading_zeros() {
        let cases: &[u64] = &[
            0,
            1,
            2,
            0xFF,
            0x8000_0000,
            0x8000_0000_0000_0000,
            u64::MAX,
            0xDEAD_BEEF_DEAD_BEEF,
        ];
        for &input in cases {
            let got = apply_unary(
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(
                got,
                input.leading_zeros() as u64,
                "CLZ({:#x}) mismatch",
                input
            );
        }
    }

    #[test]
    fn test_cls_matches_arm_spec() {
        // AArch64 CLS: count of consecutive bits matching the sign bit *after*
        // the sign bit. Spec values from the Arm reference for 64-bit form.
        let cases: &[(u64, u64)] = &[
            (0, 63),
            (u64::MAX, 63),
            (1, 62),
            (0x8000_0000_0000_0000, 0),
            (0x7FFF_FFFF_FFFF_FFFF, 0),
            (0xC000_0000_0000_0000, 1),
            (0x3FFF_FFFF_FFFF_FFFF, 1),
        ];
        for &(input, expected) in cases {
            let got = apply_unary(
                Instruction::Cls {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(got, expected, "CLS({:#x}) should be {}", input, expected);
        }
    }

    #[test]
    fn test_rbit_matches_reverse_bits() {
        let cases: &[u64] = &[
            0,
            1,
            0x8000_0000_0000_0000,
            u64::MAX,
            0xAAAA_AAAA_AAAA_AAAA,
            0xDEAD_BEEF_CAFE_BABE,
        ];
        for &input in cases {
            let got = apply_unary(
                Instruction::Rbit {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(
                got,
                input.reverse_bits(),
                "RBIT({:#x}) should match u64::reverse_bits",
                input
            );
        }
    }

    #[test]
    fn test_rev_matches_swap_bytes() {
        let cases: &[u64] = &[0, u64::MAX, 0x0102_0304_0506_0708, 0xDEAD_BEEF_CAFE_BABE];
        for &input in cases {
            let got = apply_unary(
                Instruction::Rev {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(
                got,
                input.swap_bytes(),
                "REV({:#x}) should match u64::swap_bytes",
                input
            );
        }
    }

    #[test]
    fn test_rev32_byte_reverses_each_word() {
        let cases: &[(u64, u64)] = &[
            (0x0102_0304_0506_0708, 0x0403_0201_0807_0605),
            (0, 0),
            (u64::MAX, u64::MAX),
            (0xDEAD_BEEF_CAFE_BABE, 0xEFBE_ADDE_BEBA_FECA),
        ];
        for &(input, expected) in cases {
            let got = apply_unary(
                Instruction::Rev32 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(
                got, expected,
                "REV32({:#x}) should be {:#x}",
                input, expected
            );
        }
    }

    #[test]
    fn test_rev16_byte_reverses_each_halfword() {
        let cases: &[(u64, u64)] = &[
            (0x0102_0304_0506_0708, 0x0201_0403_0605_0807),
            (0, 0),
            (u64::MAX, u64::MAX),
            (0xDEAD_BEEF_CAFE_BABE, 0xADDE_EFBE_FECA_BEBA),
        ];
        for &(input, expected) in cases {
            let got = apply_unary(
                Instruction::Rev16 {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                input,
            );
            assert_eq!(
                got, expected,
                "REV16({:#x}) should be {:#x}",
                input, expected
            );
        }
    }

    #[test]
    fn test_rev_is_involution() {
        let input = 0xDEAD_BEEF_CAFE_BABE_u64;
        let state = state_with(vec![(Register::X1, input)]);
        let seq = [
            Instruction::Rev {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Rev {
                rd: Register::X0,
                rn: Register::X0,
            },
        ];
        let final_state = apply_sequence_concrete(state, &seq);
        assert_eq!(final_state.get_register(Register::X0).as_u64(), input);
    }

    #[test]
    fn test_rbit_clz_equals_trailing_zeros() {
        // For nonzero x, RBIT then CLZ returns the count of trailing zeros.
        let cases: &[u64] = &[1, 2, 4, 0x80, 0x8000_0000_0000_0000, 0xDEAD_BEEF];
        for &input in cases {
            let state = state_with(vec![(Register::X1, input)]);
            let seq = [
                Instruction::Rbit {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X0,
                },
            ];
            let got = apply_sequence_concrete(state, &seq)
                .get_register(Register::X0)
                .as_u64();
            assert_eq!(
                got,
                input.trailing_zeros() as u64,
                "RBIT;CLZ({:#x}) should equal trailing_zeros",
                input
            );
        }
    }

    #[test]
    fn test_unpack_nzcv_bit_packing() {
        // bit3 = N, bit2 = Z, bit1 = C, bit0 = V.
        assert_eq!(
            unpack_nzcv(0b1010),
            ConditionFlags {
                n: true,
                z: false,
                c: true,
                v: false
            }
        );
        assert_eq!(unpack_nzcv(0), ConditionFlags::default());
        assert_eq!(
            unpack_nzcv(0b1111),
            ConditionFlags {
                n: true,
                z: true,
                c: true,
                v: true
            }
        );
    }

    #[test]
    fn test_ccmp_true_branch_matches_cmp() {
        // Pre-condition: Z=1 (so EQ holds). CCMP X1, X2, #0, EQ must then
        // behave like CMP X1, X2.
        let mut state = state_with(vec![(Register::X1, 7), (Register::X2, 3)]);
        state.set_flags(ConditionFlags {
            n: false,
            z: true,
            c: false,
            v: false,
        });
        let ccmp = Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 0,
            cond: Condition::EQ,
        };
        let after = apply_instruction_concrete(state.clone(), &ccmp);
        let cmp = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let after_cmp = apply_instruction_concrete(state, &cmp);
        assert_eq!(after.get_flags(), after_cmp.get_flags());
    }

    #[test]
    fn test_ccmp_false_branch_uses_nzcv_literal() {
        // Pre-condition: Z=0 (so EQ does NOT hold). CCMP must install the
        // 4-bit nzcv immediate as the new flag set.
        let mut state = state_with(vec![(Register::X1, 7), (Register::X2, 3)]);
        state.set_flags(ConditionFlags {
            n: false,
            z: false,
            c: false,
            v: false,
        });
        let ccmp = Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 0b1010, // N=1, Z=0, C=1, V=0
            cond: Condition::EQ,
        };
        let after = apply_instruction_concrete(state, &ccmp);
        assert_eq!(
            after.get_flags(),
            ConditionFlags {
                n: true,
                z: false,
                c: true,
                v: false
            }
        );
    }

    #[test]
    fn test_ccmn_true_branch_matches_cmn() {
        let mut state = state_with(vec![(Register::X1, 5), (Register::X2, 0)]);
        state.set_flags(ConditionFlags {
            n: false,
            z: true,
            c: false,
            v: false,
        });
        let ccmn = Instruction::Ccmn {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 0,
            cond: Condition::EQ,
        };
        let after = apply_instruction_concrete(state.clone(), &ccmn);
        let cmn = Instruction::Cmn {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let after_cmn = apply_instruction_concrete(state, &cmn);
        assert_eq!(after.get_flags(), after_cmn.get_flags());
    }

    #[test]
    fn test_csinc_nv_selects_rn_concrete() {
        // Concrete-interpreter pair for the SMT test
        // `test_csel_nv_evaluates_as_always_true`. NV per ARM ARM still
        // satisfies condition_holds = true; CSINC must select rn, not rm+1.
        let state = state_with(vec![(Register::X1, 7), (Register::X2, 2)]);
        let csinc = Instruction::Csinc {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::NV,
        };
        let after = apply_instruction_concrete(state, &csinc);
        assert_eq!(after.get_register(Register::X0).as_u64(), 7);
    }

    #[test]
    fn test_ccmp_immediate_rm() {
        // Pre-condition Z=1 so EQ holds. The true branch computes
        // 31 - 31 = 0, so the resulting Z must again be 1. Use EQ (not AL,
        // which is_encodable_aarch64 rejects for CCMP) to keep the test
        // consistent with the encoder contract.
        let mut state = state_with(vec![(Register::X1, 31)]);
        state.set_flags(ConditionFlags {
            n: false,
            z: true,
            c: false,
            v: false,
        });
        let ccmp = Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Immediate(31),
            nzcv: 0,
            cond: Condition::EQ,
        };
        let after = apply_instruction_concrete(state, &ccmp);
        assert!(after.get_flags().z);
    }

    #[test]
    fn test_add_with_uxtb_extended_register_operand() {
        // Issue #60: ADD X0, X1, X2, UXTB #2 takes the low byte of X2,
        // zero-extends it to 64, shifts left by 2, then adds X1.
        // X1 = 0x100, X2 = 0xDEAD_BEEF_CAFE_5678 → byte = 0x78 → shifted
        // by 2 = 0x1E0 → + 0x100 = 0x2E0.
        let state = state_with(vec![
            (Register::X1, 0x100),
            (Register::X2, 0xDEAD_BEEF_CAFE_5678),
        ]);
        let after = apply_instruction_concrete(
            state,
            &Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: crate::ir::ExtendKind::Uxtb,
                    shift: 2,
                },
            },
        );
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x2E0);
    }

    #[test]
    fn test_sub_with_sxtb_extended_register_operand() {
        // ADD/SUB with SXTB must sign-extend the low byte. If X2's low byte
        // is 0xFF (i.e. -1 as i8), then SUB X0, X1, X2, SXTB #0 computes
        // X1 - (-1) = X1 + 1.
        let state = state_with(vec![(Register::X1, 100), (Register::X2, 0xFF)]);
        let after = apply_instruction_concrete(
            state,
            &Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: crate::ir::ExtendKind::Sxtb,
                    shift: 0,
                },
            },
        );
        assert_eq!(after.get_register(Register::X0).as_u64(), 101);
    }

    #[test]
    fn test_uxtb_extracts_low_byte() {
        // UXTB X0, X1 with X1 = 0xDEAD_BEEF_CAFE_5678 → X0 = 0x78.
        let state = state_with(vec![(Register::X1, 0xDEAD_BEEF_CAFE_5678)]);
        let after = apply_instruction_concrete(
            state,
            &Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
        );
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x78);
    }

    #[test]
    fn test_uxtb_zero_extends() {
        // The high bits of X1 must NOT bleed into X0 — UXTB zero-extends.
        let state = state_with(vec![(Register::X1, 0xFFFF_FFFF_FFFF_FFFF)]);
        let after = apply_instruction_concrete(
            state,
            &Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
        );
        assert_eq!(after.get_register(Register::X0).as_u64(), 0xFF);
    }

    #[test]
    fn test_ubfx_extracts_zero_extended_field() {
        // UBFX X0, X1, #8, #16: take bits [23:8] of X1, zero-extend into X0.
        let state = state_with(vec![(Register::X1, 0xDEAD_BEEF_CAFE_0123)]);
        let instr = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 16,
        };
        let after = apply_instruction_concrete(state, &instr);
        // bits [23:8] of 0xDEAD_BEEF_CAFE_0123 = 0xFE01
        assert_eq!(after.get_register(Register::X0).as_u64(), 0xFE01);
    }

    #[test]
    fn test_ubfx_full_width_is_identity() {
        // UBFX X0, X1, #0, #64 — extracts the whole word. Exercises the
        // `1u64 << 64` UB guard documented in the plan.
        let state = state_with(vec![(Register::X1, 0xFFFF_0000_5555_AAAA)]);
        let instr = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 0,
            width: 64,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(
            after.get_register(Register::X0).as_u64(),
            0xFFFF_0000_5555_AAAA
        );
    }

    #[test]
    fn test_sbfx_sign_extends_negative_field() {
        // SBFX X0, X1, #4, #8: extract bits [11:4] of X1 (= 0xF0) and
        // sign-extend. The MSB of the field is 1, so the upper 56 bits of X0
        // become all-ones.
        let state = state_with(vec![(Register::X1, 0xF00)]);
        let instr = Instruction::Sbfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // 0xF0 sign-extended from 8 bits = 0xFFFF_FFFF_FFFF_FFF0
        assert_eq!(
            after.get_register(Register::X0).as_u64(),
            0xFFFF_FFFF_FFFF_FFF0
        );
    }

    #[test]
    fn test_sbfx_positive_field_no_extension() {
        // SBFX with MSB of the extracted field = 0: result equals UBFX.
        let state = state_with(vec![(Register::X1, 0x7F00)]);
        let instr = Instruction::Sbfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x7F);
    }

    #[test]
    fn test_sbfiz_sign_extends_field_above_lsb_plus_width() {
        // SBFIZ X0, X1, #4, #8: low 8 bits of X1 = 0xAB (MSB set),
        // sign-extend across bits [63:12], shift left by 4, zero bits [3:0].
        let state = state_with(vec![(Register::X1, 0xAB)]);
        let instr = Instruction::Sbfiz {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // 0xAB sign-extended from 8 bits → 0xFFFF_FFFF_FFFF_FFAB
        // <<4 → 0xFFFF_FFFF_FFFF_FAB0
        assert_eq!(
            after.get_register(Register::X0).as_u64(),
            0xFFFF_FFFF_FFFF_FAB0
        );
    }

    #[test]
    fn test_sbfiz_positive_field() {
        // MSB of field clear → result equals UBFIZ.
        let state = state_with(vec![(Register::X1, 0x7F)]);
        let instr = Instruction::Sbfiz {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // 0x7F << 4 = 0x7F0; no sign extension.
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x7F0);
    }

    #[test]
    fn test_ubfiz_zero_extends_field_shifted_into_position() {
        // UBFIZ X0, X1, #4, #8: take low 8 bits of X1 (= 0xAB),
        // shift left by 4, zero the rest. Existing X0 contents are discarded.
        let state = state_with(vec![
            (Register::X0, 0xFFFF_FFFF_FFFF_FFFF), // discarded
            (Register::X1, 0x0000_0000_0000_00AB),
        ]);
        let instr = Instruction::Ubfiz {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // 0xAB << 4 = 0xAB0; everything else zero.
        assert_eq!(after.get_register(Register::X0).as_u64(), 0xAB0);
    }

    #[test]
    fn test_bfxil_extracts_then_inserts_low() {
        // BFXIL X0, X1, #8, #8: take bits [15:8] of X1 → 0xAB,
        // place at bits [7:0] of X0, preserving X0's upper bits.
        let state = state_with(vec![
            (Register::X0, 0xFFFF_FFFF_FFFF_FFFF),
            (Register::X1, 0x0000_0000_0000_AB00),
        ]);
        let instr = Instruction::Bfxil {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 8,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // X0 upper 56 bits preserved (all ones), low 8 bits = 0xAB
        assert_eq!(
            after.get_register(Register::X0).as_u64(),
            0xFFFF_FFFF_FFFF_FFAB
        );
    }

    #[test]
    fn test_bfi_preserves_other_bits_of_rd() {
        // BFI X0, X1, #4, #8: insert low 8 bits of X1 at position 4 of X0,
        // leaving the other bits of X0 unchanged.
        let state = state_with(vec![
            (Register::X0, 0xFFFF_FFFF_FFFF_0FFF),
            (Register::X1, 0x000A_BEEF_DEAD_BEAA), // low 8 bits = 0xAA
        ]);
        let instr = Instruction::Bfi {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 4,
            width: 8,
        };
        let after = apply_instruction_concrete(state, &instr);
        // Bits [11:4] become 0xAA (from rn low 8 bits); other bits of X0 preserved.
        // Original X0 = 0xFFFF_FFFF_FFFF_0FFF
        //   bits [11:4] = 0xFF (within the 0x0FFF nibble pattern)
        // After insert:
        //   bits [11:4] = 0xAA → result = 0xFFFF_FFFF_FFFF_0AAF
        assert_eq!(
            after.get_register(Register::X0).as_u64(),
            0xFFFF_FFFF_FFFF_0AAF
        );
    }

    #[test]
    fn test_ubfx_high_lsb_boundary() {
        // UBFX X0, X1, #63, #1 — extracts the topmost bit.
        let state = state_with(vec![(Register::X1, 0x8000_0000_0000_0000)]);
        let instr = Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: 63,
            width: 1,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), 1);
    }

    // ---- Memory ops (issue #68 step 6) ----

    #[test]
    fn str_then_ldr_round_trips_via_memory() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let state = state_with(vec![
            (Register::X0, 0xDEADBEEF_CAFEBABE),
            (Register::X1, 0x1000),
        ]);
        // STR x0, [x1] ; LDR x2, [x1]
        let seq = vec![
            Instruction::Str {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
            Instruction::Ldr {
                rt: Register::X2,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
        ];
        let after = apply_sequence_concrete(state, &seq);
        assert_eq!(
            after.get_register(Register::X2).as_u64(),
            0xDEADBEEF_CAFEBABE
        );
    }

    #[test]
    fn ldrb_zero_extends() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mut state = state_with(vec![(Register::X1, 0x1000)]);
        state.write_bytes(0x1000, 0xFF, AccessWidth::Byte);
        let instr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), 0xFF);
    }

    #[test]
    fn ldrsb_sign_extends() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mut state = state_with(vec![(Register::X1, 0x1000)]);
        state.write_bytes(0x1000, 0xFF, AccessWidth::Byte);
        let instr = Instruction::Ldrs {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Byte,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), u64::MAX);
    }

    #[test]
    fn pre_index_writeback_updates_base_before_access() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mut state = state_with(vec![(Register::X0, 0x42), (Register::X1, 0x1000)]);
        state.write_bytes(0x1008, 0x99, AccessWidth::Byte);
        // LDR x2, [x1, #8]! — effective address is x1+8=0x1008, x1 updated to 0x1008.
        let instr = Instruction::Ldr {
            rt: Register::X2,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 8,
                mode: IndexMode::PreIndex,
            },
            width: AccessWidth::Byte,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X2).as_u64(), 0x99);
        assert_eq!(after.get_register(Register::X1).as_u64(), 0x1008);
    }

    #[test]
    fn post_index_writeback_uses_old_address_then_updates() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mut state = state_with(vec![(Register::X1, 0x1000)]);
        state.write_bytes(0x1000, 0x77, AccessWidth::Byte);
        // LDR x0, [x1], #16 — read at original x1=0x1000, then x1 ← 0x1010.
        let instr = Instruction::Ldr {
            rt: Register::X0,
            addr: AddressOperand::Imm {
                base: Register::X1,
                offset: 16,
                mode: IndexMode::PostIndex,
            },
            width: AccessWidth::Byte,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x77);
        assert_eq!(after.get_register(Register::X1).as_u64(), 0x1010);
    }

    #[test]
    fn ldp_reads_two_consecutive_words() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let mut state = state_with(vec![(Register::X2, 0x1000)]);
        state.write_bytes(0x1000, 0x1111, AccessWidth::Extended);
        state.write_bytes(0x1008, 0x2222, AccessWidth::Extended);
        let instr = Instruction::Ldp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X2,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
            signed: false,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.get_register(Register::X0).as_u64(), 0x1111);
        assert_eq!(after.get_register(Register::X1).as_u64(), 0x2222);
    }

    #[test]
    fn stp_writes_two_consecutive_words() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let state = state_with(vec![
            (Register::X0, 0xAAAA),
            (Register::X1, 0xBBBB),
            (Register::X2, 0x1000),
        ]);
        let instr = Instruction::Stp {
            rt1: Register::X0,
            rt2: Register::X1,
            addr: AddressOperand::Imm {
                base: Register::X2,
                offset: 0,
                mode: IndexMode::Offset,
            },
            width: AccessWidth::Extended,
        };
        let after = apply_instruction_concrete(state, &instr);
        assert_eq!(after.read_bytes(0x1000, AccessWidth::Extended), 0xAAAA);
        assert_eq!(after.read_bytes(0x1008, AccessWidth::Extended), 0xBBBB);
    }
}

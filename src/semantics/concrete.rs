//! Concrete interpreter for fast validation of instruction sequences

use crate::ir::{Condition, Instruction, Operand, Register};
use crate::semantics::live_out::LiveOutRegisters;
use crate::semantics::state::{ConcreteMachineState, ConcreteValue, ConditionFlags};

/// Evaluate an operand to get its concrete value
fn eval_operand(state: &ConcreteMachineState, operand: &Operand) -> ConcreteValue {
    match operand {
        Operand::Register(reg) => state.get_register(*reg),
        Operand::Immediate(imm) => ConcreteValue::from_i64(*imm),
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
            } else if lhs == i64::MIN && rhs == -1 {
                i64::MIN // Overflow case returns dividend
            } else {
                lhs / rhs
            };
            state.set_register(*rd, ConcreteValue::from_i64(result));
        }
        Instruction::Udiv { rd, rn, rm } => {
            let lhs = state.get_register(*rn).as_u64();
            let rhs = state.get_register(*rm).as_u64();
            let result = if rhs == 0 {
                0 // Division by zero returns 0 in AArch64
            } else {
                lhs / rhs
            };
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
                ConcreteValue::from_i64(-(state.get_register(*rm).as_i64()))
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
    }
    state
}

/// Evaluate a condition code against the current flags
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

/// Check if two concrete states are equal for the specified live-out registers
pub fn states_equal_for_live_out(
    state1: &ConcreteMachineState,
    state2: &ConcreteMachineState,
    live_out: &LiveOutRegisters,
) -> bool {
    for reg in live_out.iter() {
        if state1.get_register(*reg) != state2.get_register(*reg) {
            return false;
        }
    }
    true
}

/// Find the first differing register between two states for live-out registers
pub fn find_first_difference(
    state1: &ConcreteMachineState,
    state2: &ConcreteMachineState,
    live_out: &LiveOutRegisters,
) -> Option<(Register, ConcreteValue, ConcreteValue)> {
    for reg in live_out.iter() {
        let v1 = state1.get_register(*reg);
        let v2 = state2.get_register(*reg);
        if v1 != v2 {
            return Some((*reg, v1, v2));
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

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
        assert!(states_equal_for_live_out(&state1, &state2, &live_out));
    }

    #[test]
    fn test_states_equal_for_live_out_different() {
        let state1 = state_with(vec![(Register::X0, 42)]);
        let state2 = state_with(vec![(Register::X0, 43)]);

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
        assert!(!states_equal_for_live_out(&state1, &state2, &live_out));
    }

    #[test]
    fn test_find_first_difference() {
        let state1 = state_with(vec![(Register::X0, 42), (Register::X1, 100)]);
        let state2 = state_with(vec![(Register::X0, 42), (Register::X1, 200)]);

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0, Register::X1]);
        let diff = find_first_difference(&state1, &state2, &live_out);
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

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
        let diff = find_first_difference(&state1, &state2, &live_out);
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

        let live_out = LiveOutRegisters::from_registers(vec![Register::X0]);
        assert!(states_equal_for_live_out(&state1, &state2, &live_out));
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
}

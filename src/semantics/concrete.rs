//! Concrete interpreter for fast validation of instruction sequences

use crate::ir::{Instruction, Operand, Register};
use crate::semantics::state::{ConcreteMachineState, ConcreteValue, LiveOutMask};

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
    }
    state
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
    live_out: &LiveOutMask,
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
    live_out: &LiveOutMask,
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

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
        assert!(states_equal_for_live_out(&state1, &state2, &live_out));
    }

    #[test]
    fn test_states_equal_for_live_out_different() {
        let state1 = state_with(vec![(Register::X0, 42)]);
        let state2 = state_with(vec![(Register::X0, 43)]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
        assert!(!states_equal_for_live_out(&state1, &state2, &live_out));
    }

    #[test]
    fn test_find_first_difference() {
        let state1 = state_with(vec![(Register::X0, 42), (Register::X1, 100)]);
        let state2 = state_with(vec![(Register::X0, 42), (Register::X1, 200)]);

        let live_out = LiveOutMask::from_registers(vec![Register::X0, Register::X1]);
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

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
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

        let live_out = LiveOutMask::from_registers(vec![Register::X0]);
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
}

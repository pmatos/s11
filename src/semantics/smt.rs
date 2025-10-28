//! SMT constraint generation for AArch64 instructions

use crate::ir::{Instruction, Operand, Register};
use std::collections::HashMap;
use z3::ast::BV;

/// Machine state representation for SMT solving
#[derive(Clone)]
pub struct MachineState {
    /// Register values as 64-bit bitvectors
    pub registers: HashMap<Register, BV>,
}

impl MachineState {
    /// Create a new symbolic machine state
    pub fn new_symbolic(prefix: &str) -> Self {
        let mut registers = HashMap::new();

        // Create symbolic variables for all registers
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                let name = format!("{}_x{}", prefix, i);
                registers.insert(reg, BV::new_const(name, 64));
            }
        }

        // XZR is always zero
        registers.insert(Register::XZR, BV::from_i64(0, 64));

        // SP is also symbolic
        registers.insert(Register::SP, BV::new_const(format!("{}_sp", prefix), 64));

        MachineState { registers }
    }

    /// Get the value of a register
    pub fn get_register(&self, reg: Register) -> &BV {
        self.registers.get(&reg).expect("Register not found")
    }

    /// Set the value of a register
    pub fn set_register(&mut self, reg: Register, value: BV) {
        // XZR writes are ignored (always zero)
        if reg != Register::XZR {
            self.registers.insert(reg, value);
        }
    }

    /// Evaluate an operand to get its value
    pub fn eval_operand(&self, operand: &Operand) -> BV {
        match operand {
            Operand::Register(reg) => self.get_register(*reg).clone(),
            Operand::Immediate(imm) => BV::from_i64(*imm, 64),
        }
    }
}

/// Apply an instruction to a machine state, returning the new state
pub fn apply_instruction(mut state: MachineState, instruction: &Instruction) -> MachineState {
    match instruction {
        Instruction::MovReg { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, value);
        }
        Instruction::MovImm { rd, imm } => {
            let value = BV::from_i64(*imm, 64);
            state.set_register(*rd, value);
        }
        Instruction::Add { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvadd(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Sub { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvsub(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::And { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Orr { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvor(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Eor { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvxor(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Lsl { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // LSL is logical shift left
            let result = value.bvshl(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Lsr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // LSR is logical shift right
            let result = value.bvlshr(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Asr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // ASR is arithmetic shift right
            let result = value.bvashr(&shift_amount);
            state.set_register(*rd, result);
        }
    }
    state
}

/// Apply a sequence of instructions to a machine state
pub fn apply_sequence(mut state: MachineState, instructions: &[Instruction]) -> MachineState {
    for instruction in instructions {
        state = apply_instruction(state, instruction);
    }
    state
}

/// Check if two machine states are not equal (for any register values)
pub fn states_not_equal(state1: &MachineState, state2: &MachineState) -> z3::ast::Bool {
    let mut not_equal = z3::ast::Bool::from_bool(false);

    // Check all general purpose registers
    for i in 0..=30 {
        if let Some(reg) = Register::from_index(i) {
            let val1 = state1.get_register(reg);
            let val2 = state2.get_register(reg);
            let reg_not_equal = val1.eq(val2).not();
            not_equal = z3::ast::Bool::or(&[&not_equal, &reg_not_equal]);
        }
    }

    // Also check SP
    let sp1 = state1.get_register(Register::SP);
    let sp2 = state2.get_register(Register::SP);
    let sp_not_equal = sp1.eq(sp2).not();
    not_equal = z3::ast::Bool::or(&[&not_equal, &sp_not_equal]);

    not_equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    #[test]
    fn test_mov_zero_equivalence() {
        let solver = Solver::new();

        // Create initial symbolic state
        let initial_state = MachineState::new_symbolic("pre");

        // Sequence 1: MOV X0, #0
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let state1 = apply_sequence(initial_state.clone(), &seq1);

        // Sequence 2: EOR X0, X0, X0
        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        let state2 = apply_sequence(initial_state, &seq2);

        // Assert states are not equal
        solver.assert(&states_not_equal(&state1, &state2));

        // If UNSAT, states are always equal
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_add_immediate() {
        let mut state = MachineState::new_symbolic("test");

        // Set X1 = 10
        state.set_register(Register::X1, BV::from_i64(10, 64));

        // ADD X0, X1, #5
        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };

        let new_state = apply_instruction(state, &add);

        // X0 should be 15
        let x0_val = new_state.get_register(Register::X0);
        let expected = BV::from_i64(15, 64);

        let solver = Solver::new();
        solver.assert(&x0_val.eq(&expected).not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }
}

//! Mutation operators for stochastic search
//!
//! Implements four mutation operators:
//! 1. Operand mutation (50%): Change a register or immediate in a random instruction
//! 2. Opcode mutation (16%): Change the opcode while keeping operand structure
//! 3. Swap mutation (16%): Swap two instructions
//! 4. Instruction mutation (18%): Replace an entire instruction

use crate::ir::{Instruction, Operand, Register};
use crate::search::candidate::{generate_random_instruction, is_binary_op, is_shift_op};
use crate::search::config::MutationWeights;
use rand::Rng;

/// Mutation operator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationType {
    /// Change a register or immediate operand
    Operand,
    /// Change the opcode (e.g., ADD -> SUB)
    Opcode,
    /// Swap two instructions
    Swap,
    /// Replace entire instruction
    Instruction,
}

/// Mutator for instruction sequences
pub struct Mutator {
    registers: Vec<Register>,
    immediates: Vec<i64>,
    weights: MutationWeights,
}

impl Mutator {
    pub fn new(registers: Vec<Register>, immediates: Vec<i64>, weights: MutationWeights) -> Self {
        Self {
            registers,
            immediates,
            weights,
        }
    }

    /// Select a mutation type based on weights
    pub fn select_mutation_type<R: Rng>(&self, rng: &mut R) -> MutationType {
        let thresholds = self.weights.cumulative_thresholds();
        let r: f64 = rng.random();

        if r < thresholds[0] {
            MutationType::Operand
        } else if r < thresholds[1] {
            MutationType::Opcode
        } else if r < thresholds[2] {
            MutationType::Swap
        } else {
            MutationType::Instruction
        }
    }

    /// Apply a random mutation to a sequence
    pub fn mutate<R: Rng>(&self, rng: &mut R, sequence: &[Instruction]) -> Vec<Instruction> {
        if sequence.is_empty() {
            return sequence.to_vec();
        }

        let mut result = sequence.to_vec();
        let mutation_type = self.select_mutation_type(rng);

        match mutation_type {
            MutationType::Operand => self.mutate_operand(rng, &mut result),
            MutationType::Opcode => self.mutate_opcode(rng, &mut result),
            MutationType::Swap => self.mutate_swap(rng, &mut result),
            MutationType::Instruction => self.mutate_instruction(rng, &mut result),
        }

        result
    }

    /// Operand mutation: change a register or immediate in a random instruction
    fn mutate_operand<R: Rng>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() || self.registers.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        let instr = &mut sequence[idx];

        match instr {
            Instruction::MovReg { rd, rn } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *rn = self.random_register(rng);
                }
            }
            Instruction::MovImm { rd, imm } => {
                if rng.random_bool(0.5) {
                    *rd = self.random_register(rng);
                } else {
                    *imm = self.random_immediate(rng);
                }
            }
            Instruction::Add { rd, rn, rm }
            | Instruction::Sub { rd, rn, rm }
            | Instruction::And { rd, rn, rm }
            | Instruction::Orr { rd, rn, rm }
            | Instruction::Eor { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_operand(rng),
                }
            }
            Instruction::Lsl { rd, rn, shift }
            | Instruction::Lsr { rd, rn, shift }
            | Instruction::Asr { rd, rn, shift } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *shift = self.random_shift_operand(rng),
                }
            }
            Instruction::Mul { rd, rn, rm }
            | Instruction::Sdiv { rd, rn, rm }
            | Instruction::Udiv { rd, rn, rm } => {
                let choice = rng.random_range(0..3);
                match choice {
                    0 => *rd = self.random_register(rng),
                    1 => *rn = self.random_register(rng),
                    _ => *rm = self.random_register(rng),
                }
            }
        }
    }

    /// Opcode mutation: change the opcode while keeping operand structure
    fn mutate_opcode<R: Rng>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        let instr = sequence[idx];

        sequence[idx] = match instr {
            Instruction::MovReg { rd, rn } => {
                if rng.random_bool(0.5) {
                    Instruction::MovImm {
                        rd,
                        imm: self.random_immediate(rng),
                    }
                } else {
                    Instruction::MovReg { rd, rn }
                }
            }
            Instruction::MovImm { rd, .. } => {
                if rng.random_bool(0.5) {
                    Instruction::MovReg {
                        rd,
                        rn: self.random_register(rng),
                    }
                } else {
                    Instruction::MovImm {
                        rd,
                        imm: self.random_immediate(rng),
                    }
                }
            }
            Instruction::Add { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Sub { rd, rn, rm },
                1 => Instruction::And { rd, rn, rm },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Add { rd, rn, rm },
            },
            Instruction::Sub { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::And { rd, rn, rm },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Sub { rd, rn, rm },
            },
            Instruction::And { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::Sub { rd, rn, rm },
                2 => Instruction::Orr { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::And { rd, rn, rm },
            },
            Instruction::Orr { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::Sub { rd, rn, rm },
                2 => Instruction::And { rd, rn, rm },
                3 => Instruction::Eor { rd, rn, rm },
                _ => Instruction::Orr { rd, rn, rm },
            },
            Instruction::Eor { rd, rn, rm } => match rng.random_range(0..5) {
                0 => Instruction::Add { rd, rn, rm },
                1 => Instruction::Sub { rd, rn, rm },
                2 => Instruction::And { rd, rn, rm },
                3 => Instruction::Orr { rd, rn, rm },
                _ => Instruction::Eor { rd, rn, rm },
            },
            Instruction::Lsl { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsr { rd, rn, shift },
                1 => Instruction::Asr { rd, rn, shift },
                _ => Instruction::Lsl { rd, rn, shift },
            },
            Instruction::Lsr { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsl { rd, rn, shift },
                1 => Instruction::Asr { rd, rn, shift },
                _ => Instruction::Lsr { rd, rn, shift },
            },
            Instruction::Asr { rd, rn, shift } => match rng.random_range(0..3) {
                0 => Instruction::Lsl { rd, rn, shift },
                1 => Instruction::Lsr { rd, rn, shift },
                _ => Instruction::Asr { rd, rn, shift },
            },
            Instruction::Mul { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Sdiv { rd, rn, rm },
                1 => Instruction::Udiv { rd, rn, rm },
                _ => Instruction::Mul { rd, rn, rm },
            },
            Instruction::Sdiv { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Udiv { rd, rn, rm },
                _ => Instruction::Sdiv { rd, rn, rm },
            },
            Instruction::Udiv { rd, rn, rm } => match rng.random_range(0..3) {
                0 => Instruction::Mul { rd, rn, rm },
                1 => Instruction::Sdiv { rd, rn, rm },
                _ => Instruction::Udiv { rd, rn, rm },
            },
        };
    }

    /// Swap mutation: swap two instructions in the sequence
    fn mutate_swap<R: Rng>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.len() < 2 {
            return;
        }

        let idx1 = rng.random_range(0..sequence.len());
        let idx2 = rng.random_range(0..sequence.len());
        sequence.swap(idx1, idx2);
    }

    /// Instruction mutation: replace an entire instruction with a random one
    fn mutate_instruction<R: Rng>(&self, rng: &mut R, sequence: &mut [Instruction]) {
        if sequence.is_empty() {
            return;
        }

        let idx = rng.random_range(0..sequence.len());
        sequence[idx] = generate_random_instruction(rng, &self.registers, &self.immediates);
    }

    fn random_register<R: Rng>(&self, rng: &mut R) -> Register {
        if self.registers.is_empty() {
            Register::X0
        } else {
            self.registers[rng.random_range(0..self.registers.len())]
        }
    }

    fn random_immediate<R: Rng>(&self, rng: &mut R) -> i64 {
        if self.immediates.is_empty() {
            0
        } else {
            self.immediates[rng.random_range(0..self.immediates.len())]
        }
    }

    fn random_operand<R: Rng>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.5) && !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(self.random_immediate(rng))
        }
    }

    fn random_shift_operand<R: Rng>(&self, rng: &mut R) -> Operand {
        if rng.random_bool(0.7) {
            let shifts = [0, 1, 2, 4, 8, 16, 32];
            Operand::Immediate(shifts[rng.random_range(0..shifts.len())])
        } else if !self.registers.is_empty() {
            Operand::Register(self.random_register(rng))
        } else {
            Operand::Immediate(1)
        }
    }
}

/// Perform operand mutation on a specific instruction (for testing)
pub fn mutate_operand_in_place<R: Rng>(
    rng: &mut R,
    instr: &mut Instruction,
    registers: &[Register],
    immediates: &[i64],
) {
    let mutator = Mutator::new(
        registers.to_vec(),
        immediates.to_vec(),
        MutationWeights::default(),
    );
    let mut seq = vec![*instr];
    mutator.mutate_operand(rng, &mut seq);
    *instr = seq[0];
}

/// Change opcode while preserving operand structure (for testing)
pub fn mutate_opcode_in_place<R: Rng>(rng: &mut R, instr: &mut Instruction) {
    let mutator = Mutator::new(
        vec![Register::X0, Register::X1, Register::X2],
        vec![0, 1],
        MutationWeights::default(),
    );
    let mut seq = vec![*instr];
    mutator.mutate_opcode(rng, &mut seq);
    *instr = seq[0];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_mutator() -> Mutator {
        Mutator::new(
            vec![Register::X0, Register::X1, Register::X2],
            vec![-1, 0, 1, 2],
            MutationWeights::default(),
        )
    }

    #[test]
    fn test_mutation_type_selection() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut operand_count = 0;
        let mut opcode_count = 0;
        let mut swap_count = 0;
        let mut instr_count = 0;

        for _ in 0..10000 {
            match mutator.select_mutation_type(&mut rng) {
                MutationType::Operand => operand_count += 1,
                MutationType::Opcode => opcode_count += 1,
                MutationType::Swap => swap_count += 1,
                MutationType::Instruction => instr_count += 1,
            }
        }

        // Operand should be most frequent (50%)
        assert!(operand_count > opcode_count);
        assert!(operand_count > swap_count);
        assert!(operand_count > instr_count);

        // All should have some samples
        assert!(opcode_count > 0);
        assert!(swap_count > 0);
        assert!(instr_count > 0);
    }

    #[test]
    fn test_mutate_produces_different_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let mut different_count = 0;
        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &original);
            if mutated != original {
                different_count += 1;
            }
        }

        // Most mutations should produce different results
        assert!(different_count > 50);
    }

    #[test]
    fn test_mutate_preserves_length_except_empty() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::MovReg {
                rd: Register::X2,
                rn: Register::X1,
            },
        ];

        for _ in 0..100 {
            let mutated = mutator.mutate(&mut rng, &original);
            assert_eq!(mutated.len(), original.len());
        }
    }

    #[test]
    fn test_mutate_empty_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let empty: Vec<Instruction> = vec![];
        let mutated = mutator.mutate(&mut rng, &empty);
        assert!(mutated.is_empty());
    }

    #[test]
    fn test_operand_mutation_changes_operands() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        let original = seq[0];
        let mut changed = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_operand(&mut rng, &mut seq);
            if seq[0] != original {
                changed = true;
                break;
            }
        }

        assert!(changed);
    }

    #[test]
    fn test_opcode_mutation_changes_opcode() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        let original = seq[0];
        let mut changed_to_different_opcode = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_opcode(&mut rng, &mut seq);

            if !matches!(seq[0], Instruction::Add { .. }) {
                changed_to_different_opcode = true;
                break;
            }
        }

        assert!(changed_to_different_opcode);
    }

    #[test]
    fn test_swap_mutation() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 1,
            },
        ];

        let first = seq[0];
        let second = seq[1];

        let mut swapped = false;
        for _ in 0..100 {
            seq = vec![first, second];
            mutator.mutate_swap(&mut rng, &mut seq);
            if seq[0] == second && seq[1] == first {
                swapped = true;
                break;
            }
        }

        assert!(swapped);
    }

    #[test]
    fn test_instruction_mutation_replaces() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let mut seq = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        let original = seq[0];
        let mut replaced = false;

        for _ in 0..100 {
            seq[0] = original;
            mutator.mutate_instruction(&mut rng, &mut seq);
            if seq[0] != original {
                replaced = true;
                break;
            }
        }

        assert!(replaced);
    }

    #[test]
    fn test_mutate_single_instruction_sequence() {
        let mutator = default_mutator();
        let mut rng = rand::rng();

        let original = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let mut mutated = mutator.mutate(&mut rng, &original);
        assert_eq!(mutated.len(), 1);

        // Swap mutation should be a no-op on single instruction
        mutator.mutate_swap(&mut rng, &mut mutated);
        assert_eq!(mutated.len(), 1);
    }
}

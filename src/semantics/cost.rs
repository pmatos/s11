//! Cost model for instruction sequences

use crate::ir::Instruction;

/// Cost metric for evaluating instruction sequences
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CostMetric {
    /// Count the number of instructions (default)
    #[default]
    InstructionCount,
    /// Sum of instruction latencies
    Latency,
    /// Total code size in bytes (4 per instruction for AArch64)
    CodeSize,
}

/// Get the cost of a single instruction
pub fn instruction_cost(instr: &Instruction, metric: &CostMetric) -> u64 {
    match metric {
        CostMetric::InstructionCount => 1,
        CostMetric::Latency => instruction_latency(instr),
        CostMetric::CodeSize => 4,
    }
}

/// Get the latency of an instruction (simplified model)
fn instruction_latency(instr: &Instruction) -> u64 {
    match instr {
        Instruction::MovReg { .. } | Instruction::MovImm { .. } => 1,
        Instruction::Add { .. } | Instruction::Sub { .. } => 1,
        Instruction::And { .. } | Instruction::Orr { .. } | Instruction::Eor { .. } => 1,
        Instruction::Lsl { .. } | Instruction::Lsr { .. } | Instruction::Asr { .. } => 1,
        // Multiply has higher latency than simple ALU ops
        Instruction::Mul { .. } => 3,
        // Division has the highest latency
        Instruction::Sdiv { .. } | Instruction::Udiv { .. } => 12,
    }
}

/// Calculate the total cost of an instruction sequence
pub fn sequence_cost(instructions: &[Instruction], metric: &CostMetric) -> u64 {
    instructions
        .iter()
        .map(|i| instruction_cost(i, metric))
        .sum()
}

/// Check if sequence `a` is cheaper than sequence `b`
pub fn is_cheaper(a: &[Instruction], b: &[Instruction], metric: &CostMetric) -> bool {
    sequence_cost(a, metric) < sequence_cost(b, metric)
}

/// Check if sequence `a` is cheaper than or equal to sequence `b`
pub fn is_cheaper_or_equal(a: &[Instruction], b: &[Instruction], metric: &CostMetric) -> bool {
    sequence_cost(a, metric) <= sequence_cost(b, metric)
}

/// Get the cost difference (positive means `a` is more expensive)
pub fn cost_difference(a: &[Instruction], b: &[Instruction], metric: &CostMetric) -> i64 {
    sequence_cost(a, metric) as i64 - sequence_cost(b, metric) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};

    fn mov_imm(rd: Register, imm: i64) -> Instruction {
        Instruction::MovImm { rd, imm }
    }

    fn add_imm(rd: Register, rn: Register, imm: i64) -> Instruction {
        Instruction::Add {
            rd,
            rn,
            rm: Operand::Immediate(imm),
        }
    }

    #[test]
    fn test_instruction_cost_count() {
        let instr = mov_imm(Register::X0, 0);
        assert_eq!(instruction_cost(&instr, &CostMetric::InstructionCount), 1);
    }

    #[test]
    fn test_instruction_cost_code_size() {
        let instr = mov_imm(Register::X0, 0);
        assert_eq!(instruction_cost(&instr, &CostMetric::CodeSize), 4);
    }

    #[test]
    fn test_instruction_cost_latency() {
        let instr = mov_imm(Register::X0, 0);
        assert_eq!(instruction_cost(&instr, &CostMetric::Latency), 1);
    }

    #[test]
    fn test_sequence_cost_empty() {
        let cost = sequence_cost(&[], &CostMetric::InstructionCount);
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_sequence_cost_single() {
        let seq = vec![mov_imm(Register::X0, 0)];
        assert_eq!(sequence_cost(&seq, &CostMetric::InstructionCount), 1);
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize), 4);
    }

    #[test]
    fn test_sequence_cost_multiple() {
        let seq = vec![
            mov_imm(Register::X0, 0),
            add_imm(Register::X1, Register::X0, 1),
        ];
        assert_eq!(sequence_cost(&seq, &CostMetric::InstructionCount), 2);
        assert_eq!(sequence_cost(&seq, &CostMetric::CodeSize), 8);
    }

    #[test]
    fn test_is_cheaper_true() {
        let short = vec![mov_imm(Register::X0, 0)];
        let long = vec![
            mov_imm(Register::X0, 0),
            add_imm(Register::X1, Register::X0, 1),
        ];
        assert!(is_cheaper(&short, &long, &CostMetric::InstructionCount));
    }

    #[test]
    fn test_is_cheaper_false() {
        let short = vec![mov_imm(Register::X0, 0)];
        let long = vec![
            mov_imm(Register::X0, 0),
            add_imm(Register::X1, Register::X0, 1),
        ];
        assert!(!is_cheaper(&long, &short, &CostMetric::InstructionCount));
    }

    #[test]
    fn test_is_cheaper_equal() {
        let seq1 = vec![mov_imm(Register::X0, 0)];
        let seq2 = vec![mov_imm(Register::X1, 1)];
        assert!(!is_cheaper(&seq1, &seq2, &CostMetric::InstructionCount));
        assert!(!is_cheaper(&seq2, &seq1, &CostMetric::InstructionCount));
    }

    #[test]
    fn test_is_cheaper_or_equal() {
        let seq1 = vec![mov_imm(Register::X0, 0)];
        let seq2 = vec![mov_imm(Register::X1, 1)];
        assert!(is_cheaper_or_equal(
            &seq1,
            &seq2,
            &CostMetric::InstructionCount
        ));
        assert!(is_cheaper_or_equal(
            &seq2,
            &seq1,
            &CostMetric::InstructionCount
        ));
    }

    #[test]
    fn test_cost_difference_positive() {
        let expensive = vec![
            mov_imm(Register::X0, 0),
            mov_imm(Register::X1, 1),
            mov_imm(Register::X2, 2),
        ];
        let cheap = vec![mov_imm(Register::X0, 0)];
        assert_eq!(
            cost_difference(&expensive, &cheap, &CostMetric::InstructionCount),
            2
        );
    }

    #[test]
    fn test_cost_difference_negative() {
        let expensive = vec![
            mov_imm(Register::X0, 0),
            mov_imm(Register::X1, 1),
            mov_imm(Register::X2, 2),
        ];
        let cheap = vec![mov_imm(Register::X0, 0)];
        assert_eq!(
            cost_difference(&cheap, &expensive, &CostMetric::InstructionCount),
            -2
        );
    }

    #[test]
    fn test_cost_difference_zero() {
        let seq1 = vec![mov_imm(Register::X0, 0)];
        let seq2 = vec![mov_imm(Register::X1, 1)];
        assert_eq!(
            cost_difference(&seq1, &seq2, &CostMetric::InstructionCount),
            0
        );
    }

    #[test]
    fn test_all_instruction_types_have_cost() {
        let instructions = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(1),
            },
            Instruction::Mul {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sdiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Udiv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
            },
        ];

        for instr in &instructions {
            assert!(instruction_cost(instr, &CostMetric::InstructionCount) > 0);
            assert!(instruction_cost(instr, &CostMetric::Latency) > 0);
            assert!(instruction_cost(instr, &CostMetric::CodeSize) > 0);
        }
    }

    #[test]
    fn test_mul_div_latency() {
        let mul = Instruction::Mul {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let sdiv = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let udiv = Instruction::Udiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        };

        // MUL has higher latency than ADD
        assert!(
            instruction_cost(&mul, &CostMetric::Latency)
                > instruction_cost(&add, &CostMetric::Latency)
        );
        // DIV has higher latency than MUL
        assert!(
            instruction_cost(&sdiv, &CostMetric::Latency)
                > instruction_cost(&mul, &CostMetric::Latency)
        );
        assert!(
            instruction_cost(&udiv, &CostMetric::Latency)
                > instruction_cost(&mul, &CostMetric::Latency)
        );
    }
}

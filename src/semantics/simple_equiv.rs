//! Simple equivalence checker without SMT solver (for testing)

use crate::ir::{Instruction, Operand, Register};

/// Simple pattern-based equivalence checker for testing
pub fn check_equivalence_simple(seq1: &[Instruction], seq2: &[Instruction]) -> bool {
    // Identical sequences
    if seq1 == seq2 {
        return true;
    }

    // MOV X, #0 ≡ EOR X, X, X
    if seq1.len() == 1 && seq2.len() == 1 {
        match (&seq1[0], &seq2[0]) {
            (
                Instruction::MovImm { rd: rd1, imm: 0 },
                Instruction::Eor {
                    rd: rd2,
                    rn,
                    rm: Operand::Register(rm),
                },
            ) if rd1 == rd2 && rd1 == rn && rn == rm => return true,
            (
                Instruction::Eor {
                    rd: rd1,
                    rn,
                    rm: Operand::Register(rm),
                },
                Instruction::MovImm { rd: rd2, imm: 0 },
            ) if rd1 == rd2 && rd1 == rn && rn == rm => return true,
            _ => {}
        }
    }

    // MOV X0, X1; ADD X0, X0, #N ≡ ADD X0, X1, #N
    if seq1.len() == 2 && seq2.len() == 1 {
        if let [Instruction::MovReg { rd: rd1, rn }, Instruction::Add {
            rd: rd2,
            rn: rn2,
            rm: Operand::Immediate(imm),
        }] = seq1
        {
            if let [Instruction::Add {
                rd: rd3,
                rn: rn3,
                rm: Operand::Immediate(imm2),
            }] = seq2
            {
                if rd1 == rd2 && rd2 == rd3 && rd1 == rn2 && rn == rn3 && imm == imm2 {
                    return true;
                }
            }
        }
    }

    // Check reverse
    if seq1.len() == 1 && seq2.len() == 2 {
        return check_equivalence_simple(seq2, seq1);
    }

    // ADD commutativity
    if seq1.len() == 1 && seq2.len() == 1 {
        match (&seq1[0], &seq2[0]) {
            (
                Instruction::Add {
                    rd: rd1,
                    rn: rn1,
                    rm: Operand::Register(rm1),
                },
                Instruction::Add {
                    rd: rd2,
                    rn: rn2,
                    rm: Operand::Register(rm2),
                },
            ) if rd1 == rd2 && ((rn1 == rn2 && rm1 == rm2) || (rn1 == rm2 && rm1 == rn2)) => {
                return true
            }
            _ => {}
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_zero_eor_equiv() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        assert!(check_equivalence_simple(&seq1, &seq2));
    }

    #[test]
    fn test_sequence_optimization() {
        let seq1 = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(5),
            },
        ];
        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        }];
        assert!(check_equivalence_simple(&seq1, &seq2));
    }
}
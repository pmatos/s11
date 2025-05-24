//! AArch64 instruction definitions for the IR

use crate::ir::types::{Operand, Register};
use std::fmt;

/// AArch64 instructions supported by the IR
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Instruction {
    // Data movement
    MovReg {
        rd: Register,
        rn: Register,
    },
    MovImm {
        rd: Register,
        imm: i64,
    },

    // Arithmetic
    Add {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Sub {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Logical
    And {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Orr {
        rd: Register,
        rn: Register,
        rm: Operand,
    },
    Eor {
        rd: Register,
        rn: Register,
        rm: Operand,
    },

    // Shifts
    Lsl {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Lsr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
    Asr {
        rd: Register,
        rn: Register,
        shift: Operand,
    },
}

impl Instruction {
    /// Get the destination register for this instruction
    #[allow(dead_code)]
    pub fn destination(&self) -> Register {
        match self {
            Instruction::MovReg { rd, .. }
            | Instruction::MovImm { rd, .. }
            | Instruction::Add { rd, .. }
            | Instruction::Sub { rd, .. }
            | Instruction::And { rd, .. }
            | Instruction::Orr { rd, .. }
            | Instruction::Eor { rd, .. }
            | Instruction::Lsl { rd, .. }
            | Instruction::Lsr { rd, .. }
            | Instruction::Asr { rd, .. } => *rd,
        }
    }

    /// Get all source registers used by this instruction
    #[allow(dead_code)]
    pub fn source_registers(&self) -> Vec<Register> {
        match self {
            Instruction::MovReg { rn, .. } => vec![*rn],
            Instruction::MovImm { .. } => vec![],
            Instruction::Add { rn, rm, .. }
            | Instruction::Sub { rn, rm, .. }
            | Instruction::And { rn, rm, .. }
            | Instruction::Orr { rn, rm, .. }
            | Instruction::Eor { rn, rm, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = rm {
                    regs.push(*r);
                }
                regs
            }
            Instruction::Lsl { rn, shift, .. }
            | Instruction::Lsr { rn, shift, .. }
            | Instruction::Asr { rn, shift, .. } => {
                let mut regs = vec![*rn];
                if let Operand::Register(r) = shift {
                    regs.push(*r);
                }
                regs
            }
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::MovReg { rd, rn } => write!(f, "mov {}, {}", rd, rn),
            Instruction::MovImm { rd, imm } => write!(f, "mov {}, #{}", rd, imm),
            Instruction::Add { rd, rn, rm } => write!(f, "add {}, {}, {}", rd, rn, rm),
            Instruction::Sub { rd, rn, rm } => write!(f, "sub {}, {}, {}", rd, rn, rm),
            Instruction::And { rd, rn, rm } => write!(f, "and {}, {}, {}", rd, rn, rm),
            Instruction::Orr { rd, rn, rm } => write!(f, "orr {}, {}, {}", rd, rn, rm),
            Instruction::Eor { rd, rn, rm } => write!(f, "eor {}, {}, {}", rd, rn, rm),
            Instruction::Lsl { rd, rn, shift } => write!(f, "lsl {}, {}, {}", rd, rn, shift),
            Instruction::Lsr { rd, rn, shift } => write!(f, "lsr {}, {}, {}", rd, rn, shift),
            Instruction::Asr { rd, rn, shift } => write!(f, "asr {}, {}, {}", rd, rn, shift),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_display() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(format!("{}", mov_reg), "mov x0, x1");

        let mov_imm = Instruction::MovImm {
            rd: Register::X2,
            imm: 42,
        };
        assert_eq!(format!("{}", mov_imm), "mov x2, #42");

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(format!("{}", add), "add x0, x1, x2");

        let eor = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        };
        assert_eq!(format!("{}", eor), "eor x0, x0, x0");
    }

    #[test]
    fn test_destination() {
        let instr = Instruction::Add {
            rd: Register::X5,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        };
        assert_eq!(instr.destination(), Register::X5);
    }

    #[test]
    fn test_source_registers() {
        let mov_reg = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        assert_eq!(mov_reg.source_registers(), vec![Register::X1]);

        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        assert_eq!(add.source_registers(), vec![Register::X1, Register::X2]);

        let add_imm = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };
        assert_eq!(add_imm.source_registers(), vec![Register::X1]);
    }
}

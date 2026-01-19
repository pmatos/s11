//! RISC-V ISA implementation
//!
//! This module provides the RISC-V (RV32I/RV64I) implementation of the ISA traits.

#![allow(dead_code)]

use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};
use std::fmt;
use std::hash::Hash;

use rand::Rng;

/// RISC-V register enumeration (x0-x31)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RiscVRegister {
    X0,  // zero register (always 0)
    X1,  // ra (return address)
    X2,  // sp (stack pointer)
    X3,  // gp (global pointer)
    X4,  // tp (thread pointer)
    X5,  // t0 (temporary)
    X6,  // t1
    X7,  // t2
    X8,  // s0/fp (saved/frame pointer)
    X9,  // s1 (saved)
    X10, // a0 (argument/return)
    X11, // a1
    X12, // a2
    X13, // a3
    X14, // a4
    X15, // a5
    X16, // a6
    X17, // a7
    X18, // s2 (saved)
    X19, // s3
    X20, // s4
    X21, // s5
    X22, // s6
    X23, // s7
    X24, // s8
    X25, // s9
    X26, // s10
    X27, // s11
    X28, // t3 (temporary)
    X29, // t4
    X30, // t5
    X31, // t6
}

impl RiscVRegister {
    pub fn index(&self) -> Option<u8> {
        Some(match self {
            RiscVRegister::X0 => 0,
            RiscVRegister::X1 => 1,
            RiscVRegister::X2 => 2,
            RiscVRegister::X3 => 3,
            RiscVRegister::X4 => 4,
            RiscVRegister::X5 => 5,
            RiscVRegister::X6 => 6,
            RiscVRegister::X7 => 7,
            RiscVRegister::X8 => 8,
            RiscVRegister::X9 => 9,
            RiscVRegister::X10 => 10,
            RiscVRegister::X11 => 11,
            RiscVRegister::X12 => 12,
            RiscVRegister::X13 => 13,
            RiscVRegister::X14 => 14,
            RiscVRegister::X15 => 15,
            RiscVRegister::X16 => 16,
            RiscVRegister::X17 => 17,
            RiscVRegister::X18 => 18,
            RiscVRegister::X19 => 19,
            RiscVRegister::X20 => 20,
            RiscVRegister::X21 => 21,
            RiscVRegister::X22 => 22,
            RiscVRegister::X23 => 23,
            RiscVRegister::X24 => 24,
            RiscVRegister::X25 => 25,
            RiscVRegister::X26 => 26,
            RiscVRegister::X27 => 27,
            RiscVRegister::X28 => 28,
            RiscVRegister::X29 => 29,
            RiscVRegister::X30 => 30,
            RiscVRegister::X31 => 31,
        })
    }

    pub fn from_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(RiscVRegister::X0),
            1 => Some(RiscVRegister::X1),
            2 => Some(RiscVRegister::X2),
            3 => Some(RiscVRegister::X3),
            4 => Some(RiscVRegister::X4),
            5 => Some(RiscVRegister::X5),
            6 => Some(RiscVRegister::X6),
            7 => Some(RiscVRegister::X7),
            8 => Some(RiscVRegister::X8),
            9 => Some(RiscVRegister::X9),
            10 => Some(RiscVRegister::X10),
            11 => Some(RiscVRegister::X11),
            12 => Some(RiscVRegister::X12),
            13 => Some(RiscVRegister::X13),
            14 => Some(RiscVRegister::X14),
            15 => Some(RiscVRegister::X15),
            16 => Some(RiscVRegister::X16),
            17 => Some(RiscVRegister::X17),
            18 => Some(RiscVRegister::X18),
            19 => Some(RiscVRegister::X19),
            20 => Some(RiscVRegister::X20),
            21 => Some(RiscVRegister::X21),
            22 => Some(RiscVRegister::X22),
            23 => Some(RiscVRegister::X23),
            24 => Some(RiscVRegister::X24),
            25 => Some(RiscVRegister::X25),
            26 => Some(RiscVRegister::X26),
            27 => Some(RiscVRegister::X27),
            28 => Some(RiscVRegister::X28),
            29 => Some(RiscVRegister::X29),
            30 => Some(RiscVRegister::X30),
            31 => Some(RiscVRegister::X31),
            _ => None,
        }
    }

    /// Get the ABI name for this register
    pub fn abi_name(&self) -> &'static str {
        match self {
            RiscVRegister::X0 => "zero",
            RiscVRegister::X1 => "ra",
            RiscVRegister::X2 => "sp",
            RiscVRegister::X3 => "gp",
            RiscVRegister::X4 => "tp",
            RiscVRegister::X5 => "t0",
            RiscVRegister::X6 => "t1",
            RiscVRegister::X7 => "t2",
            RiscVRegister::X8 => "s0",
            RiscVRegister::X9 => "s1",
            RiscVRegister::X10 => "a0",
            RiscVRegister::X11 => "a1",
            RiscVRegister::X12 => "a2",
            RiscVRegister::X13 => "a3",
            RiscVRegister::X14 => "a4",
            RiscVRegister::X15 => "a5",
            RiscVRegister::X16 => "a6",
            RiscVRegister::X17 => "a7",
            RiscVRegister::X18 => "s2",
            RiscVRegister::X19 => "s3",
            RiscVRegister::X20 => "s4",
            RiscVRegister::X21 => "s5",
            RiscVRegister::X22 => "s6",
            RiscVRegister::X23 => "s7",
            RiscVRegister::X24 => "s8",
            RiscVRegister::X25 => "s9",
            RiscVRegister::X26 => "s10",
            RiscVRegister::X27 => "s11",
            RiscVRegister::X28 => "t3",
            RiscVRegister::X29 => "t4",
            RiscVRegister::X30 => "t5",
            RiscVRegister::X31 => "t6",
        }
    }
}

impl fmt::Display for RiscVRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x{}", self.index().unwrap())
    }
}

impl RegisterType for RiscVRegister {
    fn index(&self) -> Option<u8> {
        RiscVRegister::index(self)
    }

    fn from_index(idx: u8) -> Option<Self> {
        RiscVRegister::from_index(idx)
    }

    fn is_zero_register(&self) -> bool {
        matches!(self, RiscVRegister::X0)
    }

    fn is_special(&self) -> bool {
        matches!(self, RiscVRegister::X0 | RiscVRegister::X2)
    }
}

/// RISC-V operand type
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RiscVOperand {
    Register(RiscVRegister),
    Immediate(i64),
}

impl fmt::Display for RiscVOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiscVOperand::Register(r) => write!(f, "{}", r),
            RiscVOperand::Immediate(i) => write!(f, "#{}", i),
        }
    }
}

impl OperandType for RiscVOperand {
    type Register = RiscVRegister;

    fn as_register(&self) -> Option<RiscVRegister> {
        match self {
            RiscVOperand::Register(r) => Some(*r),
            RiscVOperand::Immediate(_) => None,
        }
    }

    fn as_immediate(&self) -> Option<i64> {
        match self {
            RiscVOperand::Register(_) => None,
            RiscVOperand::Immediate(i) => Some(*i),
        }
    }

    fn from_register(reg: RiscVRegister) -> Self {
        RiscVOperand::Register(reg)
    }

    fn from_immediate(imm: i64) -> Self {
        RiscVOperand::Immediate(imm)
    }
}

/// RISC-V instruction set (RV32I/RV64I base)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RiscVInstruction {
    // Register-Register operations
    Add {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Sub {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    And {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Or {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Xor {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Sll {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Srl {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },
    Sra {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        rs2: RiscVRegister,
    },

    // Register-Immediate operations
    Addi {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        imm: i64,
    },
    Andi {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        imm: i64,
    },
    Ori {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        imm: i64,
    },
    Xori {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        imm: i64,
    },
    Slli {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        shamt: u8,
    },
    Srli {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        shamt: u8,
    },
    Srai {
        rd: RiscVRegister,
        rs1: RiscVRegister,
        shamt: u8,
    },

    // Load upper immediate
    Lui {
        rd: RiscVRegister,
        imm: i64,
    },
}

impl RiscVInstruction {
    pub fn destination(&self) -> RiscVRegister {
        match self {
            RiscVInstruction::Add { rd, .. }
            | RiscVInstruction::Sub { rd, .. }
            | RiscVInstruction::And { rd, .. }
            | RiscVInstruction::Or { rd, .. }
            | RiscVInstruction::Xor { rd, .. }
            | RiscVInstruction::Sll { rd, .. }
            | RiscVInstruction::Srl { rd, .. }
            | RiscVInstruction::Sra { rd, .. }
            | RiscVInstruction::Addi { rd, .. }
            | RiscVInstruction::Andi { rd, .. }
            | RiscVInstruction::Ori { rd, .. }
            | RiscVInstruction::Xori { rd, .. }
            | RiscVInstruction::Slli { rd, .. }
            | RiscVInstruction::Srli { rd, .. }
            | RiscVInstruction::Srai { rd, .. }
            | RiscVInstruction::Lui { rd, .. } => *rd,
        }
    }

    pub fn source_registers(&self) -> Vec<RiscVRegister> {
        match self {
            RiscVInstruction::Add { rs1, rs2, .. }
            | RiscVInstruction::Sub { rs1, rs2, .. }
            | RiscVInstruction::And { rs1, rs2, .. }
            | RiscVInstruction::Or { rs1, rs2, .. }
            | RiscVInstruction::Xor { rs1, rs2, .. }
            | RiscVInstruction::Sll { rs1, rs2, .. }
            | RiscVInstruction::Srl { rs1, rs2, .. }
            | RiscVInstruction::Sra { rs1, rs2, .. } => vec![*rs1, *rs2],

            RiscVInstruction::Addi { rs1, .. }
            | RiscVInstruction::Andi { rs1, .. }
            | RiscVInstruction::Ori { rs1, .. }
            | RiscVInstruction::Xori { rs1, .. }
            | RiscVInstruction::Slli { rs1, .. }
            | RiscVInstruction::Srli { rs1, .. }
            | RiscVInstruction::Srai { rs1, .. } => vec![*rs1],

            RiscVInstruction::Lui { .. } => vec![],
        }
    }
}

impl fmt::Display for RiscVInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiscVInstruction::Add { rd, rs1, rs2 } => write!(f, "add {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Sub { rd, rs1, rs2 } => write!(f, "sub {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::And { rd, rs1, rs2 } => write!(f, "and {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Or { rd, rs1, rs2 } => write!(f, "or {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Xor { rd, rs1, rs2 } => write!(f, "xor {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Sll { rd, rs1, rs2 } => write!(f, "sll {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Srl { rd, rs1, rs2 } => write!(f, "srl {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Sra { rd, rs1, rs2 } => write!(f, "sra {}, {}, {}", rd, rs1, rs2),
            RiscVInstruction::Addi { rd, rs1, imm } => write!(f, "addi {}, {}, {}", rd, rs1, imm),
            RiscVInstruction::Andi { rd, rs1, imm } => write!(f, "andi {}, {}, {}", rd, rs1, imm),
            RiscVInstruction::Ori { rd, rs1, imm } => write!(f, "ori {}, {}, {}", rd, rs1, imm),
            RiscVInstruction::Xori { rd, rs1, imm } => write!(f, "xori {}, {}, {}", rd, rs1, imm),
            RiscVInstruction::Slli { rd, rs1, shamt } => {
                write!(f, "slli {}, {}, {}", rd, rs1, shamt)
            }
            RiscVInstruction::Srli { rd, rs1, shamt } => {
                write!(f, "srli {}, {}, {}", rd, rs1, shamt)
            }
            RiscVInstruction::Srai { rd, rs1, shamt } => {
                write!(f, "srai {}, {}, {}", rd, rs1, shamt)
            }
            RiscVInstruction::Lui { rd, imm } => write!(f, "lui {}, {}", rd, imm),
        }
    }
}

impl InstructionType for RiscVInstruction {
    type Register = RiscVRegister;
    type Operand = RiscVOperand;

    fn destination(&self) -> Option<RiscVRegister> {
        Some(RiscVInstruction::destination(self))
    }

    fn source_registers(&self) -> Vec<RiscVRegister> {
        RiscVInstruction::source_registers(self)
    }

    fn opcode_id(&self) -> u8 {
        match self {
            RiscVInstruction::Add { .. } => 0,
            RiscVInstruction::Sub { .. } => 1,
            RiscVInstruction::And { .. } => 2,
            RiscVInstruction::Or { .. } => 3,
            RiscVInstruction::Xor { .. } => 4,
            RiscVInstruction::Sll { .. } => 5,
            RiscVInstruction::Srl { .. } => 6,
            RiscVInstruction::Sra { .. } => 7,
            RiscVInstruction::Addi { .. } => 8,
            RiscVInstruction::Andi { .. } => 9,
            RiscVInstruction::Ori { .. } => 10,
            RiscVInstruction::Xori { .. } => 11,
            RiscVInstruction::Slli { .. } => 12,
            RiscVInstruction::Srli { .. } => 13,
            RiscVInstruction::Srai { .. } => 14,
            RiscVInstruction::Lui { .. } => 15,
        }
    }

    fn mnemonic(&self) -> &'static str {
        match self {
            RiscVInstruction::Add { .. } => "add",
            RiscVInstruction::Sub { .. } => "sub",
            RiscVInstruction::And { .. } => "and",
            RiscVInstruction::Or { .. } => "or",
            RiscVInstruction::Xor { .. } => "xor",
            RiscVInstruction::Sll { .. } => "sll",
            RiscVInstruction::Srl { .. } => "srl",
            RiscVInstruction::Sra { .. } => "sra",
            RiscVInstruction::Addi { .. } => "addi",
            RiscVInstruction::Andi { .. } => "andi",
            RiscVInstruction::Ori { .. } => "ori",
            RiscVInstruction::Xori { .. } => "xori",
            RiscVInstruction::Slli { .. } => "slli",
            RiscVInstruction::Srli { .. } => "srli",
            RiscVInstruction::Srai { .. } => "srai",
            RiscVInstruction::Lui { .. } => "lui",
        }
    }

    fn has_side_effects(&self) -> bool {
        false
    }
}

/// RISC-V 32-bit ISA marker type
#[derive(Clone, Debug)]
pub struct RiscV32;

impl ISA for RiscV32 {
    type Register = RiscVRegister;
    type Operand = RiscVOperand;
    type Instruction = RiscVInstruction;

    fn name(&self) -> &'static str {
        "RISC-V 32"
    }

    fn register_count(&self) -> usize {
        32
    }

    fn register_width(&self) -> u32 {
        32
    }

    fn instruction_size(&self) -> Option<usize> {
        Some(4)
    }

    fn general_registers(&self) -> Vec<Self::Register> {
        (0..32).filter_map(RiscVRegister::from_index).collect()
    }

    fn zero_register(&self) -> Option<Self::Register> {
        Some(RiscVRegister::X0)
    }
}

/// RISC-V 64-bit ISA marker type
#[derive(Clone, Debug)]
pub struct RiscV64;

impl ISA for RiscV64 {
    type Register = RiscVRegister;
    type Operand = RiscVOperand;
    type Instruction = RiscVInstruction;

    fn name(&self) -> &'static str {
        "RISC-V 64"
    }

    fn register_count(&self) -> usize {
        32
    }

    fn register_width(&self) -> u32 {
        64
    }

    fn instruction_size(&self) -> Option<usize> {
        Some(4)
    }

    fn general_registers(&self) -> Vec<Self::Register> {
        (0..32).filter_map(RiscVRegister::from_index).collect()
    }

    fn zero_register(&self) -> Option<Self::Register> {
        Some(RiscVRegister::X0)
    }
}

/// RISC-V instruction generator
#[derive(Clone, Debug, Default)]
pub struct RiscVInstructionGenerator;

impl InstructionGenerator<RiscVInstruction> for RiscVInstructionGenerator {
    fn generate_all(
        &self,
        registers: &[RiscVRegister],
        immediates: &[i64],
    ) -> Vec<RiscVInstruction> {
        let mut instructions = Vec::new();

        // Register-Register operations
        for &rd in registers {
            for &rs1 in registers {
                for &rs2 in registers {
                    instructions.push(RiscVInstruction::Add { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Sub { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::And { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Or { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Xor { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Sll { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Srl { rd, rs1, rs2 });
                    instructions.push(RiscVInstruction::Sra { rd, rs1, rs2 });
                }
            }
        }

        // Register-Immediate operations
        for &rd in registers {
            for &rs1 in registers {
                for &imm in immediates {
                    instructions.push(RiscVInstruction::Addi { rd, rs1, imm });
                    instructions.push(RiscVInstruction::Andi { rd, rs1, imm });
                    instructions.push(RiscVInstruction::Ori { rd, rs1, imm });
                    instructions.push(RiscVInstruction::Xori { rd, rs1, imm });
                }
            }
        }

        // Shift immediate operations (shamt is 0-31 for RV32, 0-63 for RV64)
        let shift_amounts: Vec<u8> = vec![0, 1, 2, 4, 8, 16, 31];
        for &rd in registers {
            for &rs1 in registers {
                for &shamt in &shift_amounts {
                    instructions.push(RiscVInstruction::Slli { rd, rs1, shamt });
                    instructions.push(RiscVInstruction::Srli { rd, rs1, shamt });
                    instructions.push(RiscVInstruction::Srai { rd, rs1, shamt });
                }
            }
        }

        // LUI (load upper immediate)
        for &rd in registers {
            for &imm in immediates {
                instructions.push(RiscVInstruction::Lui { rd, imm });
            }
        }

        instructions
    }

    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
        registers: &[RiscVRegister],
        immediates: &[i64],
    ) -> RiscVInstruction {
        let opcode = rng.random_range(0..16);
        let rd = registers[rng.random_range(0..registers.len())];
        let rs1 = registers[rng.random_range(0..registers.len())];
        let rs2 = registers[rng.random_range(0..registers.len())];
        let imm = immediates[rng.random_range(0..immediates.len())];
        let shift_amounts: [u8; 7] = [0, 1, 2, 4, 8, 16, 31];
        let shamt = shift_amounts[rng.random_range(0..shift_amounts.len())];

        match opcode {
            0 => RiscVInstruction::Add { rd, rs1, rs2 },
            1 => RiscVInstruction::Sub { rd, rs1, rs2 },
            2 => RiscVInstruction::And { rd, rs1, rs2 },
            3 => RiscVInstruction::Or { rd, rs1, rs2 },
            4 => RiscVInstruction::Xor { rd, rs1, rs2 },
            5 => RiscVInstruction::Sll { rd, rs1, rs2 },
            6 => RiscVInstruction::Srl { rd, rs1, rs2 },
            7 => RiscVInstruction::Sra { rd, rs1, rs2 },
            8 => RiscVInstruction::Addi { rd, rs1, imm },
            9 => RiscVInstruction::Andi { rd, rs1, imm },
            10 => RiscVInstruction::Ori { rd, rs1, imm },
            11 => RiscVInstruction::Xori { rd, rs1, imm },
            12 => RiscVInstruction::Slli { rd, rs1, shamt },
            13 => RiscVInstruction::Srli { rd, rs1, shamt },
            14 => RiscVInstruction::Srai { rd, rs1, shamt },
            15 => RiscVInstruction::Lui { rd, imm },
            _ => unreachable!(),
        }
    }

    fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        instruction: &RiscVInstruction,
        registers: &[RiscVRegister],
        immediates: &[i64],
    ) -> RiscVInstruction {
        let strategy = rng.random_range(0..3);

        match strategy {
            0 => {
                // Change opcode - generate a completely new instruction
                self.generate_random(rng, registers, immediates)
            }
            1 => {
                // Change destination register
                let new_rd = registers[rng.random_range(0..registers.len())];
                match *instruction {
                    RiscVInstruction::Add { rs1, rs2, .. } => RiscVInstruction::Add {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Sub { rs1, rs2, .. } => RiscVInstruction::Sub {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::And { rs1, rs2, .. } => RiscVInstruction::And {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Or { rs1, rs2, .. } => RiscVInstruction::Or {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Xor { rs1, rs2, .. } => RiscVInstruction::Xor {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Sll { rs1, rs2, .. } => RiscVInstruction::Sll {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Srl { rs1, rs2, .. } => RiscVInstruction::Srl {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Sra { rs1, rs2, .. } => RiscVInstruction::Sra {
                        rd: new_rd,
                        rs1,
                        rs2,
                    },
                    RiscVInstruction::Addi { rs1, imm, .. } => RiscVInstruction::Addi {
                        rd: new_rd,
                        rs1,
                        imm,
                    },
                    RiscVInstruction::Andi { rs1, imm, .. } => RiscVInstruction::Andi {
                        rd: new_rd,
                        rs1,
                        imm,
                    },
                    RiscVInstruction::Ori { rs1, imm, .. } => RiscVInstruction::Ori {
                        rd: new_rd,
                        rs1,
                        imm,
                    },
                    RiscVInstruction::Xori { rs1, imm, .. } => RiscVInstruction::Xori {
                        rd: new_rd,
                        rs1,
                        imm,
                    },
                    RiscVInstruction::Slli { rs1, shamt, .. } => RiscVInstruction::Slli {
                        rd: new_rd,
                        rs1,
                        shamt,
                    },
                    RiscVInstruction::Srli { rs1, shamt, .. } => RiscVInstruction::Srli {
                        rd: new_rd,
                        rs1,
                        shamt,
                    },
                    RiscVInstruction::Srai { rs1, shamt, .. } => RiscVInstruction::Srai {
                        rd: new_rd,
                        rs1,
                        shamt,
                    },
                    RiscVInstruction::Lui { imm, .. } => RiscVInstruction::Lui { rd: new_rd, imm },
                }
            }
            2 => {
                // Change source operand
                let new_rs1 = registers[rng.random_range(0..registers.len())];
                let new_rs2 = registers[rng.random_range(0..registers.len())];
                let new_imm = immediates[rng.random_range(0..immediates.len())];
                let shift_amounts: [u8; 7] = [0, 1, 2, 4, 8, 16, 31];
                let new_shamt = shift_amounts[rng.random_range(0..shift_amounts.len())];

                match *instruction {
                    RiscVInstruction::Add { rd, .. } => RiscVInstruction::Add {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Sub { rd, .. } => RiscVInstruction::Sub {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::And { rd, .. } => RiscVInstruction::And {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Or { rd, .. } => RiscVInstruction::Or {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Xor { rd, .. } => RiscVInstruction::Xor {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Sll { rd, .. } => RiscVInstruction::Sll {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Srl { rd, .. } => RiscVInstruction::Srl {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Sra { rd, .. } => RiscVInstruction::Sra {
                        rd,
                        rs1: new_rs1,
                        rs2: new_rs2,
                    },
                    RiscVInstruction::Addi { rd, .. } => RiscVInstruction::Addi {
                        rd,
                        rs1: new_rs1,
                        imm: new_imm,
                    },
                    RiscVInstruction::Andi { rd, .. } => RiscVInstruction::Andi {
                        rd,
                        rs1: new_rs1,
                        imm: new_imm,
                    },
                    RiscVInstruction::Ori { rd, .. } => RiscVInstruction::Ori {
                        rd,
                        rs1: new_rs1,
                        imm: new_imm,
                    },
                    RiscVInstruction::Xori { rd, .. } => RiscVInstruction::Xori {
                        rd,
                        rs1: new_rs1,
                        imm: new_imm,
                    },
                    RiscVInstruction::Slli { rd, .. } => RiscVInstruction::Slli {
                        rd,
                        rs1: new_rs1,
                        shamt: new_shamt,
                    },
                    RiscVInstruction::Srli { rd, .. } => RiscVInstruction::Srli {
                        rd,
                        rs1: new_rs1,
                        shamt: new_shamt,
                    },
                    RiscVInstruction::Srai { rd, .. } => RiscVInstruction::Srai {
                        rd,
                        rs1: new_rs1,
                        shamt: new_shamt,
                    },
                    RiscVInstruction::Lui { rd, .. } => RiscVInstruction::Lui { rd, imm: new_imm },
                }
            }
            _ => unreachable!(),
        }
    }

    fn opcode_count(&self) -> u8 {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::InstructionType as _;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_riscv32_isa_metadata() {
        let isa = RiscV32;
        assert_eq!(isa.name(), "RISC-V 32");
        assert_eq!(isa.register_count(), 32);
        assert_eq!(isa.register_width(), 32);
        assert_eq!(isa.instruction_size(), Some(4));
    }

    #[test]
    fn test_riscv64_isa_metadata() {
        let isa = RiscV64;
        assert_eq!(isa.name(), "RISC-V 64");
        assert_eq!(isa.register_count(), 32);
        assert_eq!(isa.register_width(), 64);
        assert_eq!(isa.instruction_size(), Some(4));
    }

    #[test]
    fn test_register_traits() {
        assert!(RiscVRegister::X0.is_zero_register());
        assert!(!RiscVRegister::X1.is_zero_register());

        assert!(RiscVRegister::X0.is_special()); // zero register
        assert!(RiscVRegister::X2.is_special()); // sp
        assert!(!RiscVRegister::X5.is_special());

        assert_eq!(
            <RiscVRegister as RegisterType>::from_index(0),
            Some(RiscVRegister::X0)
        );
        assert_eq!(
            <RiscVRegister as RegisterType>::from_index(31),
            Some(RiscVRegister::X31)
        );
        assert_eq!(<RiscVRegister as RegisterType>::from_index(32), None);
    }

    #[test]
    fn test_register_abi_names() {
        assert_eq!(RiscVRegister::X0.abi_name(), "zero");
        assert_eq!(RiscVRegister::X1.abi_name(), "ra");
        assert_eq!(RiscVRegister::X2.abi_name(), "sp");
        assert_eq!(RiscVRegister::X10.abi_name(), "a0");
        assert_eq!(RiscVRegister::X31.abi_name(), "t6");
    }

    #[test]
    fn test_operand_traits() {
        let reg_op = <RiscVOperand as OperandType>::from_register(RiscVRegister::X5);
        assert_eq!(reg_op.as_register(), Some(RiscVRegister::X5));
        assert_eq!(reg_op.as_immediate(), None);
        assert!(reg_op.is_register());
        assert!(!reg_op.is_immediate());

        let imm_op = <RiscVOperand as OperandType>::from_immediate(42);
        assert_eq!(imm_op.as_register(), None);
        assert_eq!(imm_op.as_immediate(), Some(42));
        assert!(!imm_op.is_register());
        assert!(imm_op.is_immediate());
    }

    #[test]
    fn test_instruction_traits() {
        let add = RiscVInstruction::Add {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            rs2: RiscVRegister::X12,
        };

        assert_eq!(add.destination(), RiscVRegister::X10);
        assert_eq!(
            add.source_registers(),
            vec![RiscVRegister::X11, RiscVRegister::X12]
        );
        assert_eq!(add.opcode_id(), 0);
        assert_eq!(add.mnemonic(), "add");
        assert!(!add.has_side_effects());
    }

    #[test]
    fn test_instruction_display() {
        let add = RiscVInstruction::Add {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            rs2: RiscVRegister::X12,
        };
        assert_eq!(format!("{}", add), "add x10, x11, x12");

        let addi = RiscVInstruction::Addi {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            imm: 42,
        };
        assert_eq!(format!("{}", addi), "addi x10, x11, 42");

        let lui = RiscVInstruction::Lui {
            rd: RiscVRegister::X10,
            imm: 0x12345,
        };
        assert_eq!(format!("{}", lui), "lui x10, 74565");
    }

    #[test]
    fn test_instruction_generator() {
        let generator = RiscVInstructionGenerator;
        let regs = vec![RiscVRegister::X10, RiscVRegister::X11];
        let imms = vec![0, 1];

        let instructions = generator.generate_all(&regs, &imms);
        assert!(!instructions.is_empty());

        // Verify we have various instruction types
        let has_add = instructions
            .iter()
            .any(|i| matches!(i, RiscVInstruction::Add { .. }));
        assert!(has_add);

        let has_addi = instructions
            .iter()
            .any(|i| matches!(i, RiscVInstruction::Addi { .. }));
        assert!(has_addi);

        let has_lui = instructions
            .iter()
            .any(|i| matches!(i, RiscVInstruction::Lui { .. }));
        assert!(has_lui);
    }

    #[test]
    fn test_random_instruction_generation() {
        let generator = RiscVInstructionGenerator;
        let regs = vec![RiscVRegister::X10, RiscVRegister::X11, RiscVRegister::X12];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for _ in 0..100 {
            let instr = generator.generate_random(&mut rng, &regs, &imms);
            assert!(instr.opcode_id() < 16);
        }
    }

    #[test]
    fn test_instruction_mutation() {
        let generator = RiscVInstructionGenerator;
        let regs = vec![RiscVRegister::X10, RiscVRegister::X11, RiscVRegister::X12];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let original = RiscVInstruction::Add {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            rs2: RiscVRegister::X12,
        };

        for _ in 0..100 {
            let mutated = generator.mutate(&mut rng, &original, &regs, &imms);
            assert!(mutated.opcode_id() < 16);
        }
    }

    #[test]
    fn test_lui_source_registers_empty() {
        let lui = RiscVInstruction::Lui {
            rd: RiscVRegister::X10,
            imm: 0x12345,
        };
        assert!(lui.source_registers().is_empty());
    }

    #[test]
    fn test_immediate_instruction_source_registers() {
        let addi = RiscVInstruction::Addi {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            imm: 42,
        };
        assert_eq!(addi.source_registers(), vec![RiscVRegister::X11]);

        let slli = RiscVInstruction::Slli {
            rd: RiscVRegister::X10,
            rs1: RiscVRegister::X11,
            shamt: 4,
        };
        assert_eq!(slli.source_registers(), vec![RiscVRegister::X11]);
    }
}

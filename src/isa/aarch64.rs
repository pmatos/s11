//! AArch64 ISA implementation
//!
//! This module provides the AArch64-specific implementation of the ISA traits.

use crate::ir::{Instruction, Operand, Register};
use crate::isa::traits::{ISA, InstructionGenerator, InstructionType, OperandType, RegisterType};

use rand::Rng;

/// AArch64 ISA marker type
#[derive(Clone, Debug)]
pub struct AArch64;

impl ISA for AArch64 {
    type Register = Register;
    type Operand = Operand;
    type Instruction = Instruction;

    fn name(&self) -> &'static str {
        "AArch64"
    }

    fn register_count(&self) -> usize {
        31 // X0-X30, plus XZR
    }

    fn register_width(&self) -> u32 {
        64
    }

    fn instruction_size(&self) -> Option<usize> {
        Some(4) // All AArch64 instructions are 4 bytes
    }

    fn general_registers(&self) -> Vec<Self::Register> {
        (0..31).filter_map(Register::from_index).collect()
    }

    fn zero_register(&self) -> Option<Self::Register> {
        Some(Register::XZR)
    }
}

impl RegisterType for Register {
    fn index(&self) -> Option<u8> {
        Register::index(self)
    }

    fn from_index(idx: u8) -> Option<Self> {
        Register::from_index(idx)
    }

    fn is_zero_register(&self) -> bool {
        matches!(self, Register::XZR)
    }

    fn is_special(&self) -> bool {
        matches!(self, Register::SP | Register::XZR)
    }
}

impl OperandType for Operand {
    type Register = Register;

    fn as_register(&self) -> Option<Register> {
        match self {
            Operand::Register(r) => Some(*r),
            Operand::Immediate(_) => None,
        }
    }

    fn as_immediate(&self) -> Option<i64> {
        match self {
            Operand::Register(_) => None,
            Operand::Immediate(i) => Some(*i),
        }
    }

    fn from_register(reg: Register) -> Self {
        Operand::Register(reg)
    }

    fn from_immediate(imm: i64) -> Self {
        Operand::Immediate(imm)
    }
}

impl InstructionType for Instruction {
    type Register = Register;
    type Operand = Operand;

    fn destination(&self) -> Option<Register> {
        Instruction::destination(self)
    }

    fn source_registers(&self) -> Vec<Register> {
        Instruction::source_registers(self)
    }

    fn opcode_id(&self) -> u8 {
        match self {
            Instruction::MovReg { .. } => 0,
            Instruction::MovImm { .. } => 1,
            Instruction::Add { .. } => 2,
            Instruction::Sub { .. } => 3,
            Instruction::And { .. } => 4,
            Instruction::Orr { .. } => 5,
            Instruction::Eor { .. } => 6,
            Instruction::Lsl { .. } => 7,
            Instruction::Lsr { .. } => 8,
            Instruction::Asr { .. } => 9,
            Instruction::Mul { .. } => 10,
            Instruction::Sdiv { .. } => 11,
            Instruction::Udiv { .. } => 12,
            Instruction::Cmp { .. } => 13,
            Instruction::Cmn { .. } => 14,
            Instruction::Tst { .. } => 15,
            Instruction::Csel { .. } => 16,
            Instruction::Csinc { .. } => 17,
            Instruction::Csinv { .. } => 18,
            Instruction::Csneg { .. } => 19,
        }
    }

    fn mnemonic(&self) -> &'static str {
        match self {
            Instruction::MovReg { .. } | Instruction::MovImm { .. } => "mov",
            Instruction::Add { .. } => "add",
            Instruction::Sub { .. } => "sub",
            Instruction::And { .. } => "and",
            Instruction::Orr { .. } => "orr",
            Instruction::Eor { .. } => "eor",
            Instruction::Lsl { .. } => "lsl",
            Instruction::Lsr { .. } => "lsr",
            Instruction::Asr { .. } => "asr",
            Instruction::Mul { .. } => "mul",
            Instruction::Sdiv { .. } => "sdiv",
            Instruction::Udiv { .. } => "udiv",
            Instruction::Cmp { .. } => "cmp",
            Instruction::Cmn { .. } => "cmn",
            Instruction::Tst { .. } => "tst",
            Instruction::Csel { .. } => "csel",
            Instruction::Csinc { .. } => "csinc",
            Instruction::Csinv { .. } => "csinv",
            Instruction::Csneg { .. } => "csneg",
        }
    }

    fn has_side_effects(&self) -> bool {
        false // Current instructions have no side effects
    }
}

/// AArch64 instruction generator
#[derive(Clone, Debug, Default)]
pub struct AArch64InstructionGenerator;

impl InstructionGenerator<Instruction> for AArch64InstructionGenerator {
    fn generate_all(&self, registers: &[Register], immediates: &[i64]) -> Vec<Instruction> {
        let mut instructions = Vec::new();

        // MovReg: rd <- rn
        for &rd in registers {
            for &rn in registers {
                instructions.push(Instruction::MovReg { rd, rn });
            }
        }

        // MovImm: rd <- imm
        for &rd in registers {
            for &imm in immediates {
                instructions.push(Instruction::MovImm { rd, imm });
            }
        }

        // Binary register-register operations: Add, Sub, And, Orr, Eor
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    let rm_op = Operand::Register(rm);
                    instructions.push(Instruction::Add { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Sub { rd, rn, rm: rm_op });
                    instructions.push(Instruction::And { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Orr { rd, rn, rm: rm_op });
                    instructions.push(Instruction::Eor { rd, rn, rm: rm_op });
                }
            }
        }

        // Binary register-immediate operations: Add, Sub
        for &rd in registers {
            for &rn in registers {
                for &imm in immediates {
                    let imm_op = Operand::Immediate(imm);
                    instructions.push(Instruction::Add { rd, rn, rm: imm_op });
                    instructions.push(Instruction::Sub { rd, rn, rm: imm_op });
                }
            }
        }

        // Shift operations
        let shift_amounts: Vec<i64> = vec![0, 1, 2, 4, 8, 16, 32];
        for &rd in registers {
            for &rn in registers {
                // Register shifts
                for &rm in registers {
                    let rm_op = Operand::Register(rm);
                    instructions.push(Instruction::Lsl {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                    instructions.push(Instruction::Lsr {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                    instructions.push(Instruction::Asr {
                        rd,
                        rn,
                        shift: rm_op,
                    });
                }
                // Immediate shifts
                for &shift in &shift_amounts {
                    let shift_op = Operand::Immediate(shift);
                    instructions.push(Instruction::Lsl {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                    instructions.push(Instruction::Lsr {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                    instructions.push(Instruction::Asr {
                        rd,
                        rn,
                        shift: shift_op,
                    });
                }
            }
        }

        // Multiplication and division (register-register only)
        for &rd in registers {
            for &rn in registers {
                for &rm in registers {
                    instructions.push(Instruction::Mul { rd, rn, rm });
                    instructions.push(Instruction::Sdiv { rd, rn, rm });
                    instructions.push(Instruction::Udiv { rd, rn, rm });
                }
            }
        }

        instructions
    }

    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
        registers: &[Register],
        immediates: &[i64],
    ) -> Instruction {
        let opcode = rng.random_range(0..13);
        let rd = registers[rng.random_range(0..registers.len())];
        let rn = registers[rng.random_range(0..registers.len())];

        match opcode {
            0 => Instruction::MovReg { rd, rn },
            1 => {
                let imm = immediates[rng.random_range(0..immediates.len())];
                Instruction::MovImm { rd, imm }
            }
            2..=6 => {
                let use_imm = rng.random_bool(0.5);
                let rm = if use_imm && (opcode == 2 || opcode == 3) {
                    Operand::Immediate(immediates[rng.random_range(0..immediates.len())])
                } else {
                    Operand::Register(registers[rng.random_range(0..registers.len())])
                };
                match opcode {
                    2 => Instruction::Add { rd, rn, rm },
                    3 => Instruction::Sub { rd, rn, rm },
                    4 => Instruction::And { rd, rn, rm },
                    5 => Instruction::Orr { rd, rn, rm },
                    6 => Instruction::Eor { rd, rn, rm },
                    _ => unreachable!(),
                }
            }
            7..=9 => {
                let use_imm = rng.random_bool(0.5);
                let shift = if use_imm {
                    let amounts = [0, 1, 2, 4, 8, 16, 32];
                    Operand::Immediate(amounts[rng.random_range(0..amounts.len())])
                } else {
                    Operand::Register(registers[rng.random_range(0..registers.len())])
                };
                match opcode {
                    7 => Instruction::Lsl { rd, rn, shift },
                    8 => Instruction::Lsr { rd, rn, shift },
                    9 => Instruction::Asr { rd, rn, shift },
                    _ => unreachable!(),
                }
            }
            10..=12 => {
                let rm = registers[rng.random_range(0..registers.len())];
                match opcode {
                    10 => Instruction::Mul { rd, rn, rm },
                    11 => Instruction::Sdiv { rd, rn, rm },
                    12 => Instruction::Udiv { rd, rn, rm },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        instruction: &Instruction,
        registers: &[Register],
        immediates: &[i64],
    ) -> Instruction {
        // Random mutation strategy: change opcode, change operand, or change register
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
                    Instruction::MovReg { rn, .. } => Instruction::MovReg { rd: new_rd, rn },
                    Instruction::MovImm { imm, .. } => Instruction::MovImm { rd: new_rd, imm },
                    Instruction::Add { rn, rm, .. } => Instruction::Add { rd: new_rd, rn, rm },
                    Instruction::Sub { rn, rm, .. } => Instruction::Sub { rd: new_rd, rn, rm },
                    Instruction::And { rn, rm, .. } => Instruction::And { rd: new_rd, rn, rm },
                    Instruction::Orr { rn, rm, .. } => Instruction::Orr { rd: new_rd, rn, rm },
                    Instruction::Eor { rn, rm, .. } => Instruction::Eor { rd: new_rd, rn, rm },
                    Instruction::Lsl { rn, shift, .. } => Instruction::Lsl {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Lsr { rn, shift, .. } => Instruction::Lsr {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Asr { rn, shift, .. } => Instruction::Asr {
                        rd: new_rd,
                        rn,
                        shift,
                    },
                    Instruction::Mul { rn, rm, .. } => Instruction::Mul { rd: new_rd, rn, rm },
                    Instruction::Sdiv { rn, rm, .. } => Instruction::Sdiv { rd: new_rd, rn, rm },
                    Instruction::Udiv { rn, rm, .. } => Instruction::Udiv { rd: new_rd, rn, rm },
                    // Comparison instructions have no destination - generate random instead
                    Instruction::Cmp { .. } | Instruction::Cmn { .. } | Instruction::Tst { .. } => {
                        self.generate_random(rng, registers, immediates)
                    }
                    // Conditional select instructions
                    Instruction::Csel { rn, rm, cond, .. } => Instruction::Csel {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csinc { rn, rm, cond, .. } => Instruction::Csinc {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csinv { rn, rm, cond, .. } => Instruction::Csinv {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                    Instruction::Csneg { rn, rm, cond, .. } => Instruction::Csneg {
                        rd: new_rd,
                        rn,
                        rm,
                        cond,
                    },
                }
            }
            2 => {
                // Change source operand
                match *instruction {
                    Instruction::MovReg { rd, .. } => {
                        let new_rn = registers[rng.random_range(0..registers.len())];
                        Instruction::MovReg { rd, rn: new_rn }
                    }
                    Instruction::MovImm { rd, .. } => {
                        let new_imm = immediates[rng.random_range(0..immediates.len())];
                        Instruction::MovImm { rd, imm: new_imm }
                    }
                    Instruction::Add { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates);
                        Instruction::Add { rd, rn, rm: new_rm }
                    }
                    Instruction::Sub { rd, rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates);
                        Instruction::Sub { rd, rn, rm: new_rm }
                    }
                    Instruction::And { rd, rn, rm: _ } => {
                        // AND doesn't support immediates, so only change register
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::And { rd, rn, rm: new_rm }
                    }
                    Instruction::Orr { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Orr { rd, rn, rm: new_rm }
                    }
                    Instruction::Eor { rd, rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Eor { rd, rn, rm: new_rm }
                    }
                    Instruction::Lsl { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Lsl {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Lsr { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Lsr {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Asr { rd, rn, shift } => {
                        let new_shift = mutate_shift_operand(rng, shift, registers);
                        Instruction::Asr {
                            rd,
                            rn,
                            shift: new_shift,
                        }
                    }
                    Instruction::Mul { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Mul { rd, rn, rm: new_rm }
                    }
                    Instruction::Sdiv { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Sdiv { rd, rn, rm: new_rm }
                    }
                    Instruction::Udiv { rd, rn, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Udiv { rd, rn, rm: new_rm }
                    }
                    // Comparison instructions - change operand
                    Instruction::Cmp { rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates);
                        Instruction::Cmp { rn, rm: new_rm }
                    }
                    Instruction::Cmn { rn, rm } => {
                        let new_rm = mutate_operand(rng, rm, registers, immediates);
                        Instruction::Cmn { rn, rm: new_rm }
                    }
                    Instruction::Tst { rn, rm: _ } => {
                        let new_rm =
                            Operand::Register(registers[rng.random_range(0..registers.len())]);
                        Instruction::Tst { rn, rm: new_rm }
                    }
                    // Conditional select - change operands
                    Instruction::Csel { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csel {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csinc { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csinc {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csinv { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csinv {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                    Instruction::Csneg { rd, rn, cond, .. } => {
                        let new_rm = registers[rng.random_range(0..registers.len())];
                        Instruction::Csneg {
                            rd,
                            rn,
                            rm: new_rm,
                            cond,
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn opcode_count(&self) -> u8 {
        20 // MovReg, MovImm, Add, Sub, And, Orr, Eor, Lsl, Lsr, Asr, Mul, Sdiv, Udiv, Cmp, Cmn, Tst, Csel, Csinc, Csinv, Csneg
    }
}

fn mutate_operand<R: Rng>(
    rng: &mut R,
    operand: Operand,
    registers: &[Register],
    immediates: &[i64],
) -> Operand {
    match operand {
        Operand::Register(_) => {
            if rng.random_bool(0.7) {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            } else {
                Operand::Immediate(immediates[rng.random_range(0..immediates.len())])
            }
        }
        Operand::Immediate(_) => {
            if rng.random_bool(0.7) {
                Operand::Immediate(immediates[rng.random_range(0..immediates.len())])
            } else {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            }
        }
    }
}

fn mutate_shift_operand<R: Rng>(rng: &mut R, operand: Operand, registers: &[Register]) -> Operand {
    let shift_amounts: [i64; 7] = [0, 1, 2, 4, 8, 16, 32];
    match operand {
        Operand::Register(_) => {
            if rng.random_bool(0.5) {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            } else {
                Operand::Immediate(shift_amounts[rng.random_range(0..shift_amounts.len())])
            }
        }
        Operand::Immediate(_) => {
            if rng.random_bool(0.5) {
                Operand::Immediate(shift_amounts[rng.random_range(0..shift_amounts.len())])
            } else {
                Operand::Register(registers[rng.random_range(0..registers.len())])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::InstructionType as _;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_aarch64_isa_metadata() {
        let isa = AArch64;
        assert_eq!(isa.name(), "AArch64");
        assert_eq!(isa.register_count(), 31);
        assert_eq!(isa.register_width(), 64);
        assert_eq!(isa.instruction_size(), Some(4));
    }

    #[test]
    fn test_register_traits() {
        assert!(Register::XZR.is_zero_register());
        assert!(!Register::X0.is_zero_register());

        assert!(Register::SP.is_special());
        assert!(Register::XZR.is_special());
        assert!(!Register::X0.is_special());

        assert_eq!(
            <Register as RegisterType>::from_index(0),
            Some(Register::X0)
        );
        assert_eq!(
            <Register as RegisterType>::from_index(30),
            Some(Register::X30)
        );
        assert_eq!(
            <Register as RegisterType>::from_index(31),
            Some(Register::XZR)
        );
        assert_eq!(<Register as RegisterType>::from_index(32), None);
    }

    #[test]
    fn test_operand_traits() {
        let reg_op = <Operand as OperandType>::from_register(Register::X5);
        assert_eq!(reg_op.as_register(), Some(Register::X5));
        assert_eq!(reg_op.as_immediate(), None);
        assert!(reg_op.is_register());
        assert!(!reg_op.is_immediate());

        let imm_op = <Operand as OperandType>::from_immediate(42);
        assert_eq!(imm_op.as_register(), None);
        assert_eq!(imm_op.as_immediate(), Some(42));
        assert!(!imm_op.is_register());
        assert!(imm_op.is_immediate());
    }

    #[test]
    fn test_instruction_traits() {
        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };

        assert_eq!(add.destination(), Some(Register::X0));
        assert_eq!(add.source_registers(), vec![Register::X1, Register::X2]);
        assert_eq!(add.opcode_id(), 2);
        assert_eq!(add.mnemonic(), "add");
        assert!(!add.has_side_effects());
    }

    #[test]
    fn test_instruction_generator() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1];
        let imms = vec![0, 1];

        let instructions = generator.generate_all(&regs, &imms);
        assert!(!instructions.is_empty());

        // Verify we have MovReg instructions
        let has_mov_reg = instructions
            .iter()
            .any(|i| matches!(i, Instruction::MovReg { .. }));
        assert!(has_mov_reg);

        // Verify we have Add instructions
        let has_add = instructions
            .iter()
            .any(|i| matches!(i, Instruction::Add { .. }));
        assert!(has_add);
    }

    #[test]
    fn test_random_instruction_generation() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Generate several random instructions and verify they're valid
        for _ in 0..100 {
            let instr = generator.generate_random(&mut rng, &regs, &imms);
            // Just verify it doesn't panic and produces valid instructions
            assert!(instr.opcode_id() < 13);
        }
    }

    #[test]
    fn test_instruction_mutation() {
        let generator = AArch64InstructionGenerator;
        let regs = vec![Register::X0, Register::X1, Register::X2];
        let imms = vec![-1, 0, 1, 2];

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let original = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };

        // Mutate several times and verify we get valid instructions
        for _ in 0..100 {
            let mutated = generator.mutate(&mut rng, &original, &regs, &imms);
            assert!(mutated.opcode_id() < 13);
        }
    }
}

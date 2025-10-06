use crate::ir::{Instruction, Operand, Register};
use dynasmrt::{DynasmApi, dynasm};

pub struct AArch64Assembler {
    ops: dynasmrt::aarch64::Assembler,
}

impl AArch64Assembler {
    pub fn new() -> Self {
        Self {
            ops: dynasmrt::aarch64::Assembler::new().unwrap(),
        }
    }

    pub fn assemble_instructions(
        &mut self,
        instructions: &[Instruction],
    ) -> Result<Vec<u8>, String> {
        // Create a new assembler for this operation
        let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();

        for instr in instructions {
            self.encode_instruction_on(&mut ops, instr)?;
        }

        Ok(ops.finalize().unwrap().to_vec())
    }

    fn encode_instruction_on(
        &self,
        ops: &mut dynasmrt::aarch64::Assembler,
        instr: &Instruction,
    ) -> Result<(), String> {
        match instr {
            Instruction::MovReg { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mov X(rd_reg), X(rn_reg)
                );
                Ok(())
            }
            Instruction::MovImm { rd, imm } => {
                let rd_reg = register_to_dynasm(*rd)?;

                if *imm < 0 || *imm > 0xFFFF {
                    return Err(format!("Immediate {} out of range for MOV", imm));
                }

                dynasm!(ops
                    ; .arch aarch64
                    ; mov X(rd_reg), *imm as u64
                );
                Ok(())
            }
            Instruction::Add { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; add X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADD", imm));
                        }
                        // Use XSP register type for ADD immediate (allows SP addressing)
                        dynasm!(ops
                            ; .arch aarch64
                            ; add XSP(rd_reg), XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                }
            }
            _ => Err(format!("Instruction encoding not implemented: {}", instr)),
        }
    }
}

fn register_to_dynasm(reg: Register) -> Result<u32, String> {
    match reg {
        Register::X0 => Ok(0),
        Register::X1 => Ok(1),
        Register::X2 => Ok(2),
        Register::X3 => Ok(3),
        Register::X4 => Ok(4),
        Register::X5 => Ok(5),
        Register::X6 => Ok(6),
        Register::X7 => Ok(7),
        Register::X8 => Ok(8),
        Register::X9 => Ok(9),
        Register::X10 => Ok(10),
        Register::X11 => Ok(11),
        Register::X12 => Ok(12),
        Register::X13 => Ok(13),
        Register::X14 => Ok(14),
        Register::X15 => Ok(15),
        Register::X16 => Ok(16),
        Register::X17 => Ok(17),
        Register::X18 => Ok(18),
        Register::X19 => Ok(19),
        Register::X20 => Ok(20),
        Register::X21 => Ok(21),
        Register::X22 => Ok(22),
        Register::X23 => Ok(23),
        Register::X24 => Ok(24),
        Register::X25 => Ok(25),
        Register::X26 => Ok(26),
        Register::X27 => Ok(27),
        Register::X28 => Ok(28),
        Register::X29 => Ok(29),
        Register::X30 => Ok(30),
        Register::XZR => Ok(31),
        Register::SP => Err("SP register encoding not supported".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mov_reg_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 4); // One 32-bit instruction
        assert_ne!(bytes, [0, 0, 0, 0]); // Should not be empty
    }

    #[test]
    fn test_mov_imm_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_add_reg_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_add_imm_encoding() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        }];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_invalid_immediate() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0x10000, // Too large
        }];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_instructions() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 42,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let result = assembler.assemble_instructions(&instructions);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 8); // Two 32-bit instructions
    }
}

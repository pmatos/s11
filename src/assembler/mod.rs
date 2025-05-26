use crate::ir::{Instruction, Operand, Register};

pub struct AArch64Assembler {
    instructions: Vec<u32>,
}

impl AArch64Assembler {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
        }
    }

    pub fn assemble_instructions(
        &mut self,
        instructions: &[Instruction],
    ) -> Result<Vec<u8>, String> {
        self.instructions.clear();

        for instr in instructions {
            let encoded = self.encode_instruction(instr)?;
            self.instructions.push(encoded);
        }

        // Convert u32 instructions to bytes (little-endian)
        let mut bytes = Vec::new();
        for instr in &self.instructions {
            bytes.extend_from_slice(&instr.to_le_bytes());
        }

        Ok(bytes)
    }

    fn encode_instruction(&self, instr: &Instruction) -> Result<u32, String> {
        match instr {
            Instruction::MovReg { rd, rn } => {
                // MOV (register) - actually ORR Wd, WZR, Wm
                // Encoding: sf|01|01010|shift|0|Rm|imm6|Rn|Rd
                // For 64-bit: 1|01|01010|00|0|Rm|000000|11111|Rd
                let rd_bits = register_to_bits(*rd)?;
                let rn_bits = register_to_bits(*rn)?;

                // MOV Xd, Xn is encoded as ORR Xd, XZR, Xn
                let encoding = 0xAA000000u32 // Base ORR (shifted register) encoding
                    | (rn_bits << 16)        // Rm field (source)
                    | (0x1F << 5)            // Rn field (XZR)
                    | rd_bits; // Rd field

                Ok(encoding)
            }
            Instruction::MovImm { rd, imm } => {
                // MOV (wide immediate) - MOVZ with LSL #0
                // Encoding: sf|10|100101|hw|imm16|Rd
                let rd_bits = register_to_bits(*rd)?;

                if *imm < 0 || *imm > 0xFFFF {
                    return Err(format!("Immediate {} out of range for simple MOV", imm));
                }

                let encoding = 0xD2800000u32  // MOVZ 64-bit, LSL #0
                    | ((*imm as u32 & 0xFFFF) << 5)  // imm16 field
                    | rd_bits; // Rd field

                Ok(encoding)
            }
            Instruction::Add { rd, rn, rm } => {
                let rd_bits = register_to_bits(*rd)?;
                let rn_bits = register_to_bits(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        // ADD (shifted register) - no shift
                        // Encoding: sf|00|01011|shift|0|Rm|imm6|Rn|Rd
                        let rm_bits = register_to_bits(*rm_reg)?;

                        let encoding = 0x8B000000u32  // ADD 64-bit (shifted register)
                            | (rm_bits << 16)         // Rm field
                            | (rn_bits << 5)          // Rn field
                            | rd_bits; // Rd field

                        Ok(encoding)
                    }
                    Operand::Immediate(imm) => {
                        // ADD (immediate)
                        // Encoding: sf|00|100010|shift|imm12|Rn|Rd
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADD", imm));
                        }

                        let encoding = 0x91000000u32  // ADD 64-bit (immediate)
                            | ((*imm as u32 & 0xFFF) << 10)  // imm12 field
                            | (rn_bits << 5)                  // Rn field
                            | rd_bits; // Rd field

                        Ok(encoding)
                    }
                }
            }
            _ => Err(format!("Instruction encoding not implemented: {}", instr)),
        }
    }
}

fn register_to_bits(reg: Register) -> Result<u32, String> {
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
        Register::SP => Err("SP register encoding not supported in basic assembler".to_string()),
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

        // Check that we got some encoded instruction
        let instr = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_ne!(instr, 0);
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
}

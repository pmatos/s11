use crate::ir::types::Condition;
use crate::ir::{Instruction, Operand, Register};
use dynasmrt::{DynasmApi, dynasm};

pub struct AArch64Assembler;

impl AArch64Assembler {
    pub fn new() -> Self {
        Self
    }

    pub fn assemble_instructions(
        &mut self,
        instructions: &[Instruction],
    ) -> Result<Vec<u8>, String> {
        // Create a new assembler for this operation
        let mut ops = dynasmrt::aarch64::Assembler::new()
            .map_err(|e| format!("Failed to create assembler: {:?}", e))?;

        for instr in instructions {
            self.encode_instruction_on(&mut ops, instr)?;
        }

        ops.finalize()
            .map(|buf| buf.to_vec())
            .map_err(|e| format!("Failed to finalize assembly: {:?}", e))
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
                        // ADD immediate requires XSP register type (Xn|SP format) per AArch64 spec.
                        // The X register type only works for register operands, not immediates.
                        // XSP allows both general-purpose X registers and SP in this encoding.
                        dynasm!(ops
                            ; .arch aarch64
                            ; add XSP(rd_reg), XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Sub { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; sub X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for SUB", imm));
                        }
                        // SUB immediate also requires XSP register type (Xn|SP format)
                        dynasm!(ops
                            ; .arch aarch64
                            ; sub XSP(rd_reg), XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::And { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; and X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(_imm) => {
                        // AND with immediate uses logical immediate encoding which is complex.
                        // For now, only support register operands.
                        Err("AND immediate encoding not yet supported".to_string())
                    }
                }
            }
            Instruction::Orr { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; orr X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(_imm) => {
                        // ORR with immediate uses logical immediate encoding which is complex.
                        // For now, only support register operands.
                        Err("ORR immediate encoding not yet supported".to_string())
                    }
                }
            }
            Instruction::Eor { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; eor X(rd_reg), X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(_imm) => {
                        // EOR with immediate uses logical immediate encoding which is complex.
                        // For now, only support register operands.
                        Err("EOR immediate encoding not yet supported".to_string())
                    }
                }
            }
            Instruction::Lsl { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsl X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for LSL (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsl X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Lsr { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsr X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for LSR (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; lsr X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Asr { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;

                match shift {
                    Operand::Register(shift_reg) => {
                        let shift_reg_num = register_to_dynasm(*shift_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; asr X(rd_reg), X(rn_reg), X(shift_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(shift_amt) => {
                        if *shift_amt < 0 || *shift_amt > 63 {
                            return Err(format!(
                                "Shift amount {} out of range for ASR (0-63)",
                                shift_amt
                            ));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; asr X(rd_reg), X(rn_reg), *shift_amt as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Mul { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mul X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Sdiv { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; sdiv X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Udiv { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; udiv X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Cmp { rn, rm } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmp X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for CMP", imm));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmp XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Cmn { rn, rm } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmn X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for CMN", imm));
                        }
                        dynasm!(ops
                            ; .arch aarch64
                            ; cmn XSP(rn_reg), #*imm as u32
                        );
                        Ok(())
                    }
                }
            }
            Instruction::Tst { rn, rm } => {
                let rn_reg = register_to_dynasm(*rn)?;

                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_reg_num = register_to_dynasm(*rm_reg)?;
                        dynasm!(ops
                            ; .arch aarch64
                            ; tst X(rn_reg), X(rm_reg_num)
                        );
                        Ok(())
                    }
                    Operand::Immediate(_imm) => {
                        Err("TST immediate encoding not yet supported".to_string())
                    }
                }
            }
            Instruction::Csel { .. } => {
                // TODO: dynasm doesn't easily support condition code operands
                // This requires raw encoding or dynasm macro extension
                Err("CSEL encoding not yet supported".to_string())
            }
            Instruction::Csinc { .. } => Err("CSINC encoding not yet supported".to_string()),
            Instruction::Csinv { .. } => Err("CSINV encoding not yet supported".to_string()),
            Instruction::Csneg { .. } => Err("CSNEG encoding not yet supported".to_string()),
        }
    }
}

impl Default for AArch64Assembler {
    fn default() -> Self {
        Self::new()
    }
}

fn register_to_dynasm(reg: Register) -> Result<u8, String> {
    reg.index()
        .ok_or_else(|| format!("Register {:?} not supported in dynasm encoding", reg))
}

fn condition_to_dynasm(cond: Condition) -> Result<u8, String> {
    Ok(match cond {
        Condition::EQ => 0b0000,
        Condition::NE => 0b0001,
        Condition::CS => 0b0010,
        Condition::CC => 0b0011,
        Condition::MI => 0b0100,
        Condition::PL => 0b0101,
        Condition::VS => 0b0110,
        Condition::VC => 0b0111,
        Condition::HI => 0b1000,
        Condition::LS => 0b1001,
        Condition::GE => 0b1010,
        Condition::LT => 0b1011,
        Condition::GT => 0b1100,
        Condition::LE => 0b1101,
        Condition::AL => 0b1110,
        Condition::NV => 0b1111,
    })
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
        let bytes = result.expect("MOV register encoding should succeed");
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
        let bytes = result.expect("MOV immediate encoding should succeed");
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
        let bytes = result.expect("ADD register encoding should succeed");
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
        let bytes = result.expect("ADD immediate encoding should succeed");
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
        let bytes = result.expect("Multiple instruction encoding should succeed");
        assert_eq!(bytes.len(), 8); // Two 32-bit instructions
    }

    // Disassembly-based correctness tests
    // These tests verify that generated machine code disassembles to the expected instructions

    fn disassemble_and_verify(
        bytes: &[u8],
        expected_mnemonic: &str,
        expected_operands_contain: &[&str],
    ) {
        use capstone::prelude::*;

        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("Failed to create Capstone instance");

        let insns = cs.disasm_all(bytes, 0x0).expect("Failed to disassemble");

        assert_eq!(insns.len(), 1, "Expected exactly one instruction");

        let insn = insns.iter().next().expect("No instruction found");
        let mnemonic = insn.mnemonic().expect("No mnemonic");
        let op_str = insn.op_str().expect("No operands");

        assert_eq!(
            mnemonic, expected_mnemonic,
            "Mnemonic mismatch: got '{}', expected '{}'",
            mnemonic, expected_mnemonic
        );

        for expected_op in expected_operands_contain {
            assert!(
                op_str.contains(expected_op),
                "Operand string '{}' does not contain expected '{}'",
                op_str,
                expected_op
            );
        }
    }

    #[test]
    fn test_mov_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MOV register encoding should succeed");
        disassemble_and_verify(&bytes, "mov", &["x0", "x1"]);
    }

    #[test]
    fn test_mov_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MOV immediate encoding should succeed");
        disassemble_and_verify(&bytes, "mov", &["x0", "0x2a"]);
    }

    #[test]
    fn test_add_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ADD register encoding should succeed");
        disassemble_and_verify(&bytes, "add", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_add_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(10),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ADD immediate encoding should succeed");
        disassemble_and_verify(&bytes, "add", &["x0", "x1", "0xa"]);
    }

    #[test]
    fn test_sub_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("SUB register encoding should succeed");
        disassemble_and_verify(&bytes, "sub", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_sub_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Sub {
            rd: Register::X5,
            rn: Register::X5,
            rm: Operand::Immediate(1),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("SUB immediate encoding should succeed");
        disassemble_and_verify(&bytes, "sub", &["x5", "x5", "#1"]);
    }

    #[test]
    fn test_and_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("AND encoding should succeed");
        disassemble_and_verify(&bytes, "and", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_orr_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ORR encoding should succeed");
        disassemble_and_verify(&bytes, "orr", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_eor_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("EOR encoding should succeed");
        disassemble_and_verify(&bytes, "eor", &["x0", "x0", "x0"]);
    }

    #[test]
    fn test_lsl_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(5),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("LSL immediate encoding should succeed");
        disassemble_and_verify(&bytes, "lsl", &["x0", "x1", "#5"]);
    }

    #[test]
    fn test_lsr_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(8),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("LSR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "lsr", &["x0", "x1", "#8"]);
    }

    #[test]
    fn test_asr_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Asr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(16),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ASR immediate encoding should succeed");
        disassemble_and_verify(&bytes, "asr", &["x0", "x1", "0x10"]);
    }

    #[test]
    fn test_lsl_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        }];

        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("LSL register encoding should succeed");
        disassemble_and_verify(&bytes, "lsl", &["x0", "x1", "x2"]);
    }
}

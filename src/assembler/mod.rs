pub mod x86;

use crate::ir::types::Condition;
use crate::ir::{Instruction, Operand, Register};
use dynasmrt::{DynasmApi, dynasm};

/// Emits one of the four CSEL-family mnemonics with the given register
/// indices and a runtime `Condition` value. dynasm-rs requires the condition
/// suffix to be a compile-time literal, so we dispatch via a 16-arm match.
macro_rules! emit_csel {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $cond:expr) => {{
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), le),
            Condition::AL => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), al),
            Condition::NV => dynasm!($ops ; .arch aarch64 ; $mnem X($rd), X($rn), X($rm), nv),
        }
    }};
}

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

    #[allow(clippy::useless_conversion)]
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
            Instruction::Csel { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csel, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csinc { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csinc, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csinv { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csinv, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Csneg { rd, rn, rm, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                emit_csel!(ops, csneg, rd_reg, rn_reg, rm_reg, *cond);
                Ok(())
            }
            Instruction::Mvn { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; mvn X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::Neg { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; neg X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::Negs { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; negs X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::MovN { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movn X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVN shift {} out of range", other)),
                }
                Ok(())
            }
            Instruction::Bic { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; bic X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("BIC immediate encoding not supported".to_string())
                    }
                }
            }
            Instruction::Bics { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; bics X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("BICS immediate encoding not supported".to_string())
                    }
                }
            }
            Instruction::Orn { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; orn X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("ORN immediate encoding not supported".to_string())
                    }
                }
            }
            Instruction::Eon { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; eon X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("EON immediate encoding not supported".to_string())
                    }
                }
            }
            Instruction::Adds { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADDS", imm));
                        }
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                }
            }
            Instruction::Subs { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for SUBS", imm));
                        }
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                }
            }
            Instruction::Ands { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; ands X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(_) => {
                        Err("ANDS immediate encoding not supported".to_string())
                    }
                }
            }
            // CSET / CSETM lower to CSINC/CSINV with XZR sources and inverted cond.
            // Capstone canonicalises the disassembly back to `cset`/`csetm`.
            Instruction::Cset { rd, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let xzr: u8 = 31;
                let inv = cond.invert();
                emit_csel!(ops, csinc, rd_reg, xzr, xzr, inv);
                Ok(())
            }
            Instruction::Csetm { rd, cond } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let xzr: u8 = 31;
                let inv = cond.invert();
                emit_csel!(ops, csinv, rd_reg, xzr, xzr, inv);
                Ok(())
            }
            Instruction::Ror { rd, rn, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                match shift {
                    Operand::Register(r) => {
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; ror X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 63 {
                            return Err(format!("ROR shift {} out of range", imm));
                        }
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; ror X(rd_reg), X(rn_reg), imm);
                        Ok(())
                    }
                }
            }
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

    #[test]
    fn test_csel_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSEL encoding should succeed");
        disassemble_and_verify(&bytes, "csel", &["x0", "x1", "x2", "eq"]);
    }

    #[test]
    fn test_csinc_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csinc {
            rd: Register::X3,
            rn: Register::X4,
            rm: Register::X5,
            cond: Condition::NE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSINC encoding should succeed");
        disassemble_and_verify(&bytes, "csinc", &["x3", "x4", "x5", "ne"]);
    }

    #[test]
    fn test_csinv_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csinv {
            rd: Register::X10,
            rn: Register::X11,
            rm: Register::X12,
            cond: Condition::LT,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSINV encoding should succeed");
        disassemble_and_verify(&bytes, "csinv", &["x10", "x11", "x12", "lt"]);
    }

    #[test]
    fn test_csneg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csneg {
            rd: Register::X20,
            rn: Register::X21,
            rm: Register::X22,
            cond: Condition::GE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSNEG encoding should succeed");
        disassemble_and_verify(&bytes, "csneg", &["x20", "x21", "x22", "ge"]);
    }

    #[test]
    fn test_mvn_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Mvn {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MVN encoding should succeed");
        disassemble_and_verify(&bytes, "mvn", &["x0", "x1"]);
    }

    #[test]
    fn test_neg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("NEG encoding should succeed");
        disassemble_and_verify(&bytes, "neg", &["x0", "x1"]);
    }

    #[test]
    fn test_negs_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Negs {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("NEGS encoding should succeed");
        disassemble_and_verify(&bytes, "negs", &["x0", "x1"]);
    }

    #[test]
    fn test_movn_correctness_shift_0() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 0xFFFF,
            shift: 0,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MOVN encoding should succeed");
        // Capstone may render this as `mov x0, #-65536` (canonicalises movn → mov #-N)
        // so we only assert that the instruction is exactly 4 bytes and not zero.
        assert_eq!(bytes.len(), 4);
        assert_ne!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_cset_disassembles_to_cset() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Cset {
            rd: Register::X0,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSET encoding should succeed");
        // Capstone canonicalises `csinc x0, xzr, xzr, ne` back to `cset x0, eq`
        disassemble_and_verify(&bytes, "cset", &["x0", "eq"]);
    }

    #[test]
    fn test_ror_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ror {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Immediate(5),
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ROR imm encoding should succeed");
        disassemble_and_verify(&bytes, "ror", &["x0", "x1"]);
    }

    #[test]
    fn test_ror_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ror {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("ROR reg encoding should succeed");
        disassemble_and_verify(&bytes, "ror", &["x0", "x1", "x2"]);
    }

    #[test]
    fn test_csetm_disassembles_to_csetm() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csetm {
            rd: Register::X3,
            cond: Condition::NE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSETM encoding should succeed");
        disassemble_and_verify(&bytes, "csetm", &["x3", "ne"]);
    }

    #[test]
    fn test_movn_correctness_shift_16() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 1,
            shift: 16,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MOVN encoding with shift should succeed");
        assert_eq!(bytes.len(), 4);
    }

    /// Ensures we emit the 64-bit (sf=1) form, not the 32-bit Wn form —
    /// regression for the encoding bit-pattern error.
    #[test]
    fn test_csinv_is_xform_not_wform() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Csinv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CSINV encoding should succeed");
        // disassemble_and_verify asserts mnemonic and operand presence; here
        // we additionally assert the operands are xN, not wN.
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .expect("Capstone");
        let insns = cs.disasm_all(&bytes, 0).expect("disasm");
        let insn = insns.iter().next().expect("instruction");
        let op_str = insn.op_str().expect("op_str");
        assert!(
            op_str.contains("x0") && op_str.contains("x1") && op_str.contains("x2"),
            "Expected 64-bit Xn form, got: {}",
            op_str
        );
        assert!(
            !op_str.contains("w0") && !op_str.contains("w1") && !op_str.contains("w2"),
            "Got 32-bit Wn form (sf-bit error); op_str: {}",
            op_str
        );
    }
}

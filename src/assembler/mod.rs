pub mod x86;

use crate::ir::types::{Condition, ShiftKind};
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

/// Emit a 3-operand arithmetic shifted-register instruction (Add/Sub) of the
/// form `<mnem> X(rd), X(rn), X(rm), <kind> #amt`. ROR is rejected here because
/// the AArch64 ADD/SUB shifted-register encoding does not accept ROR — see ARM
/// ARM. `is_encodable_aarch64` already screens this out; the Err is defensive.
macro_rules! emit_shifted_reg_3op_arith {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => Err(format!(
                "{} cannot use ROR shift (rejected by is_encodable_aarch64)",
                stringify!($mnem)
            )),
        }
    }};
}

/// 3-operand logical shifted-register instruction (And/Orr/Eor) — accepts all
/// four ShiftKinds including ROR.
macro_rules! emit_shifted_reg_3op_logical {
    ($ops:expr, $mnem:ident, $rd:expr, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rd_n: u8 = $rd;
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSL amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), LSR amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ASR amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Ror => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rd_n), X(rn_n), X(rm_n), ROR amt_n);
                Ok::<(), String>(())
            }
        }
    }};
}

/// 2-operand arithmetic shifted-register form (Cmp/Cmn) — no ROR.
macro_rules! emit_shifted_reg_2op_arith {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSL amt_n);
                Ok(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSR amt_n);
                Ok(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ASR amt_n);
                Ok(())
            }
            ShiftKind::Ror => Err(format!(
                "{} cannot use ROR shift (rejected by is_encodable_aarch64)",
                stringify!($mnem)
            )),
        }
    }};
}

/// 2-operand logical shifted-register form (Tst) — accepts all four kinds.
macro_rules! emit_shifted_reg_2op_logical {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $kind:expr, $amt:expr) => {{
        let rn_n: u8 = $rn;
        let rm_n: u8 = $rm;
        let amt_n: u32 = ($amt) as u32;
        match $kind {
            ShiftKind::Lsl => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSL amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Lsr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), LSR amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Asr => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ASR amt_n);
                Ok::<(), String>(())
            }
            ShiftKind::Ror => {
                dynasm!($ops ; .arch aarch64 ; $mnem X(rn_n), X(rm_n), ROR amt_n);
                Ok::<(), String>(())
            }
        }
    }};
}

/// CCMP/CCMN reg form: `ccmp Xn, Xm, #nzcv, cond`. The condition suffix
/// must be a compile-time literal for dynasm-rs, so we expand 14 condition
/// arms; `$nzcv` is bound to a `u32`-cast value once at the top so the
/// dynasm `#` literal slot accepts it at emit time. AL and NV are forbidden
/// by `is_encodable_aarch64` and excluded from the macro arms.
macro_rules! emit_ccmp_reg {
    ($ops:expr, $mnem:ident, $rn:expr, $rm:expr, $nzcv:expr, $cond:expr) => {{
        let n = $nzcv as u32;
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), X($rm), #n, le),
            Condition::AL | Condition::NV => {
                return Err("CCMP/CCMN forbid AL/NV per ARM ARM C6.2.36".to_string());
            }
        }
    }};
}

/// CCMP/CCMN immediate form: `ccmp Xn, #imm5, #nzcv, cond`.
macro_rules! emit_ccmp_imm {
    ($ops:expr, $mnem:ident, $rn:expr, $imm5:expr, $nzcv:expr, $cond:expr) => {{
        let i = $imm5 as u32;
        let n = $nzcv as u32;
        match $cond {
            Condition::EQ => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, eq),
            Condition::NE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ne),
            Condition::CS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, cs),
            Condition::CC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, cc),
            Condition::MI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, mi),
            Condition::PL => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, pl),
            Condition::VS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, vs),
            Condition::VC => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, vc),
            Condition::HI => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, hi),
            Condition::LS => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ls),
            Condition::GE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, ge),
            Condition::LT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, lt),
            Condition::GT => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, gt),
            Condition::LE => dynasm!($ops ; .arch aarch64 ; $mnem X($rn), #i, #n, le),
            Condition::AL | Condition::NV => {
                return Err("CCMP/CCMN forbid AL/NV per ARM ARM C6.2.36".to_string());
            }
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_arith!(
                            ops, add, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_arith!(
                            ops, sub, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, and, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, orr, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_3op_logical!(
                            ops, eor, rd_reg, rn_reg, rm_reg_num, kind, *amount
                        )
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
                    // Rejected by is_encodable_aarch64; shift slot is not a
                    // shifted-register form.
                    Operand::ShiftedRegister { .. } => {
                        Err("LSL shift amount cannot be a ShiftedRegister".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("LSR shift amount cannot be a ShiftedRegister".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("ASR shift amount cannot be a ShiftedRegister".to_string())
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
            Instruction::Madd { rd, rn, rm, ra } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                let ra_reg = register_to_dynasm(*ra)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; madd X(rd_reg), X(rn_reg), X(rm_reg), X(ra_reg)
                );
                Ok(())
            }
            Instruction::Msub { rd, rn, rm, ra } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;
                let ra_reg = register_to_dynasm(*ra)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; msub X(rd_reg), X(rn_reg), X(rm_reg), X(ra_reg)
                );
                Ok(())
            }
            Instruction::Mneg { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; mneg X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Smulh { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; smulh X(rd_reg), X(rn_reg), X(rm_reg)
                );
                Ok(())
            }
            Instruction::Umulh { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                let rm_reg = register_to_dynasm(*rm)?;

                dynasm!(ops
                    ; .arch aarch64
                    ; umulh X(rd_reg), X(rn_reg), X(rm_reg)
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_arith!(ops, cmp, rn_reg, rm_reg_num, kind, *amount)
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_arith!(ops, cmn, rn_reg, rm_reg_num, kind, *amount)
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
                    Operand::ShiftedRegister { reg, kind, amount } => {
                        let rm_reg_num = register_to_dynasm(*reg)?;
                        emit_shifted_reg_2op_logical!(ops, tst, rn_reg, rm_reg_num, kind, *amount)
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
            Instruction::Ccmp { rn, rm, nzcv, cond } => {
                if *nzcv > 15 {
                    return Err(format!("CCMP nzcv {} out of range (0..=15)", nzcv));
                }
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_idx = register_to_dynasm(*rm_reg)?;
                        emit_ccmp_reg!(ops, ccmp, rn_reg, rm_idx, *nzcv, *cond);
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 31 {
                            return Err(format!("CCMP imm5 {} out of range (0..=31)", imm));
                        }
                        emit_ccmp_imm!(ops, ccmp, rn_reg, *imm, *nzcv, *cond);
                    }
                    Operand::ShiftedRegister { .. } => {
                        return Err("CCMP does not support shifted-register operand".to_string());
                    }
                }
                Ok(())
            }
            Instruction::Ccmn { rn, rm, nzcv, cond } => {
                if *nzcv > 15 {
                    return Err(format!("CCMN nzcv {} out of range (0..=15)", nzcv));
                }
                let rn_reg = register_to_dynasm(*rn)?;
                match rm {
                    Operand::Register(rm_reg) => {
                        let rm_idx = register_to_dynasm(*rm_reg)?;
                        emit_ccmp_reg!(ops, ccmn, rn_reg, rm_idx, *nzcv, *cond);
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 31 {
                            return Err(format!("CCMN imm5 {} out of range (0..=31)", imm));
                        }
                        emit_ccmp_imm!(ops, ccmn, rn_reg, *imm, *nzcv, *cond);
                    }
                    Operand::ShiftedRegister { .. } => {
                        return Err("CCMN does not support shifted-register operand".to_string());
                    }
                }
                Ok(())
            }
            Instruction::Mvn { rd, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rm_reg = register_to_dynasm(*rm)?;
                dynasm!(ops ; .arch aarch64 ; mvn X(rd_reg), X(rm_reg));
                Ok(())
            }
            Instruction::Clz { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; clz X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Cls { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; cls X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rbit { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rbit X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev32 { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev32 X(rd_reg), X(rn_reg));
                Ok(())
            }
            Instruction::Rev16 { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; rev16 X(rd_reg), X(rn_reg));
                Ok(())
            }
            // UXTB Wd, Wn — alias of UBFM Wd, Wn, #0, #7. Issue #60.
            // dynasm-rs emits the 32-bit (W) form; the upper 32 bits of Xd
            // are zeroed by the AArch64 architectural rule for 32-bit ops.
            Instruction::Uxtb { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; uxtb W(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTB Xd, Wn — alias of SBFM Xd, Xn, #0, #7. Issue #60.
            Instruction::Sxtb { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxtb X(rd_reg), W(rn_reg));
                Ok(())
            }
            // UXTH Wd, Wn — alias of UBFM Wd, Wn, #0, #15. Issue #60.
            Instruction::Uxth { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; uxth W(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTH Xd, Wn — alias of SBFM Xd, Xn, #0, #15. Issue #60.
            Instruction::Sxth { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxth X(rd_reg), W(rn_reg));
                Ok(())
            }
            // SXTW Xd, Wn — alias of SBFM Xd, Xn, #0, #31. Issue #60.
            Instruction::Sxtw { rd, rn } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let rn_reg = register_to_dynasm(*rn)?;
                dynasm!(ops ; .arch aarch64 ; sxtw X(rd_reg), W(rn_reg));
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
            Instruction::MovZ { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movz X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVZ shift {} out of range", other)),
                }
                Ok(())
            }
            Instruction::MovK { rd, imm, shift } => {
                let rd_reg = register_to_dynasm(*rd)?;
                let imm = *imm as u32;
                match shift {
                    0 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm),
                    16 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #16),
                    32 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #32),
                    48 => dynasm!(ops ; .arch aarch64 ; movk X(rd_reg), imm, lsl #48),
                    other => return Err(format!("MOVK shift {} out of range", other)),
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
                    Operand::ShiftedRegister { .. } => {
                        Err("BIC shifted-register form not yet supported (issue #59 covers AND/ORR/EOR/TST only)".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("BICS shifted-register form not yet supported".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("ORN shifted-register form not yet supported".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("EON shifted-register form not yet supported".to_string())
                    }
                }
            }
            Instruction::Adds { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                match rm {
                    Operand::Register(r) => {
                        // Shifted-register form: slot 31 = XZR; plain
                        // `register_to_dynasm` mapping is correct.
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for ADDS", imm));
                        }
                        // The immediate-form encoding uses the `Xn|SP` slot —
                        // 31 decodes as SP, not XZR. `register_to_dynasm_xsp`
                        // accepts SP and rejects XZR, keeping the encoding
                        // unambiguous and consistent with what the parser /
                        // is_encodable_aarch64 admit.
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; adds X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("ADDS shifted-register form not yet supported (issue #59 covers ADD without flags)".to_string())
                    }
                }
            }
            Instruction::Subs { rd, rn, rm } => {
                let rd_reg = register_to_dynasm(*rd)?;
                match rm {
                    Operand::Register(r) => {
                        // Shifted-register form: slot 31 = XZR.
                        let rn_reg = register_to_dynasm(*rn)?;
                        let rm_reg = register_to_dynasm(*r)?;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), X(rn_reg), X(rm_reg));
                        Ok(())
                    }
                    Operand::Immediate(imm) => {
                        if *imm < 0 || *imm > 0xFFF {
                            return Err(format!("Immediate {} out of range for SUBS", imm));
                        }
                        // Immediate form uses the Xn|SP slot — same caveat
                        // as ADDS above; `register_to_dynasm_xsp` accepts SP
                        // and rejects XZR.
                        let rn_reg = register_to_dynasm_xsp(*rn)?;
                        let imm = *imm as u32;
                        dynasm!(ops ; .arch aarch64 ; subs X(rd_reg), XSP(rn_reg), imm);
                        Ok(())
                    }
                    Operand::ShiftedRegister { .. } => {
                        Err("SUBS shifted-register form not yet supported".to_string())
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
                    Operand::ShiftedRegister { .. } => {
                        Err("ANDS shifted-register form not yet supported".to_string())
                    }
                }
            }
            // CSET / CSETM lower to CSINC/CSINV with XZR sources and inverted cond.
            // Capstone canonicalises the disassembly back to `cset`/`csetm`.
            //
            // Defense-in-depth: reject AL/NV here too. `is_encodable_aarch64`
            // already filters them at the IR level, but a caller could
            // construct the variant directly and bypass that check. Without
            // this guard, `Cset { cond: AL }` would lower to `csinc ..., nv`
            // (because invert(AL) = NV), which on AArch64 writes 0 — the
            // opposite of the IR's "always 1" semantics. CSETM has the
            // symmetric issue.
            Instruction::Cset { rd, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return Err(format!(
                        "CSET with {} is not encodable (AL/NV reserved)",
                        cond
                    ));
                }
                let rd_reg = register_to_dynasm(*rd)?;
                let xzr: u8 = 31;
                let inv = cond.invert();
                emit_csel!(ops, csinc, rd_reg, xzr, xzr, inv);
                Ok(())
            }
            Instruction::Csetm { rd, cond } => {
                if matches!(cond, Condition::AL | Condition::NV) {
                    return Err(format!(
                        "CSETM with {} is not encodable (AL/NV reserved)",
                        cond
                    ));
                }
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
                    Operand::ShiftedRegister { .. } => {
                        Err("ROR shift amount cannot be a ShiftedRegister".to_string())
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

/// Map a register to the `Xn|SP` encoding slot. Returns Err for XZR —
/// `Register::XZR.index() == Some(31)` would otherwise silently alias to SP.
fn register_to_dynasm_xsp(reg: Register) -> Result<u8, String> {
    match reg {
        Register::XZR => {
            Err("XZR is not encodable in the Xn|SP register slot (would decode as SP)".to_string())
        }
        Register::SP => Ok(31),
        other => other.index().ok_or_else(|| {
            format!(
                "Register {:?} not supported in dynasm Xn|SP encoding",
                other
            )
        }),
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
    fn test_ccmp_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 5,
            cond: Condition::EQ,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CCMP register form should encode");
        disassemble_and_verify(&bytes, "ccmp", &["x1", "x2", "#5", "eq"]);
    }

    #[test]
    fn test_ccmp_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmp {
            rn: Register::X3,
            rm: Operand::Immediate(15),
            nzcv: 0,
            cond: Condition::NE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CCMP immediate form should encode");
        disassemble_and_verify(&bytes, "ccmp", &["x3", "#0xf", "#0", "ne"]);
    }

    #[test]
    fn test_ccmn_reg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmn {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
            nzcv: 15,
            cond: Condition::LT,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CCMN register form should encode");
        disassemble_and_verify(&bytes, "ccmn", &["x0", "x1", "#0xf", "lt"]);
    }

    #[test]
    fn test_ccmn_imm_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Ccmn {
            rn: Register::X4,
            rm: Operand::Immediate(7),
            nzcv: 4,
            cond: Condition::GE,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("CCMN immediate form should encode");
        disassemble_and_verify(&bytes, "ccmn", &["x4", "#7", "#4", "ge"]);
    }

    #[test]
    fn test_madd_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MADD encoding should succeed");
        disassemble_and_verify(&bytes, "madd", &["x0", "x1", "x2", "x3"]);
    }

    #[test]
    fn test_msub_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Msub {
            rd: Register::X4,
            rn: Register::X5,
            rm: Register::X6,
            ra: Register::X7,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MSUB encoding should succeed");
        disassemble_and_verify(&bytes, "msub", &["x4", "x5", "x6", "x7"]);
    }

    #[test]
    fn test_mneg_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Mneg {
            rd: Register::X10,
            rn: Register::X11,
            rm: Register::X12,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("MNEG encoding should succeed");
        disassemble_and_verify(&bytes, "mneg", &["x10", "x11", "x12"]);
    }

    #[test]
    fn test_smulh_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Smulh {
            rd: Register::X13,
            rn: Register::X14,
            rm: Register::X15,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("SMULH encoding should succeed");
        disassemble_and_verify(&bytes, "smulh", &["x13", "x14", "x15"]);
    }

    #[test]
    fn test_umulh_correctness() {
        let mut assembler = AArch64Assembler::new();
        let instructions = vec![Instruction::Umulh {
            rd: Register::X16,
            rn: Register::X17,
            rm: Register::X18,
        }];
        let bytes = assembler
            .assemble_instructions(&instructions)
            .expect("UMULH encoding should succeed");
        disassemble_and_verify(&bytes, "umulh", &["x16", "x17", "x18"]);
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
        // Exact byte-level check. MOVN 64-bit base is 0x92800000; imm16<<5
        // for #0xFFFF gives 0x1FFFE0; Rd=0 contributes nothing → word
        // 0x929FFFE0, little-endian = [0xE0, 0xFF, 0x9F, 0x92]. An off-by-one
        // in either the imm16 or hw bits would fail this rather than slip
        // through a Capstone mnemonic check.
        assert_eq!(bytes, [0xE0, 0xFF, 0x9F, 0x92]);
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
        // Include the literal shift amount: an off-by-one in the encoded
        // immediate would otherwise slip through.
        disassemble_and_verify(&bytes, "ror", &["x0", "x1", "#5"]);
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

    /// ADDS/SUBS immediate-form accepts SP as `rn` (the `Xn|SP` encoding
    /// slot decodes 31 as SP). The parser and `is_encodable_aarch64` both
    /// admit this — the encoder must too.
    #[test]
    fn test_adds_subs_imm_accept_sp_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            },
        ] {
            let bytes = assembler
                .assemble_instructions(&[instr])
                .unwrap_or_else(|e| {
                    panic!(
                        "Expected SP-as-rn to encode, got Err({}) for {:?}",
                        e, instr
                    )
                });
            assert_eq!(bytes.len(), 4);
        }
    }

    /// Capstone round-trip for ADDS with SP as `rn` — guards against silent
    /// off-by-one in the encoded slot. Capstone must disassemble back to
    /// `adds` with `sp` in the rn position.
    #[test]
    fn test_adds_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            }])
            .expect("ADDS imm with SP rn should encode");
        disassemble_and_verify(&bytes, "adds", &["x0", "sp", "#8"]);
    }

    /// SUBS counterpart to `test_adds_imm_sp_rn_roundtrip`. The encoding
    /// logic is shared via `register_to_dynasm_xsp` but a regression
    /// specific to SUBS would otherwise go unnoticed.
    #[test]
    fn test_subs_imm_sp_rn_roundtrip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(8),
            }])
            .expect("SUBS imm with SP rn should encode");
        disassemble_and_verify(&bytes, "subs", &["x0", "sp", "#8"]);
    }

    /// Defense-in-depth: SP as `rd` for ADDS/SUBS is rejected. Architecturally,
    /// the `rd` slot is `Xd|XZR` (decodes 31 as XZR), so dynasm's `X(31)`
    /// maps to XZR — but `Register::SP` has `index() == None`, so
    /// `register_to_dynasm(SP)` returns Err and the encoder bails early.
    /// Test that this remains the case.
    #[test]
    fn test_adds_subs_imm_reject_sp_rd() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::SP,
                rn: Register::X0,
                rm: Operand::Immediate(8),
            },
            Instruction::Subs {
                rd: Register::SP,
                rn: Register::X0,
                rm: Operand::Immediate(8),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr]);
            assert!(
                result.is_err(),
                "Expected encoder to reject SP as rd, got {:?} for {:?}",
                result,
                instr
            );
        }
    }

    /// Defense-in-depth: ADDS/SUBS with immediate `rm` and XZR as `rn` would
    /// encode to `ADDS Xd, SP, #imm` because the immediate-form encoding
    /// slot is `Xn|SP` (where register 31 means SP, not XZR). The encoder
    /// must refuse this construction rather than silently using SP.
    #[test]
    fn test_adds_subs_imm_reject_xzr_rn() {
        let mut assembler = AArch64Assembler::new();
        for instr in [
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
        ] {
            let result = assembler.assemble_instructions(&[instr]);
            assert!(
                result.is_err(),
                "Expected encoder to reject {:?}, got {:?}",
                instr,
                result
            );
        }
        // Register-form ADDS/SUBS with XZR as rn must still succeed — the
        // register-form encoding decodes 31 as XZR correctly.
        let ok = assembler.assemble_instructions(&[Instruction::Adds {
            rd: Register::X0,
            rn: Register::XZR,
            rm: Operand::Register(Register::X1),
        }]);
        assert!(ok.is_ok(), "register-form ADDS with XZR should encode");
    }

    /// Defense-in-depth: assembler must refuse CSET/CSETM with AL or NV,
    /// even if a caller bypasses `is_encodable_aarch64`. Lowering
    /// `Cset { cond: AL }` to the alias would emit `csinc ..., nv` (because
    /// invert(AL) = NV), which on AArch64 writes 0 — the opposite of the
    /// IR's "always 1" semantics.
    #[test]
    fn test_cset_rejects_al_at_encoder() {
        let mut assembler = AArch64Assembler::new();
        let cases = [
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::AL,
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::NV,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::AL,
            },
            Instruction::Csetm {
                rd: Register::X0,
                cond: Condition::NV,
            },
        ];
        for instr in cases {
            let result = assembler.assemble_instructions(&[instr]);
            assert!(
                result.is_err(),
                "Expected encoder to reject {:?}, got {:?}",
                instr,
                result
            );
        }
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
        // Base 0x92800000 | hw=1<<21 (shift/16=1) = 0x200000 | imm16=1<<5 = 0x20
        // → 0x92A00020, little-endian = [0x20, 0x00, 0xA0, 0x92].
        assert_eq!(bytes, [0x20, 0x00, 0xA0, 0x92]);
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

    #[test]
    fn assemble_remaining_success_forms() {
        let cases = [
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Lsl {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(3),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
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
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Negs {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 2,
                shift: 32,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 3,
                shift: 48,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 0,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 16,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 32,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 48,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 0,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 32,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xABCD,
                shift: 48,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(4),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::SP,
                rm: Operand::Immediate(4),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(4),
            },
        ];

        for instr in cases {
            let mut assembler = AArch64Assembler::new();
            assembler
                .assemble_instructions(&[instr])
                .unwrap_or_else(|e| panic!("{} should assemble: {}", instr, e));
        }
    }

    #[test]
    fn reject_remaining_invalid_forms() {
        let cases = [
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1),
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
                shift: Operand::Immediate(64),
            },
            Instruction::Lsr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(-1),
            },
            Instruction::Asr {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64),
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Cmn {
                rn: Register::X1,
                rm: Operand::Immediate(-1),
            },
            Instruction::Tst {
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 8,
            },
            Instruction::MovZ {
                rd: Register::X0,
                imm: 1,
                shift: 8,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 1,
                shift: 24,
            },
            Instruction::Bic {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Bics {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Orn {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Eon {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(4096),
            },
            Instruction::Adds {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(-1),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(1),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(64),
            },
        ];

        for instr in cases {
            let mut assembler = AArch64Assembler::new();
            assert!(
                assembler.assemble_instructions(&[instr]).is_err(),
                "{} should be rejected",
                instr
            );
        }
        assert!(register_to_dynasm(Register::SP).is_err());
        assert_eq!(register_to_dynasm_xsp(Register::SP).unwrap(), 31);
    }

    #[test]
    fn test_bit_manipulation_encoders_roundtrip() {
        let cases: &[(Instruction, &str)] = &[
            (
                Instruction::Clz {
                    rd: Register::X0,
                    rn: Register::X1,
                },
                "clz",
            ),
            (
                Instruction::Cls {
                    rd: Register::X2,
                    rn: Register::X3,
                },
                "cls",
            ),
            (
                Instruction::Rbit {
                    rd: Register::X4,
                    rn: Register::X5,
                },
                "rbit",
            ),
            (
                Instruction::Rev {
                    rd: Register::X6,
                    rn: Register::X7,
                },
                "rev",
            ),
            (
                Instruction::Rev32 {
                    rd: Register::X8,
                    rn: Register::X9,
                },
                "rev32",
            ),
            (
                Instruction::Rev16 {
                    rd: Register::X10,
                    rn: Register::X11,
                },
                "rev16",
            ),
        ];
        for (instr, mnemonic) in cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(std::slice::from_ref(instr))
                .unwrap_or_else(|e| panic!("{} encoding should succeed: {}", mnemonic, e));
            let rd = instr.destination().unwrap().to_string();
            let rn = instr.source_registers()[0].to_string();
            disassemble_and_verify(&bytes, mnemonic, &[&rd, &rn]);
        }
    }

    /// Issue #60: the standalone UXTB instruction round-trips through
    /// Capstone as `uxtb w<rd>, w<rn>` (the architectural W-form per the
    /// ARM ARM UBFM alias).
    #[test]
    fn test_uxtb_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            }])
            .expect("UXTB encoding should succeed");
        disassemble_and_verify(&bytes, "uxtb", &["w0", "w1"]);
    }

    /// Issue #60: SXTW sign-extends the low word of Wn into 64-bit Xd.
    #[test]
    fn test_sxtw_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
            }])
            .expect("SXTW encoding should succeed");
        disassemble_and_verify(&bytes, "sxtw", &["x0", "w1"]);
    }

    /// Issue #60: SXTH sign-extends the low halfword of Wn into 64-bit Xd.
    #[test]
    fn test_sxth_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            }])
            .expect("SXTH encoding should succeed");
        disassemble_and_verify(&bytes, "sxth", &["x0", "w1"]);
    }

    /// Issue #60: UXTH zero-extends the low halfword of Wn, so Capstone
    /// disassembles as `uxth w<rd>, w<rn>` (32-bit form).
    #[test]
    fn test_uxth_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            }])
            .expect("UXTH encoding should succeed");
        disassemble_and_verify(&bytes, "uxth", &["w0", "w1"]);
    }

    /// Issue #60: SXTB sign-extends the low byte of Wn into the full 64-bit
    /// Xd, so Capstone disassembles as `sxtb x<rd>, w<rn>`.
    #[test]
    fn test_sxtb_encoder_round_trip() {
        let mut assembler = AArch64Assembler::new();
        let bytes = assembler
            .assemble_instructions(&[Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            }])
            .expect("SXTB encoding should succeed");
        disassemble_and_verify(&bytes, "sxtb", &["x0", "w1"]);
    }

    /// Issue #59: shifted-register forms round-trip through Capstone with the
    /// expected `<mnem> <rd>, <rn>, <rm>, <kind> #amt` text.
    #[test]
    fn test_assemble_shifted_register_round_trip() {
        // (instruction, expected mnemonic, expected operand fragments).
        // Capstone prints the shift kind lowercase: "lsl #3" etc.
        let cases: Vec<(Instruction, &str, Vec<String>)> = vec![
            (
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: ShiftKind::Lsl,
                        amount: 3,
                    },
                },
                "add",
                vec!["x0".into(), "x1".into(), "x2".into(), "lsl #3".into()],
            ),
            (
                Instruction::Sub {
                    rd: Register::X3,
                    rn: Register::X4,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X5,
                        kind: ShiftKind::Lsr,
                        amount: 5,
                    },
                },
                "sub",
                vec!["x3".into(), "x4".into(), "x5".into(), "lsr #5".into()],
            ),
            (
                Instruction::And {
                    rd: Register::X6,
                    rn: Register::X7,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X8,
                        kind: ShiftKind::Asr,
                        amount: 7,
                    },
                },
                "and",
                vec!["x6".into(), "x7".into(), "x8".into(), "asr #7".into()],
            ),
            (
                Instruction::Orr {
                    rd: Register::X9,
                    rn: Register::X10,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X11,
                        kind: ShiftKind::Ror,
                        amount: 1,
                    },
                },
                "orr",
                vec!["x9".into(), "x10".into(), "x11".into(), "ror #1".into()],
            ),
            (
                Instruction::Eor {
                    rd: Register::X12,
                    rn: Register::X13,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X14,
                        kind: ShiftKind::Lsl,
                        amount: 2,
                    },
                },
                "eor",
                vec!["x12".into(), "x13".into(), "x14".into(), "lsl #2".into()],
            ),
            (
                Instruction::Cmp {
                    rn: Register::X15,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X16,
                        kind: ShiftKind::Lsl,
                        amount: 4,
                    },
                },
                "cmp",
                vec!["x15".into(), "x16".into(), "lsl #4".into()],
            ),
            (
                Instruction::Cmn {
                    rn: Register::X17,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X18,
                        kind: ShiftKind::Asr,
                        amount: 8,
                    },
                },
                "cmn",
                vec!["x17".into(), "x18".into(), "asr #8".into()],
            ),
            (
                Instruction::Tst {
                    rn: Register::X19,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X20,
                        kind: ShiftKind::Ror,
                        amount: 16,
                    },
                },
                "tst",
                vec!["x19".into(), "x20".into(), "ror #16".into()],
            ),
        ];

        for (instr, mnemonic, expected_ops) in cases {
            let mut assembler = AArch64Assembler::new();
            let bytes = assembler
                .assemble_instructions(&[instr])
                .unwrap_or_else(|e| panic!("{} encoding should succeed: {}", mnemonic, e));
            let refs: Vec<&str> = expected_ops.iter().map(|s| s.as_str()).collect();
            disassemble_and_verify(&bytes, mnemonic, &refs);
        }
    }

    /// ROR with arithmetic ops (Add/Sub/Cmp/Cmn) is rejected by the encoder
    /// even if a caller bypasses `is_encodable_aarch64`.
    #[test]
    fn test_assemble_shifted_arith_rejects_ror() {
        let mut assembler = AArch64Assembler::new();
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: ShiftKind::Ror,
                amount: 1,
            },
        };
        assert!(assembler.assemble_instructions(&[instr]).is_err());
    }
}

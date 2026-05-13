//! Dynasm-based assembler for the x86 backend.
//!
//! Two modes:
//! - `X86Assembler::new_64()` → uses `dynasmrt::x64::Assembler` and
//!   emits 64-bit instruction encodings.
//! - `X86Assembler::new_32()` → uses `dynasmrt::x86::Assembler` and
//!   emits 32-bit encodings (no REX prefix; R8..R15 not accessible).
//!
//! Capstone round-trip tests at the bottom verify byte-level correctness
//! for every variant: encode → disassemble → assert mnemonic + operand
//! strings match.

#![allow(dead_code)]
// The dynasm! macro auto-inserts `.into()` calls when accepting register
// indices, which clippy flags as `useless_conversion` whenever the supplied
// value is already the target type (here, `u8`). The conversion is dynasm's
// design, not ours, and there's no way to suppress it per-call without
// disfiguring the macro invocations. Allow at module scope.
#![allow(clippy::useless_conversion)]

use crate::isa::x86::{X86Instruction, X86Register};
use dynasm::dynasm;
use dynasmrt::DynasmApi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Mode {
    Mode64,
    Mode32,
}

pub struct X86Assembler {
    mode: X86Mode,
}

impl X86Assembler {
    pub fn new_64() -> Self {
        Self {
            mode: X86Mode::Mode64,
        }
    }

    pub fn new_32() -> Self {
        Self {
            mode: X86Mode::Mode32,
        }
    }

    pub fn mode(&self) -> X86Mode {
        self.mode
    }

    pub fn assemble_instructions(
        &mut self,
        instructions: &[X86Instruction],
    ) -> Result<Vec<u8>, String> {
        match self.mode {
            X86Mode::Mode64 => assemble_64(instructions),
            X86Mode::Mode32 => assemble_32(instructions),
        }
    }
}

fn reg_index(reg: X86Register) -> Result<u8, String> {
    reg.index()
        .ok_or_else(|| format!("register {:?} has no index", reg))
}

fn reg_index_32(reg: X86Register) -> Result<u8, String> {
    let i = reg_index(reg)?;
    if i >= 8 {
        return Err(format!("register {:?} not available in x86-32 mode", reg));
    }
    Ok(i)
}

fn assemble_64(instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
    let mut ops =
        dynasmrt::x64::Assembler::new().map_err(|e| format!("dynasm x64 init failed: {:?}", e))?;
    for instr in instructions {
        encode_64(&mut ops, instr)?;
    }
    let buf = ops
        .finalize()
        .map_err(|e| format!("dynasm finalize failed: {:?}", e))?;
    Ok(buf.to_vec())
}

fn assemble_32(instructions: &[X86Instruction]) -> Result<Vec<u8>, String> {
    let mut ops =
        dynasmrt::x86::Assembler::new().map_err(|e| format!("dynasm x86 init failed: {:?}", e))?;
    for instr in instructions {
        encode_32(&mut ops, instr)?;
    }
    let buf = ops
        .finalize()
        .map_err(|e| format!("dynasm finalize failed: {:?}", e))?;
    Ok(buf.to_vec())
}

fn encode_64(ops: &mut dynasmrt::x64::Assembler, instr: &X86Instruction) -> Result<(), String> {
    match instr {
        X86Instruction::MovReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; mov Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::MovImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            // Prefer the imm32 sign-extended encoding (5 bytes including
            // REX) when the immediate fits — Capstone shows this as
            // canonical "mov rax, 0x...". Fall back to MOVABS (10 bytes)
            // for the rare full 64-bit immediate case.
            if let Ok(i32_imm) = i32::try_from(*imm) {
                dynasm!(ops ; .arch x64 ; mov Rq(rd), i32_imm);
            } else {
                let imm = *imm;
                dynasm!(ops ; .arch x64 ; mov Rq(rd), QWORD imm);
            }
            Ok(())
        }
        X86Instruction::AddReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; add Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::AddImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; add Rq(rd), imm);
            Ok(())
        }
        X86Instruction::SubReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; sub Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::SubImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; sub Rq(rd), imm);
            Ok(())
        }
        X86Instruction::AndReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; and Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::AndImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; and Rq(rd), imm);
            Ok(())
        }
        X86Instruction::OrReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; or Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::OrImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; or Rq(rd), imm);
            Ok(())
        }
        X86Instruction::XorReg { rd, rs } => {
            let rd = reg_index(*rd)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; xor Rq(rd), Rq(rs));
            Ok(())
        }
        X86Instruction::XorImm { rd, imm } => {
            let rd = reg_index(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; xor Rq(rd), imm);
            Ok(())
        }
        X86Instruction::CmpReg { rn, rs } => {
            let rn = reg_index(*rn)?;
            let rs = reg_index(*rs)?;
            dynasm!(ops ; .arch x64 ; cmp Rq(rn), Rq(rs));
            Ok(())
        }
        X86Instruction::CmpImm { rn, imm } => {
            let rn = reg_index(*rn)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x64 ; cmp Rq(rn), imm);
            Ok(())
        }
    }
}

/// Truncate an `i64` immediate down to `i32` for the imm32-form opcodes.
/// Returns an error if the value would not be representable as a
/// sign-extended 32-bit immediate.
fn imm_i32(imm: i64) -> Result<i32, String> {
    i32::try_from(imm).map_err(|_| format!("immediate {} does not fit in 32 bits", imm))
}

fn encode_32(ops: &mut dynasmrt::x86::Assembler, instr: &X86Instruction) -> Result<(), String> {
    match instr {
        X86Instruction::MovReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; mov Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::MovImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; mov Rd(rd), imm);
            Ok(())
        }
        X86Instruction::AddReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; add Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::AddImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; add Rd(rd), imm);
            Ok(())
        }
        X86Instruction::SubReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; sub Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::SubImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; sub Rd(rd), imm);
            Ok(())
        }
        X86Instruction::AndReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; and Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::AndImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; and Rd(rd), imm);
            Ok(())
        }
        X86Instruction::OrReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; or Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::OrImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; or Rd(rd), imm);
            Ok(())
        }
        X86Instruction::XorReg { rd, rs } => {
            let rd = reg_index_32(*rd)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; xor Rd(rd), Rd(rs));
            Ok(())
        }
        X86Instruction::XorImm { rd, imm } => {
            let rd = reg_index_32(*rd)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; xor Rd(rd), imm);
            Ok(())
        }
        X86Instruction::CmpReg { rn, rs } => {
            let rn = reg_index_32(*rn)?;
            let rs = reg_index_32(*rs)?;
            dynasm!(ops ; .arch x86 ; cmp Rd(rn), Rd(rs));
            Ok(())
        }
        X86Instruction::CmpImm { rn, imm } => {
            let rn = reg_index_32(*rn)?;
            let imm = imm_i32(*imm)?;
            dynasm!(ops ; .arch x86 ; cmp Rd(rn), imm);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capstone::prelude::*;

    fn disasm_x86_64(bytes: &[u8]) -> Vec<(String, String)> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(bytes, 0x0).expect("disassemble");
        insns
            .iter()
            .map(|i| {
                (
                    i.mnemonic().unwrap_or("").to_string(),
                    i.op_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn disasm_x86_32(bytes: &[u8]) -> Vec<(String, String)> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()
            .expect("capstone init");
        let insns = cs.disasm_all(bytes, 0x0).expect("disassemble");
        insns
            .iter()
            .map(|i| {
                (
                    i.mnemonic().unwrap_or("").to_string(),
                    i.op_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn check_x86_32(instr: X86Instruction, expected_mnemonic: &str, expect_operands: &[&str]) {
        let mut asm = X86Assembler::new_32();
        let bytes = asm
            .assemble_instructions(&[instr])
            .expect("32-bit encoding succeeds");
        let disasm = disasm_x86_32(&bytes);
        assert_eq!(disasm.len(), 1);
        assert_eq!(
            disasm[0].0, expected_mnemonic,
            "mnemonic mismatch (operands: {})",
            disasm[0].1
        );
        for op in expect_operands {
            assert!(
                disasm[0].1.contains(op),
                "missing operand {} (got: {})",
                op,
                disasm[0].1
            );
        }
    }

    #[test]
    fn movreg_x86_32_uses_eax_form() {
        check_x86_32(
            X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "mov",
            &["eax", "ebx"],
        );
    }

    #[test]
    fn add_imm_x86_32() {
        check_x86_32(
            X86Instruction::AddImm {
                rd: X86Register::RCX,
                imm: 9,
            },
            "add",
            &["ecx", "9"],
        );
    }

    #[test]
    fn x86_32_rejects_extended_register() {
        let mut asm = X86Assembler::new_32();
        let err = asm
            .assemble_instructions(&[X86Instruction::MovReg {
                rd: X86Register::R8,
                rs: X86Register::RAX,
            }])
            .expect_err("R8 not addressable in 32-bit mode");
        assert!(
            err.contains("not available in x86-32"),
            "unexpected error: {}",
            err
        );
    }

    fn check_x86_64(instr: X86Instruction, expected_mnemonic: &str, expect_operands: &[&str]) {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[instr])
            .expect("encoding succeeds");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm.len(), 1, "expected one instruction");
        assert_eq!(
            disasm[0].0, expected_mnemonic,
            "mnemonic mismatch (operands: {})",
            disasm[0].1
        );
        for op in expect_operands {
            assert!(
                disasm[0].1.contains(op),
                "missing operand {} (got: {})",
                op,
                disasm[0].1
            );
        }
    }

    #[test]
    fn movimm_x86_64() {
        check_x86_64(
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 42,
            },
            "mov",
            &["rax", "0x2a"],
        );
    }

    #[test]
    fn add_variants_x86_64() {
        check_x86_64(
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "add",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 5,
            },
            "add",
            &["rax", "5"],
        );
    }

    #[test]
    fn sub_variants_x86_64() {
        check_x86_64(
            X86Instruction::SubReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "sub",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 5,
            },
            "sub",
            &["rax", "5"],
        );
    }

    #[test]
    fn and_or_xor_variants_x86_64() {
        check_x86_64(
            X86Instruction::AndReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "and",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::OrReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "or",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "xor",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::AndImm {
                rd: X86Register::RAX,
                imm: 0xff,
            },
            "and",
            &["rax", "0xff"],
        );
        check_x86_64(
            X86Instruction::OrImm {
                rd: X86Register::RAX,
                imm: 1,
            },
            "or",
            &["rax", "1"],
        );
        check_x86_64(
            X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm: 1,
            },
            "xor",
            &["rax", "1"],
        );
    }

    #[test]
    fn cmp_variants_x86_64() {
        check_x86_64(
            X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
            "cmp",
            &["rax", "rbx"],
        );
        check_x86_64(
            X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 7,
            },
            "cmp",
            &["rax", "7"],
        );
    }

    #[test]
    fn movreg_with_extended_register_r9() {
        check_x86_64(
            X86Instruction::MovReg {
                rd: X86Register::R9,
                rs: X86Register::RAX,
            },
            "mov",
            &["r9", "rax"],
        );
    }

    #[test]
    fn movreg_x86_64_round_trips_through_capstone() {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }])
            .expect("encode mov rax, rbx");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm.len(), 1);
        assert_eq!(disasm[0].0, "mov");
        // Capstone produces "rax, rbx" (Intel syntax).
        assert!(
            disasm[0].1.contains("rax") && disasm[0].1.contains("rbx"),
            "operands: {}",
            disasm[0].1
        );
    }

    #[test]
    fn mode_accessors_report_selected_backend() {
        assert_eq!(X86Assembler::new_64().mode(), X86Mode::Mode64);
        assert_eq!(X86Assembler::new_32().mode(), X86Mode::Mode32);
    }

    #[test]
    fn x86_32_encodes_all_minimal_variants() {
        let cases = [
            (
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "mov",
            ),
            (
                X86Instruction::AddReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "add",
            ),
            (
                X86Instruction::SubReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "sub",
            ),
            (
                X86Instruction::SubImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "sub",
            ),
            (
                X86Instruction::AndReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "and",
            ),
            (
                X86Instruction::AndImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "and",
            ),
            (
                X86Instruction::OrReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "or",
            ),
            (
                X86Instruction::OrImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "or",
            ),
            (
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "xor",
            ),
            (
                X86Instruction::XorImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
                "xor",
            ),
            (
                X86Instruction::CmpReg {
                    rn: X86Register::RAX,
                    rs: X86Register::RBX,
                },
                "cmp",
            ),
            (
                X86Instruction::CmpImm {
                    rn: X86Register::RAX,
                    imm: 1,
                },
                "cmp",
            ),
        ];

        for (instr, mnemonic) in cases {
            let mut asm = X86Assembler::new_32();
            let bytes = asm
                .assemble_instructions(&[instr])
                .unwrap_or_else(|e| panic!("{:?} should encode: {}", instr, e));
            let disasm = disasm_x86_32(&bytes);
            assert_eq!(disasm[0].0, mnemonic);
        }
    }

    #[test]
    fn x86_64_movabs_and_immediate_range_errors() {
        let mut asm = X86Assembler::new_64();
        let bytes = asm
            .assemble_instructions(&[X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect("movabs should encode full-width immediate");
        let disasm = disasm_x86_64(&bytes);
        assert_eq!(disasm[0].0, "movabs");

        let err = asm
            .assemble_instructions(&[X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect_err("imm32-only arithmetic should reject i64::MAX");
        assert!(err.contains("does not fit in 32 bits"));

        let mut asm32 = X86Assembler::new_32();
        let err = asm32
            .assemble_instructions(&[X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: i64::MAX,
            }])
            .expect_err("x86-32 mov imm requires imm32");
        assert!(err.contains("does not fit in 32 bits"));
    }
}

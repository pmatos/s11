//! Intel-syntax x86 assembly parser.
//!
//! Parses GNU/Intel-syntax x86 assembly text into the minimal-core
//! `X86Instruction` IR. Mirrors `src/parser/mod.rs::parse_assembly_string`
//! for the AArch64 path. `parse_x86_assembly_string` and the line-
//! classification helpers are unused today; they exist as the future
//! consumer surface for the deferred x86 LLM path (ADR-0004 decision 3
//! + #77 stage 1 step 13 deferral). Tests cover them so they stay
//! correct until the LLM x86 follow-up lands.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Operand, X86Register};
use crate::parser::ParseError;

/// Parse a single x86 register name (case-insensitive).
///
/// Width aliases (`eax`, `ax`, `al`) collapse to the canonical 64-bit
/// variant. Legacy high-byte aliases (`ah`, `bh`, `ch`, `dh`) are
/// intentionally excluded because the minimal x86 IR models the
/// low-byte/REX alias set.
pub fn parse_x86_register(reg_str: &str) -> Result<X86Register, String> {
    match reg_str.trim().to_lowercase().as_str() {
        "rax" | "eax" | "ax" | "al" => Ok(X86Register::RAX),
        "rcx" | "ecx" | "cx" | "cl" => Ok(X86Register::RCX),
        "rdx" | "edx" | "dx" | "dl" => Ok(X86Register::RDX),
        "rbx" | "ebx" | "bx" | "bl" => Ok(X86Register::RBX),
        "rsp" | "esp" | "sp" | "spl" => Ok(X86Register::RSP),
        "rbp" | "ebp" | "bp" | "bpl" => Ok(X86Register::RBP),
        "rsi" | "esi" | "si" | "sil" => Ok(X86Register::RSI),
        "rdi" | "edi" | "di" | "dil" => Ok(X86Register::RDI),
        "r8" | "r8d" | "r8w" | "r8b" => Ok(X86Register::R8),
        "r9" | "r9d" | "r9w" | "r9b" => Ok(X86Register::R9),
        "r10" | "r10d" | "r10w" | "r10b" => Ok(X86Register::R10),
        "r11" | "r11d" | "r11w" | "r11b" => Ok(X86Register::R11),
        "r12" | "r12d" | "r12w" | "r12b" => Ok(X86Register::R12),
        "r13" | "r13d" | "r13w" | "r13b" => Ok(X86Register::R13),
        "r14" | "r14d" | "r14w" | "r14b" => Ok(X86Register::R14),
        "r15" | "r15d" | "r15w" | "r15b" => Ok(X86Register::R15),
        _ => Err(format!("Unknown x86 register: {}", reg_str)),
    }
}

/// Parse an Intel-syntax operand string ("rax" or "42" or "0x2a").
pub fn parse_x86_operand(op_str: &str) -> Result<X86Operand, String> {
    let s = op_str.trim();
    if let Ok(reg) = parse_x86_register(s) {
        return Ok(X86Operand::Register(reg));
    }
    let imm = parse_x86_immediate(s)?;
    Ok(X86Operand::Immediate(imm))
}

pub fn parse_x86_immediate(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // Positive hex: parse via u64 then reinterpret as i64 with
        // two's-complement wrapping. Capstone's Intel-syntax
        // disassembler renders a sign-extended `imm = -1` operand as
        // the full-width `0xffffffffffffffff`, so any value with the
        // top bit set must be re-mapped to the corresponding negative
        // i64 to stay round-trippable.
        let u =
            u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex immediate: {}", s))?;
        Ok(u as i64)
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        // Negative hex: magnitude can be as large as 1<<63 (giving
        // i64::MIN). `i64::from_str_radix` rejects 0x8000_0000_0000_0000
        // positively. Parse via u64 and negate via wrapping_neg so
        // INT64_MIN survives.
        let abs =
            u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex immediate: {}", s))?;
        if abs > (1u64 << 63) {
            return Err(format!("Hex immediate {} out of i64 range", s));
        }
        Ok((abs as i64).wrapping_neg())
    } else {
        s.parse::<i64>()
            .map_err(|_| format!("Invalid immediate: {}", s))
    }
}

/// Convert a `(mnemonic, op_str)` pair (as produced by Capstone's
/// Intel-syntax disassembler) into an `X86Instruction`. Returns
/// `Ok(None)` for mnemonics outside the minimal core set.
pub fn x86_ir_from_mnemonic(
    mnemonic: &str,
    op_str: &str,
) -> Result<Option<X86Instruction>, String> {
    let mnemonic = mnemonic.trim().to_lowercase();
    // Reject unsupported mnemonics before attempting operand parsing so
    // shapes outside the minimal core (e.g. LEA `rax, [rbx+1]`) surface
    // as "unsupported mnemonic" rather than a confusing downstream
    // immediate parse error.
    if !matches!(
        mnemonic.as_str(),
        "mov" | "movabs" | "add" | "sub" | "and" | "or" | "xor" | "cmp"
    ) {
        return Ok(None);
    }
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Ok(None);
    }
    let rd = parse_x86_register(parts[0])?;
    let src_op = parse_x86_operand(parts[1])?;
    let make = |reg_form: fn(X86Register, X86Register) -> X86Instruction,
                imm_form: fn(X86Register, i64) -> X86Instruction|
     -> Result<Option<X86Instruction>, String> {
        Ok(Some(match src_op {
            X86Operand::Register(rs) => reg_form(rd, rs),
            X86Operand::Immediate(imm) => imm_form(rd, imm),
        }))
    };
    let make_cmp = |reg_form: fn(X86Register, X86Register) -> X86Instruction,
                    imm_form: fn(X86Register, i64) -> X86Instruction|
     -> Result<Option<X86Instruction>, String> {
        Ok(Some(match src_op {
            X86Operand::Register(rs) => reg_form(rd, rs),
            X86Operand::Immediate(imm) => imm_form(rd, imm),
        }))
    };
    match mnemonic.as_str() {
        "mov" | "movabs" => make(
            |rd, rs| X86Instruction::MovReg { rd, rs },
            |rd, imm| X86Instruction::MovImm { rd, imm },
        ),
        "add" => make(
            |rd, rs| X86Instruction::AddReg { rd, rs },
            |rd, imm| X86Instruction::AddImm { rd, imm },
        ),
        "sub" => make(
            |rd, rs| X86Instruction::SubReg { rd, rs },
            |rd, imm| X86Instruction::SubImm { rd, imm },
        ),
        "and" => make(
            |rd, rs| X86Instruction::AndReg { rd, rs },
            |rd, imm| X86Instruction::AndImm { rd, imm },
        ),
        "or" => make(
            |rd, rs| X86Instruction::OrReg { rd, rs },
            |rd, imm| X86Instruction::OrImm { rd, imm },
        ),
        "xor" => make(
            |rd, rs| X86Instruction::XorReg { rd, rs },
            |rd, imm| X86Instruction::XorImm { rd, imm },
        ),
        "cmp" => make_cmp(
            |rn, rs| X86Instruction::CmpReg { rn, rs },
            |rn, imm| X86Instruction::CmpImm { rn, imm },
        ),
        _ => Ok(None),
    }
}

/// Parse an Intel-syntax x86 assembly text into a sequence of
/// `X86Instruction`s. Mirrors `crate::parser::parse_assembly_string`
/// for the AArch64 path.
///
/// Recognised lines: empty, comments (`;`, `//`, `#`), labels
/// (`name:`), directives (`.foo`), and 2-operand instructions whose
/// mnemonic is one of the seven the minimal-core IR supports
/// (mov, add, sub, and, or, xor, cmp). Anything else is a parse error.
pub fn parse_x86_assembly_string(
    content: &str,
    source_name: String,
) -> Result<Vec<X86Instruction>, ParseError> {
    let mut instructions = Vec::new();
    for (line_idx, raw) in content.lines().enumerate() {
        let line_number = line_idx + 1;
        let line = strip_x86_comments(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || is_x86_label(trimmed) || is_x86_directive(trimmed) {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let mnemonic = parts.next().unwrap_or("");
        let op_str = parts.next().unwrap_or("").trim();
        if mnemonic.is_empty() {
            continue;
        }
        match x86_ir_from_mnemonic(mnemonic, op_str) {
            Ok(Some(instr)) => instructions.push(instr),
            Ok(None) => {
                return Err(ParseError::new(
                    line_number,
                    format!("unsupported x86 mnemonic: '{}'", mnemonic.to_lowercase()),
                    raw,
                ));
            }
            Err(msg) => {
                return Err(ParseError::new(line_number, msg, raw));
            }
        }
    }
    if instructions.is_empty() {
        return Err(ParseError::new(
            0,
            "no instructions found in input",
            source_name,
        ));
    }
    Ok(instructions)
}

fn strip_x86_comments(line: &str) -> &str {
    let mut end = line.len();
    if let Some(pos) = line.find("//") {
        end = end.min(pos);
    }
    if let Some(pos) = line.find(';') {
        end = end.min(pos);
    }
    if let Some(pos) = line.find('#') {
        end = end.min(pos);
    }
    &line[..end]
}

fn is_x86_label(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.ends_with(':') && !trimmed.is_empty()
}

fn is_x86_directive(line: &str) -> bool {
    line.trim().starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Register parsing (moved from main.rs::x86_parser_tests) ----

    #[test]
    fn parse_register_handles_aliased_names() {
        assert_eq!(parse_x86_register("rax").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("eax").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("RAX").unwrap(), X86Register::RAX);
        assert_eq!(parse_x86_register("r10").unwrap(), X86Register::R10);
        assert_eq!(parse_x86_register("r10d").unwrap(), X86Register::R10);
        assert!(parse_x86_register("zmm0").is_err());
    }

    #[test]
    fn parse_immediate_int64_boundaries() {
        assert_eq!(
            parse_x86_immediate("-0x8000000000000000").unwrap(),
            i64::MIN
        );
        assert_eq!(parse_x86_immediate("0x7FFFFFFFFFFFFFFF").unwrap(), i64::MAX);
        assert_eq!(parse_x86_immediate("0xffffffffffffffff").unwrap(), -1i64);
        assert_eq!(parse_x86_immediate("0xfffffffffffffffe").unwrap(), -2i64);
        assert_eq!(parse_x86_immediate("0x8000000000000000").unwrap(), i64::MIN);
        assert!(parse_x86_immediate("0x10000000000000000").is_err());
        assert!(parse_x86_immediate("-0x8000000000000001").is_err());
    }

    #[test]
    fn parse_immediate_supports_hex_decimal_signed() {
        assert_eq!(parse_x86_immediate("42").unwrap(), 42);
        assert_eq!(parse_x86_immediate("-1").unwrap(), -1);
        assert_eq!(parse_x86_immediate("0x2a").unwrap(), 42);
        assert_eq!(parse_x86_immediate("0XFF").unwrap(), 255);
        assert_eq!(parse_x86_immediate("-0x10").unwrap(), -16);
    }

    #[test]
    fn parse_operand_routes_to_register_or_immediate() {
        assert_eq!(
            parse_x86_operand("rdi").unwrap(),
            X86Operand::Register(X86Register::RDI)
        );
        assert_eq!(parse_x86_operand("7").unwrap(), X86Operand::Immediate(7));
    }

    #[test]
    fn x86_ir_recognises_seven_mnemonics() {
        let cases = [
            (
                "mov",
                "rax, rbx",
                X86Instruction::MovReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "mov",
                "rax, 42",
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 42,
                },
            ),
            (
                "add",
                "rax, rbx",
                X86Instruction::AddReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "sub",
                "rax, 1",
                X86Instruction::SubImm {
                    rd: X86Register::RAX,
                    imm: 1,
                },
            ),
            (
                "and",
                "rax, rbx",
                X86Instruction::AndReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "or",
                "rax, 0",
                X86Instruction::OrImm {
                    rd: X86Register::RAX,
                    imm: 0,
                },
            ),
            (
                "xor",
                "rax, rax",
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RAX,
                },
            ),
            (
                "cmp",
                "rax, 5",
                X86Instruction::CmpImm {
                    rn: X86Register::RAX,
                    imm: 5,
                },
            ),
        ];
        for (mn, ops, expected) in cases {
            let got = x86_ir_from_mnemonic(mn, ops).unwrap().unwrap();
            assert_eq!(got, expected, "{} {}", mn, ops);
        }
    }

    #[test]
    fn x86_ir_unsupported_mnemonic_returns_none() {
        assert!(x86_ir_from_mnemonic("ret", "").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("jmp", "0x1234").unwrap().is_none());
        // Two-operand "shl" not in the minimal set.
        assert!(x86_ir_from_mnemonic("shl", "rax, 1").unwrap().is_none());
    }

    // ---- New: parse_x86_assembly_string ----

    #[test]
    fn assembly_string_parses_single_instruction() {
        let result = parse_x86_assembly_string("mov rax, rbx", "test".to_string()).unwrap();
        assert_eq!(
            result,
            vec![X86Instruction::MovReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }]
        );
    }

    #[test]
    fn assembly_string_parses_multi_line_sequence() {
        let asm = "mov rax, 0\nxor rax, rax\nadd rax, 1";
        let result = parse_x86_assembly_string(asm, "test".to_string()).unwrap();
        assert_eq!(
            result,
            vec![
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 0
                },
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RAX
                },
                X86Instruction::AddImm {
                    rd: X86Register::RAX,
                    imm: 1
                },
            ]
        );
    }

    #[test]
    fn assembly_string_skips_comments_labels_and_directives() {
        let asm = "\
            .text\n\
            entry:\n\
            mov rax, rbx  ; copy rbx into rax\n\
            xor rax, rax  // zero it back out\n\
            # full-line comment\n\
            \n\
            cmp rax, 0\n";
        let result = parse_x86_assembly_string(asm, "test".to_string()).unwrap();
        assert_eq!(
            result,
            vec![
                X86Instruction::MovReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX
                },
                X86Instruction::XorReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RAX
                },
                X86Instruction::CmpImm {
                    rn: X86Register::RAX,
                    imm: 0
                },
            ]
        );
    }

    #[test]
    fn assembly_string_rejects_unsupported_mnemonic() {
        let err = parse_x86_assembly_string("mov rax, rbx\nlea rax, [rbx+1]", "t".to_string())
            .unwrap_err();
        assert_eq!(err.line_number, 2);
        assert!(
            err.message.contains("unsupported"),
            "expected 'unsupported' in error, got: {}",
            err.message
        );
    }

    #[test]
    fn assembly_string_rejects_empty_input() {
        assert!(parse_x86_assembly_string("", "t".to_string()).is_err());
        assert!(parse_x86_assembly_string("   \n\n; only comments\n", "t".to_string()).is_err());
    }

    #[test]
    fn assembly_string_reports_line_number_on_operand_error() {
        let err = parse_x86_assembly_string("mov rax, rbx\nadd rax, not_a_reg", "t".to_string())
            .unwrap_err();
        assert_eq!(err.line_number, 2);
    }

    #[test]
    fn assembly_string_accepts_width_suffixed_register_aliases() {
        // Intel-syntax disassemblers sometimes render 32-bit operations
        // using EAX-style aliases even when the underlying instruction
        // is 64-bit-wide for our purposes. Ensure aliases collapse.
        let result =
            parse_x86_assembly_string("mov eax, ebx\nxor r10d, r10d", "t".to_string()).unwrap();
        assert_eq!(
            result,
            vec![
                X86Instruction::MovReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX
                },
                X86Instruction::XorReg {
                    rd: X86Register::R10,
                    rs: X86Register::R10
                },
            ]
        );
    }
}

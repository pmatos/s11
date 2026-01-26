//! Assembly text parser for AArch64 instructions
//!
//! Parses GNU assembler syntax into the IR representation.

use std::fmt;
use std::path::Path;

use crate::ir::{Condition, Instruction, Operand, Register};

/// Parse error with location information
#[derive(Debug, Clone)]
pub struct ParseError {
    pub line_number: usize,
    pub column: Option<usize>,
    pub message: String,
    pub line_content: String,
}

impl ParseError {
    pub fn new(
        line_number: usize,
        message: impl Into<String>,
        line_content: impl Into<String>,
    ) -> Self {
        Self {
            line_number,
            column: None,
            message: message.into(),
            line_content: line_content.into(),
        }
    }

    pub fn with_column(mut self, column: usize) -> Self {
        self.column = Some(column);
        self
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(col) = self.column {
            write!(
                f,
                "line {}, column {}: {}\n  | {}\n  | {}^",
                self.line_number,
                col,
                self.message,
                self.line_content,
                " ".repeat(col.saturating_sub(1))
            )
        } else {
            write!(
                f,
                "line {}: {}\n  | {}",
                self.line_number, self.message, self.line_content
            )
        }
    }
}

impl std::error::Error for ParseError {}

/// Result of parsing a single line
#[derive(Debug)]
pub enum LineResult {
    /// An instruction was parsed
    Instruction(Instruction),
    /// Line was empty, a comment, label, or directive (skip it)
    Skip,
}

/// Parse a register name (case-insensitive)
pub fn parse_register(s: &str) -> Result<Register, String> {
    match s.to_lowercase().as_str() {
        "x0" => Ok(Register::X0),
        "x1" => Ok(Register::X1),
        "x2" => Ok(Register::X2),
        "x3" => Ok(Register::X3),
        "x4" => Ok(Register::X4),
        "x5" => Ok(Register::X5),
        "x6" => Ok(Register::X6),
        "x7" => Ok(Register::X7),
        "x8" => Ok(Register::X8),
        "x9" => Ok(Register::X9),
        "x10" => Ok(Register::X10),
        "x11" => Ok(Register::X11),
        "x12" => Ok(Register::X12),
        "x13" => Ok(Register::X13),
        "x14" => Ok(Register::X14),
        "x15" => Ok(Register::X15),
        "x16" => Ok(Register::X16),
        "x17" => Ok(Register::X17),
        "x18" => Ok(Register::X18),
        "x19" => Ok(Register::X19),
        "x20" => Ok(Register::X20),
        "x21" => Ok(Register::X21),
        "x22" => Ok(Register::X22),
        "x23" => Ok(Register::X23),
        "x24" => Ok(Register::X24),
        "x25" => Ok(Register::X25),
        "x26" => Ok(Register::X26),
        "x27" => Ok(Register::X27),
        "x28" => Ok(Register::X28),
        "x29" | "fp" => Ok(Register::X29),
        "x30" | "lr" => Ok(Register::X30),
        "xzr" | "wzr" => Ok(Register::XZR),
        "sp" => Ok(Register::SP),
        _ => Err(format!("unknown register: {}", s)),
    }
}

/// Parse an immediate value (with or without # prefix, hex or decimal)
pub fn parse_immediate(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let s = s.strip_prefix('#').unwrap_or(s);
    let s = s.trim();

    if s.is_empty() {
        return Err("empty immediate value".to_string());
    }

    // Handle hex
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex immediate '{}': {}", s, e))
    } else if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16)
            .map(|v| -v)
            .map_err(|e| format!("invalid hex immediate '{}': {}", s, e))
    } else {
        // Decimal
        s.parse::<i64>()
            .map_err(|e| format!("invalid immediate '{}': {}", s, e))
    }
}

/// Parse an operand (register or immediate)
pub fn parse_operand(s: &str) -> Result<Operand, String> {
    let s = s.trim();

    // If starts with # it's definitely an immediate
    if s.starts_with('#') {
        return Ok(Operand::Immediate(parse_immediate(s)?));
    }

    // Try register first, fall back to immediate
    match parse_register(s) {
        Ok(reg) => Ok(Operand::Register(reg)),
        Err(_) => {
            // Try as immediate (bare number)
            match parse_immediate(s) {
                Ok(imm) => Ok(Operand::Immediate(imm)),
                Err(_) => Err(format!("invalid operand: {}", s)),
            }
        }
    }
}

/// Parse a condition code (case-insensitive)
pub fn parse_condition(s: &str) -> Result<Condition, String> {
    match s.to_lowercase().as_str() {
        "eq" => Ok(Condition::EQ),
        "ne" => Ok(Condition::NE),
        "cs" | "hs" => Ok(Condition::CS),
        "cc" | "lo" => Ok(Condition::CC),
        "mi" => Ok(Condition::MI),
        "pl" => Ok(Condition::PL),
        "vs" => Ok(Condition::VS),
        "vc" => Ok(Condition::VC),
        "hi" => Ok(Condition::HI),
        "ls" => Ok(Condition::LS),
        "ge" => Ok(Condition::GE),
        "lt" => Ok(Condition::LT),
        "gt" => Ok(Condition::GT),
        "le" => Ok(Condition::LE),
        "al" => Ok(Condition::AL),
        "nv" => Ok(Condition::NV),
        _ => Err(format!("unknown condition code: {}", s)),
    }
}

/// Strip comments from a line (handles //, ;, and @)
fn strip_comments(line: &str) -> &str {
    // Find the first comment marker
    let mut end = line.len();

    if let Some(pos) = line.find("//") {
        end = end.min(pos);
    }
    if let Some(pos) = line.find(';') {
        end = end.min(pos);
    }
    if let Some(pos) = line.find('@') {
        end = end.min(pos);
    }

    &line[..end]
}

/// Check if a line is a label definition
fn is_label(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.ends_with(':') && !trimmed.is_empty()
}

/// Check if a line is a directive
fn is_directive(line: &str) -> bool {
    line.trim().starts_with('.')
}

/// Split operands by comma, handling whitespace
fn split_operands(operands_str: &str) -> Vec<&str> {
    operands_str.split(',').map(|s| s.trim()).collect()
}

/// Parse a MOV instruction
fn parse_mov(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("mov requires 2 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let src = parse_operand(operands[1])?;

    match src {
        Operand::Register(rn) => Ok(Instruction::MovReg { rd, rn }),
        Operand::Immediate(imm) => Ok(Instruction::MovImm { rd, imm }),
    }
}

/// Parse ADD instruction
fn parse_add(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("add requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;

    Ok(Instruction::Add { rd, rn, rm })
}

/// Parse SUB instruction
fn parse_sub(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("sub requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;

    Ok(Instruction::Sub { rd, rn, rm })
}

/// Parse AND instruction
fn parse_and(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("and requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;

    Ok(Instruction::And { rd, rn, rm })
}

/// Parse ORR instruction
fn parse_orr(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("orr requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;

    Ok(Instruction::Orr { rd, rn, rm })
}

/// Parse EOR instruction
fn parse_eor(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("eor requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;

    Ok(Instruction::Eor { rd, rn, rm })
}

/// Parse LSL instruction
fn parse_lsl(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("lsl requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let shift = parse_operand(operands[2])?;

    Ok(Instruction::Lsl { rd, rn, shift })
}

/// Parse LSR instruction
fn parse_lsr(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("lsr requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let shift = parse_operand(operands[2])?;

    Ok(Instruction::Lsr { rd, rn, shift })
}

/// Parse ASR instruction
fn parse_asr(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("asr requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let shift = parse_operand(operands[2])?;

    Ok(Instruction::Asr { rd, rn, shift })
}

/// Parse MUL instruction
fn parse_mul(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("mul requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Mul { rd, rn, rm })
}

/// Parse SDIV instruction
fn parse_sdiv(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("sdiv requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Sdiv { rd, rn, rm })
}

/// Parse UDIV instruction
fn parse_udiv(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("udiv requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Udiv { rd, rn, rm })
}

/// Parse CMP instruction
fn parse_cmp(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("cmp requires 2 operands, got {}", operands.len()));
    }

    let rn = parse_register(operands[0])?;
    let rm = parse_operand(operands[1])?;

    Ok(Instruction::Cmp { rn, rm })
}

/// Parse CMN instruction
fn parse_cmn(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("cmn requires 2 operands, got {}", operands.len()));
    }

    let rn = parse_register(operands[0])?;
    let rm = parse_operand(operands[1])?;

    Ok(Instruction::Cmn { rn, rm })
}

/// Parse TST instruction
fn parse_tst(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("tst requires 2 operands, got {}", operands.len()));
    }

    let rn = parse_register(operands[0])?;
    let rm = parse_operand(operands[1])?;

    Ok(Instruction::Tst { rn, rm })
}

/// Parse CSEL instruction
fn parse_csel(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("csel requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let cond = parse_condition(operands[3])?;

    Ok(Instruction::Csel { rd, rn, rm, cond })
}

/// Parse CSINC instruction
fn parse_csinc(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("csinc requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let cond = parse_condition(operands[3])?;

    Ok(Instruction::Csinc { rd, rn, rm, cond })
}

/// Parse CSINV instruction
fn parse_csinv(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("csinv requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let cond = parse_condition(operands[3])?;

    Ok(Instruction::Csinv { rd, rn, rm, cond })
}

/// Parse CSNEG instruction
fn parse_csneg(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("csneg requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let cond = parse_condition(operands[3])?;

    Ok(Instruction::Csneg { rd, rn, rm, cond })
}

/// Parse a single line of assembly
pub fn parse_line(line: &str) -> Result<LineResult, String> {
    // Strip comments first
    let line = strip_comments(line);
    let trimmed = line.trim();

    // Skip empty lines
    if trimmed.is_empty() {
        return Ok(LineResult::Skip);
    }

    // Skip labels
    if is_label(trimmed) {
        return Ok(LineResult::Skip);
    }

    // Skip directives
    if is_directive(trimmed) {
        return Ok(LineResult::Skip);
    }

    // Parse instruction: split into opcode and operands
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let opcode = parts.next().unwrap_or("").to_lowercase();
    let operands_str = parts.next().unwrap_or("").trim();

    if opcode.is_empty() {
        return Ok(LineResult::Skip);
    }

    let operands = if operands_str.is_empty() {
        vec![]
    } else {
        split_operands(operands_str)
    };

    let instruction = match opcode.as_str() {
        "mov" => parse_mov(&operands)?,
        "add" => parse_add(&operands)?,
        "sub" => parse_sub(&operands)?,
        "and" => parse_and(&operands)?,
        "orr" => parse_orr(&operands)?,
        "eor" => parse_eor(&operands)?,
        "lsl" => parse_lsl(&operands)?,
        "lsr" => parse_lsr(&operands)?,
        "asr" => parse_asr(&operands)?,
        "mul" => parse_mul(&operands)?,
        "sdiv" => parse_sdiv(&operands)?,
        "udiv" => parse_udiv(&operands)?,
        "cmp" => parse_cmp(&operands)?,
        "cmn" => parse_cmn(&operands)?,
        "tst" => parse_tst(&operands)?,
        "csel" => parse_csel(&operands)?,
        "csinc" => parse_csinc(&operands)?,
        "csinv" => parse_csinv(&operands)?,
        "csneg" => parse_csneg(&operands)?,
        _ => return Err(format!("unknown instruction: {}", opcode)),
    };

    // Validate encoding
    if !instruction.is_encodable_aarch64() {
        return Err(format!(
            "instruction cannot be encoded in AArch64: {}",
            instruction
        ));
    }

    Ok(LineResult::Instruction(instruction))
}

/// Parse an assembly file into a sequence of instructions
pub fn parse_assembly_file(path: &Path) -> Result<Vec<Instruction>, ParseError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ParseError::new(
            0,
            format!("failed to read file: {}", e),
            path.display().to_string(),
        )
    })?;

    parse_assembly_string(&content, path.display().to_string())
}

/// Parse an assembly string into a sequence of instructions
pub fn parse_assembly_string(
    content: &str,
    source_name: String,
) -> Result<Vec<Instruction>, ParseError> {
    let mut instructions = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_number = line_num + 1; // 1-indexed

        match parse_line(line) {
            Ok(LineResult::Instruction(instr)) => {
                instructions.push(instr);
            }
            Ok(LineResult::Skip) => {
                // Nothing to do
            }
            Err(msg) => {
                return Err(ParseError::new(line_number, msg, line));
            }
        }
    }

    if instructions.is_empty() {
        return Err(ParseError::new(
            0,
            "no instructions found in file",
            source_name,
        ));
    }

    Ok(instructions)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Register parsing tests
    #[test]
    fn test_parse_register() {
        assert_eq!(parse_register("x0").unwrap(), Register::X0);
        assert_eq!(parse_register("X0").unwrap(), Register::X0);
        assert_eq!(parse_register("x30").unwrap(), Register::X30);
        assert_eq!(parse_register("xzr").unwrap(), Register::XZR);
        assert_eq!(parse_register("XZR").unwrap(), Register::XZR);
        assert_eq!(parse_register("sp").unwrap(), Register::SP);
        assert_eq!(parse_register("SP").unwrap(), Register::SP);
        assert_eq!(parse_register("fp").unwrap(), Register::X29);
        assert_eq!(parse_register("lr").unwrap(), Register::X30);
    }

    #[test]
    fn test_parse_register_invalid() {
        assert!(parse_register("x32").is_err());
        assert!(parse_register("r0").is_err());
        assert!(parse_register("").is_err());
    }

    // Immediate parsing tests
    #[test]
    fn test_parse_immediate() {
        assert_eq!(parse_immediate("#42").unwrap(), 42);
        assert_eq!(parse_immediate("42").unwrap(), 42);
        assert_eq!(parse_immediate("#-1").unwrap(), -1);
        assert_eq!(parse_immediate("-1").unwrap(), -1);
        assert_eq!(parse_immediate("#0x10").unwrap(), 16);
        assert_eq!(parse_immediate("0x10").unwrap(), 16);
        assert_eq!(parse_immediate("#0xFF").unwrap(), 255);
        assert_eq!(parse_immediate("-0x10").unwrap(), -16);
    }

    #[test]
    fn test_parse_immediate_invalid() {
        assert!(parse_immediate("").is_err());
        assert!(parse_immediate("#").is_err());
        assert!(parse_immediate("abc").is_err());
    }

    // Operand parsing tests
    #[test]
    fn test_parse_operand() {
        assert_eq!(
            parse_operand("x0").unwrap(),
            Operand::Register(Register::X0)
        );
        assert_eq!(parse_operand("#42").unwrap(), Operand::Immediate(42));
        assert_eq!(parse_operand("42").unwrap(), Operand::Immediate(42));
    }

    // Condition parsing tests
    #[test]
    fn test_parse_condition() {
        assert_eq!(parse_condition("eq").unwrap(), Condition::EQ);
        assert_eq!(parse_condition("EQ").unwrap(), Condition::EQ);
        assert_eq!(parse_condition("ne").unwrap(), Condition::NE);
        assert_eq!(parse_condition("lt").unwrap(), Condition::LT);
        assert_eq!(parse_condition("gt").unwrap(), Condition::GT);
        assert_eq!(parse_condition("hs").unwrap(), Condition::CS);
        assert_eq!(parse_condition("lo").unwrap(), Condition::CC);
    }

    // Line parsing tests
    #[test]
    fn test_parse_line_mov() {
        match parse_line("mov x0, x1").unwrap() {
            LineResult::Instruction(Instruction::MovReg { rd, rn }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X1);
            }
            _ => panic!("expected MovReg"),
        }

        match parse_line("mov x0, #42").unwrap() {
            LineResult::Instruction(Instruction::MovImm { rd, imm }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(imm, 42);
            }
            _ => panic!("expected MovImm"),
        }
    }

    #[test]
    fn test_parse_line_add() {
        match parse_line("add x0, x1, x2").unwrap() {
            LineResult::Instruction(Instruction::Add { rd, rn, rm }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X1);
                assert_eq!(rm, Operand::Register(Register::X2));
            }
            _ => panic!("expected Add"),
        }

        match parse_line("add x0, x1, #1").unwrap() {
            LineResult::Instruction(Instruction::Add { rd, rn, rm }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X1);
                assert_eq!(rm, Operand::Immediate(1));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn test_parse_line_csel() {
        match parse_line("csel x0, x1, x2, eq").unwrap() {
            LineResult::Instruction(Instruction::Csel { rd, rn, rm, cond }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X1);
                assert_eq!(rm, Register::X2);
                assert_eq!(cond, Condition::EQ);
            }
            _ => panic!("expected Csel"),
        }
    }

    #[test]
    fn test_parse_line_skip() {
        assert!(matches!(parse_line("").unwrap(), LineResult::Skip));
        assert!(matches!(parse_line("   ").unwrap(), LineResult::Skip));
        assert!(matches!(
            parse_line("// comment").unwrap(),
            LineResult::Skip
        ));
        assert!(matches!(parse_line("; comment").unwrap(), LineResult::Skip));
        assert!(matches!(parse_line("@ comment").unwrap(), LineResult::Skip));
        assert!(matches!(parse_line("label:").unwrap(), LineResult::Skip));
        assert!(matches!(parse_line(".text").unwrap(), LineResult::Skip));
        assert!(matches!(
            parse_line(".global _start").unwrap(),
            LineResult::Skip
        ));
    }

    #[test]
    fn test_parse_line_with_comment() {
        match parse_line("add x0, x1, #1 // increment").unwrap() {
            LineResult::Instruction(Instruction::Add { rd, rn, rm }) => {
                assert_eq!(rd, Register::X0);
                assert_eq!(rn, Register::X1);
                assert_eq!(rm, Operand::Immediate(1));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn test_parse_line_encoding_validation() {
        // Valid ADD immediate
        assert!(parse_line("add x0, x1, #4095").is_ok());

        // Invalid ADD immediate (out of range)
        assert!(parse_line("add x0, x1, #4096").is_err());

        // AND with immediate not encodable (we don't support bitmask encoding)
        assert!(parse_line("and x0, x1, #1").is_err());
    }

    // Full assembly parsing tests
    #[test]
    fn test_parse_assembly_string() {
        let asm = r#"
            .text
            .global _start
        _start:
            mov x0, x1          // copy
            add x0, x0, #1      ; increment
        "#;

        let instructions = parse_assembly_string(asm, "test".to_string()).unwrap();
        assert_eq!(instructions.len(), 2);
        assert!(matches!(instructions[0], Instruction::MovReg { .. }));
        assert!(matches!(instructions[1], Instruction::Add { .. }));
    }

    #[test]
    fn test_parse_assembly_string_empty() {
        let asm = "// just a comment\n.text\n";
        let result = parse_assembly_string(asm, "test".to_string());
        assert!(result.is_err());
    }
}

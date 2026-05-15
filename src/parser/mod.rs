//! Assembly text parser for AArch64 instructions
//!
//! Parses GNU assembler syntax into the IR representation.

use std::fmt;
use std::path::Path;

use crate::ir::instructions::MOVW_LEGAL_SHIFTS;
use crate::ir::{Condition, Instruction, Operand, Register, ShiftKind};

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

    #[allow(dead_code)]
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

/// Structured failure mode for `parse_line`. Distinguishes "the parser doesn't
/// recognise this opcode" from any other parse failure (operand parsing,
/// encoding-range violations, etc.) so consumers can act on the unknown
/// mnemonic without string-matching the human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseLineError {
    /// The leading token is not one of the parser's supported mnemonics.
    /// The string is the offending mnemonic, lowercased.
    UnknownInstruction(String),
    /// Any other parse failure (operand error, encoding error, etc.).
    Other(String),
}

impl fmt::Display for ParseLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseLineError::UnknownInstruction(m) => write!(f, "unknown instruction: {}", m),
            ParseLineError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for ParseLineError {}

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
        Operand::ShiftedRegister { .. } | Operand::ExtendedRegister { .. } => {
            Err("mov second operand must be a register or immediate".to_string())
        }
    }
}

/// Parse MVN instruction
fn parse_mvn(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("mvn requires 2 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rm = parse_register(operands[1])?;
    Ok(Instruction::Mvn { rd, rm })
}

/// Parse a single-source bit-manipulation instruction (CLZ/CLS/RBIT/REV/REV32/REV16).
fn parse_unary_rd_rn<F>(mnemonic: &str, operands: &[&str], build: F) -> Result<Instruction, String>
where
    F: FnOnce(Register, Register) -> Instruction,
{
    if operands.len() != 2 {
        return Err(format!(
            "{} requires 2 operands, got {}",
            mnemonic,
            operands.len()
        ));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(build(rd, rn))
}

/// Parse NEG instruction
fn parse_neg(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("neg requires 2 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rm = parse_register(operands[1])?;
    Ok(Instruction::Neg { rd, rm })
}

/// Parse NEGS instruction
fn parse_negs(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("negs requires 2 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rm = parse_register(operands[1])?;
    Ok(Instruction::Negs { rd, rm })
}

/// Parse BIC instruction (register-only rm)
fn parse_bic(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("bic requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = Operand::Register(parse_register(operands[2])?);
    Ok(Instruction::Bic { rd, rn, rm })
}

/// Parse BICS instruction (register-only rm)
fn parse_bics(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("bics requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = Operand::Register(parse_register(operands[2])?);
    Ok(Instruction::Bics { rd, rn, rm })
}

/// Parse ORN instruction (register-only rm)
fn parse_orn(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("orn requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = Operand::Register(parse_register(operands[2])?);
    Ok(Instruction::Orn { rd, rn, rm })
}

/// Parse EON instruction (register-only rm)
fn parse_eon(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("eon requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = Operand::Register(parse_register(operands[2])?);
    Ok(Instruction::Eon { rd, rn, rm })
}

/// Parse ADDS instruction
fn parse_adds(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("adds requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;
    Ok(Instruction::Adds { rd, rn, rm })
}

/// Parse SUBS instruction
fn parse_subs(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("subs requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_operand(operands[2])?;
    Ok(Instruction::Subs { rd, rn, rm })
}

/// Parse ANDS instruction (register-only rm)
fn parse_ands(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("ands requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = Operand::Register(parse_register(operands[2])?);
    Ok(Instruction::Ands { rd, rn, rm })
}

/// Parse CSET instruction: `cset rd, cond`
fn parse_cset(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("cset requires 2 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let cond = parse_condition(operands[1])?;
    Ok(Instruction::Cset { rd, cond })
}

/// Parse CSETM instruction: `csetm rd, cond`
fn parse_csetm(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("csetm requires 2 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let cond = parse_condition(operands[1])?;
    Ok(Instruction::Csetm { rd, cond })
}

/// Parse ROR instruction: `ror rd, rn, #imm` or `ror rd, rn, rm`
fn parse_ror(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("ror requires 3 operands, got {}", operands.len()));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let shift = parse_operand(operands[2])?;
    Ok(Instruction::Ror { rd, rn, shift })
}

/// Parse the operand list for a move-wide-immediate mnemonic (MOVN / MOVZ /
/// MOVK). All three share the same operand grammar:
/// `<mnem> rd, #imm` or `<mnem> rd, #imm, lsl #shift`. The `mnem` argument is
/// used only in error messages so the diagnostic still names the original
/// mnemonic the user typed.
fn parse_movw_operands(mnem: &str, operands: &[&str]) -> Result<(Register, u16, u8), String> {
    if operands.len() != 2 && operands.len() != 3 {
        return Err(format!(
            "{} requires 2 or 3 operands (rd, #imm[, lsl #shift]), got {}",
            mnem,
            operands.len()
        ));
    }
    let rd = parse_register(operands[0])?;
    let imm_val = match parse_operand(operands[1])? {
        Operand::Immediate(v) => v,
        Operand::Register(_)
        | Operand::ShiftedRegister { .. }
        | Operand::ExtendedRegister { .. } => {
            return Err(format!("{} second operand must be an immediate", mnem));
        }
    };
    if !(0..=0xFFFF).contains(&imm_val) {
        return Err(format!("{} immediate {} out of u16 range", mnem, imm_val));
    }
    let imm = imm_val as u16;

    let shift = if operands.len() == 2 {
        0u8
    } else {
        // Expect form "lsl #N" (whitespace-separated within the 3rd operand).
        let tail = operands[2].trim();
        let mut parts = tail.splitn(2, char::is_whitespace);
        let kw = parts.next().unwrap_or("").trim();
        let rest = parts.next().unwrap_or("").trim();
        if !kw.eq_ignore_ascii_case("lsl") {
            return Err(format!(
                "{} shift form must be `lsl #N`, got `{}`",
                mnem, tail
            ));
        }
        let s = match parse_operand(rest)? {
            Operand::Immediate(v) => v,
            Operand::Register(_)
        | Operand::ShiftedRegister { .. }
        | Operand::ExtendedRegister { .. } => {
                return Err(format!("{} shift must be an immediate", mnem));
            }
        };
        let s_u8 = u8::try_from(s).ok();
        if !s_u8.is_some_and(|v| MOVW_LEGAL_SHIFTS.contains(&v)) {
            return Err(format!("{} shift {} must be one of 0/16/32/48", mnem, s));
        }
        s_u8.unwrap()
    };

    Ok((rd, imm, shift))
}

/// Parse MOVN instruction: `movn rd, #imm` or `movn rd, #imm, lsl #shift`.
fn parse_movn(operands: &[&str]) -> Result<Instruction, String> {
    let (rd, imm, shift) = parse_movw_operands("movn", operands)?;
    Ok(Instruction::MovN { rd, imm, shift })
}

/// Parse MOVZ instruction: `movz rd, #imm` or `movz rd, #imm, lsl #shift`.
fn parse_movz(operands: &[&str]) -> Result<Instruction, String> {
    let (rd, imm, shift) = parse_movw_operands("movz", operands)?;
    Ok(Instruction::MovZ { rd, imm, shift })
}

/// Parse MOVK instruction: `movk rd, #imm` or `movk rd, #imm, lsl #shift`.
/// MOVK preserves the unmodified 16-bit lanes of rd, so callers must treat
/// rd as live-in.
fn parse_movk(operands: &[&str]) -> Result<Instruction, String> {
    let (rd, imm, shift) = parse_movw_operands("movk", operands)?;
    Ok(Instruction::MovK { rd, imm, shift })
}

/// Parse the trailing shift modifier (`"<kind> #<amount>"`) attached to a
/// shifted-register operand. Returns the assembled `Operand::ShiftedRegister`.
/// `tail` is the single comma-separated trailing token after the rm register
/// (already trimmed by `split_operands`); do NOT re-split on commas here.
fn parse_shifted_register_tail(mnem: &str, reg: Register, tail: &str) -> Result<Operand, String> {
    let tail = tail.trim();
    let mut parts = tail.splitn(2, char::is_whitespace);
    let kw = parts.next().unwrap_or("").trim();
    let rest = parts.next().unwrap_or("").trim();
    let kind = match kw.to_ascii_lowercase().as_str() {
        "lsl" => ShiftKind::Lsl,
        "lsr" => ShiftKind::Lsr,
        "asr" => ShiftKind::Asr,
        "ror" => ShiftKind::Ror,
        _ => {
            return Err(format!(
                "{} shift kind must be one of lsl/lsr/asr/ror, got `{}`",
                mnem, kw
            ));
        }
    };
    let amt = match parse_operand(rest)? {
        Operand::Immediate(v) => v,
        Operand::Register(_)
        | Operand::ShiftedRegister { .. }
        | Operand::ExtendedRegister { .. } => {
            return Err(format!("{} shift amount must be an immediate", mnem));
        }
    };
    if !(0..=63).contains(&amt) {
        return Err(format!(
            "{} shift amount {} out of range (0..=63)",
            mnem, amt
        ));
    }
    Ok(Operand::ShiftedRegister {
        reg,
        kind,
        amount: amt as u8,
    })
}

/// Parse the rm slot for the 3-operand arith/logical instructions
/// (Add/Sub/And/Orr/Eor). Returns either the existing register/immediate form
/// or a new shifted-register operand if a 4th comma-separated token is present.
fn parse_rm_3op(mnem: &str, operands: &[&str]) -> Result<Operand, String> {
    if operands.len() == 3 {
        parse_operand(operands[2])
    } else if operands.len() == 4 {
        let reg = parse_register(operands[2])?;
        parse_shifted_register_tail(mnem, reg, operands[3])
    } else {
        Err(format!(
            "{} requires 3 or 4 operands, got {}",
            mnem,
            operands.len()
        ))
    }
}

/// Parse ADD instruction
fn parse_add(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_3op("add", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Add { rd, rn, rm })
}

/// Parse SUB instruction
fn parse_sub(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_3op("sub", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Sub { rd, rn, rm })
}

/// Parse AND instruction
fn parse_and(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_3op("and", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::And { rd, rn, rm })
}

/// Parse ORR instruction
fn parse_orr(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_3op("orr", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Orr { rd, rn, rm })
}

/// Parse EOR instruction
fn parse_eor(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_3op("eor", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
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

/// Parse MADD instruction (4 register operands: rd, rn, rm, ra)
fn parse_madd(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("madd requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let ra = parse_register(operands[3])?;

    Ok(Instruction::Madd { rd, rn, rm, ra })
}

/// Parse MSUB instruction (4 register operands: rd, rn, rm, ra)
fn parse_msub(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 4 {
        return Err(format!("msub requires 4 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;
    let ra = parse_register(operands[3])?;

    Ok(Instruction::Msub { rd, rn, rm, ra })
}

/// Parse MNEG instruction (3 register operands: rd, rn, rm)
fn parse_mneg(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("mneg requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Mneg { rd, rn, rm })
}

/// Parse SMULH instruction (3 register operands: rd, rn, rm)
fn parse_smulh(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("smulh requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Smulh { rd, rn, rm })
}

/// Parse UMULH instruction (3 register operands: rd, rn, rm)
fn parse_umulh(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("umulh requires 3 operands, got {}", operands.len()));
    }

    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let rm = parse_register(operands[2])?;

    Ok(Instruction::Umulh { rd, rn, rm })
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

/// Parse the rm slot for the 2-operand comparison instructions
/// (Cmp/Cmn/Tst). Returns either the existing register/immediate form or a new
/// shifted-register operand if a 3rd comma-separated token is present.
fn parse_rm_2op(mnem: &str, operands: &[&str]) -> Result<Operand, String> {
    if operands.len() == 2 {
        parse_operand(operands[1])
    } else if operands.len() == 3 {
        let reg = parse_register(operands[1])?;
        parse_shifted_register_tail(mnem, reg, operands[2])
    } else {
        Err(format!(
            "{} requires 2 or 3 operands, got {}",
            mnem,
            operands.len()
        ))
    }
}

/// Parse CMP instruction
fn parse_cmp(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_2op("cmp", operands)?;
    let rn = parse_register(operands[0])?;
    Ok(Instruction::Cmp { rn, rm })
}

/// Parse CMN instruction
fn parse_cmn(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_2op("cmn", operands)?;
    let rn = parse_register(operands[0])?;
    Ok(Instruction::Cmn { rn, rm })
}

/// Parse TST instruction
fn parse_tst(operands: &[&str]) -> Result<Instruction, String> {
    let rm = parse_rm_2op("tst", operands)?;
    let rn = parse_register(operands[0])?;
    Ok(Instruction::Tst { rn, rm })
}

/// Parse CCMP instruction: `ccmp Xn, <Xm | #imm5>, #nzcv, cond`.
fn parse_ccmp(operands: &[&str]) -> Result<Instruction, String> {
    parse_ccmp_like(operands, "ccmp").map(|(rn, rm, nzcv, cond)| Instruction::Ccmp {
        rn,
        rm,
        nzcv,
        cond,
    })
}

/// Parse CCMN instruction: `ccmn Xn, <Xm | #imm5>, #nzcv, cond`.
fn parse_ccmn(operands: &[&str]) -> Result<Instruction, String> {
    parse_ccmp_like(operands, "ccmn").map(|(rn, rm, nzcv, cond)| Instruction::Ccmn {
        rn,
        rm,
        nzcv,
        cond,
    })
}

fn parse_ccmp_like(
    operands: &[&str],
    mnem: &str,
) -> Result<(Register, Operand, u8, Condition), String> {
    if operands.len() != 4 {
        return Err(format!(
            "{} requires 4 operands, got {}",
            mnem,
            operands.len()
        ));
    }
    let rn = parse_register(operands[0])?;
    let rm = parse_operand(operands[1])?;
    if let Operand::Immediate(imm) = rm {
        if !(0..=31).contains(&imm) {
            return Err(format!("{} imm5 {} out of range (0..=31)", mnem, imm));
        }
    }
    let nzcv_raw = parse_immediate(operands[2])?;
    if !(0..=15).contains(&nzcv_raw) {
        return Err(format!("{} nzcv {} out of range (0..=15)", mnem, nzcv_raw));
    }
    let cond = parse_condition(operands[3])?;
    Ok((rn, rm, nzcv_raw as u8, cond))
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
pub fn parse_line(line: &str) -> Result<LineResult, ParseLineError> {
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
        "mov" => parse_mov(&operands).map_err(ParseLineError::Other)?,
        "add" => parse_add(&operands).map_err(ParseLineError::Other)?,
        "sub" => parse_sub(&operands).map_err(ParseLineError::Other)?,
        "and" => parse_and(&operands).map_err(ParseLineError::Other)?,
        "orr" => parse_orr(&operands).map_err(ParseLineError::Other)?,
        "eor" => parse_eor(&operands).map_err(ParseLineError::Other)?,
        "lsl" => parse_lsl(&operands).map_err(ParseLineError::Other)?,
        "lsr" => parse_lsr(&operands).map_err(ParseLineError::Other)?,
        "asr" => parse_asr(&operands).map_err(ParseLineError::Other)?,
        "mul" => parse_mul(&operands).map_err(ParseLineError::Other)?,
        "madd" => parse_madd(&operands).map_err(ParseLineError::Other)?,
        "msub" => parse_msub(&operands).map_err(ParseLineError::Other)?,
        "mneg" => parse_mneg(&operands).map_err(ParseLineError::Other)?,
        "smulh" => parse_smulh(&operands).map_err(ParseLineError::Other)?,
        "umulh" => parse_umulh(&operands).map_err(ParseLineError::Other)?,
        "sdiv" => parse_sdiv(&operands).map_err(ParseLineError::Other)?,
        "udiv" => parse_udiv(&operands).map_err(ParseLineError::Other)?,
        "cmp" => parse_cmp(&operands).map_err(ParseLineError::Other)?,
        "cmn" => parse_cmn(&operands).map_err(ParseLineError::Other)?,
        "tst" => parse_tst(&operands).map_err(ParseLineError::Other)?,
        "ccmp" => parse_ccmp(&operands).map_err(ParseLineError::Other)?,
        "ccmn" => parse_ccmn(&operands).map_err(ParseLineError::Other)?,
        "csel" => parse_csel(&operands).map_err(ParseLineError::Other)?,
        "csinc" => parse_csinc(&operands).map_err(ParseLineError::Other)?,
        "csinv" => parse_csinv(&operands).map_err(ParseLineError::Other)?,
        "csneg" => parse_csneg(&operands).map_err(ParseLineError::Other)?,
        "mvn" => parse_mvn(&operands).map_err(ParseLineError::Other)?,
        "neg" => parse_neg(&operands).map_err(ParseLineError::Other)?,
        "negs" => parse_negs(&operands).map_err(ParseLineError::Other)?,
        "movn" => parse_movn(&operands).map_err(ParseLineError::Other)?,
        "movz" => parse_movz(&operands).map_err(ParseLineError::Other)?,
        "movk" => parse_movk(&operands).map_err(ParseLineError::Other)?,
        "bic" => parse_bic(&operands).map_err(ParseLineError::Other)?,
        "bics" => parse_bics(&operands).map_err(ParseLineError::Other)?,
        "orn" => parse_orn(&operands).map_err(ParseLineError::Other)?,
        "eon" => parse_eon(&operands).map_err(ParseLineError::Other)?,
        "adds" => parse_adds(&operands).map_err(ParseLineError::Other)?,
        "subs" => parse_subs(&operands).map_err(ParseLineError::Other)?,
        "ands" => parse_ands(&operands).map_err(ParseLineError::Other)?,
        "cset" => parse_cset(&operands).map_err(ParseLineError::Other)?,
        "csetm" => parse_csetm(&operands).map_err(ParseLineError::Other)?,
        "ror" => parse_ror(&operands).map_err(ParseLineError::Other)?,
        "clz" => parse_unary_rd_rn("clz", &operands, |rd, rn| Instruction::Clz { rd, rn })
            .map_err(ParseLineError::Other)?,
        "cls" => parse_unary_rd_rn("cls", &operands, |rd, rn| Instruction::Cls { rd, rn })
            .map_err(ParseLineError::Other)?,
        "rbit" => parse_unary_rd_rn("rbit", &operands, |rd, rn| Instruction::Rbit { rd, rn })
            .map_err(ParseLineError::Other)?,
        "rev" => parse_unary_rd_rn("rev", &operands, |rd, rn| Instruction::Rev { rd, rn })
            .map_err(ParseLineError::Other)?,
        "rev32" => parse_unary_rd_rn("rev32", &operands, |rd, rn| Instruction::Rev32 { rd, rn })
            .map_err(ParseLineError::Other)?,
        "rev16" => parse_unary_rd_rn("rev16", &operands, |rd, rn| Instruction::Rev16 { rd, rn })
            .map_err(ParseLineError::Other)?,
        "uxtb" => parse_unary_rd_rn("uxtb", &operands, |rd, rn| Instruction::Uxtb { rd, rn })
            .map_err(ParseLineError::Other)?,
        "sxtb" => parse_unary_rd_rn("sxtb", &operands, |rd, rn| Instruction::Sxtb { rd, rn })
            .map_err(ParseLineError::Other)?,
        "uxth" => parse_unary_rd_rn("uxth", &operands, |rd, rn| Instruction::Uxth { rd, rn })
            .map_err(ParseLineError::Other)?,
        "sxth" => parse_unary_rd_rn("sxth", &operands, |rd, rn| Instruction::Sxth { rd, rn })
            .map_err(ParseLineError::Other)?,
        "sxtw" => parse_unary_rd_rn("sxtw", &operands, |rd, rn| Instruction::Sxtw { rd, rn })
            .map_err(ParseLineError::Other)?,
        _ => return Err(ParseLineError::UnknownInstruction(opcode)),
    };

    // Validate encoding
    if !instruction.is_encodable_aarch64() {
        return Err(ParseLineError::Other(format!(
            "instruction cannot be encoded in AArch64: {}",
            instruction
        )));
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
            Err(err) => {
                return Err(ParseError::new(line_number, err.to_string(), line));
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
    use crate::ir::ShiftKind;
    use crate::test_utils::TempFile;

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

    fn parse_one(line: &str) -> Instruction {
        match parse_line(line).expect("parse_line failed") {
            LineResult::Instruction(i) => i,
            other => panic!("expected Instruction, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_shifted_register_three_operand_arith() {
        // add x0, x1, x2, lsl #3
        let instr = parse_one("add x0, x1, x2, lsl #3");
        assert_eq!(
            instr,
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind: ShiftKind::Lsl,
                    amount: 3,
                },
            }
        );
        // round-trip via Display
        assert_eq!(format!("{}", instr), "add x0, x1, x2, lsl #3");
    }

    #[test]
    fn test_parse_shifted_register_all_kinds_case_insensitive() {
        // Case-insensitive shift keyword (matches MOVW precedent).
        for (text, kind, amount) in [
            ("sub x0, x1, x2, LSL #5", ShiftKind::Lsl, 5),
            ("and x0, x1, x2, lsr #7", ShiftKind::Lsr, 7),
            ("orr x0, x1, x2, ASR #1", ShiftKind::Asr, 1),
            ("eor x0, x1, x2, ror #16", ShiftKind::Ror, 16),
        ] {
            let instr = parse_one(text);
            let rm = match instr {
                Instruction::Sub { rm, .. }
                | Instruction::And { rm, .. }
                | Instruction::Orr { rm, .. }
                | Instruction::Eor { rm, .. } => rm,
                _ => panic!("expected an arithmetic/logical instr"),
            };
            assert_eq!(
                rm,
                Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind,
                    amount
                }
            );
        }
    }

    #[test]
    fn test_parse_shifted_register_two_operand_cmp() {
        // cmp/cmn/tst use 3 comma tokens: rn, rm, "<kind> #amt"
        let instr = parse_one("cmp x1, x2, lsl #4");
        assert_eq!(
            instr,
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind: ShiftKind::Lsl,
                    amount: 4,
                },
            }
        );

        let instr = parse_one("tst x3, x4, ror #8");
        assert_eq!(
            instr,
            Instruction::Tst {
                rn: Register::X3,
                rm: Operand::ShiftedRegister {
                    reg: Register::X4,
                    kind: ShiftKind::Ror,
                    amount: 8,
                },
            }
        );
    }

    #[test]
    fn test_parse_shifted_register_amount_out_of_range() {
        // amount > 63 must be rejected.
        assert!(parse_line("add x0, x1, x2, lsl #64").is_err());
    }

    #[test]
    fn test_parse_shifted_register_invalid_kind() {
        assert!(parse_line("add x0, x1, x2, foo #3").is_err());
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

    /// Round-trip Display → parser for every Tier 1 mnemonic.
    #[test]
    fn test_tier1_display_parser_roundtrip() {
        use crate::ir::types::Condition;
        let cases: Vec<Instruction> = vec![
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
                imm: 0xFFFF,
                shift: 0,
            },
            Instruction::MovN {
                rd: Register::X0,
                imm: 1,
                shift: 16,
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
                rm: Operand::Immediate(5),
            },
            Instruction::Subs {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Ands {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cset {
                rd: Register::X0,
                cond: Condition::EQ,
            },
            Instruction::Csetm {
                rd: Register::X3,
                cond: Condition::NE,
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Immediate(5),
            },
            Instruction::Ror {
                rd: Register::X0,
                rn: Register::X1,
                shift: Operand::Register(Register::X2),
            },
        ];
        for instr in cases {
            let printed = format!("{}", instr);
            match parse_line(&printed) {
                Ok(LineResult::Instruction(parsed)) => assert_eq!(
                    parsed, instr,
                    "Round-trip mismatch: printed `{}` parsed back as `{}`",
                    printed, parsed
                ),
                other => panic!("Failed to parse `{}` round-trip: {:?}", printed, other),
            }
        }
    }

    #[test]
    fn parse_all_aarch64_register_names() {
        for idx in 0..=30 {
            let name = format!("x{}", idx);
            assert_eq!(
                parse_register(&name).unwrap(),
                Register::from_index(idx).unwrap()
            );
        }
        assert_eq!(parse_register("wzr").unwrap(), Register::XZR);
        assert_eq!(parse_register("fp").unwrap(), Register::X29);
        assert_eq!(parse_register("lr").unwrap(), Register::X30);
    }

    #[test]
    fn parse_all_condition_codes_and_aliases() {
        let cases = [
            ("eq", Condition::EQ),
            ("ne", Condition::NE),
            ("cs", Condition::CS),
            ("hs", Condition::CS),
            ("cc", Condition::CC),
            ("lo", Condition::CC),
            ("mi", Condition::MI),
            ("pl", Condition::PL),
            ("vs", Condition::VS),
            ("vc", Condition::VC),
            ("hi", Condition::HI),
            ("ls", Condition::LS),
            ("ge", Condition::GE),
            ("lt", Condition::LT),
            ("gt", Condition::GT),
            ("le", Condition::LE),
            ("al", Condition::AL),
            ("nv", Condition::NV),
        ];
        for (text, cond) in cases {
            assert_eq!(parse_condition(text).unwrap(), cond);
            assert_eq!(parse_condition(&text.to_uppercase()).unwrap(), cond);
        }
        assert!(parse_condition("bad").is_err());
    }

    #[test]
    fn parse_ccmp_rejects_out_of_range_nzcv() {
        let line = "ccmp x1, x2, #16, eq";
        let result = parse_line(line);
        assert!(result.is_err(), "nzcv > 15 must be rejected");
    }

    #[test]
    fn parse_ccmp_rejects_out_of_range_imm5() {
        let line = "ccmp x1, #32, #0, eq";
        let result = parse_line(line);
        assert!(result.is_err(), "imm5 > 31 must be rejected");
    }

    #[test]
    fn parse_line_covers_all_core_mnemonics() {
        let cases = [
            ("sub x0, x1, #3", "sub x0, x1, #3"),
            ("and x0, x1, x2", "and x0, x1, x2"),
            ("orr x0, x1, x2", "orr x0, x1, x2"),
            ("eor x0, x1, x2", "eor x0, x1, x2"),
            ("lsl x0, x1, #4", "lsl x0, x1, #4"),
            ("lsr x0, x1, x2", "lsr x0, x1, x2"),
            ("asr x0, x1, #8", "asr x0, x1, #8"),
            ("mul x0, x1, x2", "mul x0, x1, x2"),
            ("madd x0, x1, x2, x3", "madd x0, x1, x2, x3"),
            ("msub x0, x1, x2, x3", "msub x0, x1, x2, x3"),
            ("mneg x0, x1, x2", "mneg x0, x1, x2"),
            ("smulh x0, x1, x2", "smulh x0, x1, x2"),
            ("umulh x0, x1, x2", "umulh x0, x1, x2"),
            ("sdiv x0, x1, x2", "sdiv x0, x1, x2"),
            ("udiv x0, x1, x2", "udiv x0, x1, x2"),
            ("cmp x1, #5", "cmp x1, #5"),
            ("cmn x1, x2", "cmn x1, x2"),
            ("tst x1, x2", "tst x1, x2"),
            ("ccmp x1, x2, #5, eq", "ccmp x1, x2, #5, eq"),
            ("ccmp x1, #15, #3, ne", "ccmp x1, #15, #3, ne"),
            ("ccmn x1, x2, #0, lt", "ccmn x1, x2, #0, lt"),
            ("csinc x0, x1, x2, ne", "csinc x0, x1, x2, ne"),
            ("csinv x0, x1, x2, lt", "csinv x0, x1, x2, lt"),
            ("csneg x0, x1, x2, ge", "csneg x0, x1, x2, ge"),
            ("clz x0, x1", "clz x0, x1"),
            ("cls x0, x1", "cls x0, x1"),
            ("rbit x0, x1", "rbit x0, x1"),
            ("rev x0, x1", "rev x0, x1"),
            ("rev32 x0, x1", "rev32 x0, x1"),
            ("rev16 x0, x1", "rev16 x0, x1"),
        ];

        for (line, display) in cases {
            let parsed = match parse_line(line).unwrap() {
                LineResult::Instruction(instr) => instr,
                LineResult::Skip => panic!("unexpected skip for {}", line),
            };
            assert_eq!(format!("{}", parsed), display);
        }
    }

    #[test]
    fn parse_line_wrong_arity_reaches_each_parser_error() {
        for mnemonic in [
            "mov", "mvn", "neg", "negs", "bic", "bics", "orn", "eon", "adds", "subs", "ands",
            "cset", "csetm", "ror", "movn", "movz", "movk", "add", "sub", "and", "orr", "eor",
            "lsl", "lsr", "asr", "mul", "madd", "msub", "mneg", "smulh", "umulh", "sdiv", "udiv",
            "cmp", "cmn", "tst", "csel", "csinc", "csinv", "csneg", "clz", "cls", "rbit", "rev",
            "rev32", "rev16",
        ] {
            assert!(
                matches!(parse_line(mnemonic), Err(ParseLineError::Other(_))),
                "{} should reject missing operands",
                mnemonic
            );
        }
        assert!(matches!(
            parse_line("definitely_unknown"),
            Err(ParseLineError::UnknownInstruction(m)) if m == "definitely_unknown"
        ));
    }

    #[test]
    fn parse_movn_rejects_bad_forms() {
        for line in [
            "movn x0",
            "movn x0, x1",
            "movn x0, #65536",
            "movn x0, #1, asr #16",
            "movn x0, #1, lsl x2",
            "movn x0, #1, lsl #8",
        ] {
            assert!(parse_line(line).is_err(), "{} should fail", line);
        }
    }

    #[test]
    fn parse_movz_and_movk_accept_canonical_forms() {
        let cases = [
            ("movz x0, #0x1234", "movz x0, #4660"),
            ("movz x0, #0xFFFF, lsl #48", "movz x0, #65535, lsl #48"),
            ("movk x1, #0", "movk x1, #0"),
            ("movk x1, #0x5678, lsl #16", "movk x1, #22136, lsl #16"),
        ];
        for (line, display) in cases {
            let parsed = match parse_line(line).unwrap() {
                LineResult::Instruction(instr) => instr,
                LineResult::Skip => panic!("unexpected skip for {}", line),
            };
            assert_eq!(format!("{}", parsed), display);
        }
    }

    #[test]
    fn parse_movz_and_movk_reject_bad_forms() {
        // Same grammar as MOVN: out-of-range imm, illegal shift, illegal
        // shift kind, register shift operand, and missing operands all fail.
        for line in [
            "movz x0",
            "movk x0",
            "movz x0, x1",
            "movk x0, x1",
            "movz x0, #65536",
            "movk x0, #65536",
            "movz x0, #1, lsl #8",
            "movk x0, #1, lsl #24",
            "movz x0, #1, asr #16",
            "movk x0, #1, lsl x2",
        ] {
            assert!(parse_line(line).is_err(), "{} should fail", line);
        }
    }

    #[test]
    fn parse_error_display_includes_optional_column_marker() {
        let err = ParseError::new(3, "bad operand", "add x0").with_column(5);
        let rendered = err.to_string();
        assert!(rendered.contains("line 3, column 5"));
        assert!(rendered.contains("^"));
    }

    #[test]
    fn parse_assembly_file_reads_file_and_reports_read_errors() {
        let file = TempFile::new("s11-parser-coverage", "s", "mov x0, x1\nadd x0, x0, #1\n");
        let parsed = parse_assembly_file(file.path()).unwrap();
        assert_eq!(parsed.len(), 2);

        let missing = file.path().with_extension("missing");
        let err = parse_assembly_file(&missing).unwrap_err();
        assert!(err.to_string().contains("failed to read file"));
    }

    #[test]
    fn parse_sxtw_standalone() {
        let parsed = match parse_line("sxtw x0, x1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
            }
        );
        assert_eq!(format!("{}", parsed), "sxtw x0, x1");
    }

    #[test]
    fn parse_sxth_standalone() {
        let parsed = match parse_line("sxth x0, x1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            }
        );
        assert_eq!(format!("{}", parsed), "sxth x0, x1");
    }

    #[test]
    fn parse_uxth_standalone() {
        let parsed = match parse_line("uxth x0, x1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            }
        );
        assert_eq!(format!("{}", parsed), "uxth x0, x1");
    }

    #[test]
    fn parse_sxtb_standalone() {
        let parsed = match parse_line("sxtb x0, x1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            }
        );
        assert_eq!(format!("{}", parsed), "sxtb x0, x1");
    }

    #[test]
    fn parse_uxtb_standalone() {
        // Issue #60: the standalone UXTB mnemonic produces Instruction::Uxtb.
        let parsed = match parse_line("uxtb x0, x1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            }
        );
        assert_eq!(format!("{}", parsed), "uxtb x0, x1");
    }
}

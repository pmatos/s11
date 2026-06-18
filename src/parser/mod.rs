//! Assembly text parser for AArch64 instructions
//!
//! Parses GNU assembler syntax into the IR representation. The x86
//! Intel-syntax parser lives in the [`x86`] submodule.
//!
//! Issue #77 stage 3 step 25 wraps this module's `parse_line` in a thin
//! `AArch64Parser` newtype implementing `ISAParser<Instruction>` (a new
//! associated type to be added on `ISA`). The contract is byte-for-byte
//! identical — the newtype just dispatches through the trait. `convert_to_ir`
//! in main.rs continues to delegate to `parse_line` per the project
//! CLAUDE.md invariant. RISC-V gets `convert_to_riscv_ir` (binary path only;
//! no asm-text parser until a follow-up). Blocked on step 23's RISC-V
//! semantics work.

use std::fmt;
use std::path::Path;

use crate::ir::instructions::MOVW_LEGAL_SHIFTS;
use crate::ir::types::NORMAL_CONDITIONS;
use crate::ir::{Condition, Instruction, LabelId, Operand, Register, RegisterWidth, ShiftKind};

pub mod x86;

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
    let lower = s.to_lowercase();

    if let Some(raw_index) = lower.strip_prefix('x')
        && !raw_index.is_empty()
        && raw_index.bytes().all(|b| b.is_ascii_digit())
        && (raw_index == "0" || !raw_index.starts_with('0'))
        && let Ok(index) = raw_index.parse::<u8>()
        && index <= 30
    {
        return Ok(Register::from_index(index).expect("valid AArch64 register index"));
    }

    match lower.as_str() {
        "fp" => Ok(Register::X29),
        "lr" => Ok(Register::X30),
        "xzr" | "wzr" => Ok(Register::XZR),
        "sp" => Ok(Register::SP),
        _ => Err(format!("unknown register: {}", s)),
    }
}

/// Parse a register for scoped W/X grammar slots.
///
/// Accepts the generic register set, numbered W registers as aliases for the
/// same physical registers, and WSP for places where the surrounding parser
/// carries the architectural width or W/X operand contract.
pub fn parse_w_or_x_register(s: &str) -> Result<Register, String> {
    if let Ok(reg) = parse_register(s) {
        return Ok(reg);
    }

    let lower = s.to_lowercase();
    if let Some(raw_index) = lower.strip_prefix('w')
        && !raw_index.is_empty()
        && raw_index.bytes().all(|b| b.is_ascii_digit())
        && (raw_index == "0" || !raw_index.starts_with('0'))
        && let Ok(index) = raw_index.parse::<u8>()
        && index <= 30
    {
        return Ok(Register::from_index(index).expect("valid AArch64 register index"));
    }

    match lower.as_str() {
        "wsp" => Ok(Register::SP),
        _ => Err(format!("unknown register: {}", s)),
    }
}

fn parse_sized_register(s: &str) -> Result<(Register, RegisterWidth), String> {
    let lower = s.to_lowercase();
    match lower.as_str() {
        "wzr" => return Ok((Register::XZR, RegisterWidth::W32)),
        "wsp" => return Ok((Register::SP, RegisterWidth::W32)),
        _ => {}
    }

    if let Some(raw_index) = lower.strip_prefix('w')
        && !raw_index.is_empty()
        && raw_index.bytes().all(|b| b.is_ascii_digit())
        && (raw_index == "0" || !raw_index.starts_with('0'))
        && let Ok(index) = raw_index.parse::<u8>()
        && index <= 30
    {
        return Ok((
            Register::from_index(index).expect("valid W register index"),
            RegisterWidth::W32,
        ));
    }

    parse_register(s).map(|register| (register, RegisterWidth::X64))
}

fn parse_same_width_registers(
    mnem: &str,
    operands: &[&str],
) -> Result<(Register, Register, RegisterWidth), String> {
    let (rd, rd_width) = parse_sized_register(operands[0])?;
    let (rn, rn_width) = parse_sized_register(operands[1])?;
    if rd_width != rn_width {
        return Err(format!(
            "{} operands must use matching register widths",
            mnem
        ));
    }
    Ok((rd, rn, rd_width))
}

fn parse_sized_operand(mnem: &str, operand: &str, width: RegisterWidth) -> Result<Operand, String> {
    if operand.trim().starts_with('#') {
        return Ok(Operand::Immediate(parse_immediate(operand)?));
    }
    if let Ok(imm) = parse_immediate(operand) {
        return Ok(Operand::Immediate(imm));
    }

    let (reg, reg_width) = parse_sized_register(operand)?;
    if reg_width != width {
        return Err(format!(
            "{} operands must use matching register widths",
            mnem
        ));
    }
    Ok(Operand::Register(reg))
}

/// Parse an immediate value (with or without # prefix, hex or decimal)
pub fn parse_immediate(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let s = s.strip_prefix('#').unwrap_or(s);
    let s = s.trim();

    if s.is_empty() {
        return Err("empty immediate value".to_string());
    }

    // Handle hex. Positive hex parses as u64 then reinterprets as i64 so that
    // high-bit logical-immediate masks (e.g., 0x8000_0000_0000_0000) round-trip
    // from Capstone text into the IR — i64::from_str_radix would reject them as
    // overflow.
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map(|v| v as i64)
            .map_err(|e| format!("invalid hex immediate '{}': {}", s, e))
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

/// Split operands by comma, handling whitespace. Bracket-aware: commas
/// inside `[ ... ]` (memory-operand grammar) are kept inside the same
/// token. See ADR-0007.
fn split_operands(operands_str: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = operands_str.as_bytes();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(operands_str[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(operands_str[start..].trim());
    parts
}

/// Parse a MOV instruction
fn parse_mov(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("mov requires 2 operands, got {}", operands.len()));
    }

    if let Ok((rd, RegisterWidth::W32)) = parse_sized_register(operands[0]) {
        if let Ok(imm) = parse_immediate(operands[1]) {
            return Ok(Instruction::Orr {
                rd,
                rn: Register::XZR,
                rm: Operand::Immediate(imm),
                width: RegisterWidth::W32,
            });
        }
        let (rn, rn_width) = parse_sized_register(operands[1])?;
        if rn_width != RegisterWidth::W32 {
            return Err("mov operands must use matching register widths".to_string());
        }
        return Ok(Instruction::MovRegW { rd, rn });
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

/// Parse the standalone sign/zero-extend mnemonics SXTB/SXTH/SXTW/UXTB/UXTH.
///
/// ARM ARM / Capstone canonical syntax:
///
/// - `UXTB Wd, Wn` / `UXTH Wd, Wn` — both operands W-form. The IR models
///   these as 64-bit ops with the upper 32 bits zeroed (which is the W-form
///   semantics on AArch64), so X-spelling for rd is also accepted.
/// - `SXTB Xd, Wn` / `SXTH Xd, Wn` / `SXTW Xd, Wn` — X-dest, W-src. There is
///   also a 32-bit `SXTB Wd, Wn` architectural form which writes only Wd and
///   zeroes the upper half of Xd — that is *not* what the IR models, so
///   `sxtb w0, w1` is rejected by this parser to avoid silent semantic
///   erasure (codex P1 on #144).
///
/// The IR stores everything as 64-bit X-registers; the semantics layer masks
/// to the architectural width. The W-form acceptance is scoped to this
/// helper so non-extend opcodes keep rejecting bare W-form names.
fn parse_unary_extend<F>(
    mnemonic: &str,
    operands: &[&str],
    allow_w_dest: bool,
    build: F,
) -> Result<Instruction, String>
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
    // Rn is W-form (or X for the IR's X-spelling fallback) for every kind.
    let rn = parse_w_or_x_register(operands[1])?;
    let rd = if allow_w_dest {
        parse_w_or_x_register(operands[0])?
    } else {
        let rd_str = operands[0].trim();
        // Reject W-form rd (e.g. `sxtb w0, w1`) before delegating to
        // `parse_register`. WZR is also W-form but it's an alias for XZR
        // that several callers still use, so allow it.
        let is_w_form = rd_str
            .as_bytes()
            .first()
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'w'))
            && !rd_str.eq_ignore_ascii_case("wzr");
        if is_w_form {
            return Err(format!(
                "{} destination must be X-form (the W-form `{} {}, ...` is a different 32-bit \
                 architectural instruction that this IR does not model)",
                mnemonic, mnemonic, rd_str
            ));
        }
        parse_register(rd_str)?
    };
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
    if operands.len() == 3 {
        let (rd, rn, width) = parse_same_width_registers("ands", operands)?;
        let rm = match width {
            RegisterWidth::W32 => Operand::Immediate(parse_immediate(operands[2])?),
            RegisterWidth::X64 => parse_operand(operands[2])?,
        };
        return Ok(Instruction::Ands { rd, rn, rm, width });
    }

    let rm = parse_rm_3op("ands", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Ands {
        rd,
        rn,
        rm,
        width: RegisterWidth::X64,
    })
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

/// Parse the trailing extend modifier (`"<kind> #<shift>"`) attached to an
/// extended-register operand. Returns the assembled `Operand::ExtendedRegister`.
/// Shift is 0..=4 (the ARM ARM imm3 field). Issue #60.
fn parse_extended_register_tail(mnem: &str, reg: Register, tail: &str) -> Result<Operand, String> {
    let tail = tail.trim();
    let mut parts = tail.splitn(2, char::is_whitespace);
    let kw = parts.next().unwrap_or("").trim();
    let rest = parts.next().unwrap_or("").trim();
    let kind = match kw.to_ascii_lowercase().as_str() {
        "uxtb" => crate::ir::ExtendKind::Uxtb,
        "uxth" => crate::ir::ExtendKind::Uxth,
        "uxtw" => crate::ir::ExtendKind::Uxtw,
        "uxtx" => crate::ir::ExtendKind::Uxtx,
        "sxtb" => crate::ir::ExtendKind::Sxtb,
        "sxth" => crate::ir::ExtendKind::Sxth,
        "sxtw" => crate::ir::ExtendKind::Sxtw,
        "sxtx" => crate::ir::ExtendKind::Sxtx,
        _ => {
            return Err(format!(
                "{} extend kind must be one of uxtb/uxth/uxtw/uxtx/sxtb/sxth/sxtw/sxtx, got `{}`",
                mnem, kw
            ));
        }
    };
    // The shift amount is the imm3 field of the ARM ARM encoding (0..=4).
    // The `#` prefix is conventional but optional in our parser.
    let shift = if rest.is_empty() {
        0
    } else {
        match parse_operand(rest)? {
            Operand::Immediate(v) => v,
            _ => return Err(format!("{} extend shift must be an immediate", mnem)),
        }
    };
    if !(0..=4).contains(&shift) {
        return Err(format!(
            "{} extend shift {} out of range (0..=4)",
            mnem, shift
        ));
    }
    Ok(Operand::ExtendedRegister {
        reg,
        kind,
        shift: shift as u8,
    })
}

const EXTEND_KEYWORDS: [&str; 8] = [
    "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
];

/// Returns true if the keyword names an extend kind
/// (UXTB/UXTH/UXTW/UXTX/SXTB/SXTH/SXTW/SXTX) rather than a shift kind.
fn is_extend_keyword(kw: &str) -> bool {
    EXTEND_KEYWORDS
        .iter()
        .any(|candidate| kw.eq_ignore_ascii_case(candidate))
}

/// Parse an `AddressOperand` from the bracketed-operand tokens of a
/// memory instruction. Accepts:
///   - `[Xn]`                          → Imm { offset=0, mode=Offset }
///   - `[Xn, #imm]`                    → Imm { mode=Offset }
///   - `[Xn, #imm]!`                   → Imm { mode=PreIndex }
///   - `[Xn], #imm` (two tokens)       → Imm { mode=PostIndex }
///   - `[Xn, Xm]`                      → Reg { shift=0 }
///   - `[Xn, Xm, LSL #shift]`          → Reg { shift }, where shift is 0 or
///     log2(access bytes)
///   - `[Xn, {W|X}m, UXTW/SXTW/UXTX/SXTX{ #shift}]`  → Ext
///
/// Returns the parsed operand and the number of input tokens consumed (1 for
/// the four bracketed forms, 2 for the trailing-immediate post-index form).
/// See ADR-0007.
fn parse_memory_operand(
    tokens: &[&str],
    width: crate::ir::types::AccessWidth,
) -> Result<(crate::ir::types::AddressOperand, usize), String> {
    use crate::ir::types::{AddressOperand, ExtendKind, IndexMode};

    let first = tokens.first().ok_or("missing address operand")?.trim();
    if !first.starts_with('[') {
        return Err(format!(
            "expected '[' at start of address operand, got `{}`",
            first
        ));
    }

    // Locate the closing bracket. The bracket-aware split puts the entire
    // bracketed group in a single token, so the ']' is in this same token.
    let close = first
        .rfind(']')
        .ok_or_else(|| format!("missing ']' in address operand `{}`", first))?;
    let inner = first[1..close].trim();
    let after_bracket = first[close + 1..].trim();

    // Parse the inner pieces.
    let inner_parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
    let base = parse_register(inner_parts[0])
        .map_err(|e| format!("invalid base register in memory operand: {}", e))?;

    let mut addr = if inner_parts.len() == 1 {
        AddressOperand::Imm {
            base,
            offset: 0,
            mode: IndexMode::Offset,
        }
    } else if inner_parts.len() == 2 {
        // Either `[Xn, #imm]` or `[Xn, Xm]`.
        let second = inner_parts[1];
        if let Ok(imm) = parse_immediate(second) {
            AddressOperand::Imm {
                base,
                offset: imm,
                mode: IndexMode::Offset,
            }
        } else {
            // Register-offset, no shift.
            let idx = parse_register(second)
                .map_err(|e| format!("invalid index register in memory operand: {}", e))?;
            AddressOperand::Reg {
                base,
                idx,
                shift: 0,
            }
        }
    } else if inner_parts.len() == 3 {
        // `[Xn, Xm, LSL #N]` or `[Xn, Wm, UXTW/SXTW/UXTX/SXTX{ #N}]`.
        let third = inner_parts[2];
        let kw = third.split_whitespace().next().unwrap_or("");
        if kw.eq_ignore_ascii_case("lsl") {
            let idx = parse_register(inner_parts[1])
                .map_err(|e| format!("invalid index register in memory operand: {}", e))?;
            let shift = parse_memory_lsl_amount(third, width)?;
            AddressOperand::Reg { base, idx, shift }
        } else if is_extend_keyword(kw) {
            let idx = parse_w_or_x_register(inner_parts[1])
                .map_err(|e| format!("invalid index register in memory operand: {}", e))?;
            let (kind, shift) = parse_memory_extend_tail(third)?;
            // Memory operands only accept the W/X-extend kinds (no byte/half).
            if !matches!(
                kind,
                ExtendKind::Uxtw | ExtendKind::Sxtw | ExtendKind::Uxtx | ExtendKind::Sxtx
            ) {
                return Err(format!(
                    "memory operand does not accept extend kind `{}`",
                    kw.to_lowercase()
                ));
            }
            AddressOperand::Ext {
                base,
                idx,
                kind,
                shift,
            }
        } else {
            return Err(format!("unrecognised memory-operand tail: `{}`", third));
        }
    } else {
        return Err(format!("unrecognised memory operand `{}`", first));
    };

    // Writeback (`!`) marker after `]`.
    if after_bracket == "!" {
        if let AddressOperand::Imm {
            base,
            offset,
            mode: IndexMode::Offset,
        } = addr
        {
            addr = AddressOperand::Imm {
                base,
                offset,
                mode: IndexMode::PreIndex,
            };
            return Ok((addr, 1));
        } else {
            return Err("pre-index writeback `!` requires `[Xn, #imm]` form".into());
        }
    } else if !after_bracket.is_empty() {
        return Err(format!(
            "unexpected trailing text after `]`: `{}`",
            after_bracket
        ));
    }

    // Post-index uses a second top-level token: `[Xn], #imm`.
    if tokens.len() >= 2 {
        let second = tokens[1].trim();
        if let Ok(imm) = parse_immediate(second) {
            if let AddressOperand::Imm {
                base,
                offset: 0,
                mode: IndexMode::Offset,
            } = addr
            {
                addr = AddressOperand::Imm {
                    base,
                    offset: imm,
                    mode: IndexMode::PostIndex,
                };
                return Ok((addr, 2));
            } else {
                return Err("post-index requires bare `[Xn]` base form".into());
            }
        }
    }

    Ok((addr, 1))
}

/// Parse a `LSL #N` tail (after the leading "lsl" keyword).
fn parse_lsl_amount(tail: &str) -> Result<u8, String> {
    let mut parts = tail.split_whitespace();
    let kw = parts.next().unwrap_or("");
    if !kw.eq_ignore_ascii_case("lsl") {
        return Err(format!("expected `lsl`, got `{}`", kw));
    }
    let imm_tok = parts.next().ok_or("missing LSL amount")?;
    let amt = parse_immediate(imm_tok)?;
    if !(0..=63).contains(&amt) {
        return Err(format!("LSL amount {} out of range", amt));
    }
    Ok(amt as u8)
}

/// Parse the narrower `LSL #N` tail accepted by memory register-offset forms.
fn parse_memory_lsl_amount(tail: &str, width: crate::ir::types::AccessWidth) -> Result<u8, String> {
    let shift = parse_lsl_amount(tail)?;
    let scaled_shift = match width {
        crate::ir::types::AccessWidth::Byte => 0,
        crate::ir::types::AccessWidth::Half => 1,
        crate::ir::types::AccessWidth::Word => 2,
        crate::ir::types::AccessWidth::Extended => 3,
    };

    if shift == 0 || shift == scaled_shift {
        return Ok(shift);
    }

    let access_bytes = 1u8 << scaled_shift;
    let expected = if scaled_shift == 0 {
        "0".to_string()
    } else {
        format!("0 or {}", scaled_shift)
    };
    Err(format!(
        "memory LSL amount {} invalid for {}-byte access (expected {})",
        shift, access_bytes, expected
    ))
}

/// Parse a `<extend> #shift` tail used in memory operands. Returns the
/// extend kind plus the optional shift (defaults to 0 if absent).
fn parse_memory_extend_tail(tail: &str) -> Result<(crate::ir::types::ExtendKind, u8), String> {
    use crate::ir::types::ExtendKind;
    let mut parts = tail.split_whitespace();
    let kw = parts.next().unwrap_or("").to_lowercase();
    let kind = match kw.as_str() {
        "uxtw" => ExtendKind::Uxtw,
        "sxtw" => ExtendKind::Sxtw,
        "uxtx" => ExtendKind::Uxtx,
        "sxtx" => ExtendKind::Sxtx,
        _ => return Err(format!("unsupported memory extend keyword `{}`", kw)),
    };
    let shift = match parts.next() {
        None => 0u8,
        Some(imm_tok) => {
            let amt = parse_immediate(imm_tok)?;
            if !(0..=4).contains(&amt) {
                return Err(format!("extend shift {} out of range (0..=4)", amt));
            }
            amt as u8
        }
    };
    Ok((kind, shift))
}

/// Infer `AccessWidth` for the unsized LDR/STR mnemonics (where the data
/// register's spelling — `wN` vs `xN` — chooses the width).
fn ldr_width(operands: &[&str]) -> crate::ir::types::AccessWidth {
    match operands.first().and_then(|s| s.trim().chars().next()) {
        Some('w') | Some('W') => crate::ir::types::AccessWidth::Word,
        _ => crate::ir::types::AccessWidth::Extended,
    }
}

/// Infer `AccessWidth` for LDP / STP based on whether the first paired
/// register is W-form or X-form.
fn ldp_pair_width(operands: &[&str]) -> crate::ir::types::AccessWidth {
    ldr_width(operands)
}

/// Parse a single-register LDR-family instruction (LDR/LDRB/LDRH/LDRSB/
/// LDRSH/LDRSW/STR/STRB/STRH). The destination/source register is the
/// first operand; the remaining tokens form the address operand.
fn parse_single_reg_mem(
    mnem: &str,
    operands: &[&str],
    width: crate::ir::types::AccessWidth,
    builder: fn(
        Register,
        crate::ir::types::AddressOperand,
        crate::ir::types::AccessWidth,
    ) -> Instruction,
) -> Result<Instruction, String> {
    if operands.len() < 2 {
        return Err(format!(
            "{} requires register + address operand, got {}",
            mnem,
            operands.len()
        ));
    }
    let rt =
        parse_w_or_x_register(operands[0]).map_err(|e| format!("{}: invalid Xt: {}", mnem, e))?;
    let (addr, consumed) = parse_memory_operand(&operands[1..], width)?;
    if 1 + consumed != operands.len() {
        return Err(format!(
            "{} has {} operands, expected {}",
            mnem,
            operands.len(),
            1 + consumed
        ));
    }
    Ok(builder(rt, addr, width))
}

/// Parse a pair memory instruction (LDP/STP/LDPSW). The destination
/// pair is the first two operands; the remaining tokens form the
/// address operand. `signed=true` only for LDPSW.
fn parse_pair_mem(
    mnem: &str,
    operands: &[&str],
    width: crate::ir::types::AccessWidth,
    is_load: bool,
    signed: bool,
) -> Result<Instruction, String> {
    if operands.len() < 3 {
        return Err(format!(
            "{} requires two registers + address operand, got {}",
            mnem,
            operands.len()
        ));
    }
    let rt1 = parse_w_or_x_register(operands[0])
        .map_err(|e| format!("{}: invalid first register: {}", mnem, e))?;
    let rt2 = parse_w_or_x_register(operands[1])
        .map_err(|e| format!("{}: invalid second register: {}", mnem, e))?;
    let (addr, consumed) = parse_memory_operand(&operands[2..], width)?;
    if 2 + consumed != operands.len() {
        return Err(format!(
            "{} has {} operands, expected {}",
            mnem,
            operands.len(),
            2 + consumed
        ));
    }
    match &addr {
        crate::ir::types::AddressOperand::Reg { .. } => {
            return Err(format!(
                "{}: pair instructions do not support register-offset addressing; \
                 use immediate-offset, pre-index, or post-index addressing",
                mnem
            ));
        }
        crate::ir::types::AddressOperand::Ext { .. } => {
            return Err(format!(
                "{}: pair instructions do not support register-extend addressing; \
                 use immediate-offset, pre-index, or post-index addressing",
                mnem
            ));
        }
        crate::ir::types::AddressOperand::Imm { .. } => {}
    }
    if is_load {
        Ok(Instruction::Ldp {
            rt1,
            rt2,
            addr,
            width,
            signed,
        })
    } else {
        Ok(Instruction::Stp {
            rt1,
            rt2,
            addr,
            width,
        })
    }
}

/// Parse the rm slot for the 3-operand arith/logical instructions
/// (Add/Sub/And/Orr/Eor). Returns the register/immediate form, a
/// shifted-register operand, or an extended-register operand based on the
/// shape and the keyword in the 4th token.
fn parse_rm_3op(mnem: &str, operands: &[&str]) -> Result<Operand, String> {
    if operands.len() == 3 {
        parse_operand(operands[2])
    } else if operands.len() == 4 {
        let tail = operands[3].trim();
        let kw = tail.split_whitespace().next().unwrap_or("");
        if is_extend_keyword(kw) {
            // Extended-register form: the inner register may be W-form for
            // byte/half/word kinds. Issue #60.
            let reg = parse_w_or_x_register(operands[2])?;
            parse_extended_register_tail(mnem, reg, tail)
        } else {
            let reg = parse_register(operands[2])?;
            parse_shifted_register_tail(mnem, reg, tail)
        }
    } else {
        Err(format!(
            "{} requires 3 or 4 operands, got {}",
            mnem,
            operands.len()
        ))
    }
}

fn parse_rm_3op_with_width(
    mnem: &str,
    operands: &[&str],
    width: RegisterWidth,
) -> Result<Operand, String> {
    if operands.len() == 3 {
        parse_sized_operand(mnem, operands[2], width)
    } else if operands.len() == 4 {
        let tail = operands[3].trim();
        let kw = tail.split_whitespace().next().unwrap_or("");
        if is_extend_keyword(kw) {
            let reg = parse_w_or_x_register(operands[2])?;
            parse_extended_register_tail(mnem, reg, tail)
        } else {
            let (reg, reg_width) = parse_sized_register(operands[2])?;
            if reg_width != width {
                return Err(format!(
                    "{} operands must use matching register widths",
                    mnem
                ));
            }
            parse_shifted_register_tail(mnem, reg, tail)
        }
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
    if operands.len() != 3 && operands.len() != 4 {
        return Err(format!(
            "add requires 3 or 4 operands, got {}",
            operands.len()
        ));
    }
    let (rd, rn, width) = parse_same_width_registers("add", operands)?;
    let rm = parse_rm_3op_with_width("add", operands, width)?;
    match width {
        RegisterWidth::W32 => Ok(Instruction::AddW { rd, rn, rm }),
        RegisterWidth::X64 => Ok(Instruction::Add { rd, rn, rm }),
    }
}

/// Parse SUB instruction
fn parse_sub(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 && operands.len() != 4 {
        return Err(format!(
            "sub requires 3 or 4 operands, got {}",
            operands.len()
        ));
    }
    let (rd, rn, width) = parse_same_width_registers("sub", operands)?;
    let rm = parse_rm_3op_with_width("sub", operands, width)?;
    match width {
        RegisterWidth::W32 => Ok(Instruction::SubW { rd, rn, rm }),
        RegisterWidth::X64 => Ok(Instruction::Sub { rd, rn, rm }),
    }
}

/// Parse AND instruction
fn parse_and(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() == 3 {
        let (rd, rn, width) = parse_same_width_registers("and", operands)?;
        let rm = match width {
            RegisterWidth::W32 => Operand::Immediate(parse_immediate(operands[2])?),
            RegisterWidth::X64 => parse_operand(operands[2])?,
        };
        return Ok(Instruction::And { rd, rn, rm, width });
    }

    let rm = parse_rm_3op("and", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::And {
        rd,
        rn,
        rm,
        width: RegisterWidth::X64,
    })
}

/// Parse ORR instruction
fn parse_orr(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() == 3 {
        let (rd, rn, width) = parse_same_width_registers("orr", operands)?;
        let rm = match width {
            RegisterWidth::W32 => Operand::Immediate(parse_immediate(operands[2])?),
            RegisterWidth::X64 => parse_operand(operands[2])?,
        };
        return Ok(Instruction::Orr { rd, rn, rm, width });
    }

    let rm = parse_rm_3op("orr", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Orr {
        rd,
        rn,
        rm,
        width: RegisterWidth::X64,
    })
}

/// Parse EOR instruction
fn parse_eor(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() == 3 {
        let (rd, rn, width) = parse_same_width_registers("eor", operands)?;
        let rm = match width {
            RegisterWidth::W32 => Operand::Immediate(parse_immediate(operands[2])?),
            RegisterWidth::X64 => parse_operand(operands[2])?,
        };
        return Ok(Instruction::Eor { rd, rn, rm, width });
    }

    let rm = parse_rm_3op("eor", operands)?;
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    Ok(Instruction::Eor {
        rd,
        rn,
        rm,
        width: RegisterWidth::X64,
    })
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
        let tail = operands[2].trim();
        let kw = tail.split_whitespace().next().unwrap_or("");
        if is_extend_keyword(kw) {
            // Extended-register form: the inner register may be W-form for
            // byte/half/word kinds. Issue #60.
            let reg = parse_w_or_x_register(operands[1])?;
            parse_extended_register_tail(mnem, reg, tail)
        } else {
            let reg = parse_register(operands[1])?;
            parse_shifted_register_tail(mnem, reg, tail)
        }
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
    if operands.len() == 2 {
        let (rn, width) = parse_sized_register(operands[0])?;
        let rm = match width {
            RegisterWidth::W32 => Operand::Immediate(parse_immediate(operands[1])?),
            RegisterWidth::X64 => parse_operand(operands[1])?,
        };
        return Ok(Instruction::Tst { rn, rm, width });
    }

    let rm = parse_rm_2op("tst", operands)?;
    let rn = parse_register(operands[0])?;
    Ok(Instruction::Tst {
        rn,
        rm,
        width: RegisterWidth::X64,
    })
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

/// Parse a bit-field-manipulation instruction operand list:
/// `rd, rn, #lsb, #width`. Used by UBFX/SBFX/BFI/BFXIL/UBFIZ/SBFIZ.
fn parse_bfm_like(operands: &[&str], mnem: &str) -> Result<(Register, Register, u8, u8), String> {
    if operands.len() != 4 {
        return Err(format!(
            "{} requires 4 operands, got {}",
            mnem,
            operands.len()
        ));
    }
    let rd = parse_register(operands[0])?;
    let rn = parse_register(operands[1])?;
    let lsb_raw = parse_immediate(operands[2])?;
    if !(0..=63).contains(&lsb_raw) {
        return Err(format!("{} lsb {} out of range (0..=63)", mnem, lsb_raw));
    }
    let width_raw = parse_immediate(operands[3])?;
    if !(1..=64).contains(&width_raw) {
        return Err(format!(
            "{} width {} out of range (1..=64)",
            mnem, width_raw
        ));
    }
    let lsb = lsb_raw as u8;
    let width = width_raw as u8;
    if (lsb as u16 + width as u16) > 64 {
        return Err(format!("{} lsb {} + width {} exceeds 64", mnem, lsb, width));
    }
    Ok((rd, rn, lsb, width))
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
    if let Operand::Immediate(imm) = rm
        && !(0..=31).contains(&imm)
    {
        return Err(format!("{} imm5 {} out of range (0..=31)", mnem, imm));
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

// ===== Issue #69: branch / control-flow parsers =====
//
// Branches in v1 are terminators: search holds them fixed, so the parser
// is consumed only by `.s` round-trip and Capstone-disassembled binaries.
// Numeric targets (the common Capstone form) are stored verbatim in
// LabelId(u64); identifier-style labels (.Lfoo, loop_start) are hashed
// into a stable u64. Two textually different label names hash to
// distinct LabelIds — accepted as a v1 limitation.

/// Parse a branch destination: numeric literal (0x.., decimal, optionally
/// prefixed with `#`) or identifier-style label. The numeric value is the
/// absolute target address; the assembler later resolves it to a
/// PC-relative offset (see `pc_relative_offset` in `assembler::mod`).
pub fn parse_branch_target(s: &str) -> Result<LabelId, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty branch target".to_string());
    }
    // Strip a leading `#` (Capstone-style immediate prefix).
    let body = trimmed.strip_prefix('#').unwrap_or(trimmed);
    // Numeric forms first: 0x... or plain decimal.
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .map(LabelId)
            .map_err(|e| format!("invalid hex branch target '{}': {}", s, e));
    }
    if body.chars().all(|c| c.is_ascii_digit()) {
        return body
            .parse::<u64>()
            .map(LabelId)
            .map_err(|e| format!("invalid decimal branch target '{}': {}", s, e));
    }
    // Identifier-style label: hash the name to a stable u64.
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new();
    body.hash(&mut h);
    Ok(LabelId(h.finish()))
}

fn parse_b(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 1 {
        return Err(format!("b requires 1 operand, got {}", operands.len()));
    }
    Ok(Instruction::B {
        target: parse_branch_target(operands[0])?,
    })
}

fn parse_bl(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 1 {
        return Err(format!("bl requires 1 operand, got {}", operands.len()));
    }
    Ok(Instruction::Bl {
        target: parse_branch_target(operands[0])?,
    })
}

fn parse_br(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 1 {
        return Err(format!("br requires 1 operand, got {}", operands.len()));
    }
    Ok(Instruction::Br {
        rn: parse_register(operands[0])?,
    })
}

fn parse_ret(operands: &[&str]) -> Result<Instruction, String> {
    match operands.len() {
        0 => Ok(Instruction::Ret { rn: Register::X30 }),
        1 => Ok(Instruction::Ret {
            rn: parse_register(operands[0])?,
        }),
        n => Err(format!("ret takes 0 or 1 operand, got {}", n)),
    }
}

fn parse_b_cond(cond: Condition, operands: &[&str]) -> Result<Instruction, String> {
    if !NORMAL_CONDITIONS.contains(&cond) {
        // AL → use plain `b`. NV → reserved.
        return Err(format!(
            "b.{} is not encodable (AL: use plain b; NV: reserved)",
            cond
        ));
    }
    if operands.len() != 1 {
        return Err(format!("b.cond requires 1 operand, got {}", operands.len()));
    }
    Ok(Instruction::BCond {
        target: parse_branch_target(operands[0])?,
        cond,
    })
}

fn parse_cbz(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("cbz requires 2 operands, got {}", operands.len()));
    }
    Ok(Instruction::Cbz {
        rn: parse_register(operands[0])?,
        target: parse_branch_target(operands[1])?,
    })
}

fn parse_cbnz(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 2 {
        return Err(format!("cbnz requires 2 operands, got {}", operands.len()));
    }
    Ok(Instruction::Cbnz {
        rn: parse_register(operands[0])?,
        target: parse_branch_target(operands[1])?,
    })
}

fn parse_tbz_bit(s: &str) -> Result<u8, String> {
    // The bit operand is `#N` or `N`, 0..=63.
    let body = s.trim().strip_prefix('#').unwrap_or(s.trim());
    let v: u32 = body
        .parse()
        .map_err(|e| format!("invalid TBZ/TBNZ bit '{}': {}", s, e))?;
    if v > 63 {
        return Err(format!("TBZ/TBNZ bit {} out of range (0..=63)", v));
    }
    Ok(v as u8)
}

fn parse_tbz(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("tbz requires 3 operands, got {}", operands.len()));
    }
    // Capstone prints TBZ as `wN` when bit<32, `xN` otherwise (both forms
    // share the encoded register slot). Accept either spelling.
    Ok(Instruction::Tbz {
        rt: parse_w_or_x_register(operands[0])?,
        bit: parse_tbz_bit(operands[1])?,
        target: parse_branch_target(operands[2])?,
    })
}

fn parse_tbnz(operands: &[&str]) -> Result<Instruction, String> {
    if operands.len() != 3 {
        return Err(format!("tbnz requires 3 operands, got {}", operands.len()));
    }
    Ok(Instruction::Tbnz {
        rt: parse_w_or_x_register(operands[0])?,
        bit: parse_tbz_bit(operands[1])?,
        target: parse_branch_target(operands[2])?,
    })
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
        "ubfx" => parse_bfm_like(&operands, "ubfx")
            .map(|(rd, rn, lsb, width)| Instruction::Ubfx { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
        "sbfx" => parse_bfm_like(&operands, "sbfx")
            .map(|(rd, rn, lsb, width)| Instruction::Sbfx { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
        "bfi" => parse_bfm_like(&operands, "bfi")
            .map(|(rd, rn, lsb, width)| Instruction::Bfi { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
        "bfxil" => parse_bfm_like(&operands, "bfxil")
            .map(|(rd, rn, lsb, width)| Instruction::Bfxil { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
        "ubfiz" => parse_bfm_like(&operands, "ubfiz")
            .map(|(rd, rn, lsb, width)| Instruction::Ubfiz { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
        "sbfiz" => parse_bfm_like(&operands, "sbfiz")
            .map(|(rd, rn, lsb, width)| Instruction::Sbfiz { rd, rn, lsb, width })
            .map_err(ParseLineError::Other)?,
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
        // UXTB/UXTH: Wd-write form is the only architectural form; accepting
        // X-spelling for rd is just the IR's naming convention.
        "uxtb" => parse_unary_extend("uxtb", &operands, true, |rd, rn| Instruction::Uxtb {
            rd,
            rn,
        })
        .map_err(ParseLineError::Other)?,
        "uxth" => parse_unary_extend("uxth", &operands, true, |rd, rn| Instruction::Uxth {
            rd,
            rn,
        })
        .map_err(ParseLineError::Other)?,
        // SXTB/SXTH/SXTW: X-dest only. The 32-bit `Wd` form is a distinct
        // architectural instruction that this IR does not model.
        "sxtb" => parse_unary_extend("sxtb", &operands, false, |rd, rn| Instruction::Sxtb {
            rd,
            rn,
        })
        .map_err(ParseLineError::Other)?,
        "sxth" => parse_unary_extend("sxth", &operands, false, |rd, rn| Instruction::Sxth {
            rd,
            rn,
        })
        .map_err(ParseLineError::Other)?,
        "sxtw" => parse_unary_extend("sxtw", &operands, false, |rd, rn| Instruction::Sxtw {
            rd,
            rn,
        })
        .map_err(ParseLineError::Other)?,
        // ===== Issue #69: branches / control flow =====
        "b" => parse_b(&operands).map_err(ParseLineError::Other)?,
        "bl" => parse_bl(&operands).map_err(ParseLineError::Other)?,
        "br" => parse_br(&operands).map_err(ParseLineError::Other)?,
        "ret" => parse_ret(&operands).map_err(ParseLineError::Other)?,
        "cbz" => parse_cbz(&operands).map_err(ParseLineError::Other)?,
        "cbnz" => parse_cbnz(&operands).map_err(ParseLineError::Other)?,
        "tbz" => parse_tbz(&operands).map_err(ParseLineError::Other)?,
        "tbnz" => parse_tbnz(&operands).map_err(ParseLineError::Other)?,
        // Memory ops (issue #68). Width-detecting load family.
        "ldr" => parse_single_reg_mem("ldr", &operands, ldr_width(&operands), |rt, addr, w| {
            Instruction::Ldr { rt, addr, width: w }
        })
        .map_err(ParseLineError::Other)?,
        "ldrb" => parse_single_reg_mem(
            "ldrb",
            &operands,
            crate::ir::types::AccessWidth::Byte,
            |rt, addr, w| Instruction::Ldr { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "ldrh" => parse_single_reg_mem(
            "ldrh",
            &operands,
            crate::ir::types::AccessWidth::Half,
            |rt, addr, w| Instruction::Ldr { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "ldrsb" => parse_single_reg_mem(
            "ldrsb",
            &operands,
            crate::ir::types::AccessWidth::Byte,
            |rt, addr, w| Instruction::Ldrs { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "ldrsh" => parse_single_reg_mem(
            "ldrsh",
            &operands,
            crate::ir::types::AccessWidth::Half,
            |rt, addr, w| Instruction::Ldrs { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "ldrsw" => parse_single_reg_mem(
            "ldrsw",
            &operands,
            crate::ir::types::AccessWidth::Word,
            |rt, addr, w| Instruction::Ldrs { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "str" => parse_single_reg_mem("str", &operands, ldr_width(&operands), |rt, addr, w| {
            Instruction::Str { rt, addr, width: w }
        })
        .map_err(ParseLineError::Other)?,
        "strb" => parse_single_reg_mem(
            "strb",
            &operands,
            crate::ir::types::AccessWidth::Byte,
            |rt, addr, w| Instruction::Str { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "strh" => parse_single_reg_mem(
            "strh",
            &operands,
            crate::ir::types::AccessWidth::Half,
            |rt, addr, w| Instruction::Str { rt, addr, width: w },
        )
        .map_err(ParseLineError::Other)?,
        "ldp" => parse_pair_mem("ldp", &operands, ldp_pair_width(&operands), true, false)
            .map_err(ParseLineError::Other)?,
        "stp" => parse_pair_mem("stp", &operands, ldp_pair_width(&operands), false, false)
            .map_err(ParseLineError::Other)?,
        "ldpsw" => parse_pair_mem(
            "ldpsw",
            &operands,
            crate::ir::types::AccessWidth::Word,
            true,
            true,
        )
        .map_err(ParseLineError::Other)?,
        // b.<cond> — split on the dot, parse the condition, dispatch.
        op if op.starts_with("b.") => {
            let suffix = &op[2..];
            let cond = parse_condition(suffix)
                .map_err(|_| ParseLineError::UnknownInstruction(opcode.clone()))?;
            parse_b_cond(cond, &operands).map_err(ParseLineError::Other)?
        }
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
        assert_eq!(parse_register("wzr").unwrap(), Register::XZR);
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
                width: RegisterWidth::X64,
            }
        );
    }

    #[test]
    fn test_parse_shifted_register_amount_out_of_range() {
        // amount > 63 must be rejected.
        assert!(parse_line("add x0, x1, x2, lsl #64").is_err());
    }

    #[test]
    fn test_parse_shifted_register_accepts_max_lsl_amount() {
        let instr = parse_one("add x0, x1, x2, lsl #63");
        match instr {
            Instruction::Add { rm, .. } => assert_eq!(
                rm,
                Operand::ShiftedRegister {
                    reg: Register::X2,
                    kind: ShiftKind::Lsl,
                    amount: 63,
                }
            ),
            other => panic!("expected add, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_shifted_register_invalid_kind() {
        assert!(parse_line("add x0, x1, x2, foo #3").is_err());
    }

    #[test]
    fn test_parse_register_invalid() {
        assert!(parse_register("w0").is_err());
        assert!(parse_register("W0").is_err());
        assert!(parse_register("w29").is_err());
        assert!(parse_register("w30").is_err());
        assert!(parse_register("x00").is_err());
        assert!(parse_register("x32").is_err());
        assert!(parse_register("w31").is_err());
        assert!(parse_register("w32").is_err());
        assert!(parse_register("wsp").is_err());
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
    fn parse_w_add_sub_mov_register_forms_roundtrip() {
        for text in [
            "add w0, w1, w2",
            "add w0, w1, #1",
            "add w0, w1, w2, lsl #3",
            "sub w3, w4, w5",
            "sub w3, w4, #7",
            "sub w3, w4, w5, lsl #2",
            "mov w6, w7",
        ] {
            let instr = parse_one(text);
            assert_eq!(format!("{}", instr), text);
        }
    }

    #[test]
    fn parse_w_add_sub_mov_rejects_mixed_register_widths() {
        for text in [
            "add w0, x1, w2",
            "add w0, w1, x2",
            "add w0, w1, x2, lsl #3",
            "sub x0, w1, x2",
            "mov w0, x1",
            "mov x0, w1",
        ] {
            assert!(parse_line(text).is_err(), "{text} should be rejected");
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

        // AND with a non-bitmask immediate (e.g., #5 = 0b101) is rejected by
        // the encodability check. Valid bitmask values (e.g., #1) are accepted.
        assert!(parse_line("and x0, x1, #1").is_ok());
        assert!(parse_line("and x0, x1, #5").is_err());

        // ANDS immediate must reach the encoder via the parser so Capstone
        // disassembly of an ELF region containing `ands x?, x?, #imm` round-trips.
        assert!(parse_line("ands x0, x1, #0xff").is_ok());
        assert!(parse_line("ands x0, x1, #5").is_err());

        // High-bit logical immediates (>= 2^63) must parse from positive hex.
        // i64::from_str_radix would overflow; we wrap through u64.
        assert!(parse_line("and x0, x1, #0x8000000000000000").is_ok());
        assert!(parse_line("tst x1, #0x8000000000000000").is_ok());
    }

    #[test]
    fn parse_line_rejects_sp_in_multiply_family() {
        for text in [
            "mul sp, x1, x2",
            "sdiv x0, sp, x2",
            "udiv x0, x1, sp",
            "madd x0, x1, x2, sp",
            "msub sp, x1, x2, x3",
            "mneg x0, sp, x2",
            "smulh x0, x1, sp",
            "umulh sp, x1, x2",
        ] {
            assert!(parse_line(text).is_err(), "SP must be rejected: {text}");
        }

        for text in [
            "mul xzr, xzr, xzr",
            "sdiv xzr, xzr, xzr",
            "udiv xzr, xzr, xzr",
            "madd xzr, xzr, xzr, xzr",
            "msub xzr, xzr, xzr, xzr",
            "mneg xzr, xzr, xzr",
            "smulh xzr, xzr, xzr",
            "umulh xzr, xzr, xzr",
        ] {
            assert!(parse_line(text).is_ok(), "XZR must remain valid: {text}");
        }
    }

    #[test]
    fn test_parse_w_logical_immediates_roundtrip() {
        for text in [
            "and w0, w1, #255",
            "orr w0, w1, #255",
            "eor w0, w1, #255",
            "tst w1, #255",
            "ands w0, w1, #255",
            "and wsp, w1, #255",
            "ands wzr, w1, #255",
        ] {
            let instr = parse_one(text);
            assert_eq!(format!("{}", instr), text);
        }
    }

    #[test]
    fn test_parse_mov_w_logical_immediate_aliases() {
        let instr = parse_one("mov w0, #0xff");
        assert_eq!(
            instr,
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::XZR,
                rm: Operand::Immediate(255),
                width: RegisterWidth::W32,
            }
        );
        assert_eq!(format!("{}", instr), "orr w0, wzr, #255");

        let instr = parse_one("mov wsp, #0xff");
        assert_eq!(
            instr,
            Instruction::Orr {
                rd: Register::SP,
                rn: Register::XZR,
                rm: Operand::Immediate(255),
                width: RegisterWidth::W32,
            }
        );
        assert_eq!(format!("{}", instr), "orr wsp, wzr, #255");
    }

    #[test]
    fn test_parse_w_logical_immediates_reject_invalid_slots_and_forms() {
        for text in [
            "and wzr, w1, #255",
            "ands wsp, w1, #255",
            "tst wsp, #255",
            "and w0, x1, #255",
            "and w0, w1, w2",
            "mov wzr, #0xff",
            "mov w0, #5",
        ] {
            assert!(parse_line(text).is_err(), "{text} should be rejected");
        }
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
                width: RegisterWidth::X64,
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
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Uxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxth {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Sxtw {
                rd: Register::X0,
                rn: Register::X1,
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
            let x_name = format!("x{}", idx);
            let w_name = format!("w{}", idx);
            let expected = Register::from_index(idx).unwrap();
            assert_eq!(parse_register(&x_name).unwrap(), expected);
            assert!(
                parse_register(&w_name).is_err(),
                "{w_name} should not parse through the generic register parser"
            );
            assert_eq!(
                parse_w_or_x_register(&w_name).unwrap(),
                expected,
                "{w_name} should alias {x_name} in scoped W/X parser paths"
            );
            assert_eq!(
                parse_sized_register(&w_name).unwrap(),
                (expected, RegisterWidth::W32),
                "{w_name} should carry W32 width in sized parser paths"
            );
        }
        assert_eq!(parse_register("wzr").unwrap(), Register::XZR);
        assert_eq!(parse_register("fp").unwrap(), Register::X29);
        assert_eq!(parse_register("lr").unwrap(), Register::X30);
        assert!(parse_w_or_x_register("w00").is_err());
        assert!(parse_sized_register("w00").is_err());
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
    fn parse_ccmp_and_ccmn_reject_al_nv_at_encodability_boundary() {
        // AL/NV are valid condition tokens, but CCMP/CCMN reserve those
        // encodings. `parse_line` rejects them at the final encodability gate.
        for line in [
            "ccmp x1, x2, #0, al",
            "ccmp x1, x2, #0, nv",
            "ccmn x1, x2, #0, al",
            "ccmn x1, x2, #0, nv",
        ] {
            let result = parse_line(line);
            assert!(
                matches!(
                    result,
                    Err(ParseLineError::Other(ref msg))
                        if msg.contains("instruction cannot be encoded in AArch64")
                ),
                "{line} should be rejected only after parsing reaches encodability validation"
            );
        }
    }

    #[test]
    fn parse_ubfx_roundtrip() {
        let parsed = match parse_line("ubfx x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Ubfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "ubfx x0, x1, #5, #10");
    }

    #[test]
    fn parse_sbfx_roundtrip() {
        let parsed = match parse_line("sbfx x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Sbfx {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "sbfx x0, x1, #5, #10");
    }

    #[test]
    fn parse_bfi_roundtrip() {
        let parsed = match parse_line("bfi x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Bfi {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "bfi x0, x1, #5, #10");
    }

    #[test]
    fn parse_bfxil_roundtrip() {
        let parsed = match parse_line("bfxil x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Bfxil {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "bfxil x0, x1, #5, #10");
    }

    #[test]
    fn parse_ubfiz_roundtrip() {
        let parsed = match parse_line("ubfiz x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Ubfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "ubfiz x0, x1, #5, #10");
    }

    #[test]
    fn parse_sbfiz_roundtrip() {
        let parsed = match parse_line("sbfiz x0, x1, #5, #10").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Sbfiz {
                rd: Register::X0,
                rn: Register::X1,
                lsb: 5,
                width: 10,
            }
        );
        assert_eq!(format!("{}", parsed), "sbfiz x0, x1, #5, #10");
    }

    #[test]
    fn parse_ubfx_rejects_out_of_range_lsb() {
        let result = parse_line("ubfx x0, x1, #64, #1");
        assert!(result.is_err(), "lsb >= 64 must be rejected");
    }

    #[test]
    fn parse_ubfx_rejects_zero_width() {
        let result = parse_line("ubfx x0, x1, #0, #0");
        assert!(result.is_err(), "width == 0 must be rejected");
    }

    #[test]
    fn parse_ubfx_rejects_overlap() {
        // lsb + width > 64
        let result = parse_line("ubfx x0, x1, #60, #10");
        assert!(result.is_err(), "lsb + width > 64 must be rejected");
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
            ("ubfx x0, x1, #5, #10", "ubfx x0, x1, #5, #10"),
            ("sbfx x0, x1, #5, #10", "sbfx x0, x1, #5, #10"),
            ("bfi x0, x1, #5, #10", "bfi x0, x1, #5, #10"),
            ("bfxil x0, x1, #5, #10", "bfxil x0, x1, #5, #10"),
            ("ubfiz x0, x1, #5, #10", "ubfiz x0, x1, #5, #10"),
            ("sbfiz x0, x1, #5, #10", "sbfiz x0, x1, #5, #10"),
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
            ("movz x0, #0x1234", "mov x0, #4660"),
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
    fn parse_movz_shift0_display_normalizes_to_mov_alias() {
        let parsed = match parse_line("movz x0, #0x1234").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip for movz"),
        };
        assert_eq!(
            parsed,
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0x1234,
                shift: 0,
            }
        );

        let printed = parsed.to_string();
        assert_eq!(printed, "mov x0, #4660");

        let reparsed = match parse_line(&printed).unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip for {}", printed),
        };
        assert_eq!(
            reparsed,
            Instruction::MovImm {
                rd: Register::X0,
                imm: 4660,
            }
        );
        assert_eq!(reparsed.to_string(), printed);
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
    fn parse_add_extended_register_uxtb() {
        use crate::ir::ExtendKind;
        // Issue #60: `add x0, x1, w2, uxtb #2` produces an Add with an
        // ExtendedRegister rm. The inner register parses as w2 (alias of x2).
        let parsed = match parse_line("add x0, x1, w2, uxtb #2").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Uxtb,
                    shift: 2,
                },
            }
        );
    }

    #[test]
    fn parse_cmp_extended_register_sxth() {
        use crate::ir::ExtendKind;
        let parsed = match parse_line("cmp x1, w2, sxth #1").unwrap() {
            LineResult::Instruction(instr) => instr,
            LineResult::Skip => panic!("unexpected skip"),
        };
        assert_eq!(
            parsed,
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Sxth,
                    shift: 1,
                },
            }
        );
    }

    #[test]
    fn is_extend_keyword_recognizes_ascii_case_variants() {
        for kw in [
            "uxtb", "UXTB", "UxTb", "uxth", "UXTH", "UxTh", "uxtw", "UXTW", "UxTw", "uxtx", "UXTX",
            "UxTx", "sxtb", "SXTB", "SxTb", "sxth", "SXTH", "SxTh", "sxtw", "SXTW", "SxTw", "sxtx",
            "SXTX", "SxTx",
        ] {
            assert!(is_extend_keyword(kw), "{kw} should be an extend keyword");
        }

        for kw in ["lsl", "lsr", "asr", "ror", "uxt", "uxtb2", "sxtq", ""] {
            assert!(
                !is_extend_keyword(kw),
                "{kw} should not be an extend keyword"
            );
        }
    }

    #[test]
    fn parse_extend_keyword_dispatch_accepts_mixed_case_operands() {
        use crate::ir::types::{AccessWidth, AddressOperand, ExtendKind};

        assert_eq!(
            parse_one("add x0, x1, w2, UxTb #2"),
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Uxtb,
                    shift: 2,
                },
            }
        );

        assert_eq!(
            parse_one("cmp x1, w2, SxTh #1"),
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Sxth,
                    shift: 1,
                },
            }
        );

        assert_eq!(
            parse_one("ldr x0, [x1, w2, UxTw #2]"),
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Ext {
                    base: Register::X1,
                    idx: Register::X2,
                    kind: ExtendKind::Uxtw,
                    shift: 2,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    #[test]
    fn parse_w_form_arithmetic_keeps_extended_register_fallbacks() {
        // Issue #121: W-form ADD/SUB now have explicit width-aware IR
        // variants instead of aliasing to the 64-bit ADD/SUB semantics.
        assert!(parse_line("add w0, w1, w2").is_ok());
        assert!(parse_line("sub w3, w4, w5").is_ok());
        assert!(parse_line("add w0, x1, w2").is_err());
        // The extended-register inner register accepts W-form.
        assert!(parse_line("add x0, x1, w2, uxtb #0").is_ok());
        assert!(parse_line("cmp x1, w2, sxth #1").is_ok());
        // UXTX/SXTX accept X-form inner register (still works through the
        // parse_w_or_x_register fallback to parse_register).
        assert!(parse_line("add x0, x1, x2, uxtx #2").is_ok());
    }

    #[test]
    fn parse_standalone_extend_accepts_capstone_w_form() {
        // Issue #60 follow-up (Codex P2 / claude-review): Capstone disassembles
        // the standalone extends with W-form operands:
        //   UXTB / UXTH:           `uxtb w0, w1` (both W)
        //   SXTB / SXTH / SXTW:    `sxtb x0, w1` (X-dest, W-src)
        // The parser must accept those exact forms so the ELF round-trip
        // path (Capstone disasm → parser → IR) doesn't break.
        let cases = [
            (
                "uxtb w0, w1",
                Instruction::Uxtb {
                    rd: Register::X0,
                    rn: Register::X1,
                },
            ),
            (
                "uxth w2, w3",
                Instruction::Uxth {
                    rd: Register::X2,
                    rn: Register::X3,
                },
            ),
            (
                "sxtb x4, w5",
                Instruction::Sxtb {
                    rd: Register::X4,
                    rn: Register::X5,
                },
            ),
            (
                "sxth x6, w7",
                Instruction::Sxth {
                    rd: Register::X6,
                    rn: Register::X7,
                },
            ),
            (
                "sxtw x8, w9",
                Instruction::Sxtw {
                    rd: Register::X8,
                    rn: Register::X9,
                },
            ),
        ];
        for (line, expected) in cases {
            let parsed = match parse_line(line).unwrap_or_else(|e| panic!("{}: {:?}", line, e)) {
                LineResult::Instruction(instr) => instr,
                LineResult::Skip => panic!("unexpected skip for {}", line),
            };
            assert_eq!(parsed, expected, "round-trip failed for {}", line);
        }
        // Legacy X-form input remains accepted for compatibility even though
        // Display now canonicalizes these aliases to architectural widths.
        assert!(parse_line("uxtb x0, x1").is_ok());
        assert!(parse_line("sxtw x0, x1").is_ok());
    }

    #[test]
    fn parse_sxt_rejects_w_destination() {
        // Issue #60 follow-up (Codex P1 on the rebased branch): `sxtb w0, w1`
        // is the 32-bit-Wd-write form architecturally — distinct from the
        // X-dest SXTB the IR models. Accepting it would silently erase the
        // width and let the optimizer emit Xd-write bytes against W-dest
        // input. The parser must refuse.
        for line in ["sxtb w0, w1", "sxth w0, w1", "sxtw w0, w1"] {
            assert!(
                parse_line(line).is_err(),
                "{} should reject W-form destination",
                line
            );
        }
        // The X-form destination is the correct spelling for the IR's model.
        assert!(parse_line("sxtb x0, w1").is_ok());
        assert!(parse_line("sxth x0, w1").is_ok());
        assert!(parse_line("sxtw x0, w1").is_ok());
        // UXTB/UXTH accept both W- and X-form rd (they are not architecturally
        // distinct — Xd is just the IR's spelling convention).
        assert!(parse_line("uxtb w0, w1").is_ok());
        assert!(parse_line("uxtb x0, w1").is_ok());
    }

    #[test]
    fn parse_extended_register_rejects_oversized_shift() {
        // Shift > 4 must be rejected at the parser (the encodability gate
        // would also reject, but the parser's range check fires earlier).
        assert!(parse_line("add x0, x1, w2, uxtb #5").is_err());
        // And rejected for non-arith opcodes.
        assert!(parse_line("and x0, x1, w2, uxtb #2").is_err());
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
        assert_eq!(format!("{}", parsed), "sxtw x0, w1");
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
        assert_eq!(format!("{}", parsed), "sxth x0, w1");
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
        assert_eq!(format!("{}", parsed), "uxth w0, w1");
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
        assert_eq!(format!("{}", parsed), "sxtb x0, w1");
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
        assert_eq!(format!("{}", parsed), "uxtb w0, w1");
    }

    // ===== Issue #69: branch / control-flow parsing =====

    #[test]
    fn test_parse_ret_bare_defaults_to_x30() {
        assert_eq!(parse_one("ret"), Instruction::Ret { rn: Register::X30 });
    }

    #[test]
    fn test_parse_ret_with_explicit_register() {
        assert_eq!(parse_one("ret x0"), Instruction::Ret { rn: Register::X0 });
    }

    #[test]
    fn test_parse_ret_with_two_operands_errors() {
        let result = parse_line("ret x0, x1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_b_unconditional_hex_target() {
        assert_eq!(
            parse_one("b 0x1000"),
            Instruction::B {
                target: LabelId(0x1000),
            }
        );
    }

    #[test]
    fn test_parse_b_unconditional_with_hash_prefix() {
        assert_eq!(
            parse_one("b #0x1000"),
            Instruction::B {
                target: LabelId(0x1000),
            }
        );
    }

    #[test]
    fn test_parse_bl_target() {
        assert_eq!(
            parse_one("bl 0x2000"),
            Instruction::Bl {
                target: LabelId(0x2000),
            }
        );
    }

    #[test]
    fn test_parse_br_register() {
        assert_eq!(parse_one("br x16"), Instruction::Br { rn: Register::X16 });
    }

    #[test]
    fn test_parse_b_eq() {
        assert_eq!(
            parse_one("b.eq 0x1000"),
            Instruction::BCond {
                target: LabelId(0x1000),
                cond: Condition::EQ,
            }
        );
    }

    #[test]
    fn test_parse_b_ne() {
        assert_eq!(
            parse_one("b.ne 0x1000"),
            Instruction::BCond {
                target: LabelId(0x1000),
                cond: Condition::NE,
            }
        );
    }

    #[test]
    fn test_parse_b_al_rejected() {
        // AL → use plain `b`. Parser must reject.
        let result = parse_line("b.al 0x1000");
        assert!(result.is_err(), "b.al should be rejected, got {:?}", result);
    }

    #[test]
    fn test_parse_b_nv_rejected() {
        let result = parse_line("b.nv 0x1000");
        assert!(result.is_err(), "b.nv should be rejected, got {:?}", result);
    }

    #[test]
    fn test_parse_b_garbage_suffix_unknown_instruction() {
        let result = parse_line("b.xx 0x1000");
        assert!(matches!(result, Err(ParseLineError::UnknownInstruction(_))));
    }

    #[test]
    fn test_parse_cbz() {
        assert_eq!(
            parse_one("cbz x0, 0x1000"),
            Instruction::Cbz {
                rn: Register::X0,
                target: LabelId(0x1000),
            }
        );
        assert!(parse_line("cbz w0, 0x1000").is_err());
    }

    #[test]
    fn test_parse_cbnz() {
        assert_eq!(
            parse_one("cbnz x5, 0x1000"),
            Instruction::Cbnz {
                rn: Register::X5,
                target: LabelId(0x1000),
            }
        );
        assert!(parse_line("cbnz w5, 0x1000").is_err());
    }

    #[test]
    fn test_parse_tbz_with_hash_bit() {
        assert_eq!(
            parse_one("tbz x3, #5, 0x1000"),
            Instruction::Tbz {
                rt: Register::X3,
                bit: 5,
                target: LabelId(0x1000),
            }
        );
    }

    #[test]
    fn test_parse_tbnz() {
        assert_eq!(
            parse_one("tbnz x3, #7, 0x1000"),
            Instruction::Tbnz {
                rt: Register::X3,
                bit: 7,
                target: LabelId(0x1000),
            }
        );
    }

    #[test]
    fn test_parse_tbz_accepts_w_form() {
        // Capstone prints TBZ with a W register when the tested bit is < 32.
        // TBZ is a width-aware path, so the scoped helper accepts that spelling
        // and canonicalizes to the shared physical register (issue #142).
        assert_eq!(
            parse_one("tbz w3, #5, 0x1000"),
            Instruction::Tbz {
                rt: Register::X3,
                bit: 5,
                target: LabelId(0x1000),
            }
        );
    }

    #[test]
    fn test_parse_tbnz_accepts_w_form() {
        assert_eq!(
            parse_one("tbnz w7, #31, 0x2000"),
            Instruction::Tbnz {
                rt: Register::X7,
                bit: 31,
                target: LabelId(0x2000),
            }
        );
    }

    #[test]
    fn test_parse_tbz_bit_out_of_range_errors() {
        let result = parse_line("tbz x3, #64, 0x1000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_b_identifier_label_hashes_consistently() {
        let a = parse_one("b .Lfoo");
        let b = parse_one("b .Lfoo");
        assert_eq!(a, b, "same label should hash to same LabelId");
        let c = parse_one("b .Lbar");
        assert_ne!(a, c, "different labels should hash differently");
    }

    #[test]
    fn split_operands_treats_bracketed_commas_as_one_token() {
        // Memory operands carry commas inside `[ ... ]`; the splitter must
        // not break them apart.
        let parts = split_operands("x0, [x1, x2, lsl #3]");
        assert_eq!(parts, vec!["x0", "[x1, x2, lsl #3]"]);
    }

    #[test]
    fn split_operands_flat_corpus_is_unchanged() {
        // Existing comma-separated three-operand instructions must keep
        // the same tokenisation after the bracket-aware rewrite.
        assert_eq!(split_operands("x0, x1, #8"), vec!["x0", "x1", "#8"]);
        assert_eq!(
            split_operands("x0, x1, x2, x3"),
            vec!["x0", "x1", "x2", "x3"]
        );
    }

    #[test]
    fn split_operands_handles_post_index_trailing_immediate() {
        // Post-index uses `[base], #imm` — the trailing `, #imm` is a real
        // top-level comma after the closing `]`.
        let parts = split_operands("x0, [x1], #8");
        assert_eq!(parts, vec!["x0", "[x1]", "#8"]);
    }

    #[test]
    fn parse_ldr_bare_base_yields_offset_mode_with_zero_offset() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let instr = parse_one("ldr x0, [x1]");
        assert_eq!(
            instr,
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    /// Round-trip helper: every input must `parse_line → Display` back to
    /// itself (canonical Capstone-ish form).
    fn assert_mem_round_trip(text: &str) {
        let instr = parse_one(text);
        assert_eq!(format!("{}", instr), text, "round-trip mismatch");
    }

    #[test]
    fn memory_op_round_trips_across_all_addressing_modes() {
        // Immediate-offset, including bare-base and negative offsets.
        assert_mem_round_trip("ldr x0, [x1]");
        assert_mem_round_trip("ldr x0, [x1, #8]");
        assert_mem_round_trip("ldr x0, [sp, #-8]");
        // Pre-index.
        assert_mem_round_trip("ldr x0, [x1, #16]!");
        assert_mem_round_trip("str x0, [sp, #-16]!");
        // Post-index.
        assert_mem_round_trip("ldr x0, [x1], #8");
        assert_mem_round_trip("str x0, [x1], #-8");
        // Register-offset, with and without LSL.
        assert_mem_round_trip("ldr x0, [x1, x2]");
        assert_mem_round_trip("ldr x0, [x1, x2, lsl #3]");
        // Register-extend.
        assert_mem_round_trip("ldr x0, [x1, w2, uxtw #2]");
        assert_mem_round_trip("ldr x0, [x1, w2, sxtw]");
        // Other mnemonics.
        assert_mem_round_trip("ldrb x0, [x1]");
        assert_mem_round_trip("ldrh x0, [x1, #4]");
        assert_mem_round_trip("ldrsb x0, [x1]");
        assert_mem_round_trip("ldrsh x0, [x1]");
        assert_mem_round_trip("ldrsw x0, [x1]");
        assert_mem_round_trip("strb x0, [x1]");
        assert_mem_round_trip("strh x0, [x1]");
        // Pair forms.
        assert_mem_round_trip("ldp x0, x1, [sp]");
        assert_mem_round_trip("ldp x0, x1, [sp, #16]");
        assert_mem_round_trip("ldp x0, x1, [sp, #-16]!");
        assert_mem_round_trip("ldp x0, x1, [sp], #16");
        assert_mem_round_trip("stp x29, x30, [sp, #-16]!");
        assert_mem_round_trip("ldpsw x0, x1, [sp]");
    }

    #[test]
    fn parse_ldr_pre_index_yields_pre_index_mode() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let instr = parse_one("ldr x0, [x1, #8]!");
        assert_eq!(
            instr,
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 8,
                    mode: IndexMode::PreIndex,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    #[test]
    fn parse_ldr_post_index_yields_post_index_mode() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let instr = parse_one("ldr x0, [x1], #8");
        assert_eq!(
            instr,
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 8,
                    mode: IndexMode::PostIndex,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    #[test]
    fn parse_ldr_register_offset_with_shift() {
        use crate::ir::types::{AccessWidth, AddressOperand};
        let instr = parse_one("ldr x0, [x1, x2, lsl #3]");
        assert_eq!(
            instr,
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Reg {
                    base: Register::X1,
                    idx: Register::X2,
                    shift: 3,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    #[test]
    fn parse_memory_register_offset_lsl_rejects_illegal_shift_for_access_width() {
        for (text, expected) in [
            ("ldrb x0, [x1, x2, lsl #1]", "expected 0"),
            ("ldrh x0, [x1, x2, lsl #2]", "expected 0 or 1"),
            ("ldr w0, [x1, x2, lsl #3]", "expected 0 or 2"),
            ("ldr x0, [x1, x2, lsl #17]", "expected 0 or 3"),
            ("str x0, [x1, x2, lsl #2]", "expected 0 or 3"),
        ] {
            let err = parse_line(text).expect_err("memory LSL shift should be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("memory LSL amount"),
                "{text}: error should name memory LSL amount, got {msg}"
            );
            assert!(
                msg.contains(expected),
                "{text}: error should mention {expected}, got {msg}"
            );
        }
    }

    #[test]
    fn parse_memory_register_offset_lsl_accepts_legal_shift_for_access_width() {
        use crate::ir::types::AddressOperand;

        for (text, expected_shift) in [
            ("ldrb x0, [x1, x2, lsl #0]", 0),
            ("ldrh x0, [x1, x2, lsl #1]", 1),
            ("ldr w0, [x1, x2, lsl #2]", 2),
            ("ldr x0, [x1, x2, lsl #3]", 3),
            ("str x0, [x1, x2, lsl #3]", 3),
        ] {
            let instr = parse_one(text);
            let (Instruction::Ldr { addr, .. } | Instruction::Str { addr, .. }) = instr else {
                panic!("{text}: expected ldr/str-like instruction, got {instr:?}");
            };
            assert_eq!(
                addr,
                AddressOperand::Reg {
                    base: Register::X1,
                    idx: Register::X2,
                    shift: expected_shift,
                },
                "{text}"
            );
        }
    }

    #[test]
    fn pair_mem_rejects_register_offset_addressing() {
        for text in [
            "ldp x0, x1, [x2, x3]",
            "ldp x0, x1, [x2, x3, lsl #3]",
            "stp x0, x1, [x2, x3]",
            "ldpsw x0, x1, [x2, x3, lsl #2]",
        ] {
            let err = parse_line(text).expect_err("pair register-offset should be rejected");
            let msg = err.to_string();
            let mnemonic = text.split_whitespace().next().unwrap();
            assert!(
                msg.contains(mnemonic),
                "{text}: error should name mnemonic `{mnemonic}`, got {msg}"
            );
            assert!(
                msg.contains("register-offset"),
                "{text}: error should name register-offset addressing, got {msg}"
            );
        }
    }

    #[test]
    fn pair_mem_rejects_register_extend_addressing() {
        for text in [
            "ldp x0, x1, [x2, w3, uxtw #3]",
            "stp x0, x1, [x2, w3, sxtw]",
            "ldpsw x0, x1, [x2, w3, sxtw #2]",
        ] {
            let err = parse_line(text).expect_err("pair register-extend should be rejected");
            let msg = err.to_string();
            let mnemonic = text.split_whitespace().next().unwrap();
            assert!(
                msg.contains(mnemonic),
                "{text}: error should name mnemonic `{mnemonic}`, got {msg}"
            );
            assert!(
                msg.contains("register-extend"),
                "{text}: error should name register-extend addressing, got {msg}"
            );
        }
    }

    #[test]
    fn parse_ldr_register_extend_with_w_index() {
        use crate::ir::types::{AccessWidth, AddressOperand, ExtendKind};
        let instr = parse_one("ldr x0, [x1, w2, uxtw #2]");
        assert_eq!(
            instr,
            Instruction::Ldr {
                rt: Register::X0,
                addr: AddressOperand::Ext {
                    base: Register::X1,
                    idx: Register::X2,
                    kind: ExtendKind::Uxtw,
                    shift: 2,
                },
                width: AccessWidth::Extended,
            }
        );
    }

    #[test]
    fn parse_ldp_yields_two_register_load() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
        let instr = parse_one("ldp x0, x1, [sp, #16]");
        assert_eq!(
            instr,
            Instruction::Ldp {
                rt1: Register::X0,
                rt2: Register::X1,
                addr: AddressOperand::Imm {
                    base: Register::SP,
                    offset: 16,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
                signed: false,
            }
        );
    }

    #[test]
    fn parse_ldpsw_yields_signed_pair_load() {
        let instr = parse_one("ldpsw x0, x1, [sp]");
        match instr {
            Instruction::Ldp {
                signed: true,
                width,
                ..
            } => {
                assert_eq!(width, crate::ir::types::AccessWidth::Word);
            }
            _ => panic!("expected Ldp with signed=true"),
        }
    }

    #[test]
    fn parse_ldrb_uses_byte_width() {
        let instr = parse_one("ldrb w0, [x1]");
        match instr {
            Instruction::Ldr { width, .. } => {
                assert_eq!(width, crate::ir::types::AccessWidth::Byte);
            }
            _ => panic!("expected Ldr with byte width"),
        }
    }
}

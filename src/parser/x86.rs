//! Intel-syntax x86 assembly parser.
//!
//! Parses GNU/Intel-syntax x86 assembly text into the minimal-core
//! `X86Instruction` IR. Mirrors `src/parser/mod.rs::parse_assembly_string`
//! for the AArch64 path. `parse_x86_assembly_string` and the line-
//! classification helpers are unused today; they exist as the future
//! consumer surface for the deferred x86 LLM path (ADR-0004 decision 3,
//! plus #77 stage 1 step 13 deferral). Tests cover them so they stay
//! correct until the LLM x86 follow-up lands.

#![allow(dead_code)]

use crate::isa::x86::{X86Condition, X86Instruction, X86Operand, X86Register};
use crate::parser::ParseError;

/// Parse a condition-code suffix from a SETcc / CMOVcc / Jcc mnemonic. Accepts
/// the canonical 16 codes plus the most common GAS aliases
/// (`z`/`nz`/`nae`/`nb`/`nc`/`pe`/`po`/`nge`/`nl`/`ng`/`nle`).
/// Returns `Err` on anything unrecognised so callers surface bad input
/// instead of silently dropping the instruction.
pub fn parse_x86_condition(suffix: &str) -> Result<X86Condition, String> {
    match suffix.trim().to_lowercase().as_str() {
        "e" | "z" => Ok(X86Condition::E),
        "ne" | "nz" => Ok(X86Condition::NE),
        "b" | "c" | "nae" => Ok(X86Condition::B),
        "ae" | "nb" | "nc" => Ok(X86Condition::AE),
        "be" | "na" => Ok(X86Condition::BE),
        "a" | "nbe" => Ok(X86Condition::A),
        "l" | "nge" => Ok(X86Condition::L),
        "ge" | "nl" => Ok(X86Condition::GE),
        "le" | "ng" => Ok(X86Condition::LE),
        "g" | "nle" => Ok(X86Condition::G),
        "s" => Ok(X86Condition::S),
        "ns" => Ok(X86Condition::NS),
        "o" => Ok(X86Condition::O),
        "no" => Ok(X86Condition::NO),
        "p" | "pe" => Ok(X86Condition::P),
        "np" | "po" => Ok(X86Condition::NP),
        other => Err(format!("unknown x86 condition suffix: '{}'", other)),
    }
}

/// x86 parser mode for Capstone-derived binary input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X86ParseMode {
    Mode64,
    Mode32,
}

impl X86ParseMode {
    fn mode_width(self) -> u32 {
        match self {
            X86ParseMode::Mode64 => 64,
            X86ParseMode::Mode32 => 32,
        }
    }

    fn arch_label(self) -> &'static str {
        match self {
            X86ParseMode::Mode64 => "x86-64",
            X86ParseMode::Mode32 => "x86-32",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum X86RegisterParseError {
    Unknown(String),
    UnsupportedAlias(String),
}

impl std::fmt::Display for X86RegisterParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            X86RegisterParseError::Unknown(msg) | X86RegisterParseError::UnsupportedAlias(msg) => {
                f.write_str(msg)
            }
        }
    }
}

fn classify_x86_register_alias(reg_str: &str) -> Result<(X86Register, u32), X86RegisterParseError> {
    match reg_str.trim().to_lowercase().as_str() {
        "rax" => Ok((X86Register::RAX, 64)),
        "eax" => Ok((X86Register::RAX, 32)),
        "ax" => Ok((X86Register::RAX, 16)),
        "al" => Ok((X86Register::RAX, 8)),
        "rcx" => Ok((X86Register::RCX, 64)),
        "ecx" => Ok((X86Register::RCX, 32)),
        "cx" => Ok((X86Register::RCX, 16)),
        "cl" => Ok((X86Register::RCX, 8)),
        "rdx" => Ok((X86Register::RDX, 64)),
        "edx" => Ok((X86Register::RDX, 32)),
        "dx" => Ok((X86Register::RDX, 16)),
        "dl" => Ok((X86Register::RDX, 8)),
        "rbx" => Ok((X86Register::RBX, 64)),
        "ebx" => Ok((X86Register::RBX, 32)),
        "bx" => Ok((X86Register::RBX, 16)),
        "bl" => Ok((X86Register::RBX, 8)),
        "rsp" => Ok((X86Register::RSP, 64)),
        "esp" => Ok((X86Register::RSP, 32)),
        "sp" => Ok((X86Register::RSP, 16)),
        "spl" => Ok((X86Register::RSP, 8)),
        "rbp" => Ok((X86Register::RBP, 64)),
        "ebp" => Ok((X86Register::RBP, 32)),
        "bp" => Ok((X86Register::RBP, 16)),
        "bpl" => Ok((X86Register::RBP, 8)),
        "rsi" => Ok((X86Register::RSI, 64)),
        "esi" => Ok((X86Register::RSI, 32)),
        "si" => Ok((X86Register::RSI, 16)),
        "sil" => Ok((X86Register::RSI, 8)),
        "rdi" => Ok((X86Register::RDI, 64)),
        "edi" => Ok((X86Register::RDI, 32)),
        "di" => Ok((X86Register::RDI, 16)),
        "dil" => Ok((X86Register::RDI, 8)),
        "r8" => Ok((X86Register::R8, 64)),
        "r8d" => Ok((X86Register::R8, 32)),
        "r8w" => Ok((X86Register::R8, 16)),
        "r8b" => Ok((X86Register::R8, 8)),
        "r9" => Ok((X86Register::R9, 64)),
        "r9d" => Ok((X86Register::R9, 32)),
        "r9w" => Ok((X86Register::R9, 16)),
        "r9b" => Ok((X86Register::R9, 8)),
        "r10" => Ok((X86Register::R10, 64)),
        "r10d" => Ok((X86Register::R10, 32)),
        "r10w" => Ok((X86Register::R10, 16)),
        "r10b" => Ok((X86Register::R10, 8)),
        "r11" => Ok((X86Register::R11, 64)),
        "r11d" => Ok((X86Register::R11, 32)),
        "r11w" => Ok((X86Register::R11, 16)),
        "r11b" => Ok((X86Register::R11, 8)),
        "r12" => Ok((X86Register::R12, 64)),
        "r12d" => Ok((X86Register::R12, 32)),
        "r12w" => Ok((X86Register::R12, 16)),
        "r12b" => Ok((X86Register::R12, 8)),
        "r13" => Ok((X86Register::R13, 64)),
        "r13d" => Ok((X86Register::R13, 32)),
        "r13w" => Ok((X86Register::R13, 16)),
        "r13b" => Ok((X86Register::R13, 8)),
        "r14" => Ok((X86Register::R14, 64)),
        "r14d" => Ok((X86Register::R14, 32)),
        "r14w" => Ok((X86Register::R14, 16)),
        "r14b" => Ok((X86Register::R14, 8)),
        "r15" => Ok((X86Register::R15, 64)),
        "r15d" => Ok((X86Register::R15, 32)),
        "r15w" => Ok((X86Register::R15, 16)),
        "r15b" => Ok((X86Register::R15, 8)),
        _ => Err(X86RegisterParseError::Unknown(format!(
            "Unknown x86 register: {}",
            reg_str
        ))),
    }
}

/// Parse a single x86 register name (case-insensitive).
///
/// Width aliases (`eax`, `ax`, `al`) collapse to the canonical 64-bit
/// variant. Legacy high-byte aliases (`ah`, `bh`, `ch`, `dh`) are
/// intentionally excluded because the minimal x86 IR models the
/// low-byte/REX alias set.
pub fn parse_x86_register(reg_str: &str) -> Result<X86Register, String> {
    classify_x86_register_alias(reg_str)
        .map(|(reg, _width)| reg)
        .map_err(|err| err.to_string())
}

/// Parse a single x86 register name and report the textual alias width.
///
/// This is syntax metadata only: the returned register is still the
/// canonical minimal-IR register, while the width preserves whether the
/// source text named `rax`, `eax`, `ax`, or `al`.
pub fn parse_x86_register_with_width(reg_str: &str) -> Result<(X86Register, u32), String> {
    classify_x86_register_alias(reg_str).map_err(|err| err.to_string())
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

fn parse_x86_register_for_mode(
    reg_str: &str,
    mode: X86ParseMode,
) -> Result<X86Register, X86RegisterParseError> {
    let (reg, alias_width) = classify_x86_register_alias(reg_str)?;
    let trimmed = reg_str.trim();
    if mode == X86ParseMode::Mode32
        && matches!(
            reg,
            X86Register::R8
                | X86Register::R9
                | X86Register::R10
                | X86Register::R11
                | X86Register::R12
                | X86Register::R13
                | X86Register::R14
                | X86Register::R15
        )
    {
        return Err(X86RegisterParseError::UnsupportedAlias(format!(
            "unsupported {} register alias: '{}' names an extended register, \
             which is not encodable in x86-32",
            mode.arch_label(),
            trimmed
        )));
    }
    if alias_width != mode.mode_width() {
        return Err(X86RegisterParseError::UnsupportedAlias(format!(
            "unsupported {} register alias width: '{}' is {}-bit, but the \
             current x86 IR only models {}-bit operands from binary input",
            mode.arch_label(),
            trimmed,
            alias_width,
            mode.mode_width()
        )));
    }
    Ok(reg)
}

fn parse_x86_operand_for_mode(op_str: &str, mode: X86ParseMode) -> Result<X86Operand, String> {
    let s = op_str.trim();
    match parse_x86_register_for_mode(s, mode) {
        Ok(reg) => Ok(X86Operand::Register(reg)),
        Err(X86RegisterParseError::UnsupportedAlias(msg)) => Err(msg),
        Err(X86RegisterParseError::Unknown(_)) => {
            let imm = parse_x86_immediate(s)?;
            Ok(X86Operand::Immediate(imm))
        }
    }
}

/// Parse a register, dispatching on whether an operand width is known.
///
/// `Some(mode)` is the binary/Capstone path: it width-checks the alias and
/// rejects spellings that are not the mode's native width (see
/// `parse_x86_register_for_mode`). `None` is the assembly-text path, which
/// is width-agnostic (`parse_x86_register`).
fn parse_x86_register_with_mode(
    reg_str: &str,
    mode: Option<X86ParseMode>,
) -> Result<X86Register, String> {
    match mode {
        Some(mode) => parse_x86_register_for_mode(reg_str, mode).map_err(|err| err.to_string()),
        None => parse_x86_register(reg_str),
    }
}

/// Parse the interim full-width SETcc pseudo-instruction's destination.
///
/// Width-agnostic text accepts only the canonical register spelling emitted by
/// `Display`. Mode-aware input comes from real machine code, where SETcc is a
/// partial byte write that the current IR cannot soundly represent (#75).
fn parse_x86_setcc_register_with_mode(
    reg_str: &str,
    mode: Option<X86ParseMode>,
) -> Result<X86Register, String> {
    if let Some(mode) = mode {
        return Err(format!(
            "architectural byte SETcc from {} binary input cannot be represented until #75",
            mode.arch_label()
        ));
    }
    let (reg, alias_width) = classify_x86_register_alias(reg_str).map_err(|err| err.to_string())?;
    if alias_width != 64 {
        return Err(format!(
            "SETcc full-width pseudo-instruction requires a canonical 64-bit register spelling, \
             got '{}'",
            reg_str.trim()
        ));
    }
    Ok(reg)
}

/// Operand sibling of [`parse_x86_register_with_mode`]: `Some(mode)` enforces
/// the mode's register width, `None` is the width-agnostic assembly-text path.
fn parse_x86_operand_with_mode(
    op_str: &str,
    mode: Option<X86ParseMode>,
) -> Result<X86Operand, String> {
    match mode {
        Some(mode) => parse_x86_operand_for_mode(op_str, mode),
        None => parse_x86_operand(op_str),
    }
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
    x86_ir_from_mnemonic_impl(mnemonic, op_str, None)
}

/// Convert a `(mnemonic, op_str)` pair into x86 IR for binary input
/// disassembled in a known mode. Ordinary instructions accept only mode-width
/// register aliases. MOVZX/MOVSX additionally accept an explicitly modelled
/// 8- or 16-bit source alias while keeping a mode-width destination.
pub fn x86_ir_from_mnemonic_for_mode(
    mnemonic: &str,
    op_str: &str,
    mode: X86ParseMode,
) -> Result<Option<X86Instruction>, String> {
    x86_ir_from_mnemonic_impl(mnemonic, op_str, Some(mode))
}

fn x86_ir_from_mnemonic_impl(
    mnemonic: &str,
    op_str: &str,
    mode: Option<X86ParseMode>,
) -> Result<Option<X86Instruction>, String> {
    let mnemonic = mnemonic.trim().to_lowercase();

    // SETcc — one canonical full-register destination in text pseudo-syntax.
    // Mode-aware binary input is rejected because real SETcc is a byte write
    // that cannot be represented soundly until #75.
    if let Some(suffix) = mnemonic.strip_prefix("set") {
        let cond = parse_x86_condition(suffix)?;
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 1 || parts[0].is_empty() {
            let operand_count = if op_str.trim().is_empty() {
                0
            } else {
                parts.len()
            };
            return Err(format!(
                "set{} expects 1 operand, got {}",
                suffix, operand_count
            ));
        }
        let rd = parse_x86_setcc_register_with_mode(parts[0], mode)?;
        return Ok(Some(X86Instruction::Setcc { rd, cond }));
    }

    // CMOVcc — strip "cmov" prefix, parse suffix, expect
    // two register operands. Unknown suffixes are errors, not Ok(None).
    if let Some(suffix) = mnemonic.strip_prefix("cmov") {
        let cond = parse_x86_condition(suffix)?;
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Err(format!(
                "cmov{} expects 2 operands, got {}",
                suffix,
                parts.len()
            ));
        }
        let rd = parse_x86_register_with_mode(parts[0], mode)?;
        let rs = parse_x86_register_with_mode(parts[1], mode)?;
        return Ok(Some(X86Instruction::Cmov { rd, rs, cond }));
    }

    // Jcc — strip "j" prefix (excluding "jmp"), parse suffix,
    // validate the operand is a numeric target then discard it.
    // Mnemonics like `jrcxz`/`jecxz` start with 'j' but aren't
    // flag-based conditional branches — `parse_x86_condition` rejects
    // their suffixes. Fall back to `Ok(None)` for those (same shape
    // unsupported mnemonics like `lea` get) instead of erroring; that
    // way `convert_to_x86_ir`'s unified "unsupported mnemonic" branch
    // produces an actionable window-rejection error.
    if mnemonic != "jmp"
        && let Some(suffix) = mnemonic.strip_prefix('j')
    {
        let Ok(cond) = parse_x86_condition(suffix) else {
            return Ok(None);
        };
        let op = op_str.trim();
        if op.is_empty() {
            return Err(format!("j{} expects a target operand", suffix));
        }
        // Capstone renders Jcc targets as absolute addresses. Validate
        // the operand parses as an immediate; if Capstone ever switches
        // to labels we want the failure to surface here rather than
        // silently producing a Jcc with a corrupted target reading.
        parse_x86_immediate(op)
            .map_err(|e| format!("j{} target must be numeric: {}", suffix, e))?;
        return Ok(Some(X86Instruction::Jcc { cond }));
    }

    // NEG / NOT / INC / DEC are the SINGLE-operand families. They expect
    // exactly one register operand: a comma in the operand string (e.g. the
    // two-operand `neg rax, rbx`) is rejected as an unsupported shape via
    // `Ok(None)`, the same way an unknown mnemonic is. Handled here, ahead
    // of the two-operand families below which hard-require `parts.len() == 2`.
    if matches!(mnemonic.as_str(), "neg" | "not" | "inc" | "dec") {
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 1 {
            return Ok(None);
        }
        let rd = parse_x86_register_with_mode(parts[0], mode)?;
        return Ok(Some(match mnemonic.as_str() {
            "neg" => X86Instruction::Neg { rd },
            "not" => X86Instruction::Not { rd },
            "inc" => X86Instruction::Inc { rd },
            _ => X86Instruction::Dec { rd },
        }));
    }

    // IMUL is the FIRST x86 instruction with both a two-operand and a
    // three-operand single-destination form, so it gets its own arity-aware
    // branch ahead of the strictly-two-operand families below.
    //   * `imul rd, rs`       -> ImulReg     (rd = rd * rs; rd read + written)
    //   * `imul rd, rs, imm`  -> ImulRegImm  (rd = rs * imm; rd written only)
    // The 1-operand RDX:RAX widening form (`imul rax`) is deferred and surfaces
    // as `Ok(None)` (an unsupported shape), like an unknown mnemonic. The
    // 3-operand register-source-with-register-count is not an IMUL shape; a
    // third register operand is rejected here.
    if mnemonic == "imul" {
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        match parts.len() {
            2 => {
                let rd = parse_x86_register_with_mode(parts[0], mode)?;
                let rs = parse_x86_register_with_mode(parts[1], mode)?;
                return Ok(Some(X86Instruction::ImulReg { rd, rs }));
            }
            3 => {
                let rd = parse_x86_register_with_mode(parts[0], mode)?;
                let rs = parse_x86_register_with_mode(parts[1], mode)?;
                let imm = parse_x86_immediate(parts[2])?;
                return Ok(Some(X86Instruction::ImulRegImm { rd, rs, imm }));
            }
            // 1-operand widening form (deferred) and any other arity are
            // unsupported shapes.
            _ => return Ok(None),
        }
    }

    // LEA is the FIRST x86 instruction with a memory (bracket) operand. Only
    // the minimal register-base + displacement form is modelled:
    //   * `lea rd, [base]`        -> Lea { rd, base, disp: 0 }
    //   * `lea rd, [base + disp]` -> Lea { rd, base, disp }
    //   * `lea rd, [base - disp]` -> Lea { rd, base, disp: -disp }
    // The index*scale, second-register, and RIP-relative forms are DEFERRED and
    // surface as `Ok(None)` (an unsupported shape), like an unknown mnemonic.
    // See `parse_x86_lea_memory_operand` for the bracket grammar and rejections.
    if mnemonic == "lea" {
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Ok(None);
        }
        let rd = parse_x86_register_with_mode(parts[0], mode)?;
        let Some((base, disp)) = parse_x86_lea_memory_operand(parts[1], mode)? else {
            return Ok(None);
        };
        return Ok(Some(X86Instruction::Lea { rd, base, disp }));
    }

    // MOVZX / MOVSX are the narrow exception to the mode-width-only parser
    // rule: the destination must be the selected mode width, while the source
    // alias spelling supplies the semantic 8- or 16-bit extraction width.
    if matches!(mnemonic.as_str(), "movzx" | "movsx") {
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return Ok(None);
        }

        let (rd, destination_width) = match mode {
            Some(mode) => (
                parse_x86_register_for_mode(parts[0], mode).map_err(|err| err.to_string())?,
                mode.mode_width(),
            ),
            None => parse_x86_register_with_width(parts[0])?,
        };
        if !matches!(destination_width, 32 | 64) {
            return Err(format!(
                "{} destination '{}' must be a 32- or 64-bit register",
                mnemonic, parts[0]
            ));
        }

        let (rs, src_width) =
            classify_x86_register_alias(parts[1]).map_err(|err| err.to_string())?;
        if !matches!(src_width, 8 | 16) || src_width >= destination_width {
            return Err(format!(
                "{} source '{}' must be an 8- or 16-bit register narrower than its destination",
                mnemonic, parts[1]
            ));
        }
        if mode == Some(X86ParseMode::Mode32) {
            let index = rs.index().expect("all x86 GPRs have an index");
            if index >= 8 {
                return Err(format!(
                    "unsupported x86-32 register alias: '{}' names an extended register, \
                     which is not encodable in x86-32",
                    parts[1]
                ));
            }
            if src_width == 8 && index >= 4 {
                return Err(format!(
                    "unsupported x86-32 8-bit register alias: '{}' requires a REX prefix, \
                     which is unavailable in x86-32",
                    parts[1]
                ));
            }
        }

        return Ok(Some(if mnemonic == "movzx" {
            X86Instruction::Movzx { rd, rs, src_width }
        } else {
            X86Instruction::Movsx { rd, rs, src_width }
        }));
    }

    // Reject unsupported mnemonics before attempting operand parsing so
    // shapes outside the minimal core surface as "unsupported mnemonic"
    // rather than a confusing downstream immediate parse error.
    if !matches!(
        mnemonic.as_str(),
        "mov"
            | "movabs"
            | "add"
            | "sub"
            | "and"
            | "or"
            | "xor"
            | "cmp"
            | "test"
            | "shl"
            | "sal"
            | "shr"
            | "sar"
            | "rol"
            | "ror"
    ) {
        return Ok(None);
    }
    let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
    // Every mnemonic in the minimal-core set above is two-operand
    // (reg/reg or reg/imm). A non-two-operand operand string is treated
    // as an unsupported shape and surfaces as `Ok(None)`, the same way
    // an unknown mnemonic does on the early-return above.
    if parts.len() != 2 {
        return Ok(None);
    }
    let rd = parse_x86_register_with_mode(parts[0], mode)?;
    let src_op = parse_x86_operand_with_mode(parts[1], mode)?;
    let make = |reg_form: fn(X86Register, X86Register) -> X86Instruction,
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
        "cmp" => make(
            |rn, rs| X86Instruction::CmpReg { rn, rs },
            |rn, imm| X86Instruction::CmpImm { rn, imm },
        ),
        "test" => make(
            |rn, rs| X86Instruction::TestReg { rn, rs },
            |rn, imm| X86Instruction::TestImm { rn, imm },
        ),
        // SHL/SAL, SHR, SAR take a register plus an immediate COUNT. `sal`
        // assembles identically to `shl`, so it parses to `Shl`. Only the
        // immediate-count form is modelled — the register (CL) count form is
        // deferred and surfaces as `Ok(None)` (an unsupported shape).
        "shl" | "sal" | "shr" | "sar" => match src_op {
            X86Operand::Immediate(imm) => Ok(Some(match mnemonic.as_str() {
                "shl" | "sal" => X86Instruction::Shl { rd, imm },
                "shr" => X86Instruction::Shr { rd, imm },
                _ => X86Instruction::Sar { rd, imm },
            })),
            X86Operand::Register(_) => Ok(None),
        },
        // ROL/ROR take a register plus an immediate COUNT. Only the
        // immediate-count form is modelled — the register (CL) count form is
        // deferred and surfaces as `Ok(None)` (an unsupported shape).
        "rol" | "ror" => match src_op {
            X86Operand::Immediate(imm) => Ok(Some(match mnemonic.as_str() {
                "rol" => X86Instruction::Rol { rd, imm },
                _ => X86Instruction::Ror { rd, imm },
            })),
            X86Operand::Register(_) => Ok(None),
        },
        _ => Ok(None),
    }
}

/// Parse the LEA memory operand in its minimal register-base + displacement
/// form. The accepted grammar (Intel bracket syntax, as Capstone emits) is:
///
/// ```text
///   mem  := '[' base ']'
///         | '[' base '+' disp ']'
///         | '[' base '-' disp ']'
///   base := <register>
///   disp := <immediate>   (decimal or hex, fits a signed 32-bit displacement)
/// ```
///
/// Returns `Ok(Some((base, disp)))` on a match, or `Ok(None)` for any DEFERRED
/// shape so the caller surfaces it as an unsupported instruction (like an
/// unknown mnemonic). The deferred shapes that yield `Ok(None)` are: anything
/// without the surrounding brackets; an index*scale term (`*`); a second
/// register (`[base + index]`); a compound `[base + index + disp]`; and
/// RIP/EIP-relative bases (the register parse rejects `rip`/`eip`).
///
/// A register parse error on the base (e.g. an extended register in 32-bit
/// mode) propagates as `Err`, matching the other register-operand families.
fn parse_x86_lea_memory_operand(
    op_str: &str,
    mode: Option<X86ParseMode>,
) -> Result<Option<(X86Register, i64)>, String> {
    let trimmed = op_str.trim();
    // Must be a bracketed memory operand: `[ ... ]`.
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Ok(None);
    };
    let inner = inner.trim();

    // index*scale is a deferred form.
    if inner.contains('*') {
        return Ok(None);
    }

    // Split into a base term and an optional signed displacement. A `+`/`-`
    // separates the base from the displacement; more than one separator (e.g.
    // `[base + index + disp]`) is a deferred compound form.
    let (base_str, disp) = match inner.find(['+', '-']) {
        None => (inner, 0i64),
        Some(pos) => {
            let base_str = inner[..pos].trim();
            let rest = inner[pos..].trim();
            // A second `+`/`-` in the remainder means a compound term — deferred.
            if rest[1..].contains(['+', '-']) {
                return Ok(None);
            }
            // The displacement must parse as an immediate. If it instead names a
            // register (`[base + index]`), it is a deferred second-register form,
            // not a parse error.
            let sign = &rest[..1];
            let magnitude = rest[1..].trim();
            let Ok(mag) = parse_x86_immediate(magnitude) else {
                return Ok(None);
            };
            let disp = if sign == "-" { -mag } else { mag };
            (base_str, disp)
        }
    };

    if base_str.is_empty() {
        return Ok(None);
    }
    // RIP/EIP-relative addressing is a deferred form; surface it as `Ok(None)`
    // rather than a register-parse error so it is treated as an unsupported
    // shape like the index*scale and second-register forms above.
    if matches!(base_str.to_lowercase().as_str(), "rip" | "eip") {
        return Ok(None);
    }
    // The base must be a register; a register parse error (e.g. width/mode
    // mismatch) propagates as `Err`.
    let base = parse_x86_register_with_mode(base_str, mode)?;
    Ok(Some((base, disp)))
}

/// Parse an Intel-syntax x86 assembly text into a sequence of
/// `X86Instruction`s. Mirrors `crate::parser::parse_assembly_string`
/// for the AArch64 path.
///
/// Recognised lines: empty, comments (`;`, `//`, `#`), labels
/// (`name:`), directives (`.foo`), and instructions whose mnemonic is
/// one of the supported families (mov, add, sub, and, or, xor, cmp,
/// test, the single-operand neg/not/inc/dec, the immediate-count shifts
/// shl/sal/shr/sar, the immediate-count rotates rol/ror, the two- and
/// three-operand signed multiply imul, lea in its register-base +
/// displacement form, plus the conditional setCC, cmovCC, and jCC variants).
/// Anything else is a parse error.
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
            1,
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
    fn parse_register_reports_alias_widths() {
        let cases = [
            ("rax", X86Register::RAX, 64),
            ("r8", X86Register::R8, 64),
            ("eax", X86Register::RAX, 32),
            ("r8d", X86Register::R8, 32),
            ("ax", X86Register::RAX, 16),
            ("r8w", X86Register::R8, 16),
            ("al", X86Register::RAX, 8),
            ("r8b", X86Register::R8, 8),
        ];

        for (alias, expected_register, expected_width) in cases {
            assert_eq!(
                parse_x86_register_with_width(alias).unwrap(),
                (expected_register, expected_width),
                "{alias}"
            );
        }
        assert!(parse_x86_register_with_width("zmm0").is_err());
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
    fn movzx_movsx_capture_source_width_and_round_trip_display() {
        let cases = [
            (
                "movzx",
                "rax, bl",
                X86Instruction::Movzx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width: 8,
                },
                "movzx rax, bl",
            ),
            (
                "movsx",
                "r8, r9w",
                X86Instruction::Movsx {
                    rd: X86Register::R8,
                    rs: X86Register::R9,
                    src_width: 16,
                },
                "movsx r8, r9w",
            ),
        ];

        for (mnemonic, operands, expected, display) in cases {
            let parsed = x86_ir_from_mnemonic(mnemonic, operands)
                .unwrap()
                .expect("extension mnemonic should be supported");
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), display);

            let (round_trip_mnemonic, round_trip_operands) =
                display.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(round_trip_mnemonic, round_trip_operands)
                    .unwrap()
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn movzx_movsx_mode_parser_requires_native_destination_and_encodable_narrow_source() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("movzx", "rax, bl", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 8,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("movsx", "eax, dx", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs: X86Register::RDX,
                src_width: 16,
            }
        );

        for (mode, operands) in [
            (X86ParseMode::Mode64, "eax, bl"),
            (X86ParseMode::Mode64, "rax, ebx"),
            (X86ParseMode::Mode32, "ax, bl"),
            (X86ParseMode::Mode32, "eax, ebx"),
            (X86ParseMode::Mode32, "eax, spl"),
            (X86ParseMode::Mode32, "eax, r8b"),
        ] {
            assert!(
                x86_ir_from_mnemonic_for_mode("movzx", operands, mode).is_err(),
                "unsupported extension shape should fail: {mode:?} {operands}"
            );
        }
        assert!(x86_ir_from_mnemonic("movsx", "rax, 1").is_err());
        assert!(x86_ir_from_mnemonic("movzx", "rax, ah").is_err());
    }

    #[test]
    fn x86_ir_recognises_supported_mnemonic_families() {
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
            (
                "test",
                "rax, rbx",
                X86Instruction::TestReg {
                    rn: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ),
            (
                "test",
                "rax, 5",
                X86Instruction::TestImm {
                    rn: X86Register::RAX,
                    imm: 5,
                },
            ),
            (
                "cmove",
                "rax, rbx",
                X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond: X86Condition::E,
                },
            ),
            (
                "je",
                "0x10",
                X86Instruction::Jcc {
                    cond: X86Condition::E,
                },
            ),
        ];
        for (mn, ops, expected) in cases {
            let got = x86_ir_from_mnemonic(mn, ops).unwrap().unwrap();
            assert_eq!(got, expected, "{} {}", mn, ops);
        }
    }

    #[test]
    fn x86_ir_for_mode64_accepts_mode_width_and_rejects_narrow_aliases() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("add", "rax, 0", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("cmove", "rax, rbx", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }
        );

        for (mnemonic, operands) in [
            ("add", "eax, 0"),
            ("mov", "ax, 1"),
            ("mov", "al, 1"),
            ("cmove", "eax, ebx"),
        ] {
            let err = x86_ir_from_mnemonic_for_mode(mnemonic, operands, X86ParseMode::Mode64)
                .expect_err("narrow alias should be rejected in x86-64 binary parsing");
            assert!(
                err.contains("unsupported x86-64 register alias width"),
                "unexpected error for {mnemonic} {operands}: {err}"
            );
        }
    }

    #[test]
    fn x86_ir_for_mode32_accepts_only_i386_width_register_aliases() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("add", "eax, 0", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 0,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("mov", "ecx, edx", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::MovReg {
                rd: X86Register::RCX,
                rs: X86Register::RDX,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("cmove", "eax, ebx", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            }
        );

        for (mnemonic, operands) in [("mov", "ax, 1"), ("mov", "al, 1"), ("mov", "rax, 1")] {
            let err = x86_ir_from_mnemonic_for_mode(mnemonic, operands, X86ParseMode::Mode32)
                .expect_err("non-32-bit alias should be rejected in x86-32 binary parsing");
            assert!(
                err.contains("unsupported x86-32 register alias width"),
                "unexpected error for {mnemonic} {operands}: {err}"
            );
        }

        let err = x86_ir_from_mnemonic_for_mode("mov", "r8d, 1", X86ParseMode::Mode32)
            .expect_err("x86-32 must reject extended registers");
        assert!(
            err.contains("not encodable in x86-32"),
            "unexpected error for r8d: {err}"
        );
    }

    #[test]
    fn test_mnemonic_parses_reg_and_imm_forms_and_round_trips_display() {
        // `test rax, rbx` and `test rax, 5` parse to TestReg/TestImm, and the
        // Display output round-trips back through the parser to the same IR.
        let reg = x86_ir_from_mnemonic("test", "rax, rbx").unwrap().unwrap();
        assert_eq!(
            reg,
            X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            }
        );
        assert_eq!(reg.to_string(), "test rax, rbx");

        let imm = x86_ir_from_mnemonic("test", "rax, 5").unwrap().unwrap();
        assert_eq!(
            imm,
            X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 5,
            }
        );
        assert_eq!(imm.to_string(), "test rax, 5");

        // Display → parse round-trip for both forms.
        for instr in [reg, imm] {
            let text = instr.to_string();
            let mut parts = text.splitn(2, char::is_whitespace);
            let mnemonic = parts.next().unwrap();
            let ops = parts.next().unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn test_mnemonic_round_trips_through_mode_aware_binary_path() {
        // The Capstone/binary path (mode-aware) must also accept `test`.
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("test", "rax, rbx", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("test", "eax, 5", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::TestImm {
                rn: X86Register::RAX,
                imm: 5,
            }
        );
    }

    #[test]
    fn neg_not_parse_single_operand_and_round_trip_display() {
        // `neg rax` / `not rax` parse to the single-operand variants and
        // their Display output round-trips back to the same IR.
        let neg = x86_ir_from_mnemonic("neg", "rax").unwrap().unwrap();
        assert_eq!(
            neg,
            X86Instruction::Neg {
                rd: X86Register::RAX
            }
        );
        assert_eq!(neg.to_string(), "neg rax");

        let not = x86_ir_from_mnemonic("not", "rax").unwrap().unwrap();
        assert_eq!(
            not,
            X86Instruction::Not {
                rd: X86Register::RAX
            }
        );
        assert_eq!(not.to_string(), "not rax");

        for instr in [neg, not] {
            let text = instr.to_string();
            let (mnemonic, ops) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn neg_with_two_operands_is_rejected() {
        // The single-operand families must reject a second operand: `neg rax,
        // rbx` is an unsupported shape and surfaces as Ok(None), not a Neg.
        assert!(x86_ir_from_mnemonic("neg", "rax, rbx").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("not", "rax, rbx").unwrap().is_none());
    }

    #[test]
    fn inc_dec_parse_single_operand_and_round_trip_display() {
        // `inc rax` / `dec rax` parse to the single-operand variants and
        // their Display output round-trips back to the same IR.
        let inc = x86_ir_from_mnemonic("inc", "rax").unwrap().unwrap();
        assert_eq!(
            inc,
            X86Instruction::Inc {
                rd: X86Register::RAX
            }
        );
        assert_eq!(inc.to_string(), "inc rax");

        let dec = x86_ir_from_mnemonic("dec", "rax").unwrap().unwrap();
        assert_eq!(
            dec,
            X86Instruction::Dec {
                rd: X86Register::RAX
            }
        );
        assert_eq!(dec.to_string(), "dec rax");

        for instr in [inc, dec] {
            let text = instr.to_string();
            let (mnemonic, ops) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn inc_dec_with_two_operands_is_rejected() {
        // The single-operand families must reject a second operand: `inc rax,
        // rbx` is an unsupported shape and surfaces as Ok(None), not an Inc.
        assert!(x86_ir_from_mnemonic("inc", "rax, rbx").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("dec", "rax, rbx").unwrap().is_none());
    }

    #[test]
    fn inc_dec_round_trip_through_mode_aware_binary_path() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("inc", "rax", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Inc {
                rd: X86Register::RAX
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("dec", "eax", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Dec {
                rd: X86Register::RAX
            }
        );
    }

    #[test]
    fn shift_parse_register_plus_count_and_round_trip_display() {
        // shl / shr / sar parse to the immediate-count variants and Display
        // round-trips back to the same IR.
        let shl = x86_ir_from_mnemonic("shl", "rax, 1").unwrap().unwrap();
        assert_eq!(
            shl,
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 1
            }
        );
        assert_eq!(shl.to_string(), "shl rax, 1");

        let shr = x86_ir_from_mnemonic("shr", "rbx, 3").unwrap().unwrap();
        assert_eq!(
            shr,
            X86Instruction::Shr {
                rd: X86Register::RBX,
                imm: 3
            }
        );

        let sar = x86_ir_from_mnemonic("sar", "rcx, 7").unwrap().unwrap();
        assert_eq!(
            sar,
            X86Instruction::Sar {
                rd: X86Register::RCX,
                imm: 7
            }
        );

        for instr in [shl, shr, sar] {
            let text = instr.to_string();
            let (mnemonic, ops) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn sal_parses_to_shl() {
        // SAL and SHL assemble identically; the parser folds `sal` into `Shl`.
        assert_eq!(
            x86_ir_from_mnemonic("sal", "rax, 2").unwrap().unwrap(),
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 2
            }
        );
    }

    #[test]
    fn shift_with_register_count_is_rejected() {
        // The CL-register-count form is deferred: `shl rax, rcx` is an
        // unsupported shape and surfaces as Ok(None), not a Shl.
        assert!(x86_ir_from_mnemonic("shl", "rax, rcx").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("shr", "rax, rcx").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("sar", "rax, rcx").unwrap().is_none());
        // A single operand (no count) is also an unsupported shape.
        assert!(x86_ir_from_mnemonic("shl", "rax").unwrap().is_none());
    }

    #[test]
    fn shift_round_trip_through_mode_aware_binary_path() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("shl", "rax, 1", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 1
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("sar", "eax, 4", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Sar {
                rd: X86Register::RAX,
                imm: 4
            }
        );
    }

    #[test]
    fn rotate_parse_register_plus_count_and_round_trip_display() {
        // rol / ror parse to the immediate-count variants and Display
        // round-trips back to the same IR.
        let rol = x86_ir_from_mnemonic("rol", "rax, 1").unwrap().unwrap();
        assert_eq!(
            rol,
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1
            }
        );
        assert_eq!(rol.to_string(), "rol rax, 1");

        let ror = x86_ir_from_mnemonic("ror", "rbx, 5").unwrap().unwrap();
        assert_eq!(
            ror,
            X86Instruction::Ror {
                rd: X86Register::RBX,
                imm: 5
            }
        );
        assert_eq!(ror.to_string(), "ror rbx, 5");

        for instr in [rol, ror] {
            let text = instr.to_string();
            let (mnemonic, ops) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn rotate_with_register_count_is_rejected() {
        // The CL-register-count form is deferred: `rol rax, rcx` is an
        // unsupported shape and surfaces as Ok(None), not a Rol.
        assert!(x86_ir_from_mnemonic("rol", "rax, rcx").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("ror", "rax, rcx").unwrap().is_none());
        // A single operand (no count) is also an unsupported shape.
        assert!(x86_ir_from_mnemonic("rol", "rax").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("ror", "rbx").unwrap().is_none());
    }

    #[test]
    fn rotate_round_trip_through_mode_aware_binary_path() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("rol", "rax, 1", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("ror", "eax, 4", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 4
            }
        );
    }

    #[test]
    fn imul_parses_two_and_three_operand_forms_and_round_trips_display() {
        // `imul rax, rbx` -> ImulReg; `imul rax, rbx, 4` -> ImulRegImm. Display
        // output round-trips back to the same IR for both forms.
        let two = x86_ir_from_mnemonic("imul", "rax, rbx").unwrap().unwrap();
        assert_eq!(
            two,
            X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }
        );
        assert_eq!(two.to_string(), "imul rax, rbx");

        let three = x86_ir_from_mnemonic("imul", "rax, rbx, 4")
            .unwrap()
            .unwrap();
        assert_eq!(
            three,
            X86Instruction::ImulRegImm {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                imm: 4,
            }
        );
        assert_eq!(three.to_string(), "imul rax, rbx, 4");

        for instr in [two, three] {
            let text = instr.to_string();
            let (mnemonic, ops) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, ops).unwrap().unwrap(),
                instr,
                "round-trip failed for {text}"
            );
        }
    }

    #[test]
    fn imul_one_operand_widening_form_is_rejected() {
        // The 1-operand RDX:RAX widening IMUL is deferred: `imul rax` is an
        // unsupported shape and surfaces as Ok(None), not an ImulReg.
        assert!(x86_ir_from_mnemonic("imul", "rax").unwrap().is_none());
        // A 4-operand shape is also unsupported.
        assert!(
            x86_ir_from_mnemonic("imul", "rax, rbx, 4, 5")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn imul_round_trips_through_mode_aware_binary_path() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("imul", "rax, rbx", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("imul", "eax, ebx, 4", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::ImulRegImm {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                imm: 4,
            }
        );
    }

    #[test]
    fn neg_not_round_trip_through_mode_aware_binary_path() {
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("neg", "rax", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Neg {
                rd: X86Register::RAX
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("not", "eax", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Not {
                rd: X86Register::RAX
            }
        );
    }

    #[test]
    fn x86_ir_unsupported_mnemonic_returns_none() {
        assert!(x86_ir_from_mnemonic("ret", "").unwrap().is_none());
        assert!(x86_ir_from_mnemonic("jmp", "0x1234").unwrap().is_none());
        // `lea` in the minimal register-base + displacement form is now
        // supported; its DEFERRED shapes (index*scale, second register,
        // RIP-relative) still surface as `Ok(None)`.
        assert!(
            x86_ir_from_mnemonic("lea", "rax, [rbx + rcx*4]")
                .unwrap()
                .is_none()
        );
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
        // `lea` with a deferred index*scale memory operand is an unsupported
        // shape (the minimal register-base + displacement LEA is supported).
        let err =
            parse_x86_assembly_string("mov rax, rbx\nlea rax, [rbx + rcx*4]", "t".to_string())
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
        let empty_err = parse_x86_assembly_string("", "t".to_string()).unwrap_err();
        assert_eq!(empty_err.line_number, 1);
        assert_eq!(empty_err.message, "no instructions found in input");
        assert_eq!(empty_err.line_content, "t");

        let skipped_err =
            parse_x86_assembly_string("   \n\n; only comments\n", "t".to_string()).unwrap_err();
        assert_eq!(skipped_err.line_number, 1);
        assert_eq!(skipped_err.message, "no instructions found in input");
        assert_eq!(skipped_err.line_content, "t");
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

    // --- SETcc / CMOV / Jcc mnemonic parsing ---

    #[test]
    fn parses_and_displays_all_canonical_setcc_suffixes() {
        for cond in X86Condition::ALL {
            let mnemonic = format!("set{}", cond.suffix());
            let parsed = x86_ir_from_mnemonic(&mnemonic, "rax").unwrap().unwrap();
            let expected = X86Instruction::Setcc {
                rd: X86Register::RAX,
                cond,
            };
            assert_eq!(parsed, expected, "parsing {mnemonic} failed");
            assert_eq!(parsed.to_string(), format!("{mnemonic} rax"));
            assert_eq!(
                parse_x86_assembly_string(&parsed.to_string(), "setcc-round-trip".to_string())
                    .unwrap(),
                vec![parsed],
                "canonical {mnemonic} display must parse back to the same IR"
            );
        }

        for partial_width in ["al", "ax", "eax"] {
            let err = x86_ir_from_mnemonic("setne", partial_width)
                .expect_err("partial-width SETcc text must not enter the full-width pseudo-IR");
            assert!(
                err.contains("full-width pseudo-instruction"),
                "unexpected error for {partial_width}: {err}"
            );
        }
    }

    #[test]
    fn mode_aware_setcc_parsing_rejects_architectural_byte_instructions_until_issue_75() {
        for (mode, operand) in [
            (X86ParseMode::Mode64, "al"),
            (X86ParseMode::Mode64, "spl"),
            (X86ParseMode::Mode64, "r8b"),
            (X86ParseMode::Mode64, "ah"),
            (X86ParseMode::Mode64, "byte ptr [rax]"),
            (X86ParseMode::Mode32, "al"),
            (X86ParseMode::Mode32, "bl"),
        ] {
            let err = x86_ir_from_mnemonic_for_mode("setne", operand, mode)
                .expect_err("architectural byte SETcc must not enter the full-width pseudo-IR");
            assert!(
                err.contains("cannot be represented until #75"),
                "unexpected error for {} {operand}: {err}",
                mode.arch_label()
            );
        }
    }

    #[test]
    fn setcc_rejects_unknown_conditions_and_wrong_arity() {
        assert!(x86_ir_from_mnemonic("setxx", "rax").is_err());
        assert!(x86_ir_from_mnemonic("setne", "").is_err());
        assert!(x86_ir_from_mnemonic("setne", "rax, rbx").is_err());
    }

    #[test]
    fn parses_cmove_rax_rbx() {
        use crate::isa::x86::X86Condition;
        let r = x86_ir_from_mnemonic("cmove", "rax, rbx").unwrap();
        assert_eq!(
            r,
            Some(X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E
            })
        );
    }

    #[test]
    fn parses_all_canonical_cmov_suffixes() {
        use crate::isa::x86::X86Condition;
        let cases = [
            ("cmove", X86Condition::E),
            ("cmovne", X86Condition::NE),
            ("cmovb", X86Condition::B),
            ("cmovae", X86Condition::AE),
            ("cmovbe", X86Condition::BE),
            ("cmova", X86Condition::A),
            ("cmovl", X86Condition::L),
            ("cmovge", X86Condition::GE),
            ("cmovle", X86Condition::LE),
            ("cmovg", X86Condition::G),
            ("cmovs", X86Condition::S),
            ("cmovns", X86Condition::NS),
            ("cmovo", X86Condition::O),
            ("cmovno", X86Condition::NO),
            ("cmovp", X86Condition::P),
            ("cmovnp", X86Condition::NP),
        ];
        for (mn, cond) in cases {
            let r = x86_ir_from_mnemonic(mn, "rax, rbx").unwrap().unwrap();
            assert_eq!(
                r,
                X86Instruction::Cmov {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    cond
                },
                "parsing {} failed",
                mn
            );
        }
    }

    #[test]
    fn cmov_with_unknown_suffix_errors() {
        // `cmovxx` is not a real x86 mnemonic; parser must surface the
        // failure instead of silently producing Ok(None).
        let r = x86_ir_from_mnemonic("cmovxx", "rax, rbx");
        assert!(r.is_err(), "expected Err, got {:?}", r);
    }

    #[test]
    fn parses_je_as_jcc_e() {
        use crate::isa::x86::X86Condition;
        let r = x86_ir_from_mnemonic("je", "0x1234").unwrap();
        assert_eq!(
            r,
            Some(X86Instruction::Jcc {
                cond: X86Condition::E
            })
        );
    }

    #[test]
    fn parses_all_canonical_jcc_suffixes() {
        use crate::isa::x86::X86Condition;
        let cases = [
            ("je", X86Condition::E),
            ("jne", X86Condition::NE),
            ("jb", X86Condition::B),
            ("jae", X86Condition::AE),
            ("jbe", X86Condition::BE),
            ("ja", X86Condition::A),
            ("jl", X86Condition::L),
            ("jge", X86Condition::GE),
            ("jle", X86Condition::LE),
            ("jg", X86Condition::G),
            ("js", X86Condition::S),
            ("jns", X86Condition::NS),
            ("jo", X86Condition::O),
            ("jno", X86Condition::NO),
            ("jp", X86Condition::P),
            ("jnp", X86Condition::NP),
        ];
        for (mn, cond) in cases {
            let r = x86_ir_from_mnemonic(mn, "0x4242").unwrap().unwrap();
            assert_eq!(r, X86Instruction::Jcc { cond }, "parsing {} failed", mn);
        }
    }

    #[test]
    fn jmp_is_not_parsed_as_jcc() {
        // The unconditional JMP is not in scope; must not be claimed.
        let r = x86_ir_from_mnemonic("jmp", "0x100").unwrap();
        assert_eq!(r, None);
    }

    #[test]
    fn jrcxz_and_jecxz_fall_through_to_ok_none() {
        // jrcxz / jecxz appear in real compiled binaries. They start
        // with 'j' but aren't conditional branches with a flag-based
        // condition code, so they fall outside the Jcc IR. Returning
        // Err here would propagate through convert_to_x86_ir and refuse
        // the whole window; Ok(None) lets convert_to_x86_ir reject the
        // window with a clean "unsupported mnemonic" error instead.
        for mn in ["jrcxz", "jecxz", "jcxz"] {
            let r = x86_ir_from_mnemonic(mn, "0x100");
            assert_eq!(
                r,
                Ok(None),
                "{} should be Ok(None), not propagate an unknown-suffix Err",
                mn
            );
        }
    }

    #[test]
    fn jcc_with_non_numeric_operand_errors() {
        // Capstone always renders Jcc targets as numeric addresses.
        // Anything else is a sign the disassembly format changed —
        // surface it loudly.
        let r = x86_ir_from_mnemonic("je", "label");
        assert!(r.is_err(), "expected Err, got {:?}", r);
    }

    #[test]
    fn jcc_gas_aliases_normalize_to_canonical_conditions() {
        // GAS aliases (jc → jb, jz → je, jnae → jb, jnle → jg, etc.)
        // must produce the same Jcc IR as their canonical spelling so
        // the optimizer sees identical sequences regardless of which
        // form the upstream toolchain emitted.
        use crate::isa::x86::X86Condition;
        let alias_cases = [
            ("jc", X86Condition::B),
            ("jz", X86Condition::E),
            ("jnz", X86Condition::NE),
            ("jnae", X86Condition::B),
            ("jnb", X86Condition::AE),
            ("jnc", X86Condition::AE),
            ("jna", X86Condition::BE),
            ("jnbe", X86Condition::A),
            ("jnge", X86Condition::L),
            ("jnl", X86Condition::GE),
            ("jng", X86Condition::LE),
            ("jnle", X86Condition::G),
            ("jpe", X86Condition::P),
            ("jpo", X86Condition::NP),
        ];
        for (mn, expected_cond) in alias_cases {
            let r = x86_ir_from_mnemonic(mn, "0x100")
                .unwrap_or_else(|e| panic!("parse {}: {}", mn, e))
                .unwrap_or_else(|| panic!("parse {} produced None", mn));
            assert_eq!(
                r,
                X86Instruction::Jcc {
                    cond: expected_cond
                },
                "alias {} should normalize to canonical cond",
                mn
            );
        }
    }

    // ---- LEA (register-base + displacement) ----

    #[test]
    fn lea_parses_base_plus_disp_forms_and_round_trips_display() {
        // `[base + disp]`, bare `[base]`, and `[base - disp]` parse to Lea.
        let cases = [
            (
                "rax, [rbx + 1]",
                X86Instruction::Lea {
                    rd: X86Register::RAX,
                    base: X86Register::RBX,
                    disp: 1,
                },
            ),
            (
                "rax, [rbx]",
                X86Instruction::Lea {
                    rd: X86Register::RAX,
                    base: X86Register::RBX,
                    disp: 0,
                },
            ),
            (
                "rax, [rbx - 8]",
                X86Instruction::Lea {
                    rd: X86Register::RAX,
                    base: X86Register::RBX,
                    disp: -8,
                },
            ),
        ];
        for (ops, want) in cases {
            let got = x86_ir_from_mnemonic("lea", ops)
                .unwrap_or_else(|e| panic!("parse `lea {ops}`: {e}"))
                .unwrap_or_else(|| panic!("parse `lea {ops}` produced None"));
            assert_eq!(got, want, "parse mismatch for `lea {ops}`");
        }

        // Display → parse round-trip for each of the three displacement signs.
        for instr in cases.map(|(_, want)| want) {
            let text = instr.to_string();
            let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap();
            assert_eq!(
                x86_ir_from_mnemonic(mnemonic, rest).unwrap().unwrap(),
                instr,
                "Display round-trip failed for `{text}`"
            );
        }

        // Pin the exact Display rendering of each sign.
        assert_eq!(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 1,
            }
            .to_string(),
            "lea rax, [rbx + 1]"
        );
        assert_eq!(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0,
            }
            .to_string(),
            "lea rax, [rbx]"
        );
        assert_eq!(
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: -8,
            }
            .to_string(),
            "lea rax, [rbx - 8]"
        );
    }

    #[test]
    fn lea_accepts_capstone_hex_displacements_in_binary_path() {
        // Capstone emits hex displacements in Intel syntax; the mode-aware
        // binary path must accept them.
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("lea", "rax, [rbx + 0x10]", X86ParseMode::Mode64)
                .unwrap()
                .unwrap(),
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0x10,
            }
        );
        assert_eq!(
            x86_ir_from_mnemonic_for_mode("lea", "eax, [ebx - 0x10]", X86ParseMode::Mode32)
                .unwrap()
                .unwrap(),
            X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: -0x10,
            }
        );
    }

    #[test]
    fn lea_rejects_deferred_memory_operand_forms_as_unsupported() {
        // Index*scale, a second register, a compound base+index+disp, and
        // RIP-relative addressing are DEFERRED — each surfaces as `Ok(None)`
        // (an unsupported shape), not a parse error.
        for ops in [
            "rax, [rbx + rcx]",
            "rax, [rbx + rcx*4]",
            "rax, [rbx + rcx + 1]",
            "rax, [rip + 0x100]",
        ] {
            assert!(
                x86_ir_from_mnemonic("lea", ops).unwrap().is_none(),
                "`lea {ops}` should be an unsupported (deferred) shape"
            );
        }
        // A non-bracket second operand is also unsupported.
        assert!(x86_ir_from_mnemonic("lea", "rax, rbx").unwrap().is_none());
    }
}

//! AArch64 Capstone → IR bridge.
//!
//! Capstone renders some AArch64 encodings with alias spellings the GNU-assembler
//! parser does not accept directly (wide `mov Xd, #imm`, the `cinc`/`cinv`/`cneg`
//! conditional-select aliases). This module normalizes those spellings and then
//! delegates to [`crate::parser::parse_line`], which is the single source of truth
//! for the supported mnemonic set. Keeping the delegation here is what guarantees
//! the asm-text path and the ELF/Capstone path support exactly the same mnemonics
//! (see CLAUDE.md "Adding a new AArch64 instruction").

use crate::ir::instructions::MOVW_LEGAL_SHIFTS;
use crate::ir::{Condition, Instruction};
use crate::parser;

/// Outcome of converting one Capstone `(mnemonic, op_str)` pair into IR.
#[derive(Debug)]
pub enum ConvertOutcome {
    Instruction(Instruction),
    Skip,
    Unsupported(String),
}

fn capstone_instruction_line(mnemonic: &str, op_str: &str) -> String {
    if op_str.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{} {}", mnemonic, op_str)
    }
}

fn split_capstone_alias_operands(op_str: &str) -> Vec<&str> {
    op_str.split(',').map(str::trim).collect()
}

fn move_wide_movz_encoding(value: u64) -> Option<(u16, u8)> {
    for shift in MOVW_LEGAL_SHIFTS {
        let mask = 0xffff_u64 << shift;
        if value & !mask == 0 {
            let imm = ((value >> shift) & 0xffff) as u16;
            if imm != 0 {
                return Some((imm, shift));
            }
        }
    }
    None
}

fn move_wide_movn_encoding(value: u64) -> Option<(u16, u8)> {
    let inverted = !value;
    for shift in MOVW_LEGAL_SHIFTS {
        let imm = ((inverted >> shift) & 0xffff) as u16;
        if inverted == u64::from(imm) << shift {
            return Some((imm, shift));
        }
    }
    None
}

fn format_move_wide(mnemonic: &str, rd: &str, imm: u16, shift: u8) -> String {
    if shift == 0 {
        format!("{} {}, #{}", mnemonic, rd, imm)
    } else {
        format!("{} {}, #{}, lsl #{}", mnemonic, rd, imm, shift)
    }
}

fn normalize_mov_wide_alias(op_str: &str) -> Result<Option<String>, String> {
    let operands = split_capstone_alias_operands(op_str);
    if operands.len() != 2 {
        return Ok(None);
    }

    let rd = operands[0];
    if !rd.to_ascii_lowercase().starts_with('x') || parser::parse_register(rd).is_err() {
        return Ok(None);
    }

    let Ok(imm) = parser::parse_immediate(operands[1]) else {
        return Ok(None);
    };
    if (0..=0xffff).contains(&imm) {
        return Ok(None);
    }

    let value = imm as u64;
    if let Some((imm, shift)) = move_wide_movz_encoding(value) {
        return Ok(Some(format_move_wide("movz", rd, imm, shift)));
    }
    if let Some((imm, shift)) = move_wide_movn_encoding(value) {
        return Ok(Some(format_move_wide("movn", rd, imm, shift)));
    }

    Ok(None)
}

fn normalize_cond_select_alias(mnemonic: &str, op_str: &str) -> Result<String, String> {
    let operands = split_capstone_alias_operands(op_str);
    if operands.len() != 3 {
        return Err(format!(
            "{} alias requires 3 operands (rd, rn, cond), got {}",
            mnemonic,
            operands.len()
        ));
    }

    let rd = operands[0];
    let rn = operands[1];
    parser::parse_register(rd).map_err(|err| format!("invalid {mnemonic} destination: {err}"))?;
    parser::parse_register(rn).map_err(|err| format!("invalid {mnemonic} source: {err}"))?;

    let cond = parser::parse_condition(operands[2])?;
    if matches!(cond, Condition::AL | Condition::NV) {
        return Err(format!(
            "{} alias does not support {} condition",
            mnemonic, cond
        ));
    }

    let canonical = match mnemonic {
        "cinc" => "csinc",
        "cinv" => "csinv",
        "cneg" => "csneg",
        _ => unreachable!("conditional-select alias normalizer called for {mnemonic}"),
    };

    Ok(format!(
        "{} {}, {}, {}, {}",
        canonical,
        rd,
        rn,
        rn,
        cond.invert()
    ))
}

fn normalize_capstone_alias(mnemonic: &str, op_str: &str) -> Result<Option<String>, String> {
    let mnemonic = mnemonic.to_ascii_lowercase();
    match mnemonic.as_str() {
        "mov" => normalize_mov_wide_alias(op_str),
        "cinc" | "cinv" | "cneg" => normalize_cond_select_alias(&mnemonic, op_str).map(Some),
        _ => Ok(None),
    }
}

/// Render the diagnostic for a Capstone instruction the parser rejected. When
/// the alias bridge rewrote the raw spelling, the normalized form that was
/// actually handed to the parser is surfaced too — otherwise a bridge
/// regression would be invisible in the warning. Both parser failure modes
/// share this so their diagnostics stay consistent (`UnknownInstruction`
/// carries no message, `Other` carries one appended in parentheses).
fn describe_unsupported_line(raw_line: &str, line: &str, err: Option<&str>) -> String {
    let base = if line == raw_line {
        raw_line.to_string()
    } else {
        format!("{} normalized as `{}`", raw_line, line)
    };
    match err {
        Some(err) => format!("{} ({})", base, err),
        None => base,
    }
}

/// Convert one Capstone (mnemonic, op_str) pair into an IR outcome by
/// delegating to `parser::parse_line`. Keeping a single shared parser is what
/// guarantees the asm-text path and the ELF/Capstone path support exactly the
/// same mnemonic set (see CLAUDE.md "Adding a new AArch64 instruction").
pub fn convert_capstone_op(mnemonic: &str, op_str: &str) -> ConvertOutcome {
    if mnemonic.eq_ignore_ascii_case("nop") {
        // NOPs are filtered here; the assembler re-emits any padding needed.
        return ConvertOutcome::Skip;
    }

    let raw_line = capstone_instruction_line(mnemonic, op_str);
    let line = match normalize_capstone_alias(mnemonic, op_str) {
        Ok(Some(normalized)) => normalized,
        Ok(None) => raw_line.clone(),
        Err(err) => return ConvertOutcome::Unsupported(format!("{} ({})", raw_line, err)),
    };

    match parser::parse_line(&line) {
        Ok(parser::LineResult::Instruction(instr)) => ConvertOutcome::Instruction(instr),
        Ok(parser::LineResult::Skip) => ConvertOutcome::Skip,
        Err(parser::ParseLineError::UnknownInstruction(_)) => {
            ConvertOutcome::Unsupported(describe_unsupported_line(&raw_line, &line, None))
        }
        Err(parser::ParseLineError::Other(err)) => {
            ConvertOutcome::Unsupported(describe_unsupported_line(&raw_line, &line, Some(&err)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConvertOutcome, convert_capstone_op};
    use crate::ir::{self, Instruction, Register};

    #[test]
    fn convert_capstone_op_reencodes_wide_immediate_mov_as_movz() {
        // Capstone renders wide immediates as `mov Xd, #imm`; the bridge
        // re-encodes the ones that land in a single 16-bit MOVZ field.
        // 0x10000 == 1 << 16 and 0x1_0000_0000 == 1 << 32.
        for (ops, expected) in [
            (
                "x0, #0x10000",
                Instruction::MovZ {
                    rd: Register::X0,
                    imm: 1,
                    shift: 16,
                },
            ),
            (
                "x1, #0x100000000",
                Instruction::MovZ {
                    rd: Register::X1,
                    imm: 1,
                    shift: 32,
                },
            ),
        ] {
            match convert_capstone_op("mov", ops) {
                ConvertOutcome::Instruction(instr) => assert_eq!(instr, expected),
                other => panic!("expected MovZ for `mov {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_inverts_condition_for_cinc_alias() {
        // `cinc Xd, Xn, cond` is Capstone's alias for
        // `csinc Xd, Xn, Xn, invert(cond)`; `eq` inverts to `ne`.
        match convert_capstone_op("cinc", "x0, x1, eq") {
            ConvertOutcome::Instruction(instr) => assert_eq!(
                instr,
                Instruction::Csinc {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X1,
                    cond: ir::Condition::NE,
                }
            ),
            other => panic!("expected Csinc for `cinc x0, x1, eq`, got {other:?}"),
        }
    }

    /// Locks in that the Capstone→IR converter covers every mnemonic the asm
    /// parser supports and the docs capability matrix lists. If a mnemonic in
    /// this list ever stops parsing, the binary path has silently broken; if
    /// the docs source changes without a sample here, this test fails.
    #[test]
    fn convert_capstone_op_handles_all_supported_aarch64_mnemonics() {
        let cases = [
            ("mov", "x0, x1"),
            ("mov", "w0, w1"),
            ("mov", "x0, #5"),
            ("mov", "w0, #0xff"),
            ("mov", "wsp, #0xff"),
            ("mov", "x0, v1.d[0]"),
            ("movi", "v0.2d, #0"),
            ("mvn", "x0, x1"),
            ("neg", "x0, x1"),
            ("negs", "x0, x1"),
            ("movn", "x0, #1"),
            ("movz", "x0, #0xffff, lsl #48"),
            ("movk", "x1, #0x1234, lsl #16"),
            ("add", "x0, x1, x2"),
            ("add", "w0, w1, w2"),
            ("add", "x0, x1, #4"),
            ("add", "w0, w1, #4"),
            ("add", "x0, x1, x2, lsl #3"),
            ("add", "w0, w1, w2, lsl #3"),
            ("add", "v0.2d, v1.2d, v2.2d"),
            ("sub", "x0, x1, #3"),
            ("sub", "w0, w1, #3"),
            ("adds", "x0, x1, #1"),
            ("subs", "x0, x1, x2"),
            ("adc", "x0, x1, x2"),
            ("adcs", "x0, x1, x2"),
            ("sbc", "x0, x1, x2"),
            ("sbcs", "x0, x1, x2"),
            ("and", "x0, x1, x2"),
            ("and", "w0, w1, #0xff"),
            ("ands", "x0, x1, x2"),
            ("ands", "w0, w1, #0xff"),
            ("orr", "x0, x1, x2"),
            ("orr", "w0, w1, #0xff"),
            ("eor", "x0, x1, x2"),
            ("eor", "w0, w1, #0xff"),
            ("bic", "x0, x1, x2"),
            ("bics", "x0, x1, x2"),
            ("orn", "x0, x1, x2"),
            ("eon", "x0, x1, x2"),
            ("lsl", "x0, x1, #4"),
            ("lsr", "x0, x1, x2"),
            ("asr", "x0, x1, #8"),
            ("ror", "x0, x1, #5"),
            ("mul", "x0, x1, x2"),
            ("madd", "x0, x1, x2, x3"),
            ("msub", "x0, x1, x2, x3"),
            ("mneg", "x0, x1, x2"),
            ("smulh", "x0, x1, x2"),
            ("umulh", "x0, x1, x2"),
            ("sdiv", "x0, x1, x2"),
            ("udiv", "x0, x1, x2"),
            ("cmp", "x1, #5"),
            ("cmp", "x1, x2, lsl #4"),
            ("cmn", "x1, x2"),
            ("tst", "x1, x2"),
            ("tst", "w1, #0xff"),
            ("ccmp", "x1, x2, #5, eq"),
            ("ccmn", "x1, #15, #3, ne"),
            ("csel", "x0, x1, x2, eq"),
            ("csinc", "x0, x1, x2, ne"),
            ("csinv", "x0, x1, x2, lt"),
            ("csneg", "x0, x1, x2, ge"),
            ("cset", "x0, eq"),
            ("csetm", "x3, ne"),
            ("clz", "x0, x1"),
            ("cls", "x0, x1"),
            ("rbit", "x0, x1"),
            ("rev", "x0, x1"),
            ("rev32", "x0, x1"),
            ("rev16", "x0, x1"),
            // Issue #60: extended-register operand form for ADD/SUB/CMP/CMN
            // and the five standalone UBFM/SBFM-alias mnemonics. Capstone
            // emits W-form register names for byte/half/word kinds.
            ("add", "x0, x1, w2, uxtb #2"),
            ("sub", "x0, x1, w2, sxth #1"),
            ("cmp", "x1, w2, uxtw #3"),
            ("cmn", "x1, x2, sxtx #0"),
            ("uxtb", "w0, w1"),
            ("uxth", "w0, w1"),
            ("sxtb", "x0, w1"),
            ("sxth", "x0, w1"),
            ("sxtw", "x0, w1"),
            // Issue #61: bit-field aliases of UBFM/SBFM/BFM.
            ("ubfx", "x0, x1, #8, #16"),
            ("sbfx", "x0, x1, #8, #16"),
            ("bfi", "x0, x1, #4, #8"),
            ("bfxil", "x0, x1, #8, #8"),
            ("ubfiz", "x0, x1, #4, #8"),
            ("sbfiz", "x0, x1, #4, #8"),
            // Issue #145: 32-bit W-register forms. Capstone emits `wN` operands
            // for these encodings; lsb+width stays < 32 to avoid the LSR/MOV
            // alias boundary.
            ("ubfx", "w0, w1, #8, #16"),
            ("sbfx", "w0, w1, #8, #16"),
            ("bfi", "w0, w1, #4, #8"),
            ("bfxil", "w0, w1, #8, #8"),
            ("ubfiz", "w0, w1, #4, #8"),
            ("sbfiz", "w0, w1, #4, #8"),
            // Issue #69: branch / control-flow mnemonics. Capstone emits
            // branch targets as `#0x...` (immediate-with-hash) and renders
            // TBZ/TBNZ as `wN` when bit<32, `xN` otherwise.
            ("b", "#0x1000"),
            ("bl", "#0x1000"),
            ("br", "x16"),
            ("ret", ""),
            ("ret", "x30"),
            ("b.eq", "#0x1000"),
            ("b.ne", "#0x1000"),
            ("cbz", "x0, #0x1000"),
            ("cbnz", "x5, #0x1000"),
            ("tbz", "w3, #5, #0x1000"),
            ("tbnz", "x3, #40, #0x1000"),
            // Issue #68: memory ops. 9 single-register mnemonics × 5
            // addressing modes = 45 rows; 3 pair mnemonics × 3 modes = 9
            // rows. See ADR-0007.
            // LDR (X/W form, immediate-offset / pre-index / post-index /
            // register-offset / register-extend).
            ("ldr", "x0, [x1]"),
            ("ldr", "x0, [x1, #8]!"),
            ("ldr", "x0, [x1], #8"),
            ("ldr", "x0, [x1, x2]"),
            ("ldr", "x0, [x1, w2, uxtw #3]"),
            // LDRB.
            ("ldrb", "w0, [x1]"),
            ("ldrb", "w0, [x1, #1]!"),
            ("ldrb", "w0, [x1], #1"),
            ("ldrb", "w0, [x1, x2]"),
            ("ldrb", "w0, [x1, w2, uxtw]"),
            // LDRH.
            ("ldrh", "w0, [x1]"),
            ("ldrh", "w0, [x1, #2]!"),
            ("ldrh", "w0, [x1], #2"),
            ("ldrh", "w0, [x1, x2]"),
            ("ldrh", "w0, [x1, w2, uxtw #1]"),
            // LDRSB.
            ("ldrsb", "x0, [x1]"),
            ("ldrsb", "x0, [x1, #1]!"),
            ("ldrsb", "x0, [x1], #1"),
            ("ldrsb", "x0, [x1, x2]"),
            ("ldrsb", "x0, [x1, w2, sxtw]"),
            // LDRSH.
            ("ldrsh", "x0, [x1]"),
            ("ldrsh", "x0, [x1, #2]!"),
            ("ldrsh", "x0, [x1], #2"),
            ("ldrsh", "x0, [x1, x2]"),
            ("ldrsh", "x0, [x1, w2, sxtw #1]"),
            // LDRSW.
            ("ldrsw", "x0, [x1]"),
            ("ldrsw", "x0, [x1, #4]!"),
            ("ldrsw", "x0, [x1], #4"),
            ("ldrsw", "x0, [x1, x2]"),
            ("ldrsw", "x0, [x1, w2, sxtw #2]"),
            // STR.
            ("str", "x0, [x1]"),
            ("str", "x0, [x1, #8]!"),
            ("str", "x0, [x1], #8"),
            ("str", "x0, [x1, x2]"),
            ("str", "x0, [x1, w2, uxtw #3]"),
            // STRB.
            ("strb", "w0, [x1]"),
            ("strb", "w0, [x1, #1]!"),
            ("strb", "w0, [x1], #1"),
            ("strb", "w0, [x1, x2]"),
            ("strb", "w0, [x1, w2, uxtw]"),
            // STRH.
            ("strh", "w0, [x1]"),
            ("strh", "w0, [x1, #2]!"),
            ("strh", "w0, [x1], #2"),
            ("strh", "w0, [x1, x2]"),
            ("strh", "w0, [x1, w2, uxtw #1]"),
            // LDP (offset / pre-index / post-index — register-offset and
            // register-extend are not part of the AArch64 pair grammar).
            ("ldp", "x0, x1, [sp, #16]"),
            ("ldp", "x0, x1, [sp, #-16]!"),
            ("ldp", "x0, x1, [sp], #16"),
            // STP.
            ("stp", "x0, x1, [sp, #16]"),
            ("stp", "x0, x1, [sp, #-16]!"),
            ("stp", "x0, x1, [sp], #16"),
            // LDPSW.
            ("ldpsw", "x0, x1, [sp, #8]"),
            ("ldpsw", "x0, x1, [sp, #-8]!"),
            ("ldpsw", "x0, x1, [sp], #8"),
        ];

        // Tripwire: bump in lockstep when adding/removing rows. Catches
        // accidental row deletion and forces a re-read when adding a parser
        // mnemonic without a matching test row.
        assert_eq!(cases.len(), 157);

        fn docs_mnemonic(mnemonic: &'static str) -> &'static str {
            if mnemonic.starts_with("b.") {
                "b.<cond>"
            } else {
                mnemonic
            }
        }

        let case_mnemonics: std::collections::BTreeSet<&'static str> = cases
            .iter()
            .map(|(mnemonic, _)| docs_mnemonic(mnemonic))
            .collect();
        let documented_mnemonics: std::collections::BTreeSet<&'static str> =
            crate::docs_support::AARCH64_REWRITABLE_MNEMONICS
                .iter()
                .chain(crate::docs_support::AARCH64_FIXED_TERMINATORS.iter())
                .copied()
                .collect();
        assert_eq!(case_mnemonics, documented_mnemonics);

        for (mnem, ops) in cases {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Instruction(_) => {}
                other => panic!(
                    "expected Instruction for `{} {}`, got {:?}",
                    mnem, ops, other
                ),
            }
        }
    }

    #[test]
    fn convert_capstone_op_normalizes_mov_wide_aliases() {
        for (ops, expected) in [
            (
                "x0, #0x10000",
                Instruction::MovZ {
                    rd: Register::X0,
                    imm: 1,
                    shift: 16,
                },
            ),
            (
                "x1, #0x100000000",
                Instruction::MovZ {
                    rd: Register::X1,
                    imm: 1,
                    shift: 32,
                },
            ),
            (
                "x2, #-1",
                Instruction::MovN {
                    rd: Register::X2,
                    imm: 0,
                    shift: 0,
                },
            ),
            (
                "x3, #0xffffffffffff0000",
                Instruction::MovN {
                    rd: Register::X3,
                    imm: 0xffff,
                    shift: 0,
                },
            ),
        ] {
            match convert_capstone_op("mov", ops) {
                ConvertOutcome::Instruction(instr) => assert_eq!(instr, expected),
                other => panic!("expected normalized Instruction for `mov {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_passes_mov_alias_fall_through_to_parser() {
        // The move-wide normalizer deliberately leaves `mov Xd, #imm` alone for
        // single-halfword values (0..=0xffff) and skips W-register destinations.
        // `mov` *is* a parser mnemonic, so these fall through to the parser
        // rather than becoming Unsupported: an x-register small immediate parses
        // to MovImm, and a W-register logical-immediate alias parses to Orr. Pin
        // both so the normalizer's fall-through boundary cannot silently regress.
        match convert_capstone_op("mov", "x0, #5") {
            ConvertOutcome::Instruction(Instruction::MovImm {
                rd: Register::X0,
                imm: 5,
            }) => {}
            other => panic!("expected MovImm for `mov x0, #5`, got {other:?}"),
        }
        match convert_capstone_op("mov", "w0, #0x10000") {
            ConvertOutcome::Instruction(Instruction::Orr { .. }) => {}
            other => panic!("expected Orr for `mov w0, #0x10000`, got {other:?}"),
        }
    }

    #[test]
    fn convert_capstone_op_normalizes_cond_select_aliases() {
        for (mnemonic, ops, expected) in [
            (
                "cinc",
                "x0, x1, eq",
                Instruction::Csinc {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X1,
                    cond: ir::Condition::NE,
                },
            ),
            (
                "cinv",
                "x2, x3, lt",
                Instruction::Csinv {
                    rd: Register::X2,
                    rn: Register::X3,
                    rm: Register::X3,
                    cond: ir::Condition::GE,
                },
            ),
            (
                "cneg",
                "x4, x5, ge",
                Instruction::Csneg {
                    rd: Register::X4,
                    rn: Register::X5,
                    rm: Register::X5,
                    cond: ir::Condition::LT,
                },
            ),
        ] {
            match convert_capstone_op(mnemonic, ops) {
                ConvertOutcome::Instruction(instr) => assert_eq!(instr, expected),
                other => {
                    panic!("expected normalized Instruction for `{mnemonic} {ops}`, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn convert_capstone_op_rejects_cond_select_al_nv_aliases() {
        // AL/NV have no meaningful inverse, so the conditional-select
        // normalizer rejects them rather than emitting a csinc/csinv/csneg
        // with AL/NV. Pin that error path through to the Unsupported outcome.
        for (mnemonic, ops) in [("cinc", "x0, x1, al"), ("cinv", "x2, x3, nv")] {
            match convert_capstone_op(mnemonic, ops) {
                ConvertOutcome::Unsupported(msg) => {
                    assert!(
                        msg.contains(mnemonic),
                        "diagnostic should name `{mnemonic}`: {msg}"
                    );
                    assert!(
                        msg.contains("does not support"),
                        "diagnostic should explain the rejected condition: {msg}"
                    );
                }
                other => panic!("expected Unsupported for `{mnemonic} {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_skips_nop_silently() {
        assert!(matches!(
            convert_capstone_op("nop", ""),
            ConvertOutcome::Skip
        ));
        assert!(matches!(
            convert_capstone_op("NOP", ""),
            ConvertOutcome::Skip
        ));
    }

    #[test]
    fn convert_capstone_op_flags_unknown_mnemonic_as_unsupported() {
        // NEON FADD is not parsed; memory ops were promoted to supported in
        // issue #68. See ADR-0007.
        match convert_capstone_op("fadd", "v0.4s, v1.4s, v2.4s") {
            ConvertOutcome::Unsupported(line) => {
                assert!(line.contains("fadd"), "warning line should name mnemonic");
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }

    #[test]
    fn convert_capstone_op_keeps_related_memory_mnemonics_unsupported() {
        // ADR-0007 §9 explicitly leaves these out of scope. Lock the outcome
        // here so a future Capstone-syntax shift cannot silently start
        // parsing them as supported instructions:
        //   - LDUR / STUR: unscaled-signed-offset variants Capstone uses
        //     for negative immediates that LDR-imm cannot encode.
        //   - LDR (literal): PC-relative pool load — different operand
        //     grammar than the bracketed forms supported by step 4.
        for (mnem, ops) in [
            ("ldur", "x0, [x1, #-1]"),
            ("stur", "x0, [x1, #-1]"),
            ("ldr", "x0, #0x1234"),
        ] {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Unsupported(_) => {}
                other => panic!(
                    "expected Unsupported for `{} {}`, got {:?}",
                    mnem, ops, other
                ),
            }
        }
    }

    #[test]
    fn convert_capstone_op_rejects_w_form_signed_load_destinations() {
        for (mnem, ops) in [
            ("ldrsb", "w0, [x1]"),
            ("ldrsh", "w0, [x1]"),
            ("ldrsw", "w0, [x1]"),
        ] {
            match convert_capstone_op(mnem, ops) {
                ConvertOutcome::Unsupported(line) => {
                    assert!(line.contains(mnem));
                    assert!(line.contains("X-form"));
                }
                other => panic!("expected Unsupported for `{mnem} {ops}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_capstone_op_reports_operand_errors_against_supported_mnemonic() {
        // Mnemonic recognised, but operand fails to parse — should be
        // classified as Unsupported with the parser's error appended so the
        // optimization path can reject the window with useful context.
        match convert_capstone_op("add", "x0, x1, #wat") {
            ConvertOutcome::Unsupported(line) => {
                assert!(line.contains("add"));
                assert!(line.contains("wat"));
            }
            other => panic!("expected Unsupported, got {:?}", other),
        }
    }
}

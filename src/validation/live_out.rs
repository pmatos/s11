//! Live-out register set computation and parsing

#![allow(dead_code)]

use crate::ir::{Instruction, Register};
use crate::semantics::live_out::{LiveOut, RegisterSet};
use std::str::FromStr;

/// Error type for parsing live-out register sets and live-out contracts.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseRegisterSetError {
    pub message: String,
}

impl std::fmt::Display for ParseRegisterSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseRegisterSetError {}

/// Contract-facing error type for parsing CLI `--live-out` strings.
pub type ParseLiveOutError = ParseRegisterSetError;

/// Parse a register name like "x0", "X1", "sp", "SP". Accepts the standard
/// AArch64 aliases `fp` (x29) and `lr` (x30) to match the assembly parser at
/// `src/parser/mod.rs::parse_register`.
fn parse_register(s: &str) -> Result<Register, ParseRegisterSetError> {
    let s = s.trim().to_lowercase();

    if s == "sp" {
        return Ok(Register::SP);
    }
    if s == "xzr" {
        return Ok(Register::XZR);
    }
    if s == "fp" {
        return Ok(Register::X29);
    }
    if s == "lr" {
        return Ok(Register::X30);
    }

    if let Some(num_str) = s.strip_prefix('x')
        && let Ok(num) = num_str.parse::<u8>()
        && let Some(reg) = Register::from_index(num)
    {
        return Ok(reg);
    }

    Err(ParseRegisterSetError {
        message: format!("invalid register name: '{}'", s),
    })
}

impl FromStr for RegisterSet<Register> {
    type Err = ParseRegisterSetError;

    /// Parse a comma or space-separated list of register names
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(RegisterSet::empty());
        }

        let separator = if s.contains(',') { ',' } else { ' ' };

        let mut mask = RegisterSet::empty();
        for part in s.split(separator) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let reg = parse_register(part)?;
            mask.add(reg);
        }

        Ok(mask)
    }
}

fn is_live_out_flag_token(s: &str) -> bool {
    s.eq_ignore_ascii_case("nzcv")
        || s.eq_ignore_ascii_case("n")
        || s.eq_ignore_ascii_case("z")
        || s.eq_ignore_ascii_case("c")
        || s.eq_ignore_ascii_case("v")
}

fn misplaced_flag_token_in_register_list(s: &str) -> Option<&str> {
    s.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .find(|part| is_live_out_flag_token(part))
}

fn misplaced_flag_token_error(token: &str, input: &str) -> ParseRegisterSetError {
    let message = if token.eq_ignore_ascii_case("nzcv") {
        format!(
            "flag token '{}' must follow the register list after ';' (for example ';nzcv'); got '{}'",
            token, input
        )
    } else {
        format!(
            "per-flag token '{}' is reserved for a future extension and cannot appear in the register list; use ';nzcv' for all flags; got '{}'",
            token, input
        )
    };
    ParseRegisterSetError { message }
}

/// Parse the CLI `--live-out` contract string.
///
/// Grammar: `<regs>` or `<regs>;<flags>`. The register half follows
/// `RegisterSet::<Register>::from_str` (comma- or space-separated, case-insensitive,
/// accepts `x0..x30`, `sp`, `xzr`). The flag half currently accepts only the
/// group token `nzcv`; per-flag tokens `n`/`z`/`c`/`v` are reserved for a
/// future per-flag liveness extension and rejected today. A bareword `nzcv`
/// with no leading `;` is rejected to keep that reservation unambiguous.
///
/// Returns a `LiveOut` whose `flags_live()` bit reflects the optional
/// `;nzcv` suffix (ADR-0006). The mask is consumed directly by
/// `EquivalenceConfig::with_live_out(...)`; callers no longer need to thread
/// a separate `flags_live` boolean.
pub fn parse_live_out_contract(s: &str) -> Result<LiveOut, ParseLiveOutError> {
    let trimmed = s.trim();
    let semicolon_count = trimmed.matches(';').count();
    if semicolon_count > 1 {
        return Err(ParseRegisterSetError {
            message: format!("--live-out accepts at most one ';' (got: '{}')", s),
        });
    }
    if semicolon_count == 0 {
        if trimmed.eq_ignore_ascii_case("nzcv") {
            return Err(ParseRegisterSetError {
                message: format!(
                    "flag-only live-out requires a leading ';' (e.g. \";nzcv\"); got '{}'",
                    s
                ),
            });
        }
        if let Some(token) = misplaced_flag_token_in_register_list(trimmed) {
            return Err(misplaced_flag_token_error(token, s));
        }
        let regs = RegisterSet::<Register>::from_str(trimmed)?;
        return Ok(regs);
    }
    let (regs_part, flags_part) = trimmed.split_once(';').unwrap();
    if let Some(token) = misplaced_flag_token_in_register_list(regs_part.trim()) {
        return Err(misplaced_flag_token_error(token, s));
    }
    let regs = RegisterSet::<Register>::from_str(regs_part.trim())?;
    let flags_tok = flags_part.trim().to_ascii_lowercase();
    let flags_live = match flags_tok.as_str() {
        "" => false,
        "nzcv" => true,
        "n" | "z" | "c" | "v" => {
            return Err(ParseRegisterSetError {
                message: format!(
                    "per-flag token '{}' is reserved for a future extension; use 'nzcv' for all flags",
                    flags_tok
                ),
            });
        }
        other => {
            return Err(ParseRegisterSetError {
                message: format!("unknown flag token '{}'; expected 'nzcv'", other),
            });
        }
    };
    Ok(regs.with_flags(flags_live))
}

/// Compute the set of registers written by a sequence of instructions.
/// Uses `destinations()` so memory ops with writeback (PreIndex / PostIndex)
/// or pair loads (LDP) contribute multiple registers per instruction.
pub fn compute_written_registers(instructions: &[Instruction]) -> RegisterSet<Register> {
    let mut mask = RegisterSet::empty();
    for instr in instructions {
        for dest in instr.destinations() {
            mask.add(dest);
        }
    }
    mask
}

/// Returns true if the sequence contains any memory-touching instruction.
/// Drives the auto-derivation of `EquivalenceConfig::memory_live` (and the
/// `fast_only` carve-out) in `check_equivalence_with_config`. See ADR-0007.
pub fn touches_memory(instructions: &[Instruction]) -> bool {
    instructions.iter().any(|i| {
        matches!(
            i,
            Instruction::Ldr { .. }
                | Instruction::Ldrs { .. }
                | Instruction::Str { .. }
                | Instruction::Ldp { .. }
                | Instruction::Stp { .. }
        )
    })
}

/// Returns true if NZCV may be observable after the sequence executes.
///
/// Static check: returns true iff **any** flag-writing instruction appears
/// in the sequence.
///
/// **Over-approximate.** This predicate fires whenever a flag-writer is
/// present, regardless of whether a later instruction actually reads NZCV.
/// That conservative posture is the only soundness barrier preventing the
/// equivalence checker from accepting a rewrite that silently drops a
/// flag-side-effect — SMT semantics for ADDS/SUBS/ANDS/NEGS/BICS/CMP/CMN/TST
/// model the register write but not the flag effect. A tighter "flag-writer
/// AND later read" form is tracked as a separate follow-up.
///
/// Issue #77 stage 1 step 14: routes through `FlagsAnalysis<I>` (ADR-0004
/// decision 7) instead of the inherent `Instruction::modifies_flags`. The
/// AArch64 impl delegates to the inherent method, so behaviour is identical;
/// the same shape works unchanged for x86 in stage 2.
pub fn flags_live_out(instructions: &[Instruction]) -> bool {
    use crate::isa::{AArch64, FlagsAnalysis};
    instructions
        .iter()
        .any(<AArch64 as FlagsAnalysis<Instruction>>::modifies_flags)
}

/// Returns true if any instruction reads NZCV flags before any instruction writes them.
///
/// In live-in terms: NZCV is part of the live-in set iff this returns true.
/// Consumed by the equivalence fast path to decide whether initial NZCV must
/// be varied across random/edge-case inputs (see `fast_path_initial_nzcv_variants`
/// in `src/semantics/equivalence.rs`). ADR-0001 defines the helper shape;
/// ADR-0003 omits flags from the LLM prompt for the MVP. Routed through
/// `FlagsAnalysis<I>` (ADR-0004 decision 7) for parity with the x86 wire-up.
pub fn reads_flags_before_writing(instructions: &[Instruction]) -> bool {
    use crate::isa::{AArch64, FlagsAnalysis};
    for instr in instructions {
        if <AArch64 as FlagsAnalysis<Instruction>>::reads_flags(instr) {
            return true;
        }
        if <AArch64 as FlagsAnalysis<Instruction>>::modifies_flags(instr) {
            return false;
        }
    }
    false
}

/// Compute the set of registers read before written by a sequence of instructions.
///
/// Returns the set of registers the sequence reads before defining (writing).
/// XZR is never included. The return type `RegisterSet<Register>` is the same
/// neutral carrier used by live-out analyses — live-in and live-out are both
/// architecture-register sets (closes #85; see ADR-0001 for the design rationale).
pub fn compute_live_in_registers(instructions: &[Instruction]) -> RegisterSet<Register> {
    let mut live_in = RegisterSet::empty();
    let mut written = RegisterSet::empty();

    for instr in instructions {
        for src in instr.source_registers() {
            if !written.contains(src) {
                live_in.add(src);
            }
        }
        for dest in instr.destinations() {
            written.add(dest);
        }
    }

    live_in
}

/// Build an x86 `RegisterSet` from a target sequence by treating every
/// written register as live-out and declaring EFLAGS live whenever the
/// target contains any instruction with observable side effects (i.e.
/// any non-MOV / non-CMOV / non-Jcc variant — see
/// `InstructionType::has_side_effects` for the contract).
///
/// **Asymmetry:** CMOV and Jcc READ EFLAGS but report
/// `has_side_effects=false` (they don't write flags), so a CMOV-only or
/// Jcc-only target gets `flags_live=false` from this helper.
/// x86 equivalence compensates for a fixed trailing Jcc by forcing flags into
/// the effective live-out contract before comparing prefixes. Direct callers
/// that bypass the generic equivalence entry point must apply their own
/// equivalent guard if their downstream code reads flags.
pub fn x86_live_out_from_target(
    target: &[crate::isa::x86::X86Instruction],
) -> crate::semantics::live_out::X86LiveOut {
    use crate::isa::InstructionType;
    use crate::semantics::live_out::RegisterSet;

    let registers: Vec<crate::isa::x86::X86Register> =
        target.iter().filter_map(|i| i.destination()).collect();
    let flags_live = target.iter().any(InstructionType::has_side_effects);
    RegisterSet::from_registers(registers).with_flags(flags_live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Condition, Operand};

    #[test]
    fn display_renders_message_without_type_prefix() {
        let err: ParseLiveOutError = parse_live_out_contract("x0;bogus").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown flag token 'bogus'; expected 'nzcv'"
        );
    }

    #[test]
    fn test_parse_register_x0() {
        assert_eq!(parse_register("x0"), Ok(Register::X0));
        assert_eq!(parse_register("X0"), Ok(Register::X0));
    }

    #[test]
    fn test_parse_register_x30() {
        assert_eq!(parse_register("x30"), Ok(Register::X30));
        assert_eq!(parse_register("X30"), Ok(Register::X30));
    }

    #[test]
    fn test_parse_register_sp() {
        assert_eq!(parse_register("sp"), Ok(Register::SP));
        assert_eq!(parse_register("SP"), Ok(Register::SP));
    }

    #[test]
    fn test_parse_register_xzr() {
        assert_eq!(parse_register("xzr"), Ok(Register::XZR));
        assert_eq!(parse_register("XZR"), Ok(Register::XZR));
    }

    #[test]
    fn test_parse_register_fp_lr_aliases() {
        assert_eq!(parse_register("fp"), Ok(Register::X29));
        assert_eq!(parse_register("FP"), Ok(Register::X29));
        assert_eq!(parse_register("lr"), Ok(Register::X30));
        assert_eq!(parse_register("LR"), Ok(Register::X30));
    }

    #[test]
    fn test_parse_register_invalid() {
        assert!(parse_register("r0").is_err());
        assert!(parse_register("x32").is_err());
        assert!(parse_register("foo").is_err());
    }

    #[test]
    fn test_parse_live_out_contract_accepts_fp_lr_aliases() {
        let live_out = parse_live_out_contract("fp,lr").unwrap();
        assert!(live_out.contains_register(Register::X29));
        assert!(live_out.contains_register(Register::X30));
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_fp_lr_with_flags() {
        let live_out = parse_live_out_contract("lr;nzcv").unwrap();
        assert!(live_out.contains_register(Register::X30));
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_live_out_registers_from_str_comma_separated() {
        let mask: LiveOut = "x0, x1, x2".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
    }

    #[test]
    fn test_live_out_registers_from_str_space_separated() {
        let mask: LiveOut = "x0 x1 x2".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
    }

    #[test]
    fn test_live_out_registers_from_str_mixed_case() {
        let mask: LiveOut = "X0, x1, SP".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::SP));
    }

    #[test]
    fn test_live_out_registers_from_str_empty() {
        let mask: LiveOut = "".parse().unwrap();
        assert!(mask.is_empty());
    }

    #[test]
    fn test_live_out_registers_from_str_whitespace() {
        let mask: LiveOut = "  x0  ,  x1  ".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
    }

    #[test]
    fn test_live_out_registers_from_str_invalid() {
        let result: Result<LiveOut, _> = "x0, invalid, x1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_written_registers_empty() {
        let mask = compute_written_registers(&[]);
        assert!(mask.is_empty());
    }

    #[test]
    fn test_compute_written_registers_single() {
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert!(!mask.contains(Register::X1));
    }

    #[test]
    fn test_compute_written_registers_multiple() {
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
            Instruction::MovReg {
                rd: Register::X2,
                rn: Register::X1,
            },
        ];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
    }

    #[test]
    fn test_compute_written_registers_same_register_multiple_times() {
        let instructions = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert_eq!(mask.len(), 1);
    }

    #[test]
    fn test_compute_live_in_registers_empty() {
        let mask = compute_live_in_registers(&[]);
        assert!(mask.is_empty());
    }

    #[test]
    fn test_compute_live_in_registers_mov_imm_no_sources() {
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];
        let mask = compute_live_in_registers(&instructions);
        assert!(mask.is_empty());
    }

    #[test]
    fn test_flags_live_out_empty() {
        assert!(!flags_live_out(&[]));
    }

    #[test]
    fn test_flags_live_out_cmp() {
        let instructions = vec![Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        }];
        assert!(flags_live_out(&instructions));
    }

    #[test]
    fn test_flags_live_out_add_only() {
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        assert!(!flags_live_out(&instructions));
    }

    #[test]
    fn test_flags_live_out_cmp_then_add() {
        // CMP's flags are still live at end (ADD doesn't overwrite them).
        let instructions = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Add {
                rd: Register::X2,
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
        ];
        assert!(flags_live_out(&instructions));
    }

    #[test]
    fn test_reads_flags_before_writing_empty() {
        assert!(!reads_flags_before_writing(&[]));
    }

    #[test]
    fn test_reads_flags_before_writing_csel_alone() {
        let instructions = vec![Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        }];
        assert!(reads_flags_before_writing(&instructions));
    }

    #[test]
    fn test_reads_flags_before_writing_cmp_then_csel() {
        let instructions = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
        ];
        assert!(!reads_flags_before_writing(&instructions));
    }

    #[test]
    fn test_reads_flags_before_writing_csel_then_cmp() {
        let instructions = vec![
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: Condition::EQ,
            },
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
        ];
        assert!(reads_flags_before_writing(&instructions));
    }

    #[test]
    fn test_compute_live_in_registers_xzr_excluded() {
        // MOV x0, xzr — xzr is read but must not appear in live-in (mirrors
        // compute_written_registers' exclusion of xzr writes).
        let instructions = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::XZR,
        }];
        let mask = compute_live_in_registers(&instructions);
        assert!(!mask.contains(Register::XZR));
        assert!(mask.is_empty());
    }

    #[test]
    fn test_compute_live_in_registers_cmp_reads_both() {
        // CMP has no destination but reads both operands — both are live-in.
        let instructions = vec![Instruction::Cmp {
            rn: Register::X0,
            rm: Operand::Register(Register::X1),
        }];
        let mask = compute_live_in_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert_eq!(mask.len(), 2);
    }

    #[test]
    fn test_compute_live_in_registers_def_kills_use() {
        // ADD x0, x1, #5 ; ADD x2, x0, #1 — x0 is written before second use
        let instructions = vec![
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(5),
            },
            Instruction::Add {
                rd: Register::X2,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let mask = compute_live_in_registers(&instructions);
        assert!(mask.contains(Register::X1));
        assert!(!mask.contains(Register::X0));
        assert!(!mask.contains(Register::X2));
        assert_eq!(mask.len(), 1);
    }

    #[test]
    fn test_compute_live_in_registers_add_two_sources() {
        let instructions = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let mask = compute_live_in_registers(&instructions);
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X0));
        assert_eq!(mask.len(), 2);
    }

    #[test]
    fn test_compute_written_registers_xzr_not_included() {
        let instructions = vec![Instruction::MovImm {
            rd: Register::XZR,
            imm: 42,
        }];
        let mask = compute_written_registers(&instructions);
        assert!(!mask.contains(Register::XZR));
        assert!(mask.is_empty());
    }

    #[test]
    fn test_parse_live_out_contract_regs_and_flags() {
        let live_out = parse_live_out_contract("x0,x1;nzcv").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(live_out.contains_register(Register::X1));
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_space_separated_regs_and_flags() {
        let live_out = parse_live_out_contract("x0 x1;nzcv").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(live_out.contains_register(Register::X1));
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_regs_only_flags_off() {
        let live_out = parse_live_out_contract("x0,x1").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(live_out.contains_register(Register::X1));
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_flags_only() {
        let live_out = parse_live_out_contract(";nzcv").unwrap();
        assert_eq!(live_out.len(), 0);
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_trailing_semicolon() {
        let live_out = parse_live_out_contract("x0,x1;").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_uppercase_passes() {
        let live_out = parse_live_out_contract("X0,X1;NZCV").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(live_out.contains_register(Register::X1));
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_empty_input() {
        let live_out = parse_live_out_contract("").unwrap();
        assert_eq!(live_out.len(), 0);
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_whitespace_around_semicolon() {
        let live_out = parse_live_out_contract("x0 ; nzcv").unwrap();
        assert!(live_out.contains_register(Register::X0));
        assert!(live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_lone_semicolon() {
        let live_out = parse_live_out_contract(";").unwrap();
        assert_eq!(live_out.len(), 0);
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_whitespace_only_sides() {
        let live_out = parse_live_out_contract("  ;  ").unwrap();
        assert_eq!(live_out.len(), 0);
        assert!(!live_out.flags_live());
    }

    #[test]
    fn test_parse_live_out_contract_bareword_nzcv_rejected() {
        let err = parse_live_out_contract("nzcv").unwrap_err();
        assert!(
            err.message
                .contains("flag-only live-out requires a leading ';'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_live_out_contract_nzcv_in_register_list_hints_semicolon() {
        for input in [
            "nzcv,x0",
            "x0,nzcv",
            "x0 nzcv",
            "nzcv,x0;nzcv",
            "x0,nzcv;nzcv",
        ] {
            let err = parse_live_out_contract(input).unwrap_err();
            assert!(
                err.message.contains("'nzcv'"),
                "expected error to name misplaced flag token in '{}', got: {}",
                input,
                err.message
            );
            assert!(
                err.message.contains(";nzcv"),
                "expected error to hint at ';nzcv' syntax for '{}', got: {}",
                input,
                err.message
            );
            assert!(
                !err.message.contains("invalid register name"),
                "expected live-out grammar diagnostic for '{}', got: {}",
                input,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_live_out_contract_per_flag_tokens_in_register_list_hint_semicolon() {
        for tok in ["n", "z", "c", "v"] {
            for input in [format!("{},x0", tok), format!("{} x0", tok)] {
                let err = parse_live_out_contract(&input).unwrap_err();
                assert!(
                    err.message.contains(&format!("'{}'", tok)),
                    "expected error to name misplaced flag token in '{}', got: {}",
                    input,
                    err.message
                );
                assert!(
                    err.message.contains("reserved") || err.message.contains(";nzcv"),
                    "expected error to hint at reserved flag syntax for '{}', got: {}",
                    input,
                    err.message
                );
                assert!(
                    !err.message.contains("invalid register name"),
                    "expected live-out grammar diagnostic for '{}', got: {}",
                    input,
                    err.message
                );
            }
        }
    }

    #[test]
    fn test_parse_live_out_contract_reversed_order_nzcv_x0_error() {
        let err = parse_live_out_contract("nzcv;x0").unwrap_err();
        assert_eq!(
            err.to_string(),
            "flag token 'nzcv' must follow the register list after ';' (for example ';nzcv'); got 'nzcv;x0'"
        );
    }

    #[test]
    fn test_parse_live_out_contract_multi_section_rejected() {
        assert!(parse_live_out_contract("x0;nzcv;extra").is_err());
        assert!(parse_live_out_contract(";nzcv;").is_err());
    }

    #[test]
    fn test_parse_live_out_contract_unknown_flag_rejected() {
        let err: ParseLiveOutError = parse_live_out_contract("x0;bogus").unwrap_err();
        assert!(
            err.message.contains("unknown flag token"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_live_out_contract_per_flag_tokens_reserved() {
        for tok in ["n", "z", "c", "v"] {
            let s = format!("x0;{}", tok);
            let err = parse_live_out_contract(&s).unwrap_err();
            assert!(
                err.message.contains("reserved for a future extension"),
                "expected '{}' to be rejected as reserved, got: {}",
                s,
                err.message
            );
            assert!(
                err.message.contains(&format!("per-flag token '{}'", tok)),
                "expected reserved-token error to name '{}', got: {}",
                tok,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_live_out_contract_invalid_register_still_errors() {
        assert!(parse_live_out_contract("x0,bogus;nzcv").is_err());
    }

    // ---- x86 live-out helper ----

    #[test]
    fn x86_live_out_mov_only_target_has_no_flags_live() {
        use crate::isa::x86::{X86Instruction, X86Register};
        let target = [X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mask: crate::semantics::live_out::RegisterSet<X86Register> =
            x86_live_out_from_target(&target);
        assert!(mask.contains(X86Register::RAX));
        assert!(
            !mask.flags_live(),
            "MOV does not write EFLAGS — flags must not be marked live"
        );
    }

    #[test]
    fn x86_live_out_target_with_arith_sets_flags_live() {
        use crate::isa::x86::{X86Instruction, X86Register};
        let target = [X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mask = x86_live_out_from_target(&target);
        assert!(mask.contains(X86Register::RAX));
        assert!(
            mask.flags_live(),
            "ADD has EFLAGS side effects — flags must be live"
        );
    }

    #[test]
    fn x86_live_out_target_with_cmp_only_sets_flags_live_but_no_registers() {
        use crate::isa::x86::{X86Instruction, X86Register};
        let target = [X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mask = x86_live_out_from_target(&target);
        assert!(mask.is_empty(), "CMP writes no destination register");
        assert!(mask.flags_live());
    }
}

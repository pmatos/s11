//! Candidate generation for the x86 enumerative search.
//!
//! Mirrors `search::candidate::generate_all_instructions` but produces
//! `X86Instruction` values from a register and immediate pool. No
//! encodability filter is applied here — the assembler is the authority
//! on what bytes a given variant emits; out-of-range immediates surface
//! as encoder errors at use-site.

use crate::assembler::x86::{X86Assembler, X86Mode};
use crate::isa::x86::{X86Condition, X86Instruction, X86Register};
use rand::RngExt;

/// The 16 canonical x86 condition codes enumerated for CMOV candidates.
/// Jcc is intentionally *not* enumerated here — it is a terminator
/// (see `X86Instruction::is_terminator`) and the search pool must
/// exclude terminators, mirroring the AArch64 branch precedent.
const CMOV_CONDITIONS: [X86Condition; 16] = [
    X86Condition::E,
    X86Condition::NE,
    X86Condition::B,
    X86Condition::AE,
    X86Condition::BE,
    X86Condition::A,
    X86Condition::L,
    X86Condition::GE,
    X86Condition::LE,
    X86Condition::G,
    X86Condition::S,
    X86Condition::NS,
    X86Condition::O,
    X86Condition::NO,
    X86Condition::P,
    X86Condition::NP,
];

/// Enumerate every reg/reg and reg/imm form of the minimal-core
/// variants plus CMOV (per condition × register pair) for the given
/// register and immediate pools.
pub fn generate_all_x86_instructions(
    registers: &[X86Register],
    immediates: &[i64],
) -> Vec<X86Instruction> {
    let r2 = registers.len() * registers.len();
    let mut out = Vec::with_capacity(
        r2 * 7 + registers.len() * immediates.len() * 7 + r2 * CMOV_CONDITIONS.len(),
    );

    for &rd in registers {
        for &rs in registers {
            out.push(X86Instruction::MovReg { rd, rs });
            out.push(X86Instruction::AddReg { rd, rs });
            out.push(X86Instruction::SubReg { rd, rs });
            out.push(X86Instruction::AndReg { rd, rs });
            out.push(X86Instruction::OrReg { rd, rs });
            out.push(X86Instruction::XorReg { rd, rs });
            out.push(X86Instruction::CmpReg { rn: rd, rs });
        }
    }

    for &rd in registers {
        for &imm in immediates {
            out.push(X86Instruction::MovImm { rd, imm });
            out.push(X86Instruction::AddImm { rd, imm });
            out.push(X86Instruction::SubImm { rd, imm });
            out.push(X86Instruction::AndImm { rd, imm });
            out.push(X86Instruction::OrImm { rd, imm });
            out.push(X86Instruction::XorImm { rd, imm });
            out.push(X86Instruction::CmpImm { rn: rd, imm });
        }
    }

    // Issue #74: CMOV per (rd, rs, cond). `rd == rs` is a legal but
    // wasteful no-op variant; left in for symmetry with the other
    // reg/reg loops above.
    for &rd in registers {
        for &rs in registers {
            for &cond in &CMOV_CONDITIONS {
                out.push(X86Instruction::Cmov { rd, rs, cond });
            }
        }
    }

    out
}

/// Default register pool for x86 stochastic / symbolic / hybrid / LLM
/// search. Mirrors the AArch64 baseline of 8 GPRs (X0–X7). RSP and RBP
/// are deliberately excluded so search never touches the stack frame.
pub fn default_x86_registers() -> Vec<X86Register> {
    vec![
        X86Register::RAX,
        X86Register::RCX,
        X86Register::RDX,
        X86Register::RBX,
        X86Register::RSI,
        X86Register::RDI,
        X86Register::R8,
        X86Register::R9,
    ]
}

/// Default immediate pool for x86 search. Same set of constants the
/// AArch64 path uses (`src/main.rs:522`) so the two backends share a
/// fairness baseline for comparison.
pub fn default_x86_immediates() -> Vec<i64> {
    vec![
        0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
    ]
}

/// Generate a random single x86 instruction. In `Mode32`, R8-R15 are
/// excluded automatically (the assembler at
/// `src/assembler/x86.rs:68-74` rejects them anyway, but filtering
/// here avoids wasting search cycles on unencodable proposals).
pub fn generate_random_x86_instruction<R: RngExt>(
    rng: &mut R,
    registers: &[X86Register],
    immediates: &[i64],
    mode: X86Mode,
) -> X86Instruction {
    let pool: Vec<X86Register> = registers
        .iter()
        .copied()
        .filter(|r| mode != X86Mode::Mode32 || matches!(r.index(), Some(i) if i < 8))
        .collect();
    let regs = if pool.is_empty() {
        vec![X86Register::RAX]
    } else {
        pool
    };
    let imms = if immediates.is_empty() {
        vec![0i64]
    } else {
        immediates.to_vec()
    };

    let opcode = rng.random_range(0..14u32);
    let rd = regs[rng.random_range(0..regs.len())];
    let rs = regs[rng.random_range(0..regs.len())];
    let imm = imms[rng.random_range(0..imms.len())];
    match opcode {
        0 => X86Instruction::MovReg { rd, rs },
        1 => X86Instruction::MovImm { rd, imm },
        2 => X86Instruction::AddReg { rd, rs },
        3 => X86Instruction::AddImm { rd, imm },
        4 => X86Instruction::SubReg { rd, rs },
        5 => X86Instruction::SubImm { rd, imm },
        6 => X86Instruction::AndReg { rd, rs },
        7 => X86Instruction::AndImm { rd, imm },
        8 => X86Instruction::OrReg { rd, rs },
        9 => X86Instruction::OrImm { rd, imm },
        10 => X86Instruction::XorReg { rd, rs },
        11 => X86Instruction::XorImm { rd, imm },
        12 => X86Instruction::CmpReg { rn: rd, rs },
        _ => X86Instruction::CmpImm { rn: rd, imm },
    }
}

/// Generate a random x86 instruction sequence of length `len`.
pub fn generate_random_x86_sequence<R: RngExt>(
    rng: &mut R,
    len: usize,
    registers: &[X86Register],
    immediates: &[i64],
    mode: X86Mode,
) -> Vec<X86Instruction> {
    (0..len)
        .map(|_| generate_random_x86_instruction(rng, registers, immediates, mode))
        .collect()
}

/// Return `true` when the given sequence assembles cleanly under the
/// supplied mode. Round-trips through `X86Assembler`, treating any
/// encoder error as "not encodable" (e.g. R8-R15 in `Mode32`).
pub fn is_x86_sequence_encodable(sequence: &[X86Instruction], mode: X86Mode) -> bool {
    let mut asm = match mode {
        X86Mode::Mode64 => X86Assembler::new_64(),
        X86Mode::Mode32 => X86Assembler::new_32(),
    };
    asm.assemble_instructions(sequence).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_register_pool_excludes_stack_pointer_and_base_pointer() {
        let pool = default_x86_registers();
        assert!(!pool.contains(&X86Register::RSP), "RSP must not be in pool");
        assert!(!pool.contains(&X86Register::RBP), "RBP must not be in pool");
        assert_eq!(
            pool.len(),
            8,
            "pool should mirror AArch64 X0..X7 cardinality"
        );
        // Ensure no duplicates.
        let mut sorted = pool.clone();
        sorted.sort_by_key(|r| *r as u8);
        sorted.dedup();
        assert_eq!(sorted.len(), pool.len(), "pool has duplicates");
    }

    #[test]
    fn default_immediate_pool_starts_at_zero_and_includes_powers_of_two() {
        let imms = default_x86_immediates();
        assert_eq!(imms[0], 0, "first immediate must be 0");
        for power in [1, 2, 4, 8, 16, 32, 64, 256] {
            assert!(
                imms.contains(&power),
                "missing power-of-two {} in immediate pool",
                power
            );
        }
        assert_eq!(imms.len(), 20, "pool size should mirror AArch64 baseline");
    }

    #[test]
    fn count_matches_formula() {
        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1, -1, 0xff];
        let all = generate_all_x86_instructions(&regs, &imms);
        // 7 reg-reg variants × N×N register pairs
        // + 7 reg-imm variants × N × M
        // + 16 CMOV conditions × N×N register pairs
        let expected = 7 * regs.len() * regs.len()
            + 7 * regs.len() * imms.len()
            + 16 * regs.len() * regs.len();
        assert_eq!(all.len(), expected);
    }

    #[test]
    fn covers_all_minimal_mnemonics() {
        let regs = [X86Register::RAX];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);

        let mnemonics: std::collections::HashSet<&str> = all.iter().map(|i| i.mnemonic()).collect();
        for required in ["mov", "add", "sub", "and", "or", "xor", "cmp", "cmov"] {
            assert!(mnemonics.contains(required), "missing {}", required);
        }
    }

    #[test]
    fn destinations_drawn_from_register_pool() {
        let regs = [X86Register::RAX, X86Register::RDI];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);
        for instr in &all {
            if let Some(dst) = instr.destination() {
                assert!(regs.contains(&dst), "{:?} dest not in pool", instr);
            }
        }
    }

    // --- CMOV enumeration + Jcc exclusion ---

    #[test]
    fn enumerator_includes_cmov_per_condition_and_register_pair() {
        use crate::isa::x86::X86Condition;
        let regs = [X86Register::RAX, X86Register::RBX];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);

        // For every (rd, rs, cond) triple expected, find a matching Cmov.
        let conds = [
            X86Condition::E,
            X86Condition::NE,
            X86Condition::B,
            X86Condition::AE,
            X86Condition::BE,
            X86Condition::A,
            X86Condition::L,
            X86Condition::GE,
            X86Condition::LE,
            X86Condition::G,
            X86Condition::S,
            X86Condition::NS,
            X86Condition::O,
            X86Condition::NO,
            X86Condition::P,
            X86Condition::NP,
        ];
        for &rd in &regs {
            for &rs in &regs {
                for &cond in &conds {
                    let needle = X86Instruction::Cmov { rd, rs, cond };
                    assert!(all.contains(&needle), "candidate pool missing {:?}", needle);
                }
            }
        }
    }

    #[test]
    fn enumerator_excludes_jcc_terminator() {
        let regs = [X86Register::RAX];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);
        for instr in &all {
            assert!(
                !matches!(instr, X86Instruction::Jcc { .. }),
                "Jcc must never appear in the candidate pool: {:?}",
                instr
            );
        }
    }

    #[test]
    fn covers_eight_mnemonics_after_cmov_added() {
        let regs = [X86Register::RAX];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);
        let mnemonics: std::collections::HashSet<&str> = all.iter().map(|i| i.mnemonic()).collect();
        assert!(mnemonics.contains("cmov"));
        assert!(!mnemonics.contains("jcc"));
        assert_eq!(
            mnemonics.len(),
            8,
            "expected 7 minimal-core + cmov mnemonics, got {:?}",
            mnemonics
        );
    }
}

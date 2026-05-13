//! Candidate generation for the x86 enumerative search.
//!
//! Mirrors `search::candidate::generate_all_instructions` but produces
//! `X86Instruction` values from a register and immediate pool. No
//! encodability filter is applied here — the assembler is the authority
//! on what bytes a given variant emits; out-of-range immediates surface
//! as encoder errors at use-site.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Register};

/// Enumerate every reg/reg and reg/imm form of the 14 minimal-core
/// variants for the given register and immediate pools.
pub fn generate_all_x86_instructions(
    registers: &[X86Register],
    immediates: &[i64],
) -> Vec<X86Instruction> {
    let mut out = Vec::with_capacity(
        registers.len() * registers.len() * 7 + registers.len() * immediates.len() * 7,
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

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_matches_formula() {
        let regs = [X86Register::RAX, X86Register::RBX, X86Register::RCX];
        let imms = [0i64, 1, -1, 0xff];
        let all = generate_all_x86_instructions(&regs, &imms);
        // 7 reg-reg variants × N×N register pairs
        // + 7 reg-imm variants × N × M
        let expected = 7 * regs.len() * regs.len() + 7 * regs.len() * imms.len();
        assert_eq!(all.len(), expected);
    }

    #[test]
    fn covers_all_seven_mnemonics() {
        let regs = [X86Register::RAX];
        let imms = [0i64];
        let all = generate_all_x86_instructions(&regs, &imms);

        let mnemonics: std::collections::HashSet<&str> = all.iter().map(|i| i.mnemonic()).collect();
        assert!(mnemonics.contains("mov"));
        assert!(mnemonics.contains("add"));
        assert!(mnemonics.contains("sub"));
        assert!(mnemonics.contains("and"));
        assert!(mnemonics.contains("or"));
        assert!(mnemonics.contains("xor"));
        assert!(mnemonics.contains("cmp"));
        assert_eq!(mnemonics.len(), 7);
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
}

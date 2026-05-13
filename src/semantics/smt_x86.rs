//! SMT (Z3) constraint generation for the x86 backend.
//!
//! Width-parameterised: `MachineStateX86` carries the bitvector width so
//! the same module handles both x86-64 (width=64) and x86-32 (width=32).
//! Flags are NOT modelled symbolically yet — CMP variants are encoded as
//! no-ops, mirroring the AArch64 SMT path's treatment of CMP/CMN/TST.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Register};
use std::collections::HashMap;
use z3::ast::BV;

#[derive(Clone)]
pub struct MachineStateX86 {
    pub registers: HashMap<X86Register, BV>,
    width: u32,
}

impl MachineStateX86 {
    pub fn new_symbolic(prefix: &str, width: u32) -> Self {
        let mut registers = HashMap::new();
        for i in 0..16u8 {
            if let Some(reg) = X86Register::from_index(i) {
                let name = format!("{}_r{}", prefix, i);
                registers.insert(reg, BV::new_const(name, width));
            }
        }
        MachineStateX86 { registers, width }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn get_register(&self, reg: X86Register) -> &BV {
        self.registers
            .get(&reg)
            .expect("register absent from x86 state")
    }

    pub fn set_register(&mut self, reg: X86Register, value: BV) {
        self.registers.insert(reg, value);
    }

    fn imm_bv(&self, imm: i64) -> BV {
        BV::from_i64(imm, self.width)
    }
}

/// Apply a single x86 instruction symbolically. CMP variants are no-ops
/// because we do not (yet) model EFLAGS in Z3.
pub fn apply_instruction(
    mut state: MachineStateX86,
    instruction: &X86Instruction,
) -> MachineStateX86 {
    match instruction {
        X86Instruction::MovReg { rd, rs } => {
            let value = state.get_register(*rs).clone();
            state.set_register(*rd, value);
        }
        X86Instruction::MovImm { rd, imm } => {
            let value = state.imm_bv(*imm);
            state.set_register(*rd, value);
        }
        X86Instruction::AddReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            state.set_register(*rd, lhs.bvadd(&rhs));
        }
        X86Instruction::AddImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            state.set_register(*rd, lhs.bvadd(&rhs));
        }
        X86Instruction::SubReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            state.set_register(*rd, lhs.bvsub(&rhs));
        }
        X86Instruction::SubImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            state.set_register(*rd, lhs.bvsub(&rhs));
        }
        X86Instruction::AndReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            state.set_register(*rd, lhs.bvand(&rhs));
        }
        X86Instruction::AndImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            state.set_register(*rd, lhs.bvand(&rhs));
        }
        X86Instruction::OrReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            state.set_register(*rd, lhs.bvor(&rhs));
        }
        X86Instruction::OrImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            state.set_register(*rd, lhs.bvor(&rhs));
        }
        X86Instruction::XorReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            state.set_register(*rd, lhs.bvxor(&rhs));
        }
        X86Instruction::XorImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            state.set_register(*rd, lhs.bvxor(&rhs));
        }
        // CMP sets EFLAGS only — not modelled here. Mirrors AArch64 path.
        X86Instruction::CmpReg { .. } | X86Instruction::CmpImm { .. } => {}
    }
    state
}

pub fn apply_sequence(
    mut state: MachineStateX86,
    instructions: &[X86Instruction],
) -> MachineStateX86 {
    for instr in instructions {
        state = apply_instruction(state, instr);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    #[test]
    fn new_symbolic_has_16_registers_at_width() {
        let state = MachineStateX86::new_symbolic("s", 64);
        assert_eq!(state.width(), 64);
        for i in 0..16u8 {
            let r = X86Register::from_index(i).unwrap();
            assert_eq!(state.get_register(r).get_size(), 64);
        }
    }

    #[test]
    fn new_symbolic_32bit_uses_32_wide_bvs() {
        let state = MachineStateX86::new_symbolic("s", 32);
        assert_eq!(state.width(), 32);
        for i in 0..16u8 {
            let r = X86Register::from_index(i).unwrap();
            assert_eq!(state.get_register(r).get_size(), 32);
        }
    }

    #[test]
    fn movimm_then_addreg_produces_known_value() {
        // mov rax, 5 ; mov rbx, 7 ; add rax, rbx  =>  rax == 12
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let s1 = apply_sequence(
            s0,
            &[
                X86Instruction::MovImm {
                    rd: X86Register::RAX,
                    imm: 5,
                },
                X86Instruction::MovImm {
                    rd: X86Register::RBX,
                    imm: 7,
                },
                X86Instruction::AddReg {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                },
            ],
        );
        // Z3 should be able to prove rax == 12.
        let solver = Solver::new();
        let actual = s1.get_register(X86Register::RAX);
        solver.assert(&actual.eq(&BV::from_i64(12, 64)).not());
        // If the negation is unsatisfiable, the original equality is a theorem.
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn xor_self_provably_zero() {
        // The canonical zeroing idiom must be provably equal to zero in Z3.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let s1 = apply_instruction(
            s0,
            &X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );
        let solver = Solver::new();
        let actual = s1.get_register(X86Register::RAX);
        solver.assert(&actual.eq(&BV::from_i64(0, 64)).not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn cmp_does_not_change_register_state() {
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_before = s0.get_register(X86Register::RAX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let solver = Solver::new();
        solver.assert(&s1.get_register(X86Register::RAX).eq(&rax_before).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CMP must leave RAX symbolically unchanged"
        );
    }
}

//! SMT (Z3) constraint generation for the x86 backend.
//!
//! Width-parameterised: `MachineStateX86` carries the bitvector width so
//! the same module handles both x86-64 (width=64) and x86-32 (width=32).
//!
//! Symbolic EFLAGS (issue #74) tracks five 1-bit flag BVs: CF, PF, ZF,
//! SF, OF. AF is intentionally not modelled — none of the canonical x86
//! condition codes (see `Eflags::evaluate`) reads AF, and the concrete
//! interpreter leaves AF as `false`. If a future feature requires AF
//! (e.g. BCD instructions), extend `MachineStateX86` with a sixth BV
//! and derive AF deterministically in `compute_eflags_*`.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Register};
use std::collections::HashMap;
use z3::ast::BV;

/// Symbolic EFLAGS quintuple `(cf, pf, zf, sf, of)`, mirroring
/// `Eflags` minus the unmodelled AF (see module docs).
pub type EflagsBvs = (BV, BV, BV, BV, BV);

#[derive(Clone)]
pub struct MachineStateX86 {
    pub registers: HashMap<X86Register, BV>,
    width: u32,
    cf: BV,
    pf: BV,
    zf: BV,
    sf: BV,
    of: BV,
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
        MachineStateX86 {
            registers,
            width,
            cf: BV::new_const(format!("{}_cf", prefix), 1),
            pf: BV::new_const(format!("{}_pf", prefix), 1),
            zf: BV::new_const(format!("{}_zf", prefix), 1),
            sf: BV::new_const(format!("{}_sf", prefix), 1),
            of: BV::new_const(format!("{}_of", prefix), 1),
        }
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

    /// Return the five flag BVs as `(cf, pf, zf, sf, of)`.
    pub fn get_flags(&self) -> (&BV, &BV, &BV, &BV, &BV) {
        (&self.cf, &self.pf, &self.zf, &self.sf, &self.of)
    }

    /// Replace all five flag BVs at once.
    pub fn set_flags(&mut self, flags: EflagsBvs) {
        let (cf, pf, zf, sf, of) = flags;
        self.cf = cf;
        self.pf = pf;
        self.zf = zf;
        self.sf = sf;
        self.of = of;
    }

    fn imm_bv(&self, imm: i64) -> BV {
        BV::from_i64(imm, self.width)
    }
}

// --- symbolic EFLAGS helpers (issue #74) ---

fn bv_one() -> BV {
    BV::from_u64(1, 1)
}

fn bv_zero() -> BV {
    BV::from_u64(0, 1)
}

/// PF = even parity of low 8 bits of `result`. Implemented as the XOR
/// reduction of those 8 bits, then negated.
fn parity8_bv(result: &BV) -> BV {
    let mut acc = result.extract(0, 0);
    for i in 1..8u32 {
        acc = acc.bvxor(&result.extract(i, i));
    }
    // PF = 1 iff XOR-reduction == 0 (even number of set bits).
    acc.eq(&bv_zero()).ite(&bv_one(), &bv_zero())
}

/// Top bit of `value` as a 1-bit BV (SF flag).
fn top_bit_bv(value: &BV, width: u32) -> BV {
    value.extract(width - 1, width - 1)
}

/// Zero predicate of `value` as a 1-bit BV (ZF flag).
fn is_zero_bv(value: &BV, width: u32) -> BV {
    value.eq(&BV::from_u64(0, width)).ite(&bv_one(), &bv_zero())
}

/// Symbolic flags from `lhs - rhs` at the operand width.
/// Mirrors `Eflags::from_sub` bit-for-bit.
pub fn compute_eflags_sub(lhs: &BV, rhs: &BV, width: u32) -> EflagsBvs {
    let result = lhs.bvsub(rhs);
    // CF = (lhs <u rhs) — x86 sets CF on borrow (opposite of AArch64 C).
    let cf = lhs.bvult(rhs).ite(&bv_one(), &bv_zero());
    let zf = is_zero_bv(&result, width);
    let sf = top_bit_bv(&result, width);
    // OF on sub: (lhs_sign != rhs_sign) && (lhs_sign != result_sign).
    let l = top_bit_bv(lhs, width);
    let r = top_bit_bv(rhs, width);
    let res_s = top_bit_bv(&result, width);
    let signs_differ = l.eq(&r).not();
    let lhs_vs_res = l.eq(&res_s).not();
    let of_bool = z3::ast::Bool::and(&[&signs_differ, &lhs_vs_res]);
    let of = of_bool.ite(&bv_one(), &bv_zero());
    let pf = parity8_bv(&result);
    (cf, pf, zf, sf, of)
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
        // CMP sets EFLAGS without writing a register (issue #74).
        X86Instruction::CmpReg { rn, rs } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rs).clone();
            let flags = compute_eflags_sub(&lhs, &rhs, state.width());
            state.set_flags(flags);
        }
        X86Instruction::CmpImm { rn, imm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.imm_bv(*imm);
            let flags = compute_eflags_sub(&lhs, &rhs, state.width());
            state.set_flags(flags);
        }
        // Cmov reads EFLAGS conditionally writes rd. Symbolic ITE wiring
        // lands in cycle 5; for now treat as a no-op so the type checker
        // stays happy without affecting any existing test.
        X86Instruction::Cmov { .. } => {}
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

/// Bool predicate asserting that any of the five tracked flags differs
/// between two symbolic x86 states. Used by `check_equivalence_x86` to
/// reject sequences whose flag effects diverge under `flags_live=true`.
/// AF is intentionally excluded — see module docs.
pub fn flags_not_equal_x86(a: &MachineStateX86, b: &MachineStateX86) -> z3::ast::Bool {
    let (a_cf, a_pf, a_zf, a_sf, a_of) = a.get_flags();
    let (b_cf, b_pf, b_zf, b_sf, b_of) = b.get_flags();
    z3::ast::Bool::or(&[
        &a_cf.eq(b_cf).not(),
        &a_pf.eq(b_pf).not(),
        &a_zf.eq(b_zf).not(),
        &a_sf.eq(b_sf).not(),
        &a_of.eq(b_of).not(),
    ])
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

    // --- issue #74: CMP writes symbolic EFLAGS ---

    #[test]
    fn cmp_reg_binds_zf_to_subtraction_equality() {
        // After `cmp rax, rbx`, ZF must be 1 iff rax == rbx.
        // We prove this by asserting the negation is unsatisfiable.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax = s0.get_register(X86Register::RAX).clone();
        let rbx = s0.get_register(X86Register::RBX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let zf = s1.get_flags().2; // (cf, pf, zf, sf, of) — zf at index 2
        let zf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        // Assert: NOT (zf == 1 <=> rax == rbx). If unsat, the bi-implication holds.
        let eq_regs = rax.eq(&rbx);
        let eq_zf = zf.eq(&zf_one);
        let iff = eq_zf.iff(&eq_regs);
        solver.assert(&iff.not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "ZF after CMP must equal (rax == rbx)"
        );
    }

    #[test]
    fn cmp_reg_binds_cf_to_unsigned_borrow() {
        // After `cmp rax, rbx`, CF must be 1 iff rax <u rbx (borrow).
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax = s0.get_register(X86Register::RAX).clone();
        let rbx = s0.get_register(X86Register::RBX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::CmpReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let cf = s1.get_flags().0;
        let cf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        let unsigned_lt = rax.bvult(&rbx);
        let eq_cf = cf.eq(&cf_one);
        let iff = eq_cf.iff(&unsigned_lt);
        solver.assert(&iff.not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CF after CMP must equal (rax <u rbx)"
        );
    }
}

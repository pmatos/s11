//! SMT (Z3) constraint generation for the x86 backend.
//!
//! Width-parameterised: `MachineStateX86` carries the bitvector width so
//! the same module handles both x86-64 (width=64) and x86-32 (width=32).
//!
//! Symbolic EFLAGS tracks five 1-bit flag BVs: CF, PF, ZF,
//! SF, OF. AF is intentionally not modelled — none of the canonical x86
//! condition codes (see `Eflags::evaluate`) reads AF, and the concrete
//! interpreter leaves AF as `false`. If a future feature requires AF
//! (e.g. BCD instructions), extend `MachineStateX86` with a sixth BV
//! and derive AF deterministically in `compute_eflags_*`.

#![allow(dead_code)]

use crate::isa::x86::{X86Instruction, X86Register};
use std::collections::HashMap;
use z3::ast::BV;

/// Symbolic EFLAGS BVs, mirroring `Eflags` minus the unmodelled AF
/// (see module docs).
#[derive(Clone)]
pub struct EflagsBvs {
    pub cf: BV,
    pub pf: BV,
    pub zf: BV,
    pub sf: BV,
    pub of: BV,
}

/// Borrowed view of symbolic EFLAGS.
#[derive(Clone, Copy)]
pub struct EflagsBvRefs<'a> {
    pub cf: &'a BV,
    pub pf: &'a BV,
    pub zf: &'a BV,
    pub sf: &'a BV,
    pub of: &'a BV,
}

#[derive(Clone)]
pub struct MachineStateX86 {
    pub registers: HashMap<X86Register, BV>,
    width: u32,
    flags: EflagsBvs,
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
            flags: EflagsBvs {
                cf: BV::new_const(format!("{}_cf", prefix), 1),
                pf: BV::new_const(format!("{}_pf", prefix), 1),
                zf: BV::new_const(format!("{}_zf", prefix), 1),
                sf: BV::new_const(format!("{}_sf", prefix), 1),
                of: BV::new_const(format!("{}_of", prefix), 1),
            },
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

    /// Return the five tracked flag BVs.
    pub fn get_flags(&self) -> EflagsBvRefs<'_> {
        EflagsBvRefs {
            cf: &self.flags.cf,
            pf: &self.flags.pf,
            zf: &self.flags.zf,
            sf: &self.flags.sf,
            of: &self.flags.of,
        }
    }

    /// Replace all five flag BVs at once.
    pub fn set_flags(&mut self, flags: EflagsBvs) {
        self.flags = flags;
    }

    fn imm_bv(&self, imm: i64) -> BV {
        BV::from_i64(imm, self.width)
    }
}

// --- symbolic EFLAGS helpers ---

// z3 0.20 constructors use the thread-local context. Keep this helper
// aligned with the AArch64 SMT module; an explicit-context refactor should
// move both backends together.
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
        acc = acc.bvxor(result.extract(i, i));
    }
    // PF = 1 iff XOR-reduction == 0 (even number of set bits).
    acc.eq(bv_zero()).ite(&bv_one(), &bv_zero())
}

/// Top bit of `value` as a 1-bit BV (SF flag).
fn top_bit_bv(value: &BV, width: u32) -> BV {
    value.extract(width - 1, width - 1)
}

/// Zero predicate of `value` as a 1-bit BV (ZF flag).
fn is_zero_bv(value: &BV, width: u32) -> BV {
    value.eq(BV::from_u64(0, width)).ite(&bv_one(), &bv_zero())
}

/// Translate an `X86Condition` into a symbolic `Bool` predicate over
/// the supplied flag BVs. Mirrors `Eflags::evaluate` arm-for-arm.
pub fn x86_condition_to_smt(
    cond: crate::isa::x86::X86Condition,
    flags: EflagsBvRefs<'_>,
) -> z3::ast::Bool {
    use crate::isa::x86::X86Condition;
    let one = bv_one();
    let cf1 = flags.cf.eq(&one);
    let pf1 = flags.pf.eq(&one);
    let zf1 = flags.zf.eq(&one);
    let sf1 = flags.sf.eq(&one);
    let of1 = flags.of.eq(&one);
    match cond {
        X86Condition::E => zf1,
        X86Condition::NE => zf1.not(),
        X86Condition::B => cf1,
        X86Condition::AE => cf1.not(),
        X86Condition::BE => z3::ast::Bool::or(&[&cf1, &zf1]),
        X86Condition::A => z3::ast::Bool::and(&[&cf1.not(), &zf1.not()]),
        X86Condition::L => sf1.eq(&of1).not(),
        X86Condition::GE => sf1.eq(&of1),
        X86Condition::LE => {
            let signed_lt = sf1.eq(&of1).not();
            z3::ast::Bool::or(&[&zf1, &signed_lt])
        }
        X86Condition::G => {
            let signed_ge = sf1.eq(&of1);
            z3::ast::Bool::and(&[&zf1.not(), &signed_ge])
        }
        X86Condition::S => sf1,
        X86Condition::NS => sf1.not(),
        X86Condition::O => of1,
        X86Condition::NO => of1.not(),
        X86Condition::P => pf1,
        X86Condition::NP => pf1.not(),
    }
}

/// Symbolic flags from `lhs - rhs` at the operand width.
/// Mirrors `Eflags::from_sub` bit-for-bit.
pub fn compute_eflags_sub(lhs: &BV, rhs: &BV, width: u32) -> EflagsBvs {
    let result = lhs.bvsub(rhs);
    let cf = lhs.bvult(rhs).ite(&bv_one(), &bv_zero());
    let zf = is_zero_bv(&result, width);
    let sf = top_bit_bv(&result, width);
    let l = top_bit_bv(lhs, width);
    let r = top_bit_bv(rhs, width);
    let res_s = top_bit_bv(&result, width);
    let signs_differ = l.eq(&r).not();
    let lhs_vs_res = l.eq(&res_s).not();
    let of_bool = z3::ast::Bool::and(&[&signs_differ, &lhs_vs_res]);
    let of = of_bool.ite(&bv_one(), &bv_zero());
    let pf = parity8_bv(&result);
    EflagsBvs { cf, pf, zf, sf, of }
}

/// Symbolic flags from `lhs + rhs` at the operand width.
/// Mirrors `Eflags::from_add` bit-for-bit.
pub fn compute_eflags_add(lhs: &BV, rhs: &BV, width: u32) -> EflagsBvs {
    let result = lhs.bvadd(rhs);
    // CF = unsigned overflow: result <u lhs (equivalent to <u rhs).
    let cf = result.bvult(lhs).ite(&bv_one(), &bv_zero());
    let zf = is_zero_bv(&result, width);
    let sf = top_bit_bv(&result, width);
    // OF on add: input signs match AND result sign differs from inputs.
    let l = top_bit_bv(lhs, width);
    let r = top_bit_bv(rhs, width);
    let res_s = top_bit_bv(&result, width);
    let signs_match = l.eq(&r);
    let lhs_vs_res = l.eq(&res_s).not();
    let of_bool = z3::ast::Bool::and(&[&signs_match, &lhs_vs_res]);
    let of = of_bool.ite(&bv_one(), &bv_zero());
    let pf = parity8_bv(&result);
    EflagsBvs { cf, pf, zf, sf, of }
}

/// Symbolic flags from a logical op (AND/OR/XOR). CF and OF are
/// always cleared per x86 spec; SF/ZF/PF reflect the result.
pub fn compute_eflags_logical(result: &BV, width: u32) -> EflagsBvs {
    let zf = is_zero_bv(result, width);
    let sf = top_bit_bv(result, width);
    let pf = parity8_bv(result);
    EflagsBvs {
        cf: bv_zero(),
        pf,
        zf,
        sf,
        of: bv_zero(),
    }
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Sar,
}

/// Lower an immediate-count shift symbolically. The count is a CONCRETE IR
/// value, so we mask it in Rust and branch on the result — there is no
/// symbolic-count handling. The flag model mirrors the concrete interpreter
/// (`semantics::concrete_x86::apply_shift`) bit-for-bit:
///
/// * `eff == 0`: leave `rd` and ALL flags untouched (a shift by 0 is a no-op).
/// * `eff != 0`: SF/ZF/PF from the result; CF is the last bit shifted out
///   (`extract` of the exact source bit index); OF is architecturally defined
///   only for count 1. For count > 1 OF is UNDEFINED on hardware — we model it
///   with the SAME formula as count 1 (a deterministic value). Target and
///   candidate share this lowering, so equivalence stays internally
///   consistent; downstream code must not rely on OF after a count > 1 shift.
fn apply_shift_smt(
    state: &mut MachineStateX86,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    kind: ShiftKind,
) {
    let width = state.width();
    let mask = u64::from(width - 1);
    let eff = (imm as u64) & mask;

    // Count masks to 0: no register or flag change.
    if eff == 0 {
        return;
    }

    let old = state.get_register(rd).clone();
    let amount = BV::from_u64(eff, width);
    let result = match kind {
        ShiftKind::Shl => old.bvshl(&amount),
        ShiftKind::Shr => old.bvlshr(&amount),
        ShiftKind::Sar => old.bvashr(&amount),
    };

    // CF is the last bit shifted out of the original operand. Since `eff` is
    // concrete we extract the exact bit index.
    let cf = match kind {
        // SHL: original bit at index `width - eff`.
        ShiftKind::Shl => {
            let bit = width - eff as u32;
            old.extract(bit, bit)
        }
        // SHR / SAR: original bit at index `eff - 1`.
        ShiftKind::Shr | ShiftKind::Sar => {
            let bit = eff as u32 - 1;
            old.extract(bit, bit)
        }
    };

    // OF: count-1 formula, reused for all nonzero counts (see doc comment).
    let of = match kind {
        ShiftKind::Shl => top_bit_bv(&result, width).bvxor(&cf),
        ShiftKind::Shr => top_bit_bv(&old, width),
        ShiftKind::Sar => bv_zero(),
    };

    let mut flags = compute_eflags_logical(&result, width);
    flags.cf = cf;
    flags.of = of;
    state.set_register(rd, result);
    state.set_flags(flags);
}

/// Apply a single x86 instruction symbolically. Arithmetic / logic /
/// CMP arms bind the five tracked flag BVs via `compute_eflags_*`;
/// CMOV reads them via `x86_condition_to_smt`.
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
            let result = lhs.bvadd(&rhs);
            let flags = compute_eflags_add(&lhs, &rhs, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::AddImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvadd(&rhs);
            let flags = compute_eflags_add(&lhs, &rhs, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::SubReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            let result = lhs.bvsub(&rhs);
            let flags = compute_eflags_sub(&lhs, &rhs, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::SubImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvsub(&rhs);
            let flags = compute_eflags_sub(&lhs, &rhs, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::AndReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            let result = lhs.bvand(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::AndImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvand(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::OrReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            let result = lhs.bvor(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::OrImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvor(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::XorReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            let result = lhs.bvxor(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        X86Instruction::XorImm { rd, imm } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvxor(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        // CMP sets EFLAGS without writing a register.
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
        // TEST sets EFLAGS from `rn & rhs` (the AND/logical path: CF=OF=0,
        // SF/ZF/PF from the result) without writing a register — the
        // non-destructive sibling of AND, mirroring how CMP is to SUB.
        X86Instruction::TestReg { rn, rs } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rs).clone();
            let result = lhs.bvand(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_flags(flags);
        }
        X86Instruction::TestImm { rn, imm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.imm_bv(*imm);
            let result = lhs.bvand(&rhs);
            let flags = compute_eflags_logical(&result, state.width());
            state.set_flags(flags);
        }
        // NEG computes `rd = -rd` and sets EFLAGS as if from `0 - rd`. We
        // reuse the SUB flag path with lhs = 0, rhs = old_rd so CF = (rd != 0)
        // and OF/SF/ZF/PF match `sub` bit-for-bit.
        X86Instruction::Neg { rd } => {
            let old = state.get_register(*rd).clone();
            let zero = BV::from_u64(0, state.width());
            let result = old.bvneg();
            let flags = compute_eflags_sub(&zero, &old, state.width());
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        // NOT computes `rd = !rd` (bitwise complement) and leaves EFLAGS
        // UNCHANGED — exactly like MOV, which writes only its register and
        // carries the incoming flag BVs forward untouched.
        X86Instruction::Not { rd } => {
            let result = state.get_register(*rd).bvnot();
            state.set_register(*rd, result);
        }
        // INC computes `rd = rd + 1` and sets OF/SF/ZF/PF exactly as `add rd, 1`
        // would, but — the load-bearing subtlety — leaves CF UNCHANGED (the
        // incoming carry flows through). Capture the prior CF BV FIRST, compute
        // the ADD flag path for `rd + 1`, then override CF back to the captured
        // BV so it equals the incoming CF.
        X86Instruction::Inc { rd } => {
            let prev_cf = state.get_flags().cf.clone();
            let old = state.get_register(*rd).clone();
            let one = BV::from_u64(1, state.width());
            let result = old.bvadd(&one);
            let mut flags = compute_eflags_add(&old, &one, state.width());
            flags.cf = prev_cf;
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        // DEC computes `rd = rd - 1`. Like INC it sets OF/SF/ZF/PF as `sub rd, 1`
        // would while leaving CF UNCHANGED. Capture the prior CF BV first, derive
        // flags from the SUB path for `rd - 1`, then restore CF.
        X86Instruction::Dec { rd } => {
            let prev_cf = state.get_flags().cf.clone();
            let old = state.get_register(*rd).clone();
            let one = BV::from_u64(1, state.width());
            let result = old.bvsub(&one);
            let mut flags = compute_eflags_sub(&old, &one, state.width());
            flags.cf = prev_cf;
            state.set_register(*rd, result);
            state.set_flags(flags);
        }
        // Immediate-count shifts. The count is a concrete IR value, so we branch
        // on the masked count at lowering time — no symbolic-count handling is
        // needed. See `apply_shift_smt`.
        X86Instruction::Shl { rd, imm } => apply_shift_smt(&mut state, *rd, *imm, ShiftKind::Shl),
        X86Instruction::Shr { rd, imm } => apply_shift_smt(&mut state, *rd, *imm, ShiftKind::Shr),
        X86Instruction::Sar { rd, imm } => apply_shift_smt(&mut state, *rd, *imm, ShiftKind::Sar),
        X86Instruction::Cmov { rd, rs, cond } => {
            let pred = x86_condition_to_smt(*cond, state.get_flags());
            let rs_val = state.get_register(*rs).clone();
            let rd_old = state.get_register(*rd).clone();
            state.set_register(*rd, pred.ite(&rs_val, &rd_old));
        }
        // Jcc reads EFLAGS but transfers control; nothing is observable
        // in the data-state machine modelled here. Cycle 10 peels Jccs
        // off the sequence before applying it symbolically.
        X86Instruction::Jcc { .. } => {}
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
/// between two symbolic x86 states. Used by x86's equivalence backend to
/// reject sequences whose flag effects diverge under `flags_live=true`.
/// AF is intentionally excluded — see module docs.
pub fn flags_not_equal_x86(a: &MachineStateX86, b: &MachineStateX86) -> z3::ast::Bool {
    let a_flags = a.get_flags();
    let b_flags = b.get_flags();
    z3::ast::Bool::or(&[
        &a_flags.cf.eq(b_flags.cf).not(),
        &a_flags.pf.eq(b_flags.pf).not(),
        &a_flags.zf.eq(b_flags.zf).not(),
        &a_flags.sf.eq(b_flags.sf).not(),
        &a_flags.of.eq(b_flags.of).not(),
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
        solver.assert(actual.eq(BV::from_i64(12, 64)).not());
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
        solver.assert(actual.eq(BV::from_i64(0, 64)).not());
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
        solver.assert(s1.get_register(X86Register::RAX).eq(&rax_before).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CMP must leave RAX symbolically unchanged"
        );
    }

    // --- CMP writes symbolic EFLAGS ---

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
        let zf = s1.get_flags().zf;
        let zf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        // Assert: NOT (zf == 1 <=> rax == rbx). If unsat, the bi-implication holds.
        let eq_regs = rax.eq(&rbx);
        let eq_zf = zf.eq(&zf_one);
        let iff = eq_zf.iff(&eq_regs);
        solver.assert(iff.not());
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
        let cf = s1.get_flags().cf;
        let cf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        let unsigned_lt = rax.bvult(&rbx);
        let eq_cf = cf.eq(&cf_one);
        let iff = eq_cf.iff(&unsigned_lt);
        solver.assert(iff.not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CF after CMP must equal (rax <u rbx)"
        );
    }

    // --- symbolic TEST ---

    #[test]
    fn test_does_not_change_register_state() {
        // TEST discards its result, so no register may change symbolically.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_before = s0.get_register(X86Register::RAX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let solver = Solver::new();
        solver.assert(s1.get_register(X86Register::RAX).eq(&rax_before).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "TEST must leave RAX symbolically unchanged"
        );
    }

    #[test]
    fn test_rax_rax_equivalent_to_cmp_rax_zero_on_zf_sf_and_clears_cf_of() {
        // The key correctness theorem for TEST. Both `test rax, rax` (computing
        // `rax & rax == rax`) and `cmp rax, 0` (computing `rax - 0 == rax`)
        // observe the value `rax`, so they must agree on the result-derived
        // flags. We run both over states built with the SAME symbolic prefix,
        // so both derive from one shared `rax` constant, then assert (by
        // unsat-of-negation):
        //   * ZF agrees  — both are 1 iff rax == 0,
        //   * SF agrees  — both equal the top (sign) bit of rax, and
        //   * CF and OF are constant-zero after TEST (logical semantics).
        let after_test = apply_instruction(
            MachineStateX86::new_symbolic("shared", 64),
            &X86Instruction::TestReg {
                rn: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );
        let after_cmp = apply_instruction(
            MachineStateX86::new_symbolic("shared", 64),
            &X86Instruction::CmpImm {
                rn: X86Register::RAX,
                imm: 0,
            },
        );

        let test_flags = after_test.get_flags();
        let cmp_flags = after_cmp.get_flags();
        let zero1 = BV::from_u64(0, 1);

        // ZF and SF must match the CMP-with-zero baseline; CF/OF are zero.
        let solver = Solver::new();
        solver.assert(z3::ast::Bool::or(&[
            &test_flags.zf.eq(cmp_flags.zf).not(),
            &test_flags.sf.eq(cmp_flags.sf).not(),
            &test_flags.cf.eq(&zero1).not(),
            &test_flags.of.eq(&zero1).not(),
        ]));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "TEST rax,rax must agree with CMP rax,0 on ZF/SF and clear CF/OF"
        );
    }

    // --- symbolic NEG / NOT ---

    #[test]
    fn neg_result_equals_zero_minus_rax_and_cf_tracks_nonzero() {
        // The key NEG theorem: `neg rax` writes `0 - rax` and sets CF iff
        // rax != 0 (equivalently rax >u 0, i.e. 0 <u rax). Prove both by
        // unsat-of-negation over one shared symbolic rax.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_init = s0.get_register(X86Register::RAX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::Neg {
                rd: X86Register::RAX,
            },
        );
        let rax_after = s1.get_register(X86Register::RAX).clone();
        let cf = s1.get_flags().cf.clone();

        let zero64 = BV::from_u64(0, 64);
        let cf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        // result == 0 - rax, AND CF == (rax != 0).
        let result_wrong = rax_after.eq(zero64.bvsub(&rax_init)).not();
        let nonzero = rax_init.eq(&zero64).not();
        let cf_wrong = cf.eq(&cf_one).iff(&nonzero).not();
        solver.assert(z3::ast::Bool::or(&[&result_wrong, &cf_wrong]));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "NEG must compute 0 - rax and set CF iff rax != 0"
        );
    }

    #[test]
    fn not_result_matches_xor_with_minus_one() {
        // `not rax` and `xor rax, -1` compute the same value (bitwise
        // complement). Prove result-equivalence over one shared symbolic rax.
        let after_not = apply_instruction(
            MachineStateX86::new_symbolic("shared", 64),
            &X86Instruction::Not {
                rd: X86Register::RAX,
            },
        );
        let after_xor = apply_instruction(
            MachineStateX86::new_symbolic("shared", 64),
            &X86Instruction::XorImm {
                rd: X86Register::RAX,
                imm: -1,
            },
        );
        let solver = Solver::new();
        solver.assert(
            after_not
                .get_register(X86Register::RAX)
                .eq(after_xor.get_register(X86Register::RAX))
                .not(),
        );
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "NOT rax must equal XOR rax,-1 on the result"
        );
    }

    #[test]
    fn not_leaves_all_flags_unchanged() {
        // The load-bearing NOT subtlety: unlike XOR, NOT writes NO flags.
        // Each tracked flag BV after NOT must be identical to the incoming
        // one. (XOR, by contrast, would clear CF/OF and set SF/ZF/PF — which
        // is exactly why the NOT≡XOR equivalence is result-only.)
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let cf0 = s0.get_flags().cf.clone();
        let pf0 = s0.get_flags().pf.clone();
        let zf0 = s0.get_flags().zf.clone();
        let sf0 = s0.get_flags().sf.clone();
        let of0 = s0.get_flags().of.clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::Not {
                rd: X86Register::RAX,
            },
        );
        let f = s1.get_flags();
        let solver = Solver::new();
        solver.assert(z3::ast::Bool::or(&[
            &f.cf.eq(&cf0).not(),
            &f.pf.eq(&pf0).not(),
            &f.zf.eq(&zf0).not(),
            &f.sf.eq(&sf0).not(),
            &f.of.eq(&of0).not(),
        ]));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "NOT must leave every EFLAGS bit unchanged"
        );
    }

    // --- symbolic INC / DEC ---

    // The KEY INC theorem: `inc rd` and `add rd, 1` AGREE on the result and on
    // OF/SF/ZF/PF, and differ EXACTLY in CF — `inc` leaves CF equal to the
    // incoming CF, while `add rd, 1` derives CF from the addition (so it can
    // differ from the incoming CF). We prove all three claims over one shared
    // symbolic state (same incoming rax AND same incoming CF).
    #[test]
    fn inc_matches_add_one_except_cf_which_inc_preserves() {
        let prefix = "shared";
        let s_inc = MachineStateX86::new_symbolic(prefix, 64);
        let s_add = MachineStateX86::new_symbolic(prefix, 64);
        // Both share the same symbolic incoming CF (identical const name).
        let incoming_cf = s_inc.get_flags().cf.clone();

        let after_inc = apply_instruction(
            s_inc,
            &X86Instruction::Inc {
                rd: X86Register::RAX,
            },
        );
        let after_add = apply_instruction(
            s_add,
            &X86Instruction::AddImm {
                rd: X86Register::RAX,
                imm: 1,
            },
        );

        let inc_flags = after_inc.get_flags();
        let add_flags = after_add.get_flags();

        // (1) result and OF/SF/ZF/PF agree: negation is unsat.
        {
            let solver = Solver::new();
            solver.assert(z3::ast::Bool::or(&[
                &after_inc
                    .get_register(X86Register::RAX)
                    .eq(after_add.get_register(X86Register::RAX))
                    .not(),
                &inc_flags.of.eq(add_flags.of).not(),
                &inc_flags.sf.eq(add_flags.sf).not(),
                &inc_flags.zf.eq(add_flags.zf).not(),
                &inc_flags.pf.eq(add_flags.pf).not(),
            ]));
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "INC and ADD-1 must agree on result and OF/SF/ZF/PF"
            );
        }

        // (2) INC's CF equals the incoming CF: negation is unsat.
        {
            let solver = Solver::new();
            solver.assert(inc_flags.cf.eq(&incoming_cf).not());
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "INC must leave CF == the incoming CF"
            );
        }

        // (3) ADD-1's CF is NOT pinned to the incoming CF: there exists a model
        // where they differ (e.g. rax = u64::MAX makes ADD carry to CF=1 while
        // the incoming CF can be 0). A SAT result proves INC genuinely diverges
        // from ADD-1 on CF.
        {
            let solver = Solver::new();
            solver.assert(add_flags.cf.eq(&incoming_cf).not());
            assert_eq!(
                solver.check(),
                SatResult::Sat,
                "ADD-1's CF must be able to differ from the incoming CF"
            );
        }
    }

    // The DEC sibling theorem: `dec rd` and `sub rd, 1` agree on result and
    // OF/SF/ZF/PF, but DEC preserves CF while SUB-1 derives it.
    #[test]
    fn dec_matches_sub_one_except_cf_which_dec_preserves() {
        let prefix = "shared";
        let s_dec = MachineStateX86::new_symbolic(prefix, 64);
        let s_sub = MachineStateX86::new_symbolic(prefix, 64);
        let incoming_cf = s_dec.get_flags().cf.clone();

        let after_dec = apply_instruction(
            s_dec,
            &X86Instruction::Dec {
                rd: X86Register::RAX,
            },
        );
        let after_sub = apply_instruction(
            s_sub,
            &X86Instruction::SubImm {
                rd: X86Register::RAX,
                imm: 1,
            },
        );

        let dec_flags = after_dec.get_flags();
        let sub_flags = after_sub.get_flags();

        {
            let solver = Solver::new();
            solver.assert(z3::ast::Bool::or(&[
                &after_dec
                    .get_register(X86Register::RAX)
                    .eq(after_sub.get_register(X86Register::RAX))
                    .not(),
                &dec_flags.of.eq(sub_flags.of).not(),
                &dec_flags.sf.eq(sub_flags.sf).not(),
                &dec_flags.zf.eq(sub_flags.zf).not(),
                &dec_flags.pf.eq(sub_flags.pf).not(),
            ]));
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "DEC and SUB-1 must agree on result and OF/SF/ZF/PF"
            );
        }

        {
            let solver = Solver::new();
            solver.assert(dec_flags.cf.eq(&incoming_cf).not());
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "DEC must leave CF == the incoming CF"
            );
        }

        {
            let solver = Solver::new();
            solver.assert(sub_flags.cf.eq(&incoming_cf).not());
            assert_eq!(
                solver.check(),
                SatResult::Sat,
                "SUB-1's CF must be able to differ from the incoming CF"
            );
        }
    }

    // --- symbolic SHL / SHR / SAR ---

    // The DoD SHL theorem: `shl rd, 1` is equivalent to `add rd, rd` on the
    // RESULT, ZF, and SF. (CF, OF, and PF may differ — `add` derives CF from
    // the addition and OF from signed overflow, while SHL's CF is the bit
    // shifted out and OF is `MSB(result) XOR CF`; we deliberately assert only
    // result + ZF + SF agree.) We prove the negation of that conjunction is
    // unsat over a shared symbolic input.
    #[test]
    fn shl_one_matches_add_self_on_result_zf_sf() {
        let prefix = "shared";
        let s_shl = MachineStateX86::new_symbolic(prefix, 64);
        let s_add = MachineStateX86::new_symbolic(prefix, 64);

        let after_shl = apply_instruction(
            s_shl,
            &X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        // `add rax, rax` doubles rax, exactly like a 1-bit left shift.
        let after_add = apply_instruction(
            s_add,
            &X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );

        let shl_flags = after_shl.get_flags();
        let add_flags = after_add.get_flags();

        let solver = Solver::new();
        solver.assert(z3::ast::Bool::or(&[
            &after_shl
                .get_register(X86Register::RAX)
                .eq(after_add.get_register(X86Register::RAX))
                .not(),
            &shl_flags.zf.eq(add_flags.zf).not(),
            &shl_flags.sf.eq(add_flags.sf).not(),
        ]));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "shl rax, 1 and add rax, rax must agree on result, ZF and SF"
        );
    }

    // The eff == 0 case: a shift whose masked count is 0 must leave the
    // register AND all five tracked flags BIT-IDENTICAL to the incoming state.
    // We prove the disjunction "rd changed OR any flag changed" is unsat.
    #[test]
    fn shift_by_zero_preserves_register_and_all_flags_smt() {
        for instr in [
            X86Instruction::Shl {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Shr {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Sar {
                rd: X86Register::RAX,
                imm: 0,
            },
            // 64 masks to 0 at width 64.
            X86Instruction::Sar {
                rd: X86Register::RAX,
                imm: 64,
            },
        ] {
            let before = MachineStateX86::new_symbolic("s", 64);
            let old_reg = before.get_register(X86Register::RAX).clone();
            let old_flags = before.get_flags();
            let (old_cf, old_pf, old_zf, old_sf, old_of) = (
                old_flags.cf.clone(),
                old_flags.pf.clone(),
                old_flags.zf.clone(),
                old_flags.sf.clone(),
                old_flags.of.clone(),
            );

            let after = apply_instruction(before, &instr);
            let after_flags = after.get_flags();

            let solver = Solver::new();
            solver.assert(z3::ast::Bool::or(&[
                &after.get_register(X86Register::RAX).eq(&old_reg).not(),
                &after_flags.cf.eq(&old_cf).not(),
                &after_flags.pf.eq(&old_pf).not(),
                &after_flags.zf.eq(&old_zf).not(),
                &after_flags.sf.eq(&old_sf).not(),
                &after_flags.of.eq(&old_of).not(),
            ]));
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "{instr:?} (eff==0) must preserve rd and every flag"
            );
        }
    }

    // CF correctness for SHR: `shr rax, 1` sets CF to the original low bit.
    // We prove `cf == rax[0]` is always true (negation unsat).
    #[test]
    fn shr_one_cf_equals_original_low_bit() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let orig_low = state.get_register(X86Register::RAX).extract(0, 0);
        let after = apply_instruction(
            state,
            &X86Instruction::Shr {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_flags().cf.eq(&orig_low).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "shr rax, 1 must set CF to the original low bit"
        );
    }

    // --- symbolic CMOV ---

    #[test]
    fn cmov_ites_rd_on_condition() {
        // After `cmove rax, rbx`, rax must equal (zf_init == 1 ? rbx_init : rax_init).
        use crate::isa::x86::X86Condition;
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_init = s0.get_register(X86Register::RAX).clone();
        let rbx_init = s0.get_register(X86Register::RBX).clone();
        let zf_init = s0.get_flags().zf.clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::E,
            },
        );
        let rax_after = s1.get_register(X86Register::RAX);
        // Expected: zf_init == 1 → rbx_init, else rax_init.
        let zf_one = BV::from_u64(1, 1);
        let expected = zf_init.eq(&zf_one).ite(&rbx_init, &rax_init);
        let solver = Solver::new();
        solver.assert(rax_after.eq(&expected).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CMOV must ITE rd on condition predicate"
        );
    }

    #[test]
    fn xor_self_provably_clears_cf_and_of_and_sets_zf_pf() {
        // The canonical zeroing idiom: xor rax, rax. After Cycle 6's
        // logical-flag wiring this must be observable symbolically.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let s1 = apply_instruction(
            s0,
            &X86Instruction::XorReg {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
            },
        );
        let flags = s1.get_flags();
        let zero = BV::from_u64(0, 1);
        let one = BV::from_u64(1, 1);
        let solver = Solver::new();
        solver.assert(z3::ast::Bool::or(&[
            &flags.cf.eq(&zero).not(),
            &flags.of.eq(&zero).not(),
            &flags.zf.eq(&one).not(),
            &flags.pf.eq(&one).not(),
        ]));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "XOR x,x must clear CF/OF and set ZF=PF=1"
        );
    }

    #[test]
    fn addreg_binds_zf_to_sum_equality() {
        // After `add rax, rbx`, ZF=1 iff rax_init + rbx_init == 0.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_init = s0.get_register(X86Register::RAX).clone();
        let rbx_init = s0.get_register(X86Register::RBX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let zf = s1.get_flags().zf;
        let zero = BV::from_u64(0, 64);
        let zf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        let sum_zero = rax_init.bvadd(&rbx_init).eq(&zero);
        let iff = zf.eq(&zf_one).iff(&sum_zero);
        solver.assert(iff.not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn subreg_binds_cf_to_unsigned_borrow() {
        // After `sub rax, rbx`, CF=1 iff rax_init <u rbx_init (borrow).
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let rax_init = s0.get_register(X86Register::RAX).clone();
        let rbx_init = s0.get_register(X86Register::RBX).clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::SubReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let cf = s1.get_flags().cf;
        let cf_one = BV::from_u64(1, 1);
        let solver = Solver::new();
        let borrow = rax_init.bvult(&rbx_init);
        let iff = cf.eq(&cf_one).iff(&borrow);
        solver.assert(iff.not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    // --- concrete↔SMT parity for x86 flag computation ---

    fn assert_x86_concrete_smt_parity(instr: &X86Instruction, lhs: u64, rhs: u64) {
        use crate::semantics::concrete_x86::apply_instruction_concrete_x86;
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState};

        let mut concrete_pre = X86ConcreteMachineState::new_zeroed(64);
        concrete_pre.set_register(X86Register::RAX, ConcreteValue::new(lhs));
        concrete_pre.set_register(X86Register::RBX, ConcreteValue::new(rhs));
        let concrete_post = apply_instruction_concrete_x86(concrete_pre, instr);
        let cf_post = concrete_post.get_flags();

        let symbolic_pre = MachineStateX86::new_symbolic("pre", 64);
        let solver = Solver::new();
        solver.assert(
            symbolic_pre
                .get_register(X86Register::RAX)
                .eq(BV::from_u64(lhs, 64)),
        );
        solver.assert(
            symbolic_pre
                .get_register(X86Register::RBX)
                .eq(BV::from_u64(rhs, 64)),
        );
        let symbolic_post = apply_instruction(symbolic_pre, instr);

        // Build inequality disjunct over all five tracked flags and rd
        // (when the instruction has one).
        let one_bit = |b: bool| BV::from_u64(b as u64, 1);
        let symbolic_flags = symbolic_post.get_flags();
        let mut diffs: Vec<z3::ast::Bool> = vec![
            symbolic_flags.cf.eq(one_bit(cf_post.cf)).not(),
            symbolic_flags.pf.eq(one_bit(cf_post.pf)).not(),
            symbolic_flags.zf.eq(one_bit(cf_post.zf)).not(),
            symbolic_flags.sf.eq(one_bit(cf_post.sf)).not(),
            symbolic_flags.of.eq(one_bit(cf_post.of)).not(),
        ];
        if let Some(rd) = instr.destination() {
            let expected = BV::from_u64(concrete_post.get_register(rd).as_u64(), 64);
            diffs.push(symbolic_post.get_register(rd).eq(&expected).not());
        }
        let refs: Vec<&z3::ast::Bool> = diffs.iter().collect();
        solver.assert(z3::ast::Bool::or(&refs));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "concrete/SMT parity violation for {:?} with lhs={:#x} rhs={:#x}",
            instr,
            lhs,
            rhs
        );
    }

    fn assert_x86_cmov_concrete_smt_parity(
        cond: crate::isa::x86::X86Condition,
        input_flags: crate::semantics::state::Eflags,
        lhs: u64,
        rhs: u64,
    ) {
        use crate::semantics::concrete_x86::apply_instruction_concrete_x86;
        use crate::semantics::state::{ConcreteValue, X86ConcreteMachineState};

        let instr = X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond,
        };

        let mut concrete_pre = X86ConcreteMachineState::new_zeroed(64);
        concrete_pre.set_register(X86Register::RAX, ConcreteValue::new(lhs));
        concrete_pre.set_register(X86Register::RBX, ConcreteValue::new(rhs));
        concrete_pre.set_flags(input_flags);
        let concrete_post = apply_instruction_concrete_x86(concrete_pre, &instr);
        let expected_flags = concrete_post.get_flags();

        let symbolic_pre = MachineStateX86::new_symbolic("cmov_pre", 64);
        let solver = Solver::new();
        solver.assert(
            symbolic_pre
                .get_register(X86Register::RAX)
                .eq(BV::from_u64(lhs, 64)),
        );
        solver.assert(
            symbolic_pre
                .get_register(X86Register::RBX)
                .eq(BV::from_u64(rhs, 64)),
        );

        let one_bit = |b: bool| BV::from_u64(b as u64, 1);
        let EflagsBvRefs {
            cf: cf_pre,
            pf: pf_pre,
            zf: zf_pre,
            sf: sf_pre,
            of: of_pre,
        } = symbolic_pre.get_flags();
        solver.assert(cf_pre.eq(one_bit(input_flags.cf)));
        solver.assert(pf_pre.eq(one_bit(input_flags.pf)));
        solver.assert(zf_pre.eq(one_bit(input_flags.zf)));
        solver.assert(sf_pre.eq(one_bit(input_flags.sf)));
        solver.assert(of_pre.eq(one_bit(input_flags.of)));

        let symbolic_post = apply_instruction(symbolic_pre, &instr);
        let EflagsBvRefs {
            cf: cf_s,
            pf: pf_s,
            zf: zf_s,
            sf: sf_s,
            of: of_s,
        } = symbolic_post.get_flags();
        let expected_rd = BV::from_u64(concrete_post.get_register(X86Register::RAX).as_u64(), 64);
        let diffs = [
            symbolic_post
                .get_register(X86Register::RAX)
                .eq(&expected_rd)
                .not(),
            cf_s.eq(one_bit(expected_flags.cf)).not(),
            pf_s.eq(one_bit(expected_flags.pf)).not(),
            zf_s.eq(one_bit(expected_flags.zf)).not(),
            sf_s.eq(one_bit(expected_flags.sf)).not(),
            of_s.eq(one_bit(expected_flags.of)).not(),
        ];
        let refs: Vec<&z3::ast::Bool> = diffs.iter().collect();
        solver.assert(z3::ast::Bool::or(&refs));
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CMOV concrete/SMT parity violation for {:?} with flags {:?}",
            instr,
            input_flags
        );
    }

    const PARITY_SAMPLES: &[(u64, u64)] = &[
        (0, 0),
        (0, 1),
        (1, 1),
        (5, 5),
        (5, 7),
        (7, 5),
        (u64::MAX, 1),
        (1, u64::MAX),
        (i64::MIN as u64, 1),
        (i64::MAX as u64, 1),
        (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
        (0xDEAD_BEEF_CAFE_BABE, 0x1234_5678_9ABC_DEF0),
    ];

    #[test]
    fn parity_add_reg() {
        let instr = X86Instruction::AddReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_sub_reg() {
        let instr = X86Instruction::SubReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_cmp_reg() {
        let instr = X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_test_reg() {
        let instr = X86Instruction::TestReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_neg() {
        // NEG reads/writes only RAX and sets flags deterministically, so the
        // generic register+flags parity harness applies (rhs is ignored).
        let instr = X86Instruction::Neg {
            rd: X86Register::RAX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_and_reg() {
        let instr = X86Instruction::AndReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_or_reg() {
        let instr = X86Instruction::OrReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_xor_reg() {
        let instr = X86Instruction::XorReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    #[test]
    fn parity_cmov_reg_taken_and_not_taken() {
        use crate::isa::x86::X86Condition;
        use crate::semantics::state::Eflags;

        let taken_flags = Eflags {
            cf: true,
            pf: false,
            af: true,
            zf: true,
            sf: false,
            of: true,
        };
        assert_x86_cmov_concrete_smt_parity(
            X86Condition::E,
            taken_flags,
            0x1111_2222_3333_4444,
            0xAAAA_BBBB_CCCC_DDDD,
        );

        let not_taken_flags = Eflags {
            cf: false,
            pf: true,
            af: true,
            zf: false,
            sf: true,
            of: false,
        };
        assert_x86_cmov_concrete_smt_parity(
            X86Condition::E,
            not_taken_flags,
            0x1111_2222_3333_4444,
            0xAAAA_BBBB_CCCC_DDDD,
        );
    }

    #[test]
    fn cmov_does_not_modify_flags() {
        // Cmov must leave the five tracked flag BVs symbolically untouched.
        use crate::isa::x86::X86Condition;
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let flags0 = {
            let flags = s0.get_flags();
            EflagsBvs {
                cf: flags.cf.clone(),
                pf: flags.pf.clone(),
                zf: flags.zf.clone(),
                sf: flags.sf.clone(),
                of: flags.of.clone(),
            }
        };
        let s1 = apply_instruction(
            s0,
            &X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                cond: X86Condition::NE,
            },
        );
        let solver = Solver::new();
        let flags1 = s1.get_flags();
        // Any flag differing means we touched flags.
        let diff = z3::ast::Bool::or(&[
            &flags1.cf.eq(&flags0.cf).not(),
            &flags1.pf.eq(&flags0.pf).not(),
            &flags1.zf.eq(&flags0.zf).not(),
            &flags1.sf.eq(&flags0.sf).not(),
            &flags1.of.eq(&flags0.of).not(),
        ]);
        solver.assert(&diff);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CMOV must not write any flag"
        );
    }
}

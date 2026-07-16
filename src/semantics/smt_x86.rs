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

#[derive(Clone, Copy)]
enum RotateKind {
    Rol,
    Ror,
}

/// Lower an immediate-count rotate symbolically. Mirrors the concrete
/// interpreter (`semantics::concrete_x86::apply_rotate`) bit-for-bit. The count
/// is a CONCRETE IR value, so we mask it in Rust and branch on the result.
///
/// The flag model is the load-bearing difference from the shifts: rotates touch
/// ONLY CF (plus OF for count 1). SF/ZF/PF/AF are PRESERVED. We therefore start
/// from the PRIOR flag BVs (carrying SF/ZF/PF/AF forward unchanged) and override
/// only CF, plus OF when the masked count is 1.
///
/// * `eff == 0`: leave `rd` and ALL flags untouched (a rotate by 0 is a no-op).
/// * `eff != 0`:
///   - ROL: `result = bvrotl(rd, eff)`; CF = bit 0 of the result. OF (count 1
///     only) = `MSB(result) XOR CF`.
///   - ROR: `result = bvrotr(rd, eff)`; CF = the MSB (bit `width-1`) of the
///     result. OF (count 1 only) = XOR of the result's two most-significant bits.
///   - For count != 1 OF is UNDEFINED on hardware; we preserve the incoming OF.
fn apply_rotate_smt(
    state: &mut MachineStateX86,
    rd: crate::isa::x86::X86Register,
    imm: i64,
    kind: RotateKind,
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
        RotateKind::Rol => old.bvrotl(&amount),
        RotateKind::Ror => old.bvrotr(&amount),
    };

    // CF is extracted from the result. ROL: bit 0; ROR: the MSB.
    let cf = match kind {
        RotateKind::Rol => result.extract(0, 0),
        RotateKind::Ror => top_bit_bv(&result, width),
    };

    // Start from the PRIOR flags so SF/ZF/PF (and OF for count != 1) carry over
    // unchanged; override CF, and OF only when the masked count is exactly 1.
    let prior = state.get_flags();
    let mut flags = EflagsBvs {
        cf: cf.clone(),
        pf: prior.pf.clone(),
        zf: prior.zf.clone(),
        sf: prior.sf.clone(),
        of: prior.of.clone(),
    };
    if eff == 1 {
        flags.of = match kind {
            RotateKind::Rol => top_bit_bv(&result, width).bvxor(&cf),
            // XOR of the result's two most-significant bits.
            RotateKind::Ror => {
                top_bit_bv(&result, width).bvxor(result.extract(width - 2, width - 2))
            }
        };
    }

    state.set_register(rd, result);
    state.set_flags(flags);
}

/// Lower a signed multiply (IMUL) symbolically — shared by the 2-operand
/// (`rd = rd * rs`) and 3-operand (`rd = rs * imm`) forms. `lhs`/`rhs` are the
/// width-`width` operand BVs; the result is the low `width` bits of the signed
/// product written to `rd`.
///
/// FLAG MODEL (mirrors `concrete_x86::apply_imul` bit-for-bit): only CF and OF
/// are architecturally defined. We detect signed overflow with a WIDE multiply:
/// sign-extend both operands to `2*width`, `bvmul`, and check whether the full
/// product equals the sign-extension of the truncated `width`-bit result. CF =
/// OF = NOT(fits).
///
/// SF/ZF/PF are Intel-UNDEFINED; we model them deterministically from the
/// truncated result via `compute_eflags_logical` (SF = MSB, ZF = result == 0,
/// PF = low-byte parity). Both target and candidate share this lowering, so
/// equivalence stays internally consistent and conservative. AF is not modelled
/// (see module docs).
fn apply_imul_smt(
    state: &mut MachineStateX86,
    rd: crate::isa::x86::X86Register,
    lhs: &BV,
    rhs: &BV,
) {
    let width = state.width();
    // `sign_ext(width)` adds `width` bits, giving a 2*width-bit BV.
    let wide = lhs.sign_ext(width).bvmul(rhs.sign_ext(width));
    let result = lhs.bvmul(rhs);

    // `result fits` iff the full 2*width product equals the sign-extension of
    // the truncated low-`width` result; signed overflow is the negation.
    let fits = wide.eq(result.sign_ext(width));
    let overflow = fits.ite(&bv_zero(), &bv_one());

    // SF/ZF/PF from the truncated result (Intel-undefined; modelled
    // deterministically). CF/OF then overridden with the overflow bit.
    let mut flags = compute_eflags_logical(&result, width);
    flags.cf = overflow.clone();
    flags.of = overflow;
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
        X86Instruction::Movzx { rd, rs, src_width } => {
            assert!(
                matches!(src_width, 8 | 16),
                "MOVZX source width must be 8 or 16 bits"
            );
            let narrow = state.get_register(*rs).extract(*src_width - 1, 0);
            let value = narrow.zero_ext(state.width() - *src_width);
            state.set_register(*rd, value);
        }
        X86Instruction::Movsx { rd, rs, src_width } => {
            assert!(
                matches!(src_width, 8 | 16),
                "MOVSX source width must be 8 or 16 bits"
            );
            let narrow = state.get_register(*rs).extract(*src_width - 1, 0);
            let value = narrow.sign_ext(state.width() - *src_width);
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
        // Immediate-count rotates. Same concrete-count handling as the shifts,
        // but a partial flag update (only CF, plus OF for count 1) — see
        // `apply_rotate_smt`.
        X86Instruction::Rol { rd, imm } => apply_rotate_smt(&mut state, *rd, *imm, RotateKind::Rol),
        X86Instruction::Ror { rd, imm } => apply_rotate_smt(&mut state, *rd, *imm, RotateKind::Ror),
        // IMUL (2-op): `rd = rd * rs`. rd is both source and destination.
        X86Instruction::ImulReg { rd, rs } => {
            let lhs = state.get_register(*rd).clone();
            let rhs = state.get_register(*rs).clone();
            apply_imul_smt(&mut state, *rd, &lhs, &rhs);
        }
        // IMUL (3-op): `rd = rs * imm`. rd is purely written.
        X86Instruction::ImulRegImm { rd, rs, imm } => {
            let lhs = state.get_register(*rs).clone();
            let rhs = state.imm_bv(*imm);
            apply_imul_smt(&mut state, *rd, &lhs, &rhs);
        }
        // LEA computes `rd = base + disp` (wrapping at width) and leaves EFLAGS
        // UNCHANGED — pure address arithmetic, exactly like MOV/NOT, which write
        // only their register and carry the incoming flag BVs forward untouched.
        // `disp` lowers as an immediate at the operand width.
        X86Instruction::Lea { rd, base, disp } => {
            let base = state.get_register(*base).clone();
            let disp = state.imm_bv(*disp);
            let result = base.bvadd(&disp);
            state.set_register(*rd, result);
        }
        X86Instruction::Cmov { rd, rs, cond } => {
            let pred = x86_condition_to_smt(*cond, state.get_flags());
            let rs_val = state.get_register(*rs).clone();
            let rd_old = state.get_register(*rd).clone();
            state.set_register(*rd, pred.ite(&rs_val, &rd_old));
        }
        X86Instruction::Setcc { rd, cond } => {
            let pred = x86_condition_to_smt(*cond, state.get_flags());
            let one = BV::from_u64(1, state.width());
            let zero = BV::from_u64(0, state.width());
            state.set_register(*rd, pred.ite(&one, &zero));
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

/// Bool predicate asserting that two symbolic x86 states diverge on the given
/// live-out contract: any live-out register whose value differs, or — when
/// `live_out.flags_live()` is set — any of the five tracked EFLAGS bits
/// differing, refutes equivalence.
///
/// This is the x86 twin of `smt::states_not_equal_for_live_out`. It keeps the
/// "how do two states differ on a contract" decision behind the `smt_x86`
/// interface so the equivalence backend does not have to poke `MachineStateX86`
/// register-by-register. Unlike the AArch64 twin there is no `memory_live`
/// disjunct — the x86 IR carries no memory model (see ADR-0007).
pub fn states_not_equal_for_live_out_x86(
    state1: &MachineStateX86,
    state2: &MachineStateX86,
    live_out: &crate::semantics::live_out::RegisterSet<X86Register>,
) -> z3::ast::Bool {
    let mut disjuncts: Vec<z3::ast::Bool> = Vec::new();
    for reg in live_out.iter() {
        let v1 = state1.get_register(*reg);
        let v2 = state2.get_register(*reg);
        disjuncts.push(v1.eq(v2).not());
    }
    if live_out.flags_live() {
        disjuncts.push(flags_not_equal_x86(state1, state2));
    }
    if disjuncts.is_empty() {
        z3::ast::Bool::from_bool(false)
    } else {
        z3::ast::Bool::or(&disjuncts.iter().collect::<Vec<_>>())
    }
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
    fn movsx_symbolically_sign_extends_the_extracted_source_word() {
        let before = MachineStateX86::new_symbolic("movsx", 64);
        let source = before.get_register(X86Register::RBX).clone();
        let expected = source.extract(15, 0).sign_ext(48);
        let after = apply_instruction(
            before,
            &X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                src_width: 16,
            },
        );

        let solver = Solver::new();
        solver.assert(after.get_register(X86Register::RAX).eq(&expected).not());
        assert_eq!(solver.check(), SatResult::Unsat);
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

    // --- symbolic LEA (DoD theorem) ---

    // The KEY LEA theorem (issue #627 DoD): `lea rd, [rs + imm]` agrees with
    // `mov rd, rs; add rd, imm` on the RESULT (rd == rs + imm). They differ on
    // FLAGS — LEA writes none while the mov+add sets them from the addition —
    // so we prove RESULT-equivalence here and flag-preservation separately
    // below. Both sides run over states with the same symbolic prefix, so the
    // incoming rs (rbx) and the incoming flags are shared.
    #[test]
    fn lea_result_equals_mov_then_add_immediate() {
        for imm in [
            0i64,
            1,
            -8,
            0x1000,
            -0x1000,
            i32::MAX as i64,
            i32::MIN as i64,
        ] {
            let prefix = "shared";
            let s_lea = MachineStateX86::new_symbolic(prefix, 64);
            let s_movadd = MachineStateX86::new_symbolic(prefix, 64);

            let after_lea = apply_instruction(
                s_lea,
                &X86Instruction::Lea {
                    rd: X86Register::RAX,
                    base: X86Register::RBX,
                    disp: imm,
                },
            );
            let after_movadd = apply_sequence(
                s_movadd,
                &[
                    X86Instruction::MovReg {
                        rd: X86Register::RAX,
                        rs: X86Register::RBX,
                    },
                    X86Instruction::AddImm {
                        rd: X86Register::RAX,
                        imm,
                    },
                ],
            );

            let solver = Solver::new();
            solver.assert(
                after_lea
                    .get_register(X86Register::RAX)
                    .eq(after_movadd.get_register(X86Register::RAX))
                    .not(),
            );
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "lea rd,[rs+{imm}] must equal mov rd,rs; add rd,{imm} on the result"
            );
        }
    }

    #[test]
    fn lea_leaves_all_flags_unchanged() {
        // LEA is pure address arithmetic: every tracked flag BV after LEA must
        // be identical to the incoming one (unlike the mov+add it rewrites,
        // whose ADD sets CF/OF/SF/ZF/PF). This is why the equivalence above is
        // result-only.
        let s0 = MachineStateX86::new_symbolic("s", 64);
        let cf0 = s0.get_flags().cf.clone();
        let pf0 = s0.get_flags().pf.clone();
        let zf0 = s0.get_flags().zf.clone();
        let sf0 = s0.get_flags().sf.clone();
        let of0 = s0.get_flags().of.clone();
        let s1 = apply_instruction(
            s0,
            &X86Instruction::Lea {
                rd: X86Register::RAX,
                base: X86Register::RBX,
                disp: 0x10,
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
            "LEA must leave every EFLAGS bit unchanged"
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

    // --- symbolic ROL / ROR ---

    // The DoD ROL theorem: `rol rd, 1` produces the same RESULT as the
    // shift-construction `(rd << 1) | (rd >>u (width-1))`. We prove the negation
    // of the result equality is unsat over a shared symbolic input.
    #[test]
    fn rol_one_result_matches_shift_construction() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let old = state.get_register(X86Register::RAX).clone();
        // (rd << 1) | (rd >>u 63).
        let constructed = old
            .bvshl(BV::from_u64(1, 64))
            .bvor(old.bvlshr(BV::from_u64(63, 64)));
        let after = apply_instruction(
            state,
            &X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_register(X86Register::RAX).eq(&constructed).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "rol rax, 1 must equal (rax << 1) | (rax >>u 63)"
        );
    }

    // The DoD ROR theorem: `ror rd, 1` equals `(rd >>u 1) | (rd << (width-1))`.
    #[test]
    fn ror_one_result_matches_shift_construction() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let old = state.get_register(X86Register::RAX).clone();
        // (rd >>u 1) | (rd << 63).
        let constructed = old
            .bvlshr(BV::from_u64(1, 64))
            .bvor(old.bvshl(BV::from_u64(63, 64)));
        let after = apply_instruction(
            state,
            &X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 1,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_register(X86Register::RAX).eq(&constructed).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "ror rax, 1 must equal (rax >>u 1) | (rax << 63)"
        );
    }

    // The load-bearing rotate flag model: SF/ZF/PF are PRESERVED across a rotate
    // (only CF, plus OF for count 1, changes). We seed the incoming SF/ZF/PF,
    // rotate, and prove they survive bit-identically (negation unsat). We also
    // prove CF equals the rotated-out bit for both ROL (result bit 0) and ROR
    // (result MSB).
    #[test]
    fn rotate_preserves_sf_zf_pf_and_binds_cf() {
        // ROL by 3: SF/ZF/PF unchanged; CF == result bit 0.
        {
            let state = MachineStateX86::new_symbolic("s", 64);
            let old_flags = state.get_flags();
            let (old_sf, old_zf, old_pf) = (
                old_flags.sf.clone(),
                old_flags.zf.clone(),
                old_flags.pf.clone(),
            );
            let after = apply_instruction(
                state,
                &X86Instruction::Rol {
                    rd: X86Register::RAX,
                    imm: 3,
                },
            );
            let f = after.get_flags();
            let solver = Solver::new();
            solver.assert(z3::ast::Bool::or(&[
                &f.sf.eq(&old_sf).not(),
                &f.zf.eq(&old_zf).not(),
                &f.pf.eq(&old_pf).not(),
            ]));
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "ROL must preserve SF/ZF/PF"
            );

            // CF == bit 0 of the rotated result.
            let cf_solver = Solver::new();
            let result_bit0 = after.get_register(X86Register::RAX).extract(0, 0);
            cf_solver.assert(f.cf.eq(&result_bit0).not());
            assert_eq!(
                cf_solver.check(),
                SatResult::Unsat,
                "ROL CF must equal the result's bit 0"
            );
        }
        // ROR by 3: SF/ZF/PF unchanged; CF == result MSB.
        {
            let state = MachineStateX86::new_symbolic("s", 64);
            let old_flags = state.get_flags();
            let (old_sf, old_zf, old_pf) = (
                old_flags.sf.clone(),
                old_flags.zf.clone(),
                old_flags.pf.clone(),
            );
            let after = apply_instruction(
                state,
                &X86Instruction::Ror {
                    rd: X86Register::RAX,
                    imm: 3,
                },
            );
            let f = after.get_flags();
            let solver = Solver::new();
            solver.assert(z3::ast::Bool::or(&[
                &f.sf.eq(&old_sf).not(),
                &f.zf.eq(&old_zf).not(),
                &f.pf.eq(&old_pf).not(),
            ]));
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "ROR must preserve SF/ZF/PF"
            );

            // CF == the rotated result's MSB (bit 63).
            let cf_solver = Solver::new();
            let result_msb = after.get_register(X86Register::RAX).extract(63, 63);
            cf_solver.assert(f.cf.eq(&result_msb).not());
            assert_eq!(
                cf_solver.check(),
                SatResult::Unsat,
                "ROR CF must equal the result's MSB"
            );
        }
    }

    // The eff == 0 rotate case: a masked count of 0 leaves the register AND all
    // five tracked flags bit-identical to the incoming state.
    #[test]
    fn rotate_by_zero_preserves_register_and_all_flags_smt() {
        for instr in [
            X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::Ror {
                rd: X86Register::RAX,
                imm: 0,
            },
            // 64 masks to 0 at width 64.
            X86Instruction::Ror {
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

    // OF is preserved for a rotate count != 1 (architecturally undefined). After
    // `rol rd, 3` the OF must equal the incoming OF.
    #[test]
    fn rotate_count_not_one_preserves_of() {
        let before = MachineStateX86::new_symbolic("s", 64);
        let old_of = before.get_flags().of.clone();
        let after = apply_instruction(
            before,
            &X86Instruction::Rol {
                rd: X86Register::RAX,
                imm: 3,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_flags().of.eq(&old_of).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "rotate count != 1 must leave OF == the incoming OF"
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
        let zero_flag = BV::from_u64(0, 1);
        let symbolic_pre_flags = symbolic_pre.get_flags();
        for flag in [
            symbolic_pre_flags.cf,
            symbolic_pre_flags.pf,
            symbolic_pre_flags.zf,
            symbolic_pre_flags.sf,
            symbolic_pre_flags.of,
        ] {
            solver.assert(flag.eq(&zero_flag));
        }
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
    fn parity_extension_moves() {
        for src_width in [8, 16] {
            for instruction in [
                X86Instruction::Movzx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width,
                },
                X86Instruction::Movsx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width,
                },
            ] {
                for &(a, b) in PARITY_SAMPLES {
                    assert_x86_concrete_smt_parity(&instruction, a, b);
                }
            }
        }
    }

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

    // --- symbolic IMUL ---

    // The DoD IMUL theorem: `imul rd, rs, 4` produces the same RESULT as the
    // power-of-two shift `rs << 2`. We prove the negation of the truncated
    // result equality is unsat over a shared symbolic input.
    #[test]
    fn imul_reg_imm_by_four_matches_shift_left_two() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let rbx = state.get_register(X86Register::RBX).clone();
        // rs << 2 at width 64.
        let shifted = rbx.bvshl(BV::from_u64(2, 64));
        let after = apply_instruction(
            state,
            &X86Instruction::ImulRegImm {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                imm: 4,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_register(X86Register::RAX).eq(&shifted).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "imul rd, rbx, 4 must equal rbx << 2 on the truncated result"
        );
    }

    // IMUL result is a plain bvmul of the (sign-irrelevant for the low bits)
    // operands: `imul rax, rbx` writes `rax * rbx` truncated.
    #[test]
    fn imul_reg_result_equals_bvmul() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let rax = state.get_register(X86Register::RAX).clone();
        let rbx = state.get_register(X86Register::RBX).clone();
        let product = rax.bvmul(&rbx);
        let after = apply_instruction(
            state,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let solver = Solver::new();
        solver.assert(after.get_register(X86Register::RAX).eq(&product).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "imul rax, rbx must write rax * rbx (truncated)"
        );
    }

    // CF/OF overflow correctness: CF = OF, and CF = 1 iff the FULL signed
    // product does not fit the truncated destination. We prove CF == OF always,
    // and that CF == (signext64(rax)*signext64(rbx) != signext64(low64 product))
    // — i.e. the wide-multiply overflow predicate — over a shared symbolic input.
    #[test]
    fn imul_reg_cf_of_track_signed_overflow() {
        let state = MachineStateX86::new_symbolic("s", 64);
        let rax = state.get_register(X86Register::RAX).clone();
        let rbx = state.get_register(X86Register::RBX).clone();
        let after = apply_instruction(
            state,
            &X86Instruction::ImulReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        );
        let cf = after.get_flags().cf.clone();
        let of = after.get_flags().of.clone();

        // Reference overflow predicate built independently of the lowering.
        let wide = rax.sign_ext(64).bvmul(rbx.sign_ext(64));
        let low = rax.bvmul(&rbx);
        let fits = wide.eq(low.sign_ext(64));
        let cf_one = BV::from_u64(1, 1);

        // (1) CF == OF always.
        {
            let solver = Solver::new();
            solver.assert(cf.eq(&of).not());
            assert_eq!(solver.check(), SatResult::Unsat, "IMUL CF must equal OF");
        }
        // (2) CF == 1 iff NOT fits (signed overflow).
        {
            let solver = Solver::new();
            let overflow = fits.not();
            let iff = cf.eq(&cf_one).iff(&overflow);
            solver.assert(iff.not());
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "IMUL CF must be set iff the full signed product overflows the destination"
            );
        }
    }

    // Concrete/SMT parity for the 2-operand IMUL (rd = rax, rs = rbx) over the
    // shared sample grid, covering result + all five tracked flags. This pins
    // that the SMT lowering agrees with the concrete interpreter (including the
    // deterministically-modelled SF/ZF/PF) for non-overflowing and overflowing
    // inputs alike.
    #[test]
    fn parity_imul_reg() {
        let instr = X86Instruction::ImulReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        };
        for &(a, b) in PARITY_SAMPLES {
            assert_x86_concrete_smt_parity(&instr, a, b);
        }
    }

    // Concrete/SMT parity for the 3-operand IMUL. The generic harness assumes
    // `rd = rax`, `rs = rbx`, so `imul rax, rbx, imm` fits it directly: rax is
    // purely written from rbx*imm.
    #[test]
    fn parity_imul_reg_imm() {
        for imm in [
            0i64,
            1,
            2,
            4,
            -1,
            -4,
            1000,
            i32::MAX as i64,
            i32::MIN as i64,
        ] {
            let instr = X86Instruction::ImulRegImm {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
                imm,
            };
            for &(a, b) in PARITY_SAMPLES {
                // `a` (the rax pre-value) is irrelevant to the 3-operand form;
                // the harness still seeds it, which is harmless since rd is
                // purely written.
                assert_x86_concrete_smt_parity(&instr, a, b);
            }
        }
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

    #[test]
    fn extension_moves_do_not_modify_flags() {
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
        let s1 = apply_sequence(
            s0,
            &[
                X86Instruction::Movzx {
                    rd: X86Register::RAX,
                    rs: X86Register::RBX,
                    src_width: 8,
                },
                X86Instruction::Movsx {
                    rd: X86Register::RCX,
                    rs: X86Register::RDX,
                    src_width: 16,
                },
            ],
        );
        let flags1 = s1.get_flags();
        let diff = z3::ast::Bool::or(&[
            &flags1.cf.eq(&flags0.cf).not(),
            &flags1.pf.eq(&flags0.pf).not(),
            &flags1.zf.eq(&flags0.zf).not(),
            &flags1.sf.eq(&flags0.sf).not(),
            &flags1.of.eq(&flags0.of).not(),
        ]);
        let solver = Solver::new();
        solver.assert(&diff);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "MOVZX/MOVSX must not write any flag"
        );
    }

    // --- states_not_equal_for_live_out_x86: the live-out state comparator ---
    //
    // These pin the x86 twin of `smt::states_not_equal_for_live_out`: it must
    // fold exactly the live-out register slice, and the five EFLAGS bits only
    // when the contract declares flags live. x86 has no memory model, so there
    // is no memory disjunct to exercise.

    fn mov_imm(rd: X86Register, imm: i64) -> X86Instruction {
        X86Instruction::MovImm { rd, imm }
    }

    #[test]
    fn states_not_equal_x86_detects_live_out_register_divergence() {
        // Two sequences leaving RAX at different constants must be refutable on
        // a contract that includes RAX.
        let s1 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 5)],
        );
        let s2 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 7)],
        );
        let live_out =
            crate::semantics::live_out::RegisterSet::from_registers(vec![X86Register::RAX]);
        let solver = Solver::new();
        let diff = states_not_equal_for_live_out_x86(&s1, &s2, &live_out);
        solver.assert(&diff);
        assert_eq!(
            solver.check(),
            SatResult::Sat,
            "diverging live-out register must be satisfiably not-equal"
        );
    }

    #[test]
    fn states_not_equal_x86_agrees_when_live_out_register_matches() {
        let s1 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 5)],
        );
        let s2 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 5)],
        );
        let live_out =
            crate::semantics::live_out::RegisterSet::from_registers(vec![X86Register::RAX]);
        let solver = Solver::new();
        let diff = states_not_equal_for_live_out_x86(&s1, &s2, &live_out);
        solver.assert(&diff);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "agreeing live-out register must be provably equal"
        );
    }

    #[test]
    fn states_not_equal_x86_ignores_registers_outside_the_contract() {
        // RBX differs between the two states but is NOT in the contract; RAX
        // agrees. Only the live-out slice may be compared.
        let s1 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 5), mov_imm(X86Register::RBX, 1)],
        );
        let s2 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[mov_imm(X86Register::RAX, 5), mov_imm(X86Register::RBX, 2)],
        );
        let live_out =
            crate::semantics::live_out::RegisterSet::from_registers(vec![X86Register::RAX]);
        let solver = Solver::new();
        let diff = states_not_equal_for_live_out_x86(&s1, &s2, &live_out);
        solver.assert(&diff);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "a register outside the live-out contract must not refute equivalence"
        );
    }

    #[test]
    fn states_not_equal_x86_gates_flags_on_flags_live() {
        // seq1 writes EFLAGS (add), seq2 leaves them at symbolic init.
        let s1 = apply_sequence(
            MachineStateX86::new_symbolic("init", 64),
            &[X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            }],
        );
        let s2 = apply_sequence(MachineStateX86::new_symbolic("init", 64), &[]);

        // Flags dead, no live-out registers: nothing can refute equivalence.
        let flags_dead = crate::semantics::live_out::RegisterSet::<X86Register>::empty();
        let solver = Solver::new();
        let diff_dead = states_not_equal_for_live_out_x86(&s1, &s2, &flags_dead);
        solver.assert(&diff_dead);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "an empty flags-dead contract has nothing to refute"
        );

        // Flags live: the divergent flag effects must be exposed.
        let flags_live =
            crate::semantics::live_out::RegisterSet::<X86Register>::empty().with_flags(true);
        let solver2 = Solver::new();
        let diff_live = states_not_equal_for_live_out_x86(&s1, &s2, &flags_live);
        solver2.assert(&diff_live);
        assert_eq!(
            solver2.check(),
            SatResult::Sat,
            "flags-live contract must fold in the diverging EFLAGS"
        );
    }
}

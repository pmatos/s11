//! SMT constraint generation for AArch64 instructions

#![allow(dead_code)]

use crate::ir::{Instruction, Operand, Register};
use crate::semantics::live_out::LiveOutRegisters;
use std::collections::HashMap;
use std::time::Duration;
use z3::ast::BV;
use z3::{Params, Solver};

/// Reverse the byte order of a 64-bit BV by concatenating its 8 byte slices
/// with byte 0 placed in the most-significant position.
fn bv_swap_bytes_64(value: &BV) -> BV {
    // Place byte 0 (originally at bits [7:0]) at the new top, byte 7
    // (originally at bits [63:56]) at the new bottom.
    let mut result = value.extract(7, 0);
    for i in 1..8u32 {
        let lo = i * 8;
        let hi = lo + 7;
        result = result.concat(&value.extract(hi, lo));
    }
    result
}

/// 64-bit ROR composed as `(value lshr n) | (value shl (64 - n))`.
/// Caller is responsible for masking `n` to 6 bits when needed (immediate
/// callers with `n` already in 0..=63 may skip the mask).
///
/// Edge case at n == 0: `complement` evaluates to 64, and SMTLIB2 bit-vector
/// semantics define `bvshl(x, 64) = 0` (any shift ≥ the bit-width zeroes the
/// value). So `hi = 0` and the result is just `value lshr 0 = value`.
fn bv_ror_64(value: &BV, n: &BV) -> BV {
    let mask = BV::from_u64(63, 64);
    let n_masked = n.bvand(&mask);
    let sixty_four = BV::from_u64(64, 64);
    let complement = sixty_four.bvsub(&n_masked);
    let lo = value.bvlshr(&n_masked);
    let hi = value.bvshl(&complement);
    lo.bvor(&hi)
}

/// Reverse the bit order of a 64-bit BV via 64 single-bit extracts.
fn bv_reverse_bits_64(value: &BV) -> BV {
    // Bit 0 of `value` becomes the new MSB; bit 63 becomes the new LSB.
    let mut result = value.extract(0, 0);
    for i in 1..64u32 {
        result = result.concat(&value.extract(i, i));
    }
    result
}

/// Count leading zeros of a 64-bit BV using a nested ITE chain.
/// Iterates bit positions from LSB upward; later iterations overwrite the
/// result when their bit is set, so the final result is the CLZ of the
/// input — the number of leading zeros — derived from the highest-set-bit
/// position found (or 64 if no bit is set).
//
// TODO(#112): replace this 64-deep ITE chain with an O(log n) binary-search
// decomposition (top-32 / top-16 / … / top-1) to reduce Z3 formula depth.
fn bv_clz_64(value: &BV) -> BV {
    let mut result = BV::from_u64(64, 64);
    let one_bit = BV::from_u64(1, 1);
    for pos in 0..64u32 {
        let bit = value.extract(pos, pos);
        let is_set = bit.eq(&one_bit);
        let clz_if_top = BV::from_u64(63 - pos as u64, 64);
        result = is_set.ite(&clz_if_top, &result);
    }
    result
}

/// Configuration for the SMT solver
#[derive(Debug, Clone)]
pub struct SolverConfig {
    /// Timeout for SMT solving (None means no timeout)
    pub timeout: Option<Duration>,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

impl SolverConfig {
    /// Create a config with no timeout
    pub fn no_timeout() -> Self {
        Self { timeout: None }
    }

    /// Create a config with a specific timeout in seconds
    pub fn with_timeout_secs(secs: u64) -> Self {
        Self {
            timeout: Some(Duration::from_secs(secs)),
        }
    }

    /// Create a config with a specific timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
        }
    }
}

/// Create a Z3 solver with the given configuration
pub fn create_solver_with_config(cfg: &SolverConfig) -> Solver {
    let solver = Solver::new();
    if let Some(timeout) = cfg.timeout {
        let mut params = Params::new();
        params.set_u32("timeout", timeout.as_millis() as u32);
        solver.set_params(&params);
    }
    solver
}

/// Machine state representation for SMT solving
#[derive(Clone)]
pub struct MachineState {
    /// Register values as 64-bit bitvectors
    pub registers: HashMap<Register, BV>,
    /// NZCV condition flags as 1-bit bitvectors
    pub n: BV,
    pub z: BV,
    pub c: BV,
    pub v: BV,
}

impl MachineState {
    /// Create a new symbolic machine state
    pub fn new_symbolic(prefix: &str) -> Self {
        let mut registers = HashMap::new();

        // Create symbolic variables for all registers
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                let name = format!("{}_x{}", prefix, i);
                registers.insert(reg, BV::new_const(name, 64));
            }
        }

        // XZR is always zero
        registers.insert(Register::XZR, BV::from_i64(0, 64));

        // SP is also symbolic
        registers.insert(Register::SP, BV::new_const(format!("{}_sp", prefix), 64));

        let n = BV::new_const(format!("{}_n", prefix), 1);
        let z = BV::new_const(format!("{}_z", prefix), 1);
        let c = BV::new_const(format!("{}_c", prefix), 1);
        let v = BV::new_const(format!("{}_v", prefix), 1);

        MachineState {
            registers,
            n,
            z,
            c,
            v,
        }
    }

    /// Get the value of a register
    pub fn get_register(&self, reg: Register) -> &BV {
        self.registers.get(&reg).expect("Register not found")
    }

    /// Set the value of a register
    pub fn set_register(&mut self, reg: Register, value: BV) {
        // XZR writes are ignored (always zero)
        if reg != Register::XZR {
            self.registers.insert(reg, value);
        }
    }

    /// Read the four NZCV flag bitvectors.
    pub fn get_flags(&self) -> (&BV, &BV, &BV, &BV) {
        (&self.n, &self.z, &self.c, &self.v)
    }

    /// Replace all four NZCV flag bitvectors at once.
    pub fn set_flags(&mut self, n: BV, z: BV, c: BV, v: BV) {
        self.n = n;
        self.z = z;
        self.c = c;
        self.v = v;
    }

    /// Evaluate an operand to get its value
    pub fn eval_operand(&self, operand: &Operand) -> BV {
        match operand {
            Operand::Register(reg) => self.get_register(*reg).clone(),
            Operand::Immediate(imm) => BV::from_i64(*imm, 64),
            Operand::ShiftedRegister { reg, kind, amount } => {
                let value = self.get_register(*reg).clone();
                let amt = BV::from_u64(*amount as u64, 64);
                match kind {
                    crate::ir::ShiftKind::Lsl => value.bvshl(&amt),
                    crate::ir::ShiftKind::Lsr => value.bvlshr(&amt),
                    crate::ir::ShiftKind::Asr => value.bvashr(&amt),
                    crate::ir::ShiftKind::Ror => bv_ror_64(&value, &amt),
                }
            }
        }
    }
}

/// Symbolic NZCV flag tuple `(N, Z, C, V)` produced by flag-computing helpers.
type Nzcv = (BV, BV, BV, BV);

fn bv_one() -> BV {
    BV::from_u64(1, 1)
}

fn bv_zero() -> BV {
    BV::from_u64(0, 1)
}

/// Compute symbolic NZCV for the subtraction `lhs - rhs`. Mirrors
/// `ConditionFlags::from_sub` in `state.rs` bit-for-bit.
pub fn compute_flags_sub(lhs: &BV, rhs: &BV) -> Nzcv {
    let result = lhs.bvsub(rhs);
    let zero64 = BV::from_u64(0, 64);
    let n = result.extract(63, 63);
    let z = result.eq(&zero64).ite(&bv_one(), &bv_zero());
    let c = lhs.bvuge(rhs).ite(&bv_one(), &bv_zero());
    // Signed overflow on subtraction: (lhs and rhs differ in sign) AND
    // (lhs and result differ in sign).
    let lhs_sign = lhs.extract(63, 63);
    let rhs_sign = rhs.extract(63, 63);
    let res_sign = result.extract(63, 63);
    let v = lhs_sign.bvxor(&rhs_sign).bvand(&lhs_sign.bvxor(&res_sign));
    (n, z, c, v)
}

/// Compute symbolic NZCV for the addition `lhs + rhs`. Mirrors
/// `ConditionFlags::from_add` in `state.rs`.
pub fn compute_flags_add(lhs: &BV, rhs: &BV) -> Nzcv {
    let result = lhs.bvadd(rhs);
    let zero64 = BV::from_u64(0, 64);
    let n = result.extract(63, 63);
    let z = result.eq(&zero64).ite(&bv_one(), &bv_zero());
    // Carry on add: result < lhs (unsigned).
    let c = result.bvult(lhs).ite(&bv_one(), &bv_zero());
    // Signed overflow on add: (lhs and rhs share sign) AND (lhs and result
    // differ in sign).
    let lhs_sign = lhs.extract(63, 63);
    let rhs_sign = rhs.extract(63, 63);
    let res_sign = result.extract(63, 63);
    let one_bit = bv_one();
    let signs_match = lhs_sign.bvxor(&rhs_sign).bvxor(&one_bit); // 1 when signs match
    let signs_flip = lhs_sign.bvxor(&res_sign); // 1 when lhs and result differ
    let v = signs_match.bvand(&signs_flip);
    (n, z, c, v)
}

/// Convert a 4-bit NZCV literal to four 1-bit BV constants.
/// Layout per ARM ARM: bit3 = N, bit2 = Z, bit1 = C, bit0 = V.
pub fn nzcv_to_bvs(byte: u8) -> Nzcv {
    (
        BV::from_u64(((byte >> 3) & 1) as u64, 1),
        BV::from_u64(((byte >> 2) & 1) as u64, 1),
        BV::from_u64(((byte >> 1) & 1) as u64, 1),
        BV::from_u64((byte & 1) as u64, 1),
    )
}

/// Compute symbolic NZCV for a logical (AND/ORR/EOR/TST) result. C and V are
/// always cleared per the AArch64 ARM.
pub fn compute_flags_logical(result: &BV) -> Nzcv {
    let zero64 = BV::from_u64(0, 64);
    let n = result.extract(63, 63);
    let z = result.eq(&zero64).ite(&bv_one(), &bv_zero());
    (n, z, bv_zero(), bv_zero())
}

/// Translate a `Condition` code into a 1-bit symbolic predicate over the
/// supplied NZCV flag BVs. Mirrors `ConditionFlags::evaluate` in `state.rs`
/// and `evaluate_condition` in `concrete.rs` for all 16 condition codes.
pub fn condition_to_smt(cond: crate::ir::types::Condition, n: &BV, z: &BV, c: &BV, v: &BV) -> BV {
    use crate::ir::types::Condition;
    let one = bv_one();
    let zero = bv_zero();
    let not_n = n.bvxor(&one);
    let not_z = z.bvxor(&one);
    let not_c = c.bvxor(&one);
    let not_v = v.bvxor(&one);
    let n_eq_v = n.bvxor(v).bvxor(&one); // 1 iff N == V

    match cond {
        Condition::EQ => z.clone(),
        Condition::NE => not_z,
        Condition::CS => c.clone(),
        Condition::CC => not_c,
        Condition::MI => n.clone(),
        Condition::PL => not_n,
        Condition::VS => v.clone(),
        Condition::VC => not_v,
        Condition::HI => c.bvand(&not_z),
        Condition::LS => not_c.bvor(z),
        Condition::GE => n_eq_v.clone(),
        Condition::LT => n_eq_v.bvxor(&one), // N != V
        Condition::GT => not_z.bvand(&n_eq_v),
        Condition::LE => z.bvor(&n_eq_v.bvxor(&one)),
        Condition::AL => one,
        // NV is reserved in AArch64 and treated as "never" by
        // `ConditionFlags::evaluate`; mirror that here.
        Condition::NV => zero,
    }
}

/// Apply an instruction to a machine state, returning the new state
pub fn apply_instruction(mut state: MachineState, instruction: &Instruction) -> MachineState {
    match instruction {
        Instruction::MovReg { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, value);
        }
        Instruction::MovImm { rd, imm } => {
            let value = BV::from_i64(*imm, 64);
            state.set_register(*rd, value);
        }
        Instruction::Add { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvadd(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Sub { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvsub(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::And { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Orr { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvor(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Eor { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvxor(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Lsl { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // LSL is logical shift left
            let result = value.bvshl(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Lsr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // LSR is logical shift right
            let result = value.bvlshr(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Asr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let shift_amount = state.eval_operand(shift);
            // ASR is arithmetic shift right
            let result = value.bvashr(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Mul { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let result = lhs.bvmul(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::Sdiv { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let zero = BV::from_i64(0, 64);
            let is_zero = rhs.eq(&zero);
            // AArch64: division by zero returns 0
            // For overflow case (MIN / -1), we handle it with bvsdiv which wraps correctly
            let div_result = lhs.bvsdiv(&rhs);
            let result = is_zero.ite(&zero, &div_result);
            state.set_register(*rd, result);
        }
        Instruction::Udiv { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let zero = BV::from_u64(0, 64);
            let is_zero = rhs.eq(&zero);
            // AArch64: division by zero returns 0
            let div_result = lhs.bvudiv(&rhs);
            let result = is_zero.ite(&zero, &div_result);
            state.set_register(*rd, result);
        }
        Instruction::Madd { rd, rn, rm, ra } => {
            let a = state.get_register(*rn).clone();
            let b = state.get_register(*rm).clone();
            let c = state.get_register(*ra).clone();
            state.set_register(*rd, c.bvadd(&a.bvmul(&b)));
        }
        Instruction::Msub { rd, rn, rm, ra } => {
            let a = state.get_register(*rn).clone();
            let b = state.get_register(*rm).clone();
            let c = state.get_register(*ra).clone();
            state.set_register(*rd, c.bvsub(&a.bvmul(&b)));
        }
        Instruction::Mneg { rd, rn, rm } => {
            let a = state.get_register(*rn).clone();
            let b = state.get_register(*rm).clone();
            state.set_register(*rd, a.bvmul(&b).bvneg());
        }
        Instruction::Smulh { rd, rn, rm } => {
            // 64-bit sign-extend to 128, multiply, extract upper 64 bits.
            let a = state.get_register(*rn).sign_ext(64);
            let b = state.get_register(*rm).sign_ext(64);
            let prod = a.bvmul(&b);
            state.set_register(*rd, prod.extract(127, 64));
        }
        Instruction::Umulh { rd, rn, rm } => {
            // 64-bit zero-extend to 128, multiply, extract upper 64 bits.
            let a = state.get_register(*rn).zero_ext(64);
            let b = state.get_register(*rm).zero_ext(64);
            let prod = a.bvmul(&b);
            state.set_register(*rd, prod.extract(127, 64));
        }
        // Comparison instructions set flags and don't modify registers.
        Instruction::Cmp { rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_sub(&lhs, &rhs);
            state.set_flags(n, z, c, v);
        }
        Instruction::Cmn { rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_add(&lhs, &rhs);
            state.set_flags(n, z, c, v);
        }
        Instruction::Tst { rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(&rhs);
            let (n, z, c, v) = compute_flags_logical(&result);
            state.set_flags(n, z, c, v);
        }
        // CCMP / CCMN: ITE between freshly-computed sub/add NZCV (true branch)
        // and the unpacked 4-bit immediate (false branch), gated on the
        // current symbolic NZCV-derived predicate.
        Instruction::Ccmp { rn, rm, nzcv, cond } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n_t, z_t, c_t, v_t) = compute_flags_sub(&lhs, &rhs);
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            let (n_f, z_f, c_f, v_f) = nzcv_to_bvs(*nzcv);
            state.set_flags(
                pred.ite(&n_t, &n_f),
                pred.ite(&z_t, &z_f),
                pred.ite(&c_t, &c_f),
                pred.ite(&v_t, &v_f),
            );
        }
        Instruction::Ccmn { rn, rm, nzcv, cond } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n_t, z_t, c_t, v_t) = compute_flags_add(&lhs, &rhs);
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            let (n_f, z_f, c_f, v_f) = nzcv_to_bvs(*nzcv);
            state.set_flags(
                pred.ite(&n_t, &n_f),
                pred.ite(&z_t, &z_f),
                pred.ite(&c_t, &c_f),
                pred.ite(&v_t, &v_f),
            );
        }
        // CSEL family: rd = cond ? rn : f(rm), encoded as an SMT ITE over the
        // 1-bit predicate produced by condition_to_smt.
        Instruction::Csel { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_v = state.get_register(*rm).clone();
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_v));
        }
        Instruction::Csinc { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_plus_one = state.get_register(*rm).bvadd(&BV::from_u64(1, 64));
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_plus_one));
        }
        Instruction::Csinv { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_not = state.get_register(*rm).bvnot();
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_not));
        }
        Instruction::Csneg { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_neg = state.get_register(*rm).bvneg();
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_neg));
        }
        Instruction::Mvn { rd, rm } => {
            let value = state.get_register(*rm).bvnot();
            state.set_register(*rd, value);
        }
        Instruction::Neg { rd, rm } => {
            let value = state.get_register(*rm).bvneg();
            state.set_register(*rd, value);
        }
        // NEGS = SUBS rd, XZR, rm — write rd and the resulting NZCV.
        Instruction::Negs { rd, rm } => {
            let rhs = state.get_register(*rm).clone();
            let zero = BV::from_u64(0, 64);
            let value = zero.bvsub(&rhs);
            let (n, z, c, v) = compute_flags_sub(&zero, &rhs);
            state.set_register(*rd, value);
            state.set_flags(n, z, c, v);
        }
        Instruction::MovN { rd, imm, shift } => {
            let value = !((*imm as u64) << (*shift as u32));
            state.set_register(*rd, BV::from_u64(value, 64));
        }
        Instruction::MovZ { rd, imm, shift } => {
            let value = (*imm as u64) << (*shift as u32);
            state.set_register(*rd, BV::from_u64(value, 64));
        }
        // MOVK keeps the 48 unwritten bits of rd. Encode as
        // `(rd_old & ~mask) | new_chunk` so the solver sees the data-flow
        // dependence on the prior rd value.
        Instruction::MovK { rd, imm, shift } => {
            let prev = state.get_register(*rd).clone();
            let mask = BV::from_u64(!(0xFFFF_u64 << (*shift as u32)), 64);
            let new_chunk = BV::from_u64((*imm as u64) << (*shift as u32), 64);
            let result = prev.bvand(&mask).bvor(&new_chunk);
            state.set_register(*rd, result);
        }
        // BIC: rd = rn & !rm (no flag side-effect).
        Instruction::Bic { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(rhs.bvnot());
            state.set_register(*rd, result);
        }
        // BICS: same data path as BIC plus logical-NZCV computation.
        Instruction::Bics { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(rhs.bvnot());
            let (n, z, c, v) = compute_flags_logical(&result);
            state.set_register(*rd, result);
            state.set_flags(n, z, c, v);
        }
        Instruction::Orn { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvor(rhs.bvnot());
            state.set_register(*rd, result);
        }
        Instruction::Eon { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvxor(rhs.bvnot());
            state.set_register(*rd, result);
        }
        // Flag-setting arithmetic/logical instructions: write rd AND set the
        // four NZCV flag BVs via the appropriate compute_flags helper.
        Instruction::Adds { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_add(&lhs, &rhs);
            state.set_register(*rd, lhs.bvadd(&rhs));
            state.set_flags(n, z, c, v);
        }
        Instruction::Subs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_sub(&lhs, &rhs);
            state.set_register(*rd, lhs.bvsub(&rhs));
            state.set_flags(n, z, c, v);
        }
        Instruction::Ands { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(&rhs);
            let (n, z, c, v) = compute_flags_logical(&result);
            state.set_register(*rd, result);
            state.set_flags(n, z, c, v);
        }
        // CSET / CSETM: rd = cond ? 1 : 0 (or all-ones for CSETM).
        Instruction::Cset { rd, cond } => {
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            let one64 = BV::from_u64(1, 64);
            let zero64 = BV::from_u64(0, 64);
            state.set_register(*rd, pred.ite(&one64, &zero64));
        }
        Instruction::Csetm { rd, cond } => {
            let pred =
                condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(&bv_one());
            let ones = BV::from_u64(u64::MAX, 64);
            let zero64 = BV::from_u64(0, 64);
            state.set_register(*rd, pred.ite(&ones, &zero64));
        }
        // ROR: composed via bv_ror_64 (see helper at top of file for the
        // edge-case discussion at n == 0).
        Instruction::Ror { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let n = state.eval_operand(shift);
            state.set_register(*rd, bv_ror_64(&value, &n));
        }
        // CLZ: count leading zero bits; returns 64 when the value is zero.
        Instruction::Clz { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_clz_64(&value));
        }
        // CLS: count leading sign-bit replicas (excluding the sign bit).
        // Fold the sign bit out via `x XOR (x ASR 63)` so the answer reduces
        // to `clz(folded) - 1`. Bit 63 of `folded` is always 0 (a positive
        // sign cancels its own top bit; a negative sign inverts it to 0),
        // so `bv_clz_64(folded) ∈ [1, 64]` and the subtraction lands in
        // `[0, 63]` — `bvsub` never wraps. For all-sign inputs (0 or -1)
        // folded is zero, clz is 64, and the result is 63.
        Instruction::Cls { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let asr = value.bvashr(&BV::from_u64(63, 64));
            let folded = value.bvxor(&asr);
            let clz = bv_clz_64(&folded);
            let result = clz.bvsub(&BV::from_u64(1, 64));
            state.set_register(*rd, result);
        }
        // RBIT: reverse the 64 bits.
        Instruction::Rbit { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_reverse_bits_64(&value));
        }
        // REV: byte-reverse the 64-bit value.
        Instruction::Rev { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_swap_bytes_64(&value));
        }
        // REV32: byte-reverse within each 32-bit half independently.
        Instruction::Rev32 { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let lo = value.extract(31, 0);
            let hi = value.extract(63, 32);
            // Each half byte-reversed: concat its 4 byte slices with the
            // original LSB byte at the new MSB position.
            let rev_half = |h: &BV| -> BV {
                let mut acc = h.extract(7, 0);
                for i in 1..4u32 {
                    let l = i * 8;
                    acc = acc.concat(&h.extract(l + 7, l));
                }
                acc
            };
            let result = rev_half(&hi).concat(&rev_half(&lo));
            state.set_register(*rd, result);
        }
        // REV16: byte-reverse within each 16-bit half (four halves).
        Instruction::Rev16 { rd, rn } => {
            let value = state.get_register(*rn).clone();
            // For each of the 4 half-words, swap its high and low byte.
            let swap_half = |start: u32| -> BV {
                value
                    .extract(start + 7, start)
                    .concat(&value.extract(start + 15, start + 8))
            };
            let h3 = swap_half(48);
            let h2 = swap_half(32);
            let h1 = swap_half(16);
            let h0 = swap_half(0);
            let result = h3.concat(&h2).concat(&h1).concat(&h0);
            state.set_register(*rd, result);
        }
    }
    state
}

/// Apply a sequence of instructions to a machine state
pub fn apply_sequence(mut state: MachineState, instructions: &[Instruction]) -> MachineState {
    for instruction in instructions {
        state = apply_instruction(state, instruction);
    }
    state
}

fn flags_not_equal(state1: &MachineState, state2: &MachineState) -> z3::ast::Bool {
    z3::ast::Bool::or(&[
        &state1.n.eq(&state2.n).not(),
        &state1.z.eq(&state2.z).not(),
        &state1.c.eq(&state2.c).not(),
        &state1.v.eq(&state2.v).not(),
    ])
}

/// Check if two machine states are not equal (full state: every register plus
/// the four NZCV flags). Used by the unmasked `check_equivalence` entry point.
pub fn states_not_equal(state1: &MachineState, state2: &MachineState) -> z3::ast::Bool {
    let mut not_equal = z3::ast::Bool::from_bool(false);

    // Check all general purpose registers
    for i in 0..=30 {
        if let Some(reg) = Register::from_index(i) {
            let val1 = state1.get_register(reg);
            let val2 = state2.get_register(reg);
            let reg_not_equal = val1.eq(val2).not();
            not_equal = z3::ast::Bool::or(&[&not_equal, &reg_not_equal]);
        }
    }

    // Also check SP
    let sp1 = state1.get_register(Register::SP);
    let sp2 = state2.get_register(Register::SP);
    let sp_not_equal = sp1.eq(sp2).not();
    not_equal = z3::ast::Bool::or(&[&not_equal, &sp_not_equal]);

    // And the NZCV flag bits.
    z3::ast::Bool::or(&[&not_equal, &flags_not_equal(state1, state2)])
}

/// Check if two machine states are not equal for the specified live-out
/// registers, optionally including the NZCV flag bits.
pub fn states_not_equal_for_live_out(
    state1: &MachineState,
    state2: &MachineState,
    live_out: &LiveOutRegisters,
    flags_live: bool,
) -> z3::ast::Bool {
    let mut not_equal = z3::ast::Bool::from_bool(false);

    for reg in live_out.iter() {
        let val1 = state1.get_register(*reg);
        let val2 = state2.get_register(*reg);
        let reg_not_equal = val1.eq(val2).not();
        not_equal = z3::ast::Bool::or(&[&not_equal, &reg_not_equal]);
    }

    if flags_live {
        not_equal = z3::ast::Bool::or(&[&not_equal, &flags_not_equal(state1, state2)]);
    }

    not_equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    #[test]
    fn test_mov_zero_equivalence() {
        let solver = Solver::new();

        // Create initial symbolic state
        let initial_state = MachineState::new_symbolic("pre");

        // Sequence 1: MOV X0, #0
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let state1 = apply_sequence(initial_state.clone(), &seq1);

        // Sequence 2: EOR X0, X0, X0
        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        let state2 = apply_sequence(initial_state, &seq2);

        // Assert states are not equal
        solver.assert(&states_not_equal(&state1, &state2));

        // If UNSAT, states are always equal
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_shifted_register_acceptance_lsl() {
        // Issue #59 acceptance: SMT proves
        //   LSL x10, x2, #3 ; ADD x0, x1, x10
        // ≡ ADD x0, x1, x2, LSL #3
        // (modulo the temp x10 — restrict the equivalence to the live-out x0).
        let initial = MachineState::new_symbolic("pre");

        let seq_split = vec![
            Instruction::Lsl {
                rd: Register::X10,
                rn: Register::X2,
                shift: Operand::Immediate(3),
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X10),
            },
        ];
        let seq_fused = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: crate::ir::ShiftKind::Lsl,
                amount: 3,
            },
        }];

        let s1 = apply_sequence(initial.clone(), &seq_split);
        let s2 = apply_sequence(initial, &seq_fused);

        // Live-out is just X0; the split sequence clobbers X10 but X0 must match.
        let solver = Solver::new();
        solver.assert(
            s1.get_register(Register::X0)
                .eq(s2.get_register(Register::X0))
                .not(),
        );
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_shifted_register_acceptance_ror_logical() {
        // ROR-on-logical case: AND x0, x1, x2, ROR #4
        // ≡ ROR x10, x2, #4 ; AND x0, x1, x10  (modulo temp x10).
        let initial = MachineState::new_symbolic("pre");

        let seq_split = vec![
            Instruction::Ror {
                rd: Register::X10,
                rn: Register::X2,
                shift: Operand::Immediate(4),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X10),
            },
        ];
        let seq_fused = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::ShiftedRegister {
                reg: Register::X2,
                kind: crate::ir::ShiftKind::Ror,
                amount: 4,
            },
        }];

        let s1 = apply_sequence(initial.clone(), &seq_split);
        let s2 = apply_sequence(initial, &seq_fused);

        let solver = Solver::new();
        solver.assert(
            s1.get_register(Register::X0)
                .eq(s2.get_register(Register::X0))
                .not(),
        );
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_add_immediate() {
        let mut state = MachineState::new_symbolic("test");

        // Set X1 = 10
        state.set_register(Register::X1, BV::from_i64(10, 64));

        // ADD X0, X1, #5
        let add = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(5),
        };

        let new_state = apply_instruction(state, &add);

        // X0 should be 15
        let x0_val = new_state.get_register(Register::X0);
        let expected = BV::from_i64(15, 64);

        let solver = Solver::new();
        solver.assert(&x0_val.eq(&expected).not());
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn test_mvn_smt_inverts_bits() {
        // Prove MVN x0, x1 ≡ EOR x0, x1, #(all-ones) — but the IR has no EOR
        // with a 64-bit immediate, so instead prove the simpler identity that
        // applying MVN twice gives back the original value:
        // MVN x0, x1; MVN x0, x0  ⇒  x0 == original x1.
        let initial = MachineState::new_symbolic("pre");
        let initial_x1 = initial.get_register(Register::X1).clone();

        let seq = vec![
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X0,
            },
        ];
        let final_state = apply_sequence(initial, &seq);
        let final_x0 = final_state.get_register(Register::X0);

        let solver = Solver::new();
        solver.assert(&final_x0.eq(&initial_x1).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "MVN is an involution: MVN(MVN(x)) must equal x"
        );
    }

    /// Soundness regression: CSEL must NOT be proved equivalent to MOV.
    /// The condition's value depends on NZCV which we don't model; the SMT
    /// result must be unconstrained so the solver can find inputs where they
    /// differ.
    #[test]
    fn test_csel_not_equivalent_to_mov() {
        use crate::ir::types::Condition;

        let initial_state = MachineState::new_symbolic("pre");

        // CSEL X0, X1, X2, EQ — should NOT be the same as MOV X0, X1
        // (it depends on flags; without flag modeling, we must remain
        // conservative — i.e. uninformative, never wrongly equivalent).
        let csel = vec![Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        }];
        let state_csel = apply_sequence(initial_state.clone(), &csel);

        let mov = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];
        let state_mov = apply_sequence(initial_state, &mov);

        // states_not_equal SAT ⇒ solver found inputs where they differ
        //                       ⇒ the two sequences are NOT proved equivalent
        // states_not_equal UNSAT ⇒ they are always equal ⇒ unsound for CSEL
        let solver = Solver::new();
        solver.assert(&states_not_equal(&state_csel, &state_mov));
        assert_eq!(
            solver.check(),
            SatResult::Sat,
            "CSEL must not be proved equivalent to MOV — SMT model is unsound"
        );
    }

    fn assert_involution(op: fn(Register, Register) -> Instruction, label: &str) {
        let initial = MachineState::new_symbolic("pre");
        let initial_x1 = initial.get_register(Register::X1).clone();
        let seq = vec![
            op(Register::X0, Register::X1),
            op(Register::X0, Register::X0),
        ];
        let final_state = apply_sequence(initial, &seq);
        let final_x0 = final_state.get_register(Register::X0);

        let solver = Solver::new();
        solver.assert(&final_x0.eq(&initial_x1).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "{} should be an involution: op(op(x)) must equal x",
            label
        );
    }

    #[test]
    fn test_rev_smt_is_involution() {
        assert_involution(|rd, rn| Instruction::Rev { rd, rn }, "REV");
    }

    #[test]
    fn test_rbit_smt_is_involution() {
        assert_involution(|rd, rn| Instruction::Rbit { rd, rn }, "RBIT");
    }

    #[test]
    fn test_rev32_smt_is_involution() {
        assert_involution(|rd, rn| Instruction::Rev32 { rd, rn }, "REV32");
    }

    #[test]
    fn test_rev16_smt_is_involution() {
        assert_involution(|rd, rn| Instruction::Rev16 { rd, rn }, "REV16");
    }

    #[test]
    fn test_clz_of_one_is_63() {
        // CLZ of an input known to equal 1 must be 63. Concrete constant
        // rewrite: `MOV x1, #1; CLZ x0, x1` ≡ `MOV x0, #63`.
        let initial = MachineState::new_symbolic("pre");
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 1,
            },
            Instruction::Clz {
                rd: Register::X0,
                rn: Register::X1,
            },
        ];
        let final_state = apply_sequence(initial, &seq);
        let final_x0 = final_state.get_register(Register::X0);
        let solver = Solver::new();
        solver.assert(&final_x0.eq(&BV::from_u64(63, 64)).not());
        assert_eq!(solver.check(), SatResult::Unsat, "CLZ(1) must be 63");
    }

    /// Floor-log2 acceptance test (issue #58): for nonzero `x1`, the sequence
    /// `CLZ x0, x1; MOV x2, #63; SUB x0, x2, x0` produces the highest-set-bit
    /// position. We characterise that position bitwise — the bit at the
    /// resulting index is set, and no higher bit is set — and assert the
    /// solver cannot find a counterexample. The "modulo zero-input edge case"
    /// caveat from the issue is encoded as the `x1 != 0` precondition.
    #[test]
    fn test_clz_floor_log2_pattern() {
        let initial = MachineState::new_symbolic("pre");
        let initial_x1 = initial.get_register(Register::X1).clone();

        let seq = vec![
            Instruction::Clz {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::MovImm {
                rd: Register::X2,
                imm: 63,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X2,
                rm: Operand::Register(Register::X0),
            },
        ];
        let final_state = apply_sequence(initial, &seq);
        let result = final_state.get_register(Register::X0).clone();

        let zero = BV::from_u64(0, 64);
        let one = BV::from_u64(1, 64);

        // Bit at position `result` is set: (x1 >> result) & 1 == 1.
        let bit_at_result = initial_x1.bvlshr(&result).bvand(&one).eq(&one);

        // No higher bit set: x1 >> (result + 1) == 0. SMTLIB BV shifts wider
        // than the bit-width yield zero, so result == 63 makes this vacuous.
        let next = result.bvadd(&one);
        let higher_zero = initial_x1.bvlshr(&next).eq(&zero);

        let solver = Solver::new();
        let nonzero = initial_x1.bvugt(&zero);
        solver.assert(&nonzero);
        // Look for a counterexample: nonzero x1 where the post-condition fails.
        let violated = z3::ast::Bool::or(&[&bit_at_result.not(), &higher_zero.not()]);
        solver.assert(&violated);

        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CLZ; MOV #63; SUB pattern must produce floor_log2(x1) for nonzero x1"
        );
    }

    #[test]
    fn test_symbolic_state_has_independent_nzcv_flags() {
        // After new_symbolic, each NZCV flag is its own 1-bit symbolic BV.
        // Two independent states must be free to disagree on every flag bit
        // simultaneously — i.e. the conjunction (n1!=n2 ∧ z1!=z2 ∧ c1!=c2 ∧ v1!=v2)
        // must be satisfiable. This proves the four flags are distinct
        // symbolic constants, not aliased to the same name or to register BVs.
        let s1 = MachineState::new_symbolic("a");
        let s2 = MachineState::new_symbolic("b");
        let (n1, z1, c1, v1) = s1.get_flags();
        let (n2, z2, c2, v2) = s2.get_flags();

        let solver = Solver::new();
        solver.assert(&n1.eq(n2).not());
        solver.assert(&z1.eq(z2).not());
        solver.assert(&c1.eq(c2).not());
        solver.assert(&v1.eq(v2).not());
        assert_eq!(solver.check(), SatResult::Sat);
    }

    fn assert_state_flags_equal_bvs(state: &MachineState, expected: &Nzcv, ctx: &str) {
        let solver = Solver::new();
        let (n_e, z_e, c_e, v_e) = expected;
        let neq = z3::ast::Bool::or(&[
            &state.n.eq(n_e).not(),
            &state.z.eq(z_e).not(),
            &state.c.eq(c_e).not(),
            &state.v.eq(v_e).not(),
        ]);
        solver.assert(&neq);
        assert_eq!(solver.check(), SatResult::Unsat, "{}", ctx);
    }

    #[test]
    fn test_cmp_sets_symbolic_flags() {
        // Applying CMP X0, X1 must leave the four flag BVs in agreement with
        // compute_flags_sub(X0, X1) — a property check across all symbolic
        // input values.
        let state = MachineState::new_symbolic("pre");
        let x0 = state.get_register(Register::X0).clone();
        let x1 = state.get_register(Register::X1).clone();
        let expected = compute_flags_sub(&x0, &x1);
        let after = apply_instruction(
            state,
            &Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
        );
        assert_state_flags_equal_bvs(&after, &expected, "CMP x0, x1");
    }

    fn force_flags(state: &mut MachineState, n: u64, z: u64, c: u64, v: u64) {
        state.set_flags(
            BV::from_u64(n, 1),
            BV::from_u64(z, 1),
            BV::from_u64(c, 1),
            BV::from_u64(v, 1),
        );
    }

    fn assert_register_eq(state: &MachineState, reg: Register, expected: &BV, ctx: &str) {
        let solver = Solver::new();
        solver.assert(&state.get_register(reg).eq(expected).not());
        assert_eq!(solver.check(), SatResult::Unsat, "{}", ctx);
    }

    #[test]
    fn test_states_not_equal_detects_flag_divergence() {
        // Build two symbolic states whose registers are pin-locked equal
        // and whose flags are forced to differ. states_not_equal must be
        // satisfiable in this configuration — proving that flag inequality
        // is part of full-state equivalence.
        let mut s1 = MachineState::new_symbolic("a");
        let mut s2 = MachineState::new_symbolic("b");
        // Force each register and SP to the same concrete value across
        // both states so register equality holds trivially.
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                let v = BV::from_u64(0, 64);
                s1.set_register(reg, v.clone());
                s2.set_register(reg, v);
            }
        }
        s1.set_register(Register::SP, BV::from_u64(0, 64));
        s2.set_register(Register::SP, BV::from_u64(0, 64));
        // Force flags: s1 has Z=1, s2 has Z=0. Registers are identical.
        force_flags(&mut s1, 0, 1, 0, 0);
        force_flags(&mut s2, 0, 0, 0, 0);

        let solver = Solver::new();
        solver.assert(&states_not_equal(&s1, &s2));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_csel_family_uses_symbolic_flag_ite() {
        // For each CS-family variant, pin the NZCV flags concretely so that
        // EQ is true (Z=1) or false (Z=0) and assert rd takes the spec-defined
        // branch in each case.
        let rn_val = BV::from_u64(7, 64);
        let rm_val = BV::from_u64(2, 64);

        let setup = |cond_true: bool| {
            let mut s = MachineState::new_symbolic("pre");
            s.set_register(Register::X1, rn_val.clone());
            s.set_register(Register::X2, rm_val.clone());
            force_flags(&mut s, 0, cond_true as u64, 0, 0);
            s
        };

        // CSEL: x0 = z==1 ? x1 : x2
        for &cond_true in &[true, false] {
            let s = setup(cond_true);
            let after = apply_instruction(
                s,
                &Instruction::Csel {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Register::X2,
                    cond: crate::ir::types::Condition::EQ,
                },
            );
            let expected = if cond_true { &rn_val } else { &rm_val };
            assert_register_eq(&after, Register::X0, expected, "CSEL EQ branch");
        }

        // CSINC: x0 = z==1 ? x1 : (x2 + 1)
        let s = setup(false);
        let after = apply_instruction(
            s,
            &Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_register_eq(
            &after,
            Register::X0,
            &BV::from_u64(3, 64),
            "CSINC EQ-false branch is rm+1",
        );

        // CSINV: x0 = z==1 ? x1 : ~x2
        let s = setup(false);
        let after = apply_instruction(
            s,
            &Instruction::Csinv {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_register_eq(
            &after,
            Register::X0,
            &BV::from_u64(!2u64, 64),
            "CSINV EQ-false branch is ~rm",
        );

        // CSNEG: x0 = z==1 ? x1 : -x2
        let s = setup(false);
        let after = apply_instruction(
            s,
            &Instruction::Csneg {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_register_eq(
            &after,
            Register::X0,
            &BV::from_u64((-2i64) as u64, 64),
            "CSNEG EQ-false branch is -rm",
        );

        // CSET: x0 = z==1 ? 1 : 0
        for &cond_true in &[true, false] {
            let s = setup(cond_true);
            let after = apply_instruction(
                s,
                &Instruction::Cset {
                    rd: Register::X0,
                    cond: crate::ir::types::Condition::EQ,
                },
            );
            let expected = BV::from_u64(cond_true as u64, 64);
            assert_register_eq(&after, Register::X0, &expected, "CSET EQ");
        }

        // CSETM: x0 = z==1 ? -1 : 0
        for &cond_true in &[true, false] {
            let s = setup(cond_true);
            let after = apply_instruction(
                s,
                &Instruction::Csetm {
                    rd: Register::X0,
                    cond: crate::ir::types::Condition::EQ,
                },
            );
            let expected = BV::from_u64(if cond_true { u64::MAX } else { 0 }, 64);
            assert_register_eq(&after, Register::X0, &expected, "CSETM EQ");
        }
    }

    #[test]
    fn test_ccmp_true_branch_matches_compute_flags_sub() {
        // Force the predicate to true (Z=1, cond=EQ) so the true branch
        // applies: state flags must equal compute_flags_sub(x1, x2).
        let mut state = MachineState::new_symbolic("pre");
        force_flags(&mut state, 0, 1, 0, 0);
        let x1 = state.get_register(Register::X1).clone();
        let x2 = state.get_register(Register::X2).clone();
        let expected = compute_flags_sub(&x1, &x2);
        let after = apply_instruction(
            state,
            &Instruction::Ccmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                nzcv: 0b1010,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_state_flags_equal_bvs(&after, &expected, "CCMP EQ-true matches CMP");
    }

    #[test]
    fn test_ccmp_false_branch_uses_nzcv_literal_smt() {
        // Force the predicate to false (Z=0, cond=EQ) so the false branch
        // applies: state flags must equal the 4-bit nzcv literal.
        let mut state = MachineState::new_symbolic("pre");
        force_flags(&mut state, 0, 0, 0, 0);
        let expected = nzcv_to_bvs(0b1010);
        let after = apply_instruction(
            state,
            &Instruction::Ccmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                nzcv: 0b1010,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_state_flags_equal_bvs(&after, &expected, "CCMP EQ-false uses nzcv literal");
    }

    #[test]
    fn test_ccmn_true_branch_matches_compute_flags_add() {
        let mut state = MachineState::new_symbolic("pre");
        force_flags(&mut state, 0, 1, 0, 0);
        let x1 = state.get_register(Register::X1).clone();
        let x2 = state.get_register(Register::X2).clone();
        let expected = compute_flags_add(&x1, &x2);
        let after = apply_instruction(
            state,
            &Instruction::Ccmn {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
                nzcv: 0,
                cond: crate::ir::types::Condition::EQ,
            },
        );
        assert_state_flags_equal_bvs(&after, &expected, "CCMN EQ-true matches CMN");
    }

    #[test]
    fn test_flag_writers_set_symbolic_flags() {
        // Apply each flag-writing instruction over symbolic x0/x1 and prove
        // its final NZCV agrees with the helper that mirrors concrete
        // semantics. Covers every variant of modifies_flags() except CMP
        // (already verified in test_cmp_sets_symbolic_flags).
        let pre = MachineState::new_symbolic("pre");
        let x0 = pre.get_register(Register::X0).clone();
        let x1 = pre.get_register(Register::X1).clone();
        let rm_reg = Operand::Register(Register::X1);

        let cases: Vec<(Instruction, Nzcv, &'static str)> = vec![
            (
                Instruction::Cmn {
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_add(&x0, &x1),
                "CMN x0, x1",
            ),
            (
                Instruction::Tst {
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_logical(&x0.bvand(&x1)),
                "TST x0, x1",
            ),
            (
                Instruction::Adds {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_add(&x0, &x1),
                "ADDS x2, x0, x1",
            ),
            (
                Instruction::Subs {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_sub(&x0, &x1),
                "SUBS x2, x0, x1",
            ),
            (
                Instruction::Ands {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_logical(&x0.bvand(&x1)),
                "ANDS x2, x0, x1",
            ),
            (
                Instruction::Negs {
                    rd: Register::X2,
                    rm: Register::X1,
                },
                compute_flags_sub(&BV::from_u64(0, 64), &x1),
                "NEGS x2, x1",
            ),
            (
                Instruction::Bics {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_logical(&x0.bvand(&x1.bvnot())),
                "BICS x2, x0, x1",
            ),
        ];

        for (instr, expected, ctx) in cases {
            let after = apply_instruction(pre.clone(), &instr);
            assert_state_flags_equal_bvs(&after, &expected, ctx);
        }
    }

    fn assert_flags_match(
        actual: Nzcv,
        expected: crate::semantics::state::ConditionFlags,
        ctx: &str,
    ) {
        let (n, z, c, v) = actual;
        let solver = Solver::new();
        let exp_n = BV::from_u64(expected.n as u64, 1);
        let exp_z = BV::from_u64(expected.z as u64, 1);
        let exp_c = BV::from_u64(expected.c as u64, 1);
        let exp_v = BV::from_u64(expected.v as u64, 1);
        let neq = z3::ast::Bool::or(&[
            &n.eq(&exp_n).not(),
            &z.eq(&exp_z).not(),
            &c.eq(&exp_c).not(),
            &v.eq(&exp_v).not(),
        ]);
        solver.assert(&neq);
        assert_eq!(solver.check(), SatResult::Unsat, "{}", ctx);
    }

    #[test]
    fn test_compute_flags_sub_matches_concrete() {
        use crate::semantics::state::ConditionFlags;
        let cases: &[(u64, u64)] = &[
            (5, 3),                // positive non-zero result, C set, no overflow
            (3, 3),                // zero result
            (0, 1),                // borrow / N set
            (i64::MIN as u64, 1),  // signed overflow
            (i64::MAX as u64, !0), // signed overflow other direction
        ];
        for &(a, b) in cases {
            let lhs = BV::from_u64(a, 64);
            let rhs = BV::from_u64(b, 64);
            let expected = ConditionFlags::from_sub(a, b, a.wrapping_sub(b));
            assert_flags_match(
                compute_flags_sub(&lhs, &rhs),
                expected,
                &format!("compute_flags_sub({a}, {b}) vs ConditionFlags::from_sub"),
            );
        }
    }

    #[test]
    fn test_compute_flags_add_matches_concrete() {
        use crate::semantics::state::ConditionFlags;
        let cases: &[(u64, u64)] = &[
            (5, 3),
            (0, 0),
            (u64::MAX, 1),        // unsigned wrap → C set
            (i64::MAX as u64, 1), // signed overflow
            (i64::MIN as u64, i64::MIN as u64),
        ];
        for &(a, b) in cases {
            let lhs = BV::from_u64(a, 64);
            let rhs = BV::from_u64(b, 64);
            let expected = ConditionFlags::from_add(a, b, a.wrapping_add(b));
            assert_flags_match(
                compute_flags_add(&lhs, &rhs),
                expected,
                &format!("compute_flags_add({a}, {b}) vs ConditionFlags::from_add"),
            );
        }
    }

    #[test]
    fn test_compute_flags_logical_matches_concrete() {
        use crate::semantics::state::ConditionFlags;
        let cases: &[u64] = &[0, 1, !0, 1 << 63, 0x5555_5555_5555_5555];
        for &r in cases {
            let result = BV::from_u64(r, 64);
            let expected = ConditionFlags::from_logical(r);
            assert_flags_match(
                compute_flags_logical(&result),
                expected,
                &format!("compute_flags_logical({r}) vs ConditionFlags::from_logical"),
            );
        }
    }

    #[test]
    fn test_condition_to_smt_matches_concrete() {
        use crate::ir::types::Condition;
        use crate::semantics::state::ConditionFlags;
        let conds = [
            Condition::EQ,
            Condition::NE,
            Condition::CS,
            Condition::CC,
            Condition::MI,
            Condition::PL,
            Condition::VS,
            Condition::VC,
            Condition::HI,
            Condition::LS,
            Condition::GE,
            Condition::LT,
            Condition::GT,
            Condition::LE,
            Condition::AL,
            Condition::NV,
        ];
        for nb in 0..16u8 {
            let n = (nb >> 3) & 1 == 1;
            let z = (nb >> 2) & 1 == 1;
            let c = (nb >> 1) & 1 == 1;
            let v = nb & 1 == 1;
            let flags = ConditionFlags { n, z, c, v };
            let n_bv = BV::from_u64(n as u64, 1);
            let z_bv = BV::from_u64(z as u64, 1);
            let c_bv = BV::from_u64(c as u64, 1);
            let v_bv = BV::from_u64(v as u64, 1);
            for &cond in &conds {
                let expected = flags.evaluate(cond);
                let smt = condition_to_smt(cond, &n_bv, &z_bv, &c_bv, &v_bv);
                let solver = Solver::new();
                let expected_bv = BV::from_u64(expected as u64, 1);
                solver.assert(&smt.eq(&expected_bv).not());
                assert_eq!(
                    solver.check(),
                    SatResult::Unsat,
                    "condition_to_smt({:?}) disagrees with concrete at flags={:?}",
                    cond,
                    flags,
                );
            }
        }
    }

    #[test]
    fn test_set_flags_round_trip() {
        // set_flags writes; get_flags reads back the exact BVs.
        let mut s = MachineState::new_symbolic("rt");
        let n_in = BV::from_u64(1, 1);
        let z_in = BV::from_u64(0, 1);
        let c_in = BV::from_u64(1, 1);
        let v_in = BV::from_u64(0, 1);
        s.set_flags(n_in.clone(), z_in.clone(), c_in.clone(), v_in.clone());
        let (n_out, z_out, c_out, v_out) = s.get_flags();

        let solver = Solver::new();
        let neq = z3::ast::Bool::or(&[
            &n_out.eq(&n_in).not(),
            &z_out.eq(&z_in).not(),
            &c_out.eq(&c_in).not(),
            &v_out.eq(&v_in).not(),
        ]);
        solver.assert(&neq);
        assert_eq!(solver.check(), SatResult::Unsat);
    }
}

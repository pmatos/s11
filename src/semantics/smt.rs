//! SMT constraint generation for AArch64 instructions

#![allow(dead_code)]

use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};
use crate::ir::{
    ExtendKind, Instruction, Operand, Register, RegisterWidth, VectorArrangement, VectorRegister,
};
use crate::semantics::live_out::RegisterSet;
use std::collections::HashMap;
use std::time::Duration;
use z3::ast::{Array, BV};
use z3::{Params, Solver, Sort};

/// Reverse the byte order of a 64-bit BV by concatenating its 8 byte slices
/// with byte 0 placed in the most-significant position.
/// Reverse the byte order of a `width`-bit BV by concatenating its byte
/// slices with byte 0 placed in the most-significant position. `width` must
/// be a multiple of 8.
fn bv_swap_bytes(value: &BV, width: u32) -> BV {
    debug_assert!(
        width.is_multiple_of(8),
        "bv_swap_bytes requires byte-multiple width"
    );
    let num_bytes = width / 8;
    let mut result = value.extract(7, 0);
    for i in 1..num_bytes {
        let lo = i * 8;
        let hi = lo + 7;
        result = result.concat(value.extract(hi, lo));
    }
    result
}

fn bv_shift_mask(width: u32) -> BV {
    BV::from_u64((width - 1) as u64, width)
}

/// `width`-bit ROR composed as `(value lshr n) | (value shl (width - n))`.
/// Caller is responsible for masking `n` to `log2(width)` bits when needed
/// (immediate callers with `n` already in `0..width` may skip the mask).
///
/// Edge case at n == 0: `complement` evaluates to `width`, and SMTLIB2
/// bit-vector semantics define `bvshl(x, width) = 0` (any shift ≥ the
/// bit-width zeroes the value). So `hi = 0` and the result is just
/// `value lshr 0 = value`.
fn bv_ror(value: &BV, n: &BV, width: u32) -> BV {
    let mask = bv_shift_mask(width);
    let n_masked = n.bvand(&mask);
    let width_const = BV::from_u64(width as u64, width);
    let complement = width_const.bvsub(&n_masked);
    let lo = value.bvlshr(&n_masked);
    let hi = value.bvshl(&complement);
    lo.bvor(&hi)
}

/// Reverse the bit order of a `width`-bit BV via single-bit extracts.
fn bv_reverse_bits(value: &BV, width: u32) -> BV {
    // Bit 0 of `value` becomes the new MSB; bit width-1 becomes the new LSB.
    let mut result = value.extract(0, 0);
    for i in 1..width {
        result = result.concat(value.extract(i, i));
    }
    result
}

fn bv_add_vector_lanes(lhs: &BV, rhs: &BV, arrangement: VectorArrangement) -> BV {
    let lane_width = u32::from(arrangement.lane_width());
    let lane_count = u32::from(arrangement.lane_count());
    let mut result = lhs
        .extract(lane_width - 1, 0)
        .bvadd(rhs.extract(lane_width - 1, 0));
    for lane in 1..lane_count {
        let low = lane * lane_width;
        let high = low + lane_width - 1;
        let sum = lhs.extract(high, low).bvadd(rhs.extract(high, low));
        result = sum.concat(result);
    }
    result
}

fn logical_smt_width(width: RegisterWidth, state_width: u32) -> u32 {
    match width {
        RegisterWidth::W32 => 32,
        RegisterWidth::X64 => state_width,
    }
}

fn register_logical_value(state: &MachineState, reg: Register, width: RegisterWidth) -> BV {
    let value = state.get_register(reg).clone();
    match width {
        RegisterWidth::W32 => value.extract(31, 0),
        RegisterWidth::X64 => value,
    }
}

fn eval_logical_operand(state: &MachineState, operand: &Operand, width: RegisterWidth) -> BV {
    match width {
        RegisterWidth::W32 => eval_w_operand(state, operand),
        RegisterWidth::X64 => state.eval_operand(operand),
    }
}

fn eval_w_operand(state: &MachineState, operand: &Operand) -> BV {
    match operand {
        Operand::Register(reg) => state.get_register(*reg).extract(31, 0),
        Operand::Immediate(imm) => BV::from_i64(*imm, 32),
        Operand::ShiftedRegister { reg, kind, amount } => {
            let value = state.get_register(*reg).extract(31, 0);
            let amt = BV::from_u64(u64::from(*amount), 32);
            match kind {
                crate::ir::ShiftKind::Lsl => value.bvshl(&amt),
                crate::ir::ShiftKind::Lsr => value.bvlshr(&amt),
                crate::ir::ShiftKind::Asr => value.bvashr(&amt),
                crate::ir::ShiftKind::Ror => bv_ror(&value, &amt, 32),
            }
        }
        Operand::ExtendedRegister { .. } => state.eval_operand(operand).extract(31, 0),
    }
}

fn zero_extend_to_state_width(value: BV, value_width: u32, state_width: u32) -> BV {
    if value_width == state_width {
        value
    } else {
        value.zero_ext(state_width - value_width)
    }
}

// Store a bit-field op's 64-bit result BV into `rd`, honouring the register
// width. For the W form, the low 32 bits hold the architectural result and bits
// [63:32] are zeroed (ARM ARM: writing a W register clears the upper half).
fn store_bitfield_result(
    state: &mut MachineState,
    rd: Register,
    result: BV,
    reg_width: RegisterWidth,
) {
    let stored = match reg_width {
        RegisterWidth::W32 => zero_extend_to_state_width(result.extract(31, 0), 32, state.width()),
        RegisterWidth::X64 => result,
    };
    state.set_register(rd, stored);
}

/// Count leading zeros of a `width`-bit BV with a binary-search decomposition.
///
/// The result remains `width` bits wide, while the selected chunk halves on
/// each step. If the upper half is zero, add its width to the count and
/// continue with the lower half; otherwise continue with the upper half.
fn bv_clz(value: &BV, width: u32) -> BV {
    debug_assert!(width > 0, "bv_clz requires a nonzero width");
    debug_assert!(
        width.is_power_of_two(),
        "bv_clz binary-search decomposition requires power-of-two width"
    );

    let mut chunk = value.clone();
    let mut chunk_width = width;
    let mut count = BV::from_u64(0, width);

    while chunk_width > 1 {
        let half = chunk_width / 2;
        let upper = chunk.extract(chunk_width - 1, half);
        let lower = chunk.extract(half - 1, 0);
        let upper_is_zero = upper.eq(BV::from_u64(0, half));

        let incremented = count.bvadd(BV::from_u64(half as u64, width));
        count = upper_is_zero.ite(&incremented, &count);
        chunk = upper_is_zero.ite(&lower, &upper);
        chunk_width = half;
    }

    let bit_is_zero = chunk.eq(BV::from_u64(0, 1));
    let incremented = count.bvadd(BV::from_u64(1, width));
    bit_is_zero.ite(&incremented, &count)
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

/// Machine state representation for SMT solving.
///
/// Carries a `width` field per ADR-0004 decision 1; AArch64 is always
/// width=64. All register BVs in `registers` are `width` bits wide.
#[derive(Clone)]
pub struct MachineState {
    /// Register values as `width`-bit bitvectors
    pub registers: HashMap<Register, BV>,
    /// Packed 128-bit Advanced SIMD/FP register values.
    pub vectors: HashMap<VectorRegister, BV>,
    /// NZCV condition flags as 1-bit bitvectors
    pub n: BV,
    pub z: BV,
    pub c: BV,
    pub v: BV,
    /// Byte-addressed memory. Domain is BV<64> (the address); range is
    /// BV<8> (the byte). Sound aliasing comes for free from Z3's array
    /// theory — every possible overlap of two `store(addr, byte)`
    /// operations is reasoned over without disjointness preconditions.
    /// See ADR-0007.
    pub memory: Array,
    width: u32,
}

impl MachineState {
    /// Create a new symbolic AArch64 machine state (width=64).
    pub fn new_symbolic(prefix: &str) -> Self {
        Self::new_symbolic_for_width(prefix, 64)
    }

    /// Create a new symbolic machine state with the given register width.
    pub fn new_symbolic_for_width(prefix: &str, width: u32) -> Self {
        let mut registers = HashMap::new();

        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                let name = format!("{}_x{}", prefix, i);
                registers.insert(reg, BV::new_const(name, width));
            }
        }

        registers.insert(Register::XZR, BV::from_i64(0, width));
        registers.insert(Register::SP, BV::new_const(format!("{}_sp", prefix), width));

        let vectors = (0..32)
            .filter_map(VectorRegister::from_index)
            .map(|register| {
                (
                    register,
                    BV::new_const(format!("{}_v{}", prefix, register.index()), 128),
                )
            })
            .collect();

        let n = BV::new_const(format!("{}_n", prefix), 1);
        let z = BV::new_const(format!("{}_z", prefix), 1);
        let c = BV::new_const(format!("{}_c", prefix), 1);
        let v = BV::new_const(format!("{}_v", prefix), 1);

        // Sparse symbolic memory: BV64 → BV8. The byte at address `a` is
        // `memory.select(BV::from_u64(a, 64))`. Z3's array theory handles
        // every aliasing case without disjointness preconditions.
        let memory = Array::new_const(
            format!("{}_mem", prefix),
            &Sort::bitvector(64),
            &Sort::bitvector(8),
        );

        MachineState {
            registers,
            vectors,
            n,
            z,
            c,
            v,
            memory,
            width,
        }
    }

    /// Register bit width this state was constructed with.
    pub fn width(&self) -> u32 {
        self.width
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

    pub fn get_vector(&self, reg: VectorRegister) -> &BV {
        self.vectors.get(&reg).expect("Vector register not found")
    }

    pub fn set_vector(&mut self, reg: VectorRegister, value: BV) {
        debug_assert_eq!(value.get_size(), 128);
        self.vectors.insert(reg, value);
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

    /// Read `n` consecutive bytes starting at `addr_bv`, little-endian.
    /// Returns a `(8 * n)`-bit BV whose low byte is at `addr+0` and whose
    /// high byte is at `addr+n-1`. Used by the LDR-family arms.
    pub fn select_n(&self, addr_bv: &BV, n: u32) -> BV {
        assert!(n >= 1);
        let addr0 = addr_bv.clone();
        let byte0 = self
            .memory
            .select(&addr0)
            .as_bv()
            .expect("array<BV64,BV8>::select must return BV<8>");
        let mut result = byte0;
        for i in 1..n {
            let offset = BV::from_u64(i as u64, 64);
            let idx = addr_bv.bvadd(&offset);
            let byte = self
                .memory
                .select(&idx)
                .as_bv()
                .expect("array<BV64,BV8>::select must return BV<8>");
            // Byte at addr+i is the next byte up — concat in the high position.
            result = byte.concat(&result);
        }
        result
    }

    /// Store the low `n` bytes of `value` to memory at `addr_bv`,
    /// little-endian. Replaces `self.memory` with the chained-store result.
    pub fn store_n(&mut self, addr_bv: &BV, value: &BV, n: u32) {
        assert!(n >= 1);
        let mut mem = self.memory.clone();
        for i in 0..n {
            let byte = value.extract(8 * i + 7, 8 * i);
            let idx = if i == 0 {
                addr_bv.clone()
            } else {
                let offset = BV::from_u64(i as u64, 64);
                addr_bv.bvadd(&offset)
            };
            mem = mem.store(&idx, &byte);
        }
        self.memory = mem;
    }

    /// Evaluate the effective address of an `AddressOperand`. Mirrors the
    /// concrete `compute_address` helper; returns the address as a BV64
    /// plus an optional `(base, new_base_value)` writeback that the caller
    /// commits to the register file.
    pub fn eval_address(&self, addr: &AddressOperand) -> (BV, Option<(Register, BV)>) {
        match addr {
            AddressOperand::Imm { base, offset, mode } => {
                let base_bv = self.get_register(*base).clone();
                let off_bv = BV::from_i64(*offset, 64);
                let updated = base_bv.bvadd(&off_bv);
                match mode {
                    IndexMode::Offset => (updated, None),
                    IndexMode::PreIndex => (updated.clone(), Some((*base, updated))),
                    IndexMode::PostIndex => (base_bv, Some((*base, updated))),
                }
            }
            AddressOperand::Reg { base, idx, shift } => {
                let base_bv = self.get_register(*base).clone();
                let idx_bv = self.get_register(*idx).clone();
                let shifted = if *shift == 0 {
                    idx_bv
                } else {
                    idx_bv.bvshl(BV::from_u64(*shift as u64, 64))
                };
                (base_bv.bvadd(&shifted), None)
            }
            AddressOperand::Ext {
                base,
                idx,
                kind,
                shift,
            } => {
                let base_bv = self.get_register(*base).clone();
                let idx_bv = self.get_register(*idx).clone();
                let extended = match kind {
                    ExtendKind::Uxtw => idx_bv.extract(31, 0).zero_ext(32),
                    ExtendKind::Sxtw => idx_bv.extract(31, 0).sign_ext(32),
                    ExtendKind::Uxtx | ExtendKind::Sxtx => idx_bv,
                    // Byte/half extends are rejected by is_encodable for
                    // memory operands; the SMT path defaults to UXT to
                    // keep apply_instruction total.
                    ExtendKind::Uxtb => idx_bv.extract(7, 0).zero_ext(56),
                    ExtendKind::Uxth => idx_bv.extract(15, 0).zero_ext(48),
                    ExtendKind::Sxtb => idx_bv.extract(7, 0).sign_ext(56),
                    ExtendKind::Sxth => idx_bv.extract(15, 0).sign_ext(48),
                };
                let shifted = if *shift == 0 {
                    extended
                } else {
                    extended.bvshl(BV::from_u64(*shift as u64, 64))
                };
                (base_bv.bvadd(&shifted), None)
            }
        }
    }

    /// Evaluate an operand to get its value
    pub fn eval_operand(&self, operand: &Operand) -> BV {
        match operand {
            Operand::Register(reg) => self.get_register(*reg).clone(),
            Operand::Immediate(imm) => BV::from_i64(*imm, self.width),
            Operand::ShiftedRegister { reg, kind, amount } => {
                let value = self.get_register(*reg).clone();
                // `amount` is the compile-time modifier on a shifted-register
                // operand and is bounded by parsing/encodability. Runtime
                // masking belongs to register-form LSL/LSR/ASR shift operands.
                let amt = BV::from_u64(*amount as u64, self.width);
                match kind {
                    crate::ir::ShiftKind::Lsl => value.bvshl(&amt),
                    crate::ir::ShiftKind::Lsr => value.bvlshr(&amt),
                    crate::ir::ShiftKind::Asr => value.bvashr(&amt),
                    crate::ir::ShiftKind::Ror => bv_ror(&value, &amt, self.width),
                }
            }
            // Issue #60: ExtendedRegister extracts the low N bits, then
            // sign/zero-extends to 64 and finally shifts left by `shift`.
            Operand::ExtendedRegister { reg, kind, shift } => {
                let value = self.get_register(*reg).clone();
                let extended = match kind {
                    crate::ir::ExtendKind::Uxtb => value.extract(7, 0).zero_ext(56),
                    crate::ir::ExtendKind::Uxth => value.extract(15, 0).zero_ext(48),
                    crate::ir::ExtendKind::Uxtw => value.extract(31, 0).zero_ext(32),
                    crate::ir::ExtendKind::Uxtx => value,
                    crate::ir::ExtendKind::Sxtb => value.extract(7, 0).sign_ext(56),
                    crate::ir::ExtendKind::Sxth => value.extract(15, 0).sign_ext(48),
                    crate::ir::ExtendKind::Sxtw => value.extract(31, 0).sign_ext(32),
                    crate::ir::ExtendKind::Sxtx => value,
                };
                if *shift == 0 {
                    extended
                } else {
                    extended.bvshl(BV::from_u64(*shift as u64, self.width))
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

/// Compute symbolic NZCV for the subtraction `lhs - rhs` at width `width`.
/// Mirrors `ConditionFlags::from_sub` in `state.rs` bit-for-bit.
pub fn compute_flags_sub(lhs: &BV, rhs: &BV, width: u32) -> Nzcv {
    let result = lhs.bvsub(rhs);
    let zero = BV::from_u64(0, width);
    let msb = width - 1;
    let n = result.extract(msb, msb);
    let z = result.eq(&zero).ite(&bv_one(), &bv_zero());
    let c = lhs.bvuge(rhs).ite(&bv_one(), &bv_zero());
    // Signed overflow on subtraction: (lhs and rhs differ in sign) AND
    // (lhs and result differ in sign).
    let lhs_sign = lhs.extract(msb, msb);
    let rhs_sign = rhs.extract(msb, msb);
    let res_sign = result.extract(msb, msb);
    let v = lhs_sign.bvxor(&rhs_sign).bvand(lhs_sign.bvxor(&res_sign));
    (n, z, c, v)
}

/// Compute symbolic NZCV for the addition `lhs + rhs` at width `width`.
/// Mirrors `ConditionFlags::from_add` in `state.rs`.
pub fn compute_flags_add(lhs: &BV, rhs: &BV, width: u32) -> Nzcv {
    let result = lhs.bvadd(rhs);
    let zero = BV::from_u64(0, width);
    let msb = width - 1;
    let n = result.extract(msb, msb);
    let z = result.eq(&zero).ite(&bv_one(), &bv_zero());
    // Carry on add: result < lhs (unsigned).
    let c = result.bvult(lhs).ite(&bv_one(), &bv_zero());
    // Signed overflow on add: (lhs and rhs share sign) AND (lhs and result
    // differ in sign).
    let lhs_sign = lhs.extract(msb, msb);
    let rhs_sign = rhs.extract(msb, msb);
    let res_sign = result.extract(msb, msb);
    let one_bit = bv_one();
    let signs_match = lhs_sign.bvxor(&rhs_sign).bvxor(&one_bit); // 1 when signs match
    let signs_flip = lhs_sign.bvxor(&res_sign); // 1 when lhs and result differ
    let v = signs_match.bvand(&signs_flip);
    (n, z, c, v)
}

/// Compute symbolic NZCV for add-with-carry `lhs + rhs + carry` at `width`.
/// `carry` is a 1-bit BV. Mirrors `ConditionFlags::from_adc` in `state.rs`.
/// The three addends are widened to `width + 1` bits; because `bvadd` is
/// modular same-width, the sum is `width + 1` bits and bit `width` is the
/// carry-out.
pub fn compute_flags_adc(lhs: &BV, rhs: &BV, carry: &BV, width: u32) -> Nzcv {
    let sum = lhs
        .zero_ext(1)
        .bvadd(rhs.zero_ext(1))
        .bvadd(carry.zero_ext(width));
    let result = sum.extract(width - 1, 0);
    let zero = BV::from_u64(0, width);
    let msb = width - 1;
    let n = result.extract(msb, msb);
    let z = result.eq(&zero).ite(&bv_one(), &bv_zero());
    let c = sum.extract(width, width); // carry-out
    let lhs_sign = lhs.extract(msb, msb);
    let rhs_sign = rhs.extract(msb, msb);
    let res_sign = result.extract(msb, msb);
    let signs_match = lhs_sign.bvxor(&rhs_sign).bvxor(bv_one());
    let signs_flip = lhs_sign.bvxor(&res_sign);
    let v = signs_match.bvand(&signs_flip);
    (n, z, c, v)
}

/// Compute symbolic NZCV for subtract-with-carry `lhs - rhs - (1 - carry)`,
/// which equals `lhs + NOT(rhs) + carry`. Mirrors `ConditionFlags::from_sbc`.
pub fn compute_flags_sbc(lhs: &BV, rhs: &BV, carry: &BV, width: u32) -> Nzcv {
    compute_flags_adc(lhs, &rhs.bvnot(), carry, width)
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

/// Compute symbolic NZCV for a logical (AND/ORR/EOR/TST) result at width
/// `width`. C and V are always cleared per the AArch64 ARM.
pub fn compute_flags_logical(result: &BV, width: u32) -> Nzcv {
    let zero = BV::from_u64(0, width);
    let msb = width - 1;
    let n = result.extract(msb, msb);
    let z = result.eq(&zero).ite(&bv_one(), &bv_zero());
    (n, z, bv_zero(), bv_zero())
}

/// Translate a `Condition` code into a 1-bit symbolic predicate over the
/// supplied NZCV flag BVs. Mirrors `ConditionFlags::evaluate` in `state.rs`
/// and `evaluate_condition` in `concrete.rs` for all 16 condition codes.
pub fn condition_to_smt(cond: crate::ir::types::Condition, n: &BV, z: &BV, c: &BV, v: &BV) -> BV {
    use crate::ir::types::Condition;
    let one = bv_one();
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
        Condition::LE => z.bvor(n_eq_v.bvxor(&one)),
        Condition::AL => one.clone(),
        // NV (0b1111) is reserved but per ARM ARM still satisfies
        // condition_holds = true — equivalent to AL. Concrete execution
        // selects rn for `csel/csinc/csinv/csneg ..., nv`; SMT must agree
        // or the equivalence checker can certify unsound rewrites for any
        // CSEL-family instruction encoded with the NV suffix.
        Condition::NV => one,
    }
}

/// Apply an instruction to a machine state, returning the new state
pub fn apply_instruction(mut state: MachineState, instruction: &Instruction) -> MachineState {
    let width = state.width();
    match instruction {
        Instruction::MovReg { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, value);
        }
        Instruction::MovRegW { rd, rn } => {
            let value = state.get_register(*rn).extract(31, 0);
            state.set_register(*rd, zero_extend_to_state_width(value, 32, width));
        }
        Instruction::MovImm { rd, imm } => {
            let value = BV::from_i64(*imm, width);
            state.set_register(*rd, value);
        }
        Instruction::Movi { vd, imm, .. } => {
            debug_assert_eq!(*imm, 0, "first-slice MOVI admits only #0");
            state.set_vector(*vd, BV::from_u64(0, 128));
        }
        Instruction::MovFromVectorLane { rd, vn, lane } => {
            let low = u32::from(*lane) * 64;
            let value = state.get_vector(*vn).extract(low + 63, low);
            state.set_register(*rd, value);
        }
        Instruction::VectorAdd {
            vd,
            vn,
            vm,
            arrangement,
        } => {
            let result =
                bv_add_vector_lanes(state.get_vector(*vn), state.get_vector(*vm), *arrangement);
            state.set_vector(*vd, result);
        }
        Instruction::Add { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvadd(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::AddW { rd, rn, rm } => {
            let lhs = state.get_register(*rn).extract(31, 0);
            let rhs = eval_w_operand(&state, rm);
            let result = lhs.bvadd(&rhs);
            state.set_register(*rd, zero_extend_to_state_width(result, 32, width));
        }
        Instruction::Sub { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvsub(&rhs);
            state.set_register(*rd, result);
        }
        Instruction::SubW { rd, rn, rm } => {
            let lhs = state.get_register(*rn).extract(31, 0);
            let rhs = eval_w_operand(&state, rm);
            let result = lhs.bvsub(&rhs);
            state.set_register(*rd, zero_extend_to_state_width(result, 32, width));
        }
        Instruction::And {
            rd,
            rn,
            rm,
            width: reg_width,
        } => {
            let op_width = logical_smt_width(*reg_width, width);
            let lhs = register_logical_value(&state, *rn, *reg_width);
            let rhs = eval_logical_operand(&state, rm, *reg_width);
            let result = lhs.bvand(&rhs);
            state.set_register(*rd, zero_extend_to_state_width(result, op_width, width));
        }
        Instruction::Orr {
            rd,
            rn,
            rm,
            width: reg_width,
        } => {
            let op_width = logical_smt_width(*reg_width, width);
            let lhs = register_logical_value(&state, *rn, *reg_width);
            let rhs = eval_logical_operand(&state, rm, *reg_width);
            let result = lhs.bvor(&rhs);
            state.set_register(*rd, zero_extend_to_state_width(result, op_width, width));
        }
        Instruction::Eor {
            rd,
            rn,
            rm,
            width: reg_width,
        } => {
            let op_width = logical_smt_width(*reg_width, width);
            let lhs = register_logical_value(&state, *rn, *reg_width);
            let rhs = eval_logical_operand(&state, rm, *reg_width);
            let result = lhs.bvxor(&rhs);
            state.set_register(*rd, zero_extend_to_state_width(result, op_width, width));
        }
        Instruction::Lsl { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            // AArch64 variable shifts consume only the low log2(width) bits
            // (concrete.rs masks with `& 63`). Z3's `bvshl` zeroes the result
            // when the shift amount is >= width, so we must mask first to
            // keep SMT and concrete in agreement (issue #241).
            let mask = bv_shift_mask(width);
            let shift_amount = state.eval_operand(shift).bvand(&mask);
            let result = value.bvshl(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Lsr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let mask = bv_shift_mask(width);
            let shift_amount = state.eval_operand(shift).bvand(&mask);
            let result = value.bvlshr(&shift_amount);
            state.set_register(*rd, result);
        }
        Instruction::Asr { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let mask = bv_shift_mask(width);
            let shift_amount = state.eval_operand(shift).bvand(&mask);
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
            let zero = BV::from_i64(0, width);
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
            let zero = BV::from_u64(0, width);
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
            state.set_register(*rd, c.bvadd(a.bvmul(&b)));
        }
        Instruction::Msub { rd, rn, rm, ra } => {
            let a = state.get_register(*rn).clone();
            let b = state.get_register(*rm).clone();
            let c = state.get_register(*ra).clone();
            state.set_register(*rd, c.bvsub(a.bvmul(&b)));
        }
        Instruction::Mneg { rd, rn, rm } => {
            let a = state.get_register(*rn).clone();
            let b = state.get_register(*rm).clone();
            state.set_register(*rd, a.bvmul(&b).bvneg());
        }
        Instruction::Smulh { rd, rn, rm } => {
            // `width`-bit sign-extend to 2*width, multiply, extract upper width bits.
            let a = state.get_register(*rn).sign_ext(width);
            let b = state.get_register(*rm).sign_ext(width);
            let prod = a.bvmul(&b);
            state.set_register(*rd, prod.extract(2 * width - 1, width));
        }
        Instruction::Umulh { rd, rn, rm } => {
            // `width`-bit zero-extend to 2*width, multiply, extract upper width bits.
            let a = state.get_register(*rn).zero_ext(width);
            let b = state.get_register(*rm).zero_ext(width);
            let prod = a.bvmul(&b);
            state.set_register(*rd, prod.extract(2 * width - 1, width));
        }
        // Comparison instructions set flags and don't modify registers.
        Instruction::Cmp { rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_sub(&lhs, &rhs, width);
            state.set_flags(n, z, c, v);
        }
        Instruction::Cmn { rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_add(&lhs, &rhs, width);
            state.set_flags(n, z, c, v);
        }
        Instruction::Tst {
            rn,
            rm,
            width: reg_width,
        } => {
            let op_width = logical_smt_width(*reg_width, width);
            let lhs = register_logical_value(&state, *rn, *reg_width);
            let rhs = eval_logical_operand(&state, rm, *reg_width);
            let result = lhs.bvand(&rhs);
            let (n, z, c, v) = compute_flags_logical(&result, op_width);
            state.set_flags(n, z, c, v);
        }
        // CCMP / CCMN: ITE between freshly-computed sub/add NZCV (true branch)
        // and the unpacked 4-bit immediate (false branch), gated on the
        // current symbolic NZCV-derived predicate.
        Instruction::Ccmp { rn, rm, nzcv, cond } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n_t, z_t, c_t, v_t) = compute_flags_sub(&lhs, &rhs, width);
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
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
            let (n_t, z_t, c_t, v_t) = compute_flags_add(&lhs, &rhs, width);
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
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
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_v));
        }
        Instruction::Csinc { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_plus_one = state.get_register(*rm).bvadd(BV::from_u64(1, width));
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_plus_one));
        }
        Instruction::Csinv { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_not = state.get_register(*rm).bvnot();
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
            state.set_register(*rd, pred.ite(&rn_v, &rm_not));
        }
        Instruction::Csneg { rd, rn, rm, cond } => {
            let rn_v = state.get_register(*rn).clone();
            let rm_neg = state.get_register(*rm).bvneg();
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
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
            let zero = BV::from_u64(0, width);
            let value = zero.bvsub(&rhs);
            let (n, z, c, v) = compute_flags_sub(&zero, &rhs, width);
            state.set_register(*rd, value);
            state.set_flags(n, z, c, v);
        }
        Instruction::MovN { rd, imm, shift } => {
            let value = !((*imm as u64) << (*shift as u32));
            state.set_register(*rd, BV::from_u64(value, width));
        }
        Instruction::MovZ { rd, imm, shift } => {
            let value = (*imm as u64) << (*shift as u32);
            state.set_register(*rd, BV::from_u64(value, width));
        }
        // MOVK keeps the 48 unwritten bits of rd. Encode as
        // `(rd_old & ~mask) | new_chunk` so the solver sees the data-flow
        // dependence on the prior rd value.
        Instruction::MovK { rd, imm, shift } => {
            let prev = state.get_register(*rd).clone();
            let mask = BV::from_u64(!(0xFFFF_u64 << (*shift as u32)), width);
            let new_chunk = BV::from_u64((*imm as u64) << (*shift as u32), width);
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
            let (n, z, c, v) = compute_flags_logical(&result, width);
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
            let (n, z, c, v) = compute_flags_add(&lhs, &rhs, width);
            state.set_register(*rd, lhs.bvadd(&rhs));
            state.set_flags(n, z, c, v);
        }
        Instruction::Subs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let (n, z, c, v) = compute_flags_sub(&lhs, &rhs, width);
            state.set_register(*rd, lhs.bvsub(&rhs));
            state.set_flags(n, z, c, v);
        }
        // Add with carry: rd = rn + rm + C (1-bit carry widened to `width`).
        Instruction::Adc { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let carry = state.get_flags().2.clone();
            state.set_register(*rd, lhs.bvadd(&rhs).bvadd(carry.zero_ext(width - 1)));
        }
        Instruction::Adcs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let carry = state.get_flags().2.clone();
            let (n, z, c, v) = compute_flags_adc(&lhs, &rhs, &carry, width);
            state.set_register(*rd, lhs.bvadd(&rhs).bvadd(carry.zero_ext(width - 1)));
            state.set_flags(n, z, c, v);
        }
        // Subtract with carry: rd = rn + NOT(rm) + C.
        Instruction::Sbc { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let carry = state.get_flags().2.clone();
            state.set_register(*rd, lhs.bvadd(rhs.bvnot()).bvadd(carry.zero_ext(width - 1)));
        }
        Instruction::Sbcs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.get_register(*rm).clone();
            let carry = state.get_flags().2.clone();
            let (n, z, c, v) = compute_flags_sbc(&lhs, &rhs, &carry, width);
            state.set_register(*rd, lhs.bvadd(rhs.bvnot()).bvadd(carry.zero_ext(width - 1)));
            state.set_flags(n, z, c, v);
        }
        Instruction::Ands {
            rd,
            rn,
            rm,
            width: reg_width,
        } => {
            let op_width = logical_smt_width(*reg_width, width);
            let lhs = register_logical_value(&state, *rn, *reg_width);
            let rhs = eval_logical_operand(&state, rm, *reg_width);
            let result = lhs.bvand(&rhs);
            let (n, z, c, v) = compute_flags_logical(&result, op_width);
            state.set_register(*rd, zero_extend_to_state_width(result, op_width, width));
            state.set_flags(n, z, c, v);
        }
        // CSET / CSETM: rd = cond ? 1 : 0 (or all-ones for CSETM).
        Instruction::Cset { rd, cond } => {
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
            let one = BV::from_u64(1, width);
            let zero = BV::from_u64(0, width);
            state.set_register(*rd, pred.ite(&one, &zero));
        }
        Instruction::Csetm { rd, cond } => {
            let pred = condition_to_smt(*cond, &state.n, &state.z, &state.c, &state.v).eq(bv_one());
            let ones = BV::from_i64(-1, width); // all-ones at any width
            let zero = BV::from_u64(0, width);
            state.set_register(*rd, pred.ite(&ones, &zero));
        }
        // ROR: composed via the width-aware bv_ror helper.
        Instruction::Ror { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let n = state.eval_operand(shift);
            state.set_register(*rd, bv_ror(&value, &n, width));
        }
        // CLZ: count leading zero bits; returns `width` when the value is zero.
        Instruction::Clz { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_clz(&value, width));
        }
        // CLS: count leading sign-bit replicas (excluding the sign bit).
        // Fold the sign bit out via `x XOR (x ASR (width-1))` so the answer
        // reduces to `clz(folded) - 1`. Bit width-1 of `folded` is always 0,
        // so `bv_clz(folded) ∈ [1, width]` and the subtraction lands in
        // `[0, width-1]` — `bvsub` never wraps. For all-sign inputs (0 or -1)
        // folded is zero, clz is `width`, and the result is `width - 1`.
        Instruction::Cls { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let asr = value.bvashr(BV::from_u64((width - 1) as u64, width));
            let folded = value.bvxor(&asr);
            let clz = bv_clz(&folded, width);
            let result = clz.bvsub(BV::from_u64(1, width));
            state.set_register(*rd, result);
        }
        // RBIT: reverse the bits of the value.
        Instruction::Rbit { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_reverse_bits(&value, width));
        }
        // REV: byte-reverse the value.
        Instruction::Rev { rd, rn } => {
            let value = state.get_register(*rn).clone();
            state.set_register(*rd, bv_swap_bytes(&value, width));
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
                    acc = acc.concat(h.extract(l + 7, l));
                }
                acc
            };
            let result = rev_half(&hi).concat(rev_half(&lo));
            state.set_register(*rd, result);
        }
        // REV16: byte-reverse within each 16-bit half (four halves).
        Instruction::Rev16 { rd, rn } => {
            let value = state.get_register(*rn).clone();
            // For each of the 4 half-words, swap its high and low byte.
            let swap_half = |start: u32| -> BV {
                value
                    .extract(start + 7, start)
                    .concat(value.extract(start + 15, start + 8))
            };
            let h3 = swap_half(48);
            let h2 = swap_half(32);
            let h1 = swap_half(16);
            let h0 = swap_half(0);
            let result = h3.concat(&h2).concat(&h1).concat(&h0);
            state.set_register(*rd, result);
        }
        // SXTB/SXTH/SXTW: extract low N bits, sign-extend to 64. Issue #60.
        // UXTB/UXTH: extract low N bits, zero-extend to 64. Issue #60.
        Instruction::Sxtb { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let result = value.extract(7, 0).sign_ext(56);
            state.set_register(*rd, result);
        }
        Instruction::Sxth { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let result = value.extract(15, 0).sign_ext(48);
            state.set_register(*rd, result);
        }
        Instruction::Sxtw { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let result = value.extract(31, 0).sign_ext(32);
            state.set_register(*rd, result);
        }
        Instruction::Uxtb { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let result = value.extract(7, 0).zero_ext(56);
            state.set_register(*rd, result);
        }
        Instruction::Uxth { rd, rn } => {
            let value = state.get_register(*rn).clone();
            let result = value.extract(15, 0).zero_ext(48);
            state.set_register(*rd, result);
        }
        // UBFX rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // zero-extend the result into rd.
        Instruction::Ubfx {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let value = state.get_register(*rn).clone();
            let hi = (*lsb as u32) + (*width as u32) - 1;
            let lo = *lsb as u32;
            let extracted = value.extract(hi, lo);
            // zero_extend by (64 - width); width=64 is a no-op.
            let result = if *width == 64 {
                extracted
            } else {
                extracted.zero_ext(64 - *width as u32)
            };
            store_bitfield_result(&mut state, *rd, result, *reg_width);
        }
        // SBFX rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // sign-extend into rd.
        Instruction::Sbfx {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let value = state.get_register(*rn).clone();
            let hi = (*lsb as u32) + (*width as u32) - 1;
            let lo = *lsb as u32;
            let extracted = value.extract(hi, lo);
            let result = if *width == 64 {
                extracted
            } else {
                extracted.sign_ext(64 - *width as u32)
            };
            store_bitfield_result(&mut state, *rd, result, *reg_width);
        }
        // BFI rd, rn, #lsb, #width: insert low `width` bits of rn at position
        // lsb of rd, preserving the other bits of rd.
        Instruction::Bfi {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let dest = state.get_register(*rd).clone();
            let src = state.get_register(*rn).clone();
            let low_mask_const = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let shifted_mask_const = low_mask_const << *lsb;
            let low_mask = BV::from_u64(low_mask_const, 64);
            let clear_mask = BV::from_u64(!shifted_mask_const, 64);
            let shift = BV::from_u64(*lsb as u64, 64);
            let inserted = src.bvand(&low_mask).bvshl(&shift);
            let cleared = dest.bvand(&clear_mask);
            store_bitfield_result(&mut state, *rd, cleared.bvor(&inserted), *reg_width);
        }
        // BFXIL rd, rn, #lsb, #width: extract bits [lsb+width-1:lsb] of rn,
        // place at [width-1:0] of rd preserving rd[63:width].
        Instruction::Bfxil {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let dest = state.get_register(*rd).clone();
            let src = state.get_register(*rn).clone();
            let low_mask_const = if *width == 64 {
                u64::MAX
            } else {
                (1u64 << *width) - 1
            };
            let low_mask = BV::from_u64(low_mask_const, 64);
            let clear_mask = BV::from_u64(!low_mask_const, 64);
            let shift = BV::from_u64(*lsb as u64, 64);
            // (rn >> lsb) & low_mask
            let extracted = src.bvlshr(&shift).bvand(&low_mask);
            let cleared = dest.bvand(&clear_mask);
            store_bitfield_result(&mut state, *rd, cleared.bvor(&extracted), *reg_width);
        }
        // UBFIZ rd, rn, #lsb, #width: low `width` bits of rn, zero-extend,
        // shift left by lsb → rd (other bits zero).
        Instruction::Ubfiz {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let value = state.get_register(*rn).clone();
            let field = value.extract(*width as u32 - 1, 0);
            let widened = if *width == 64 {
                field
            } else {
                field.zero_ext(64 - *width as u32)
            };
            let shift = BV::from_u64(*lsb as u64, 64);
            store_bitfield_result(&mut state, *rd, widened.bvshl(&shift), *reg_width);
        }
        // SBFIZ rd, rn, #lsb, #width: low `width` bits of rn, sign-extended
        // to 64, then shifted left by lsb → rd.
        Instruction::Sbfiz {
            rd,
            rn,
            lsb,
            width,
            reg_width,
        } => {
            let value = state.get_register(*rn).clone();
            let field = value.extract(*width as u32 - 1, 0);
            let widened = if *width == 64 {
                field
            } else {
                field.sign_ext(64 - *width as u32)
            };
            let shift = BV::from_u64(*lsb as u64, 64);
            store_bitfield_result(&mut state, *rd, widened.bvshl(&shift), *reg_width);
        }
        // Branches / terminators: callers must strip terminators before
        // apply_sequence. The equivalence layer handles them via
        // identity-check, not by symbolic execution.
        Instruction::B { .. }
        | Instruction::BCond { .. }
        | Instruction::Ret { .. }
        | Instruction::Cbz { .. }
        | Instruction::Cbnz { .. }
        | Instruction::Tbz { .. }
        | Instruction::Tbnz { .. }
        | Instruction::Bl { .. }
        | Instruction::Br { .. } => unreachable!(
            "Branches are terminators; strip them before SMT apply_sequence. Reached: {:?}",
            instruction
        ),
        // Memory ops (issue #68). SMT lowering arrives in step 7 alongside
        // the `Array<BV64, BV8>` field on `MachineState`.
        Instruction::Ldr { rt, addr, width } => {
            let (effective, writeback) = state.eval_address(addr);
            let raw = state.select_n(&effective, width.bytes());
            let extended = ldr_zero_extend(&raw, *width, state.width);
            state.set_register(*rt, extended);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, new_base);
            }
        }
        Instruction::Ldrs { rt, addr, width } => {
            let (effective, writeback) = state.eval_address(addr);
            let raw = state.select_n(&effective, width.bytes());
            let extended = ldr_sign_extend(&raw, *width, state.width);
            state.set_register(*rt, extended);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, new_base);
            }
        }
        Instruction::Str { rt, addr, width } => {
            let (effective, writeback) = state.eval_address(addr);
            let value = state.get_register(*rt).clone();
            let bits = width.bytes() * 8;
            let low = value.extract(bits - 1, 0);
            state.store_n(&effective, &low, width.bytes());
            if let Some((base, new_base)) = writeback {
                state.set_register(base, new_base);
            }
        }
        Instruction::Ldp {
            rt1,
            rt2,
            addr,
            width,
            signed,
        } => {
            let (effective, writeback) = state.eval_address(addr);
            let access_width = (*width).as_access_width();
            let bytes = width.bytes();
            let raw1 = state.select_n(&effective, bytes);
            let offset = BV::from_u64(bytes as u64, 64);
            let effective2 = effective.bvadd(&offset);
            let raw2 = state.select_n(&effective2, bytes);
            let (v1, v2) = if *signed {
                (
                    ldr_sign_extend(&raw1, access_width, state.width),
                    ldr_sign_extend(&raw2, access_width, state.width),
                )
            } else {
                (
                    ldr_zero_extend(&raw1, access_width, state.width),
                    ldr_zero_extend(&raw2, access_width, state.width),
                )
            };
            state.set_register(*rt1, v1);
            state.set_register(*rt2, v2);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, new_base);
            }
        }
        Instruction::Stp {
            rt1,
            rt2,
            addr,
            width,
        } => {
            let (effective, writeback) = state.eval_address(addr);
            let bytes = width.bytes();
            let bits = bytes * 8;
            let v1 = state.get_register(*rt1).clone();
            let v2 = state.get_register(*rt2).clone();
            let low1 = v1.extract(bits - 1, 0);
            let low2 = v2.extract(bits - 1, 0);
            state.store_n(&effective, &low1, bytes);
            let offset = BV::from_u64(bytes as u64, 64);
            let effective2 = effective.bvadd(&offset);
            state.store_n(&effective2, &low2, bytes);
            if let Some((base, new_base)) = writeback {
                state.set_register(base, new_base);
            }
        }
    }
    state
}

/// Zero-extend the low `width.bytes() * 8` bits of `raw` to `target_width`.
fn ldr_zero_extend(raw: &BV, width: AccessWidth, target_width: u32) -> BV {
    let raw_bits = width.bytes() * 8;
    assert!(
        raw_bits <= target_width,
        "raw load width {raw_bits} exceeds target register width {target_width}"
    );
    let pad = target_width - raw_bits;
    if pad == 0 {
        raw.clone()
    } else {
        raw.zero_ext(pad)
    }
}

/// Sign-extend the low `width.bytes() * 8` bits of `raw` to `target_width`.
fn ldr_sign_extend(raw: &BV, width: AccessWidth, target_width: u32) -> BV {
    let raw_bits = width.bytes() * 8;
    assert!(
        raw_bits <= target_width,
        "raw load width {raw_bits} exceeds target register width {target_width}"
    );
    let pad = target_width - raw_bits;
    if pad == 0 {
        raw.clone()
    } else {
        raw.sign_ext(pad)
    }
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

    for i in 0..32 {
        let register = VectorRegister::from_index(i).expect("valid vector register index");
        let vector_not_equal = state1
            .get_vector(register)
            .eq(state2.get_vector(register))
            .not();
        not_equal = z3::ast::Bool::or(&[&not_equal, &vector_not_equal]);
    }

    // And the NZCV flag bits and the whole memory array.
    not_equal = z3::ast::Bool::or(&[&not_equal, &flags_not_equal(state1, state2)]);
    z3::ast::Bool::or(&[&not_equal, &state1.memory.eq(&state2.memory).not()])
}

/// Check if two machine states are not equal for the specified live-out
/// contract, including the NZCV flag bits when `live_out.flags_live()` is set
/// and the whole memory image when `memory_live` is set (see ADR-0007).
pub fn states_not_equal_for_live_out(
    state1: &MachineState,
    state2: &MachineState,
    live_out: &RegisterSet<Register>,
    memory_live: bool,
) -> z3::ast::Bool {
    let mut not_equal = z3::ast::Bool::from_bool(false);

    for reg in live_out.iter() {
        let (val1, val2) = match reg {
            Register::Vector(register) => {
                (state1.get_vector(*register), state2.get_vector(*register))
            }
            _ => (state1.get_register(*reg), state2.get_register(*reg)),
        };
        let reg_not_equal = val1.eq(val2).not();
        not_equal = z3::ast::Bool::or(&[&not_equal, &reg_not_equal]);
    }

    if live_out.flags_live() {
        not_equal = z3::ast::Bool::or(&[&not_equal, &flags_not_equal(state1, state2)]);
    }

    if memory_live {
        not_equal = z3::ast::Bool::or(&[&not_equal, &state1.memory.eq(&state2.memory).not()]);
    }

    not_equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{SatResult, Solver};

    fn max_nested_ite_depth(smt: &str) -> usize {
        let bytes = smt.as_bytes();
        let mut paren_depth = 0usize;
        let mut ite_paren_depths = Vec::new();
        let mut max_depth = 0usize;
        let mut i = 0usize;

        while i < bytes.len() {
            match bytes[i] {
                b'(' => {
                    paren_depth += 1;
                    if is_ite_head(bytes, i) {
                        ite_paren_depths.push(paren_depth);
                        max_depth = max_depth.max(ite_paren_depths.len());
                    }
                    i += 1;
                }
                b')' => {
                    while ite_paren_depths.last().copied() == Some(paren_depth) {
                        ite_paren_depths.pop();
                    }
                    paren_depth = paren_depth.saturating_sub(1);
                    i += 1;
                }
                _ => i += 1,
            }
        }

        max_depth
    }

    fn is_ite_head(bytes: &[u8], open_paren: usize) -> bool {
        matches!(bytes.get(open_paren + 1..open_paren + 4), Some(b"ite"))
            && bytes
                .get(open_paren + 4)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b')')
    }

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
            width: crate::ir::RegisterWidth::X64,
        }];
        let state2 = apply_sequence(initial_state, &seq2);

        // Assert states are not equal
        solver.assert(states_not_equal(&state1, &state2));

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
                width: crate::ir::RegisterWidth::X64,
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
            width: crate::ir::RegisterWidth::X64,
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
        solver.assert(x0_val.eq(&expected).not());
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
        solver.assert(final_x0.eq(&initial_x1).not());
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
        solver.assert(states_not_equal(&state_csel, &state_mov));
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
        solver.assert(final_x0.eq(&initial_x1).not());
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
    fn test_cls_equivalent_to_clz_of_signfold() {
        let initial = MachineState::new_symbolic("pre");

        let cls = vec![Instruction::Cls {
            rd: Register::X0,
            rn: Register::X1,
        }];
        let signfold_clz = vec![
            Instruction::Asr {
                rd: Register::X10,
                rn: Register::X1,
                shift: Operand::Immediate(63),
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X10),
                width: crate::ir::RegisterWidth::X64,
            },
            Instruction::Clz {
                rd: Register::X0,
                rn: Register::X0,
            },
            Instruction::MovImm {
                rd: Register::X11,
                imm: 1,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Register(Register::X11),
            },
        ];

        let state_cls = apply_sequence(initial.clone(), &cls);
        let state_signfold_clz = apply_sequence(initial, &signfold_clz);
        let live_out = RegisterSet::<Register>::from_registers(vec![Register::X0]);

        let solver = Solver::new();
        let diseq =
            states_not_equal_for_live_out(&state_cls, &state_signfold_clz, &live_out, false);
        solver.assert(diseq);
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "CLS(x) should match CLZ(x XOR (x ASR 63)) - 1 for live-out X0"
        );
    }

    #[test]
    fn test_states_not_equal_for_live_out_reads_flags_from_mask() {
        let state1 = MachineState::new_symbolic("flag_mask_a");
        let state2 = MachineState::new_symbolic("flag_mask_b");
        let live_out = RegisterSet::<Register>::empty();

        let solver = Solver::new();
        solver.assert(states_not_equal_for_live_out(
            &state1, &state2, &live_out, false,
        ));
        assert_eq!(solver.check(), SatResult::Unsat);

        let solver = Solver::new();
        solver.assert(states_not_equal_for_live_out(
            &state1,
            &state2,
            &live_out.with_flags(true),
            false,
        ));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_extended_register_acceptance_uxtb() {
        // Issue #60 acceptance: SMT proves
        //   UXTB x10, x2 ; ADD x0, x1, x10
        // ≡ ADD x0, x1, x2, UXTB #0
        // (modulo the temp x10 — restrict the equivalence to the live-out
        // x0). The split sequence relies on the standalone UXTB
        // instruction added in earlier slices; the fused sequence uses
        // the new Operand::ExtendedRegister form.
        let initial = MachineState::new_symbolic("pre");

        let seq_split = vec![
            Instruction::Uxtb {
                rd: Register::X10,
                rn: Register::X2,
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
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: crate::ir::ExtendKind::Uxtb,
                shift: 0,
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
    fn test_extended_register_acceptance_sxth_with_shift() {
        // Issue #60: signed halfword extend with non-zero shift.
        //   SXTH x10, x2 ; LSL x10, x10, #3 ; ADD x0, x1, x10
        // ≡ ADD x0, x1, x2, SXTH #3
        // The split form needs an extra LSL because the standalone SXTH
        // doesn't carry a shift; the fused form folds both into one arith.
        let initial = MachineState::new_symbolic("pre");

        let seq_split = vec![
            Instruction::Sxth {
                rd: Register::X10,
                rn: Register::X2,
            },
            Instruction::Lsl {
                rd: Register::X10,
                rn: Register::X10,
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
            rm: Operand::ExtendedRegister {
                reg: Register::X2,
                kind: crate::ir::ExtendKind::Sxth,
                shift: 3,
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
    fn test_uxtb_extracts_low_byte() {
        // UXTB extracts the low 8 bits of the source and zero-extends to 64.
        // MOV x1, #0x5678; UXTB x0, x1  ≡  MOV x0, #0x78.
        let initial = MachineState::new_symbolic("pre");
        let seq = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 0x5678,
            },
            Instruction::Uxtb {
                rd: Register::X0,
                rn: Register::X1,
            },
        ];
        let final_state = apply_sequence(initial, &seq);
        let final_x0 = final_state.get_register(Register::X0);
        let solver = Solver::new();
        solver.assert(final_x0.eq(BV::from_u64(0x78, 64)).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "UXTB(0x5678) must be 0x78"
        );
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
        solver.assert(final_x0.eq(BV::from_u64(63, 64)).not());
        assert_eq!(solver.check(), SatResult::Unsat, "CLZ(1) must be 63");
    }

    #[test]
    fn test_bv_clz_formula_has_logarithmic_ite_depth() {
        let value = BV::new_const("x", 64);
        let clz = bv_clz(&value, 64);
        let smt = clz.to_string();

        assert!(
            max_nested_ite_depth(&smt) <= 16,
            "CLZ SMT term should be logarithmic-depth, got nested ite depth {}",
            max_nested_ite_depth(&smt)
        );
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
        solver.assert(n1.eq(n2).not());
        solver.assert(z1.eq(z2).not());
        solver.assert(c1.eq(c2).not());
        solver.assert(v1.eq(v2).not());
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
        let expected = compute_flags_sub(&x0, &x1, 64);
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
        solver.assert(state.get_register(reg).eq(expected).not());
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
        solver.assert(states_not_equal(&s1, &s2));
        assert_eq!(solver.check(), SatResult::Sat);
    }

    #[test]
    fn test_csel_nv_evaluates_as_always_true() {
        // Regression for the soundness gap caught by review on PR #128:
        // `condition_holds(NV)` is true per ARM ARM (NV is the reserved
        // encoding, not a real "never"). is_encodable_aarch64 permits NV
        // for the CSEL family, so the SMT predicate must agree with the
        // concrete interpreter (which already returns true for NV).
        //
        // `CSINC x0, x1, x2, NV` must select rn=x1 in both interpreters.
        let mut state = MachineState::new_symbolic("pre");
        // Force flags to a state where ConditionFlags::evaluate would
        // disagree if NV were treated as false somewhere.
        force_flags(&mut state, 0, 0, 0, 0);
        state.set_register(Register::X1, BV::from_u64(7, 64));
        state.set_register(Register::X2, BV::from_u64(2, 64));
        let after = apply_instruction(
            state,
            &Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: crate::ir::types::Condition::NV,
            },
        );
        assert_register_eq(
            &after,
            Register::X0,
            &BV::from_u64(7, 64),
            "CSINC NV must select rn (always-true predicate)",
        );
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
        let expected = compute_flags_sub(&x1, &x2, 64);
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
        let expected = compute_flags_add(&x1, &x2, 64);
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
                compute_flags_add(&x0, &x1, 64),
                "CMN x0, x1",
            ),
            (
                Instruction::Tst {
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                    width: crate::ir::RegisterWidth::X64,
                },
                compute_flags_logical(&x0.bvand(&x1), 64),
                "TST x0, x1",
            ),
            (
                Instruction::Adds {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_add(&x0, &x1, 64),
                "ADDS x2, x0, x1",
            ),
            (
                Instruction::Subs {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_sub(&x0, &x1, 64),
                "SUBS x2, x0, x1",
            ),
            (
                Instruction::Ands {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                    width: crate::ir::RegisterWidth::X64,
                },
                compute_flags_logical(&x0.bvand(&x1), 64),
                "ANDS x2, x0, x1",
            ),
            (
                Instruction::Negs {
                    rd: Register::X2,
                    rm: Register::X1,
                },
                compute_flags_sub(&BV::from_u64(0, 64), &x1, 64),
                "NEGS x2, x1",
            ),
            (
                Instruction::Bics {
                    rd: Register::X2,
                    rn: Register::X0,
                    rm: rm_reg.clone(),
                },
                compute_flags_logical(&x0.bvand(x1.bvnot()), 64),
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
                compute_flags_sub(&lhs, &rhs, 64),
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
                compute_flags_add(&lhs, &rhs, 64),
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
                compute_flags_logical(&result, 64),
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
                solver.assert(smt.eq(&expected_bv).not());
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

    #[test]
    fn first_neon_slice_concrete_and_smt_semantics_agree() {
        use crate::semantics::concrete::apply_instruction_concrete;
        use crate::semantics::state::ConcreteMachineState;

        fn bv128(value: u128) -> BV {
            BV::from_u64((value >> 64) as u64, 64).concat(BV::from_u64(value as u64, 64))
        }

        let lhs = 0xffff_ffff_0000_0001_ffff_ffff_ffff_ffff;
        let rhs = 0x0000_0001_ffff_ffff_0000_0001_0000_0001;
        for arrangement in [VectorArrangement::TwoD, VectorArrangement::FourS] {
            let instruction = Instruction::VectorAdd {
                vd: VectorRegister::V0,
                vn: VectorRegister::V1,
                vm: VectorRegister::V2,
                arrangement,
            };
            let mut concrete_pre = ConcreteMachineState::new_zeroed();
            concrete_pre.set_vector(VectorRegister::V1, lhs);
            concrete_pre.set_vector(VectorRegister::V2, rhs);
            let concrete_post = apply_instruction_concrete(concrete_pre, &instruction);

            let symbolic_pre = MachineState::new_symbolic("neon_add_pre");
            let solver = Solver::new();
            solver.assert(symbolic_pre.get_vector(VectorRegister::V1).eq(bv128(lhs)));
            solver.assert(symbolic_pre.get_vector(VectorRegister::V2).eq(bv128(rhs)));
            let symbolic_post = apply_instruction(symbolic_pre, &instruction);
            solver.assert(
                symbolic_post
                    .get_vector(VectorRegister::V0)
                    .eq(bv128(concrete_post.get_vector(VectorRegister::V0)))
                    .not(),
            );
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "vector add parity failed for {arrangement}"
            );
        }

        let packed = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef;
        for lane in 0..2 {
            let instruction = Instruction::MovFromVectorLane {
                rd: Register::X0,
                vn: VectorRegister::V1,
                lane,
            };
            let mut concrete_pre = ConcreteMachineState::new_zeroed();
            concrete_pre.set_vector(VectorRegister::V1, packed);
            let concrete_post = apply_instruction_concrete(concrete_pre, &instruction);

            let symbolic_pre = MachineState::new_symbolic("neon_lane_pre");
            let solver = Solver::new();
            solver.assert(
                symbolic_pre
                    .get_vector(VectorRegister::V1)
                    .eq(bv128(packed)),
            );
            let symbolic_post = apply_instruction(symbolic_pre, &instruction);
            solver.assert(
                symbolic_post
                    .get_register(Register::X0)
                    .eq(BV::from_u64(
                        concrete_post.get_register(Register::X0).as_u64(),
                        64,
                    ))
                    .not(),
            );
            assert_eq!(
                solver.check(),
                SatResult::Unsat,
                "vector lane extract parity failed for lane {lane}"
            );
        }
    }

    // Issue #77 Stage 1 / Step 2 safety nets:
    // per-opcode concrete-vs-SMT parity tests. Each test pins symbolic pre-state
    // values to sampled concrete inputs, runs both interpreters, and asserts
    // Z3 forces the symbolic post-state to agree with the concrete result.
    // The width-aware refactor in Stage 1 Step 6 must keep these passing.

    /// Pin every (register, value) in `pre_values` on both the concrete and
    /// symbolic pre-state, run each interpreter on `instr`, and assert Z3 is
    /// forced to agree with the concrete result for `dest`.
    fn assert_concrete_smt_parity(
        instr: &Instruction,
        pre_values: &[(Register, u64)],
        dest: Register,
    ) {
        use crate::semantics::concrete::apply_instruction_concrete;
        use crate::semantics::state::{ConcreteMachineState, ConcreteValue};

        let mut concrete_pre = ConcreteMachineState::new_zeroed();
        for &(reg, val) in pre_values {
            concrete_pre.set_register(reg, ConcreteValue::new(val));
        }
        let concrete_post = apply_instruction_concrete(concrete_pre, instr);
        let concrete_dest = concrete_post.get_register(dest).as_u64();

        let symbolic_pre = MachineState::new_symbolic("pre");
        let solver = Solver::new();
        for &(reg, val) in pre_values {
            solver.assert(symbolic_pre.get_register(reg).eq(BV::from_u64(val, 64)));
        }
        let symbolic_post = apply_instruction(symbolic_pre, instr);
        solver.assert(
            symbolic_post
                .get_register(dest)
                .eq(BV::from_u64(concrete_dest, 64))
                .not(),
        );

        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "concrete/SMT parity violation: {:?} with pre={:x?} yields concrete \
             {}={:#018x}, but SMT permits a different value",
            instr,
            pre_values,
            dest,
            concrete_dest,
        );
    }

    /// Extended parity helper supporting flag pre-state and flag post-state
    /// agreement. Used by flag-setting (CMP/CMN/TST/ADDS/SUBS/ANDS/BICS/NEGS),
    /// conditional (CSEL/CSINC/CSINV/CSNEG/CSET/CSETM), and flag+condition
    /// (CCMP/CCMN) opcodes.
    fn assert_concrete_smt_parity_full(
        instr: &Instruction,
        pre_values: &[(Register, u64)],
        pre_flags: Option<crate::semantics::state::ConditionFlags>,
        dest: Option<Register>,
        check_post_flags: bool,
    ) {
        use crate::semantics::concrete::apply_instruction_concrete;
        use crate::semantics::state::{ConcreteMachineState, ConcreteValue};

        let mut concrete_pre = ConcreteMachineState::new_zeroed();
        for &(reg, val) in pre_values {
            concrete_pre.set_register(reg, ConcreteValue::new(val));
        }
        if let Some(flags) = pre_flags.clone() {
            concrete_pre.set_flags(flags);
        }
        let concrete_post = apply_instruction_concrete(concrete_pre, instr);

        let symbolic_pre = MachineState::new_symbolic("pre");
        let solver = Solver::new();
        for &(reg, val) in pre_values {
            solver.assert(symbolic_pre.get_register(reg).eq(BV::from_u64(val, 64)));
        }
        if let Some(flags) = &pre_flags {
            solver.assert(symbolic_pre.n.eq(BV::from_u64(flags.n as u64, 1)));
            solver.assert(symbolic_pre.z.eq(BV::from_u64(flags.z as u64, 1)));
            solver.assert(symbolic_pre.c.eq(BV::from_u64(flags.c as u64, 1)));
            solver.assert(symbolic_pre.v.eq(BV::from_u64(flags.v as u64, 1)));
        }
        let symbolic_post = apply_instruction(symbolic_pre, instr);

        let mut disagreements: Vec<z3::ast::Bool> = Vec::new();
        if let Some(d) = dest {
            let expected = BV::from_u64(concrete_post.get_register(d).as_u64(), 64);
            disagreements.push(symbolic_post.get_register(d).eq(&expected).not());
        }
        if check_post_flags {
            let cf = concrete_post.get_flags();
            disagreements.push(symbolic_post.n.eq(BV::from_u64(cf.n as u64, 1)).not());
            disagreements.push(symbolic_post.z.eq(BV::from_u64(cf.z as u64, 1)).not());
            disagreements.push(symbolic_post.c.eq(BV::from_u64(cf.c as u64, 1)).not());
            disagreements.push(symbolic_post.v.eq(BV::from_u64(cf.v as u64, 1)).not());
        }
        assert!(
            !disagreements.is_empty(),
            "assert_concrete_smt_parity_full needs either dest or check_post_flags"
        );
        let refs: Vec<&z3::ast::Bool> = disagreements.iter().collect();
        solver.assert(z3::ast::Bool::or(&refs));

        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "concrete/SMT parity violation: {:?} pre={:x?} pre_flags={:?}",
            instr,
            pre_values,
            pre_flags,
        );
    }

    #[test]
    fn test_mov_reg_concrete_smt_parity() {
        let instr = Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        };
        let samples: &[u64] = &[
            0,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        for &v1 in samples {
            assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
        }
    }

    #[test]
    fn test_add_reg_concrete_smt_parity() {
        let instr = Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        // Pairs chosen to exercise: zero, wraparound across 2^64, sign-flip,
        // and a generic non-canonical pair.
        let samples: &[(u64, u64)] = &[
            (0, 0),
            (1, 0xFFFF_FFFF_FFFF_FFFF),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_sub_reg_concrete_smt_parity() {
        let instr = Instruction::Sub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        // Underflow, equal-args (zero result), sign-flip, and a generic pair.
        let samples: &[(u64, u64)] = &[
            (0, 1),
            (0x1234_5678_9ABC_DEF0, 0x1234_5678_9ABC_DEF0),
            (0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_and_reg_concrete_smt_parity() {
        let instr = Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_orr_reg_concrete_smt_parity() {
        let instr = Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (0x8000_0000_0000_0000, 0x0000_0000_0000_0001),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_eor_reg_concrete_smt_parity() {
        let instr = Instruction::Eor {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_w32_logical_immediate_concrete_smt_parity() {
        for (instr, pre) in [
            (
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                0xFFFF_FFFF_1234_00FF,
            ),
            (
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0x0F),
                    width: RegisterWidth::W32,
                },
                0xFFFF_FFFF_0000_00F0,
            ),
            (
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::Immediate(0xFF),
                    width: RegisterWidth::W32,
                },
                0xFFFF_FFFF_FFFF_00FF,
            ),
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, pre)], Register::X0);
        }
    }

    #[test]
    fn test_w32_logical_shifted_register_concrete_smt_parity() {
        for (instr, pre_values) in [
            (
                Instruction::And {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: crate::ir::ShiftKind::Lsr,
                        amount: 1,
                    },
                    width: RegisterWidth::W32,
                },
                vec![
                    (Register::X1, 0xFFFF_FFFF),
                    (Register::X2, 0x0000_0001_0000_0000),
                ],
            ),
            (
                Instruction::Orr {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: crate::ir::ShiftKind::Asr,
                        amount: 31,
                    },
                    width: RegisterWidth::W32,
                },
                vec![(Register::X1, 0), (Register::X2, 0x0000_0001_8000_0000)],
            ),
            (
                Instruction::Eor {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: crate::ir::ShiftKind::Ror,
                        amount: 1,
                    },
                    width: RegisterWidth::W32,
                },
                vec![(Register::X1, 0), (Register::X2, 0x0000_0001_0000_0000)],
            ),
        ] {
            assert_concrete_smt_parity(&instr, &pre_values, Register::X0);
        }
    }

    #[test]
    fn test_lsl_imm_concrete_smt_parity() {
        // LSL is width-sensitive: concrete semantics mask the shift amount
        // with `& 63` before applying. Immediate shifts >= 64 are rejected by
        // parser/encodability paths, but these IR-only samples verify internal
        // concrete/SMT parity for the same issue-#241 mask rule.
        let values: &[u64] = &[
            0,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[i64] = &[0, 1, 5, 16, 32, 63, 64, 65, 127];
        for &v1 in values {
            for &shift in shifts {
                let instr = Instruction::Lsl {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: Operand::Immediate(shift),
                };
                assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
            }
        }
    }

    #[test]
    fn test_lsr_imm_concrete_smt_parity() {
        // Mirror of LSL but logical right shift (no sign extension). The
        // extended immediate samples are IR-only; normal AArch64 input rejects
        // them before optimization.
        let values: &[u64] = &[
            0,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[i64] = &[0, 1, 5, 16, 32, 63, 64, 65, 127];
        for &v1 in values {
            for &shift in shifts {
                let instr = Instruction::Lsr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: Operand::Immediate(shift),
                };
                assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
            }
        }
    }

    #[test]
    fn test_lsl_reg_concrete_smt_parity() {
        // Register-form LSL: shift amount comes from a register and may
        // legitimately hold values >= 64. Issue #241: SMT lowering must
        // mask with `width - 1` to mirror AArch64's `shift & 63`.
        let instr = Instruction::Lsl {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        };
        let values: &[u64] = &[
            0,
            1,
            5,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[u64] = &[0, 1, 5, 63, 64, 65, 127, 128, u64::MAX];
        for &v1 in values {
            for &s in shifts {
                assert_concrete_smt_parity(
                    &instr,
                    &[(Register::X1, v1), (Register::X2, s)],
                    Register::X0,
                );
            }
        }
    }

    #[test]
    fn test_lsr_reg_concrete_smt_parity() {
        // Register-form LSR: mirrors LSL coverage.
        let instr = Instruction::Lsr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        };
        let values: &[u64] = &[
            0,
            1,
            5,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[u64] = &[0, 1, 5, 63, 64, 65, 127, 128, u64::MAX];
        for &v1 in values {
            for &s in shifts {
                assert_concrete_smt_parity(
                    &instr,
                    &[(Register::X1, v1), (Register::X2, s)],
                    Register::X0,
                );
            }
        }
    }

    #[test]
    fn test_asr_reg_concrete_smt_parity() {
        // Register-form ASR exercises sign-fill in addition to the issue
        // #241 mask, so negative dividends are added to the matrix.
        let instr = Instruction::Asr {
            rd: Register::X0,
            rn: Register::X1,
            shift: Operand::Register(Register::X2),
        };
        let values: &[u64] = &[
            0,
            1,
            (-1_i64) as u64,
            (-16_i64) as u64,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[u64] = &[0, 1, 5, 63, 64, 65, 127, 128, u64::MAX];
        for &v1 in values {
            for &s in shifts {
                assert_concrete_smt_parity(
                    &instr,
                    &[(Register::X1, v1), (Register::X2, s)],
                    Register::X0,
                );
            }
        }
    }

    #[test]
    fn test_mul_reg_concrete_smt_parity() {
        // wrapping_mul on the concrete side, Z3 bvmul on the symbolic side.
        // Samples include zero-mul, identity, MSB sign-bit, and overflow pair.
        let instr = Instruction::Mul {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xDEAD_BEEF_CAFE_BABE),
            (1, 0xDEAD_BEEF_CAFE_BABE),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // (-1) * (-1) = 1 in wrapping
            (0x8000_0000_0000_0000, 0x0000_0000_0000_0002), // overflow
            (0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_movz_imm_concrete_smt_parity() {
        // MOVZ: rd = (imm as u64) << shift, all other lanes zero.
        // Shift legality is parser-enforced as {0, 16, 32, 48}; we exercise
        // each lane to catch any width-related lowering bug.
        let imms: &[u16] = &[0, 1, 0x1234, 0xFFFF];
        let shifts: &[u8] = &[0, 16, 32, 48];
        for &imm in imms {
            for &shift in shifts {
                let instr = Instruction::MovZ {
                    rd: Register::X0,
                    imm,
                    shift,
                };
                assert_concrete_smt_parity(&instr, &[], Register::X0);
            }
        }
    }

    #[test]
    fn test_movn_imm_concrete_smt_parity() {
        // MOVN: rd = !((imm as u64) << shift).
        let imms: &[u16] = &[0, 1, 0x1234, 0xFFFF];
        let shifts: &[u8] = &[0, 16, 32, 48];
        for &imm in imms {
            for &shift in shifts {
                let instr = Instruction::MovN {
                    rd: Register::X0,
                    imm,
                    shift,
                };
                assert_concrete_smt_parity(&instr, &[], Register::X0);
            }
        }
    }

    #[test]
    fn test_movk_imm_concrete_smt_parity() {
        // MOVK reads rd before writing one 16-bit chunk. We need to pin a
        // pre-value on X0 so concrete and SMT agree on the kept lanes.
        let pre_values: &[u64] = &[0, 0xFFFF_FFFF_FFFF_FFFF, 0xAAAA_BBBB_CCCC_DDDD];
        let imms: &[u16] = &[0, 0x1234, 0xFFFF];
        let shifts: &[u8] = &[0, 16, 32, 48];
        for &pre in pre_values {
            for &imm in imms {
                for &shift in shifts {
                    let instr = Instruction::MovK {
                        rd: Register::X0,
                        imm,
                        shift,
                    };
                    assert_concrete_smt_parity(&instr, &[(Register::X0, pre)], Register::X0);
                }
            }
        }
    }

    #[test]
    fn test_mov_imm_concrete_smt_parity() {
        // MOV (immediate alias). imm range is [0, 0xFFFF] per the AArch64
        // immediate-form spec; the parser refuses anything wider.
        for imm in &[0_i64, 1, 0x100, 0x1234, 0xFFFF] {
            let instr = Instruction::MovImm {
                rd: Register::X0,
                imm: *imm,
            };
            assert_concrete_smt_parity(&instr, &[], Register::X0);
        }
    }

    #[test]
    fn test_mvn_reg_concrete_smt_parity() {
        let instr = Instruction::Mvn {
            rd: Register::X0,
            rm: Register::X1,
        };
        for v1 in &[0_u64, 0xFFFF_FFFF_FFFF_FFFF, 0xAAAA_AAAA_AAAA_AAAA, 0xDEAD] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_neg_reg_concrete_smt_parity() {
        let instr = Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        };
        for v1 in &[
            0_u64,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0xDEAD,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_bic_reg_concrete_smt_parity() {
        let instr = Instruction::Bic {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0xAAAA_AAAA_AAAA_AAAA),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_orn_reg_concrete_smt_parity() {
        let instr = Instruction::Orn {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_eon_reg_concrete_smt_parity() {
        let instr = Instruction::Eon {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_ror_imm_concrete_smt_parity() {
        // ROR: rotate right; concrete uses `rotate_right(amount & 31)` semantics
        // adjusted for 64-bit (`& 63`). SMT uses bv_ror_64 helper.
        let values: &[u64] = &[
            0,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[i64] = &[0, 1, 8, 32, 63];
        for &v1 in values {
            for &shift in shifts {
                let instr = Instruction::Ror {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: Operand::Immediate(shift),
                };
                assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
            }
        }
    }

    #[test]
    fn test_clz_concrete_smt_parity() {
        // CLZ: count leading zeros. value=0 returns 64.
        let instr = Instruction::Clz {
            rd: Register::X0,
            rn: Register::X1,
        };
        let values: &[u64] = &[
            0,
            1,
            2,
            3,
            0x10,
            1 << 31,
            1 << 32,
            1 << 63,
            0x0000_0000_0000_0080,
            0x0000_0000_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
        ];
        for &v1 in values {
            assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
        }
    }

    #[test]
    fn test_cls_concrete_smt_parity() {
        // CLS: count leading bits that match the sign bit, excluding the sign
        // itself. Returns 63 for 0 or all-ones.
        let instr = Instruction::Cls {
            rd: Register::X0,
            rn: Register::X1,
        };
        let values: &[u64] = &[
            0,                     // all zero -> 63
            0xFFFF_FFFF_FFFF_FFFF, // all one -> 63
            0x8000_0000_0000_0000, // sign-bit only -> 0
            0x4000_0000_0000_0000, // opposite sign after sign bit -> 0
            0xBFFF_FFFF_FFFF_FFFF, // negative opposite sign after sign bit -> 0
            0xC000_0000_0000_0000, // one leading sign replica -> 1
            1,                     // positive sign-fold boundary -> 62
            2,                     // positive sign-fold boundary -> 61
            3,                     // positive sign-fold boundary -> 61
            0x10,                  // positive sign-fold nibble boundary -> 59
            1 << 31,               // positive sign-fold 32-bit boundary -> 31
            1 << 32,               // positive sign-fold 32-bit boundary -> 30
            0xFFFF_FFFF_FFFF_FFFE, // negative sign-fold boundary -> 62
            0xFFFF_FFFF_FFFF_FFFD, // negative sign-fold boundary -> 61
            0xFFFF_FFFF_FFFF_FFEF, // negative sign-fold nibble boundary -> 59
            0xFFFF_FFFF_7FFF_FFFF, // negative sign-fold 32-bit boundary -> 31
            0xFFFF_FFFE_FFFF_FFFF, // negative sign-fold 32-bit boundary -> 30
            0x0000_0000_FFFF_FFFF, // mid run -> 31
        ];
        for &v1 in values {
            assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
        }
    }

    #[test]
    fn test_rbit_concrete_smt_parity() {
        let instr = Instruction::Rbit {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            1,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0x1234_5678_9ABC_DEF0,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_rev_concrete_smt_parity() {
        let instr = Instruction::Rev {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0xFFFF_FFFF_FFFF_FFFF,
            0x1122_3344_5566_7788,
            0x0102_0304_0506_0708,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_rev32_concrete_smt_parity() {
        let instr = Instruction::Rev32 {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0xFFFF_FFFF_FFFF_FFFF,
            0x1122_3344_5566_7788,
            0xDEAD_BEEF_CAFE_BABE,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_rev16_concrete_smt_parity() {
        let instr = Instruction::Rev16 {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0xFFFF_FFFF_FFFF_FFFF,
            0x1122_3344_5566_7788,
            0xDEAD_BEEF_CAFE_BABE,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_uxtb_concrete_smt_parity() {
        let instr = Instruction::Uxtb {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[0_u64, 0x7F, 0x80, 0xFF, 0x1234_5678, 0xFFFF_FFFF_FFFF_FFFF] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_uxth_concrete_smt_parity() {
        let instr = Instruction::Uxth {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0x7FFF,
            0x8000,
            0xFFFF,
            0x1234_5678,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_sxtb_concrete_smt_parity() {
        let instr = Instruction::Sxtb {
            rd: Register::X0,
            rn: Register::X1,
        };
        // 0x7F = +127 stays positive; 0x80 = -128 sign-extends.
        for v1 in &[0_u64, 0x7F, 0x80, 0xFF, 0x1234_5678, 0xFFFF_FFFF_FFFF_FFFF] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_sxth_concrete_smt_parity() {
        let instr = Instruction::Sxth {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0x7FFF,
            0x8000,
            0xFFFF,
            0x1234_5678,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_sxtw_concrete_smt_parity() {
        let instr = Instruction::Sxtw {
            rd: Register::X0,
            rn: Register::X1,
        };
        for v1 in &[
            0_u64,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x1234_5678_9ABC_DEF0,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            assert_concrete_smt_parity(&instr, &[(Register::X1, *v1)], Register::X0);
        }
    }

    #[test]
    fn test_sdiv_concrete_smt_parity() {
        // SDIV with div-by-zero (concrete returns 0; SMT ite-guards on rhs==0)
        // and the i64::MIN / -1 overflow case (concrete returns i64::MIN via
        // checked_div().unwrap_or; SMT bvsdiv wraps the same way).
        let instr = Instruction::Sdiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (10, 3),
            (10, 0),                                        // div-by-zero
            (0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF), // MIN / -1
            (0xFFFF_FFFF_FFFF_FFFF, 1),                     // -1 / 1
            (100, 0xFFFF_FFFF_FFFF_FFFE),                   // pos / -2
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_udiv_concrete_smt_parity() {
        let instr = Instruction::Udiv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (10, 3),
            (10, 0), // div-by-zero
            (0xFFFF_FFFF_FFFF_FFFF, 1),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_madd_concrete_smt_parity() {
        let instr = Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        let samples: &[(u64, u64, u64)] = &[
            (0, 0, 0),
            (2, 3, 5),
            (0xFFFF_FFFF_FFFF_FFFF, 1, 1), // -1*1 + 1 = 0
            (
                0x1234_5678_9ABC_DEF0,
                0x0FED_CBA9_8765_4321,
                0xDEAD_BEEF_CAFE_BABE,
            ),
        ];
        for &(v1, v2, v3) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2), (Register::X3, v3)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_msub_concrete_smt_parity() {
        let instr = Instruction::Msub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X3,
        };
        let samples: &[(u64, u64, u64)] = &[
            (0, 0, 0),
            (2, 3, 10),
            (1, 1, 0),
            (0x1234, 0x5678, 0x9ABC_DEF0),
        ];
        for &(v1, v2, v3) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2), (Register::X3, v3)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_mneg_concrete_smt_parity() {
        let instr = Instruction::Mneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF),
            (2, 3),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0x1234, 0x5678),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_smulh_concrete_smt_parity() {
        // SMULH: high 64 bits of signed 128-bit product.
        let instr = Instruction::Smulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF),
            (1, 1),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // (-1)*(-1) high = 0
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000), // MIN*MIN
            (0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_umulh_concrete_smt_parity() {
        // UMULH: high 64 bits of unsigned 128-bit product.
        let instr = Instruction::Umulh {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF),
            (1, 1),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0x8000_0000_0000_0000, 2),
            (0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Register::X0,
            );
        }
    }

    #[test]
    fn test_cmp_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        // CMP rn, rm sets flags via subtraction, doesn't write a register.
        let instr = Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0),                                         // equal: Z=1
            (1, 0),                                         // pos minus zero
            (0, 1),                                         // borrow: N=1, C=0
            (0x8000_0000_0000_0000, 1),                     // overflow: V=1
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // all-ones equal
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                None,
                true,
            );
        }
    }

    #[test]
    fn test_cmn_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Cmn {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0),
            (1, 0xFFFF_FFFF_FFFF_FFFF), // sum wraps to 0 -> Z=1, C=1
            (0x7FFF_FFFF_FFFF_FFFF, 1), // overflow: V=1
            (0xFFFF_FFFF_FFFF_FFFF, 1), // wraps to 0
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                None,
                true,
            );
        }
    }

    #[test]
    fn test_tst_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        // TST is AND for flags; doesn't write rd.
        let instr = Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),                     // result=0 -> Z=1
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF), // result=all-ones -> N=1
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555), // result=0
            (0xDEAD, 0xFFFF),                               // mixed
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                None,
                true,
            );
        }
    }

    #[test]
    fn test_adds_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0, 0),
            (1, 0xFFFF_FFFF_FFFF_FFFF), // sum wraps to 0 -> Z=1, C=1
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000), // both negative, V=1
            (0x7FFF_FFFF_FFFF_FFFF, 1), // positive overflow: V=1
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                Some(Register::X0),
                true,
            );
        }
    }

    #[test]
    fn test_subs_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Subs {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[(0, 0), (0, 1), (1, 0), (0x8000_0000_0000_0000, 1)];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                Some(Register::X0),
                true,
            );
        }
    }

    #[test]
    fn test_ands_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Ands {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            width: crate::ir::RegisterWidth::X64,
        };
        let samples: &[(u64, u64)] = &[
            (0, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_5555),
            (0xDEAD, 0xFFFF),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                Some(Register::X0),
                true,
            );
        }
    }

    #[test]
    fn test_w32_logical_flag_immediates_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;

        let tst_n = Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Immediate(0x8000_0000),
            width: RegisterWidth::W32,
        };
        assert_concrete_smt_parity_full(
            &tst_n,
            &[(Register::X1, 0x8000_0000)],
            Some(ConditionFlags::default()),
            None,
            true,
        );

        let tst_z = Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Immediate(0xFF),
            width: RegisterWidth::W32,
        };
        assert_concrete_smt_parity_full(
            &tst_z,
            &[(Register::X1, 0xFFFF_FFFF_0000_0000)],
            Some(ConditionFlags::default()),
            None,
            true,
        );

        let ands = Instruction::Ands {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0x8000_0000),
            width: RegisterWidth::W32,
        };
        assert_concrete_smt_parity_full(
            &ands,
            &[(Register::X1, 0xFFFF_FFFF_8000_0000)],
            Some(ConditionFlags::default()),
            Some(Register::X0),
            true,
        );
    }

    #[test]
    fn test_bics_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Bics {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        };
        let samples: &[(u64, u64)] = &[
            (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
            (0xFFFF_FFFF_FFFF_FFFF, 0),
            (0xAAAA_AAAA_AAAA_AAAA, 0xAAAA_AAAA_AAAA_AAAA),
        ];
        for &(v1, v2) in samples {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, v1), (Register::X2, v2)],
                Some(ConditionFlags::default()),
                Some(Register::X0),
                true,
            );
        }
    }

    #[test]
    fn test_negs_reg_concrete_smt_parity() {
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Negs {
            rd: Register::X0,
            rm: Register::X1,
        };
        for v1 in &[0_u64, 1, 0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF] {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, *v1)],
                Some(ConditionFlags::default()),
                Some(Register::X0),
                true,
            );
        }
    }

    #[test]
    fn test_csel_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        // CSEL reads flags + rn/rm and conditionally selects.
        let instr_eq = Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::EQ,
        };
        let pre_flags = [
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            }, // EQ holds
            ConditionFlags::default(), // EQ fails
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(
                &instr_eq,
                &[(Register::X1, 0x1111), (Register::X2, 0x2222)],
                Some(*pf),
                Some(Register::X0),
                false,
            );
        }
    }

    #[test]
    fn test_csinc_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Csinc {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::NE,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            },
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(
                &instr,
                &[
                    (Register::X1, 0x1111),
                    (Register::X2, 0xFFFF_FFFF_FFFF_FFFF),
                ],
                Some(*pf),
                Some(Register::X0),
                false,
            );
        }
    }

    #[test]
    fn test_csinv_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Csinv {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::CS,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: false,
                z: false,
                c: true,
                v: false,
            },
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(
                &instr,
                &[
                    (Register::X1, 0xAAAA_AAAA_AAAA_AAAA),
                    (Register::X2, 0x5555_5555_5555_5555),
                ],
                Some(*pf),
                Some(Register::X0),
                false,
            );
        }
    }

    #[test]
    fn test_csneg_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Csneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::MI,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: true,
                z: false,
                c: false,
                v: false,
            },
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(
                &instr,
                &[(Register::X1, 0x1234), (Register::X2, 0x5678_9ABC)],
                Some(*pf),
                Some(Register::X0),
                false,
            );
        }
    }

    #[test]
    fn test_cset_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Cset {
            rd: Register::X0,
            cond: Condition::EQ,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            },
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(&instr, &[], Some(*pf), Some(Register::X0), false);
        }
    }

    #[test]
    fn test_csetm_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Csetm {
            rd: Register::X0,
            cond: Condition::NE,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            },
        ];
        for pf in &pre_flags {
            assert_concrete_smt_parity_full(&instr, &[], Some(*pf), Some(Register::X0), false);
        }
    }

    #[test]
    fn test_ccmp_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        // CCMP: if cond holds, run SUB and set NZCV from it; else load nzcv literal.
        let instr = Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 0b1010, // N=1, Z=0, C=1, V=0
            cond: Condition::EQ,
        };
        let pre_flags = [
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            }, // EQ holds -> use SUB result
            ConditionFlags::default(), // EQ fails -> use nzcv literal
        ];
        let val_samples = [(0u64, 0u64), (5u64, 3u64)];
        for pf in &pre_flags {
            for &(v1, v2) in &val_samples {
                assert_concrete_smt_parity_full(
                    &instr,
                    &[(Register::X1, v1), (Register::X2, v2)],
                    Some(*pf),
                    None,
                    true,
                );
            }
        }
    }

    #[test]
    fn test_ccmn_concrete_smt_parity() {
        use crate::ir::Condition;
        use crate::semantics::state::ConditionFlags;
        let instr = Instruction::Ccmn {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
            nzcv: 0b0011,
            cond: Condition::NE,
        };
        let pre_flags = [
            ConditionFlags::default(),
            ConditionFlags {
                n: false,
                z: true,
                c: false,
                v: false,
            },
        ];
        let val_samples = [(0u64, 0u64), (5u64, 3u64)];
        for pf in &pre_flags {
            for &(v1, v2) in &val_samples {
                assert_concrete_smt_parity_full(
                    &instr,
                    &[(Register::X1, v1), (Register::X2, v2)],
                    Some(*pf),
                    None,
                    true,
                );
            }
        }
    }

    #[test]
    fn test_asr_imm_concrete_smt_parity() {
        // ASR is sign-sensitive: concrete semantics route through signed
        // shifting; SMT uses Z3 `bvashr`, which sign-preserves. Immediate
        // shifts >= 64 are IR-only parity cases that exercise the issue-#241
        // mask path; parser/encodability reject them in normal input.
        let values: &[u64] = &[
            0,
            1,
            0xFFFF_FFFF_FFFF_FFFF, // -1 signed
            0x8000_0000_0000_0000, // i64::MIN
            0x4000_0000_0000_0000, // positive, MSB-1 set
            0x1234_5678_9ABC_DEF0,
        ];
        let shifts: &[i64] = &[0, 1, 5, 16, 32, 63, 64, 65, 127];
        for &v1 in values {
            for &shift in shifts {
                let instr = Instruction::Asr {
                    rd: Register::X0,
                    rn: Register::X1,
                    shift: Operand::Immediate(shift),
                };
                assert_concrete_smt_parity(&instr, &[(Register::X1, v1)], Register::X0);
            }
        }
    }

    // ---- Memory ops (issue #68 step 7) ----

    #[test]
    #[should_panic(expected = "raw load width 64 exceeds target register width 32")]
    fn ldr_zero_extend_rejects_raw_width_above_target() {
        use crate::ir::types::AccessWidth;

        let raw = BV::from_u64(0, 64);
        let _ = ldr_zero_extend(&raw, AccessWidth::Extended, 32);
    }

    #[test]
    #[should_panic(expected = "raw load width 64 exceeds target register width 32")]
    fn ldr_sign_extend_rejects_raw_width_above_target() {
        use crate::ir::types::AccessWidth;

        let raw = BV::from_u64(0, 64);
        let _ = ldr_sign_extend(&raw, AccessWidth::Extended, 32);
    }

    /// `STR x0, [x1]; LDR x2, [x1]` must yield `x2 == x0` under Z3 array
    /// extensionality, even with arbitrary aliasing of `x1` against other
    /// addresses (none used here). This is the tracer-bullet test for the
    /// sound aliasing model from ADR-0007.
    #[test]
    fn str_then_ldr_round_trips_via_z3_array() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};

        let pre = MachineState::new_symbolic("pre");
        let seq = vec![
            Instruction::Str {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
            Instruction::Ldr {
                rt: Register::X2,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
        ];
        let post = apply_sequence(pre.clone(), &seq);
        let x0_pre = pre.get_register(Register::X0);
        let x2_post = post.get_register(Register::X2);

        let solver = Solver::new();
        solver.assert(x0_pre.eq(x2_post).not());
        assert_eq!(
            solver.check(),
            SatResult::Unsat,
            "STR-then-LDR round-trip must imply x2 == x0 unconditionally"
        );
    }

    /// `STR x0, [x1]; STRH w0, [x1, #2]; LDR x2, [x1]` must reflect the
    /// half-word overlap precisely — bytes 0,1,4,5,6,7 stay from x0 while
    /// bytes 2,3 come from w0. The byte-addressed array makes this fall
    /// out for free.
    #[test]
    fn overlapping_stores_resolve_per_byte_in_smt() {
        use crate::ir::types::{AccessWidth, AddressOperand, IndexMode};

        let pre = MachineState::new_symbolic("pre");
        let seq = vec![
            Instruction::Str {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
            Instruction::Str {
                rt: Register::X0,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 2,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Half,
            },
            Instruction::Ldr {
                rt: Register::X2,
                addr: AddressOperand::Imm {
                    base: Register::X1,
                    offset: 0,
                    mode: IndexMode::Offset,
                },
                width: AccessWidth::Extended,
            },
        ];
        let post = apply_sequence(pre.clone(), &seq);
        // The Z3 solver must be able to verify the load returns the expected
        // mixed bytes. We just check satisfiability of a concrete example.
        let solver = Solver::new();
        let x0_pre = pre.get_register(Register::X0);
        let zero = BV::from_u64(0, 64);
        solver.assert(x0_pre.eq(BV::from_u64(0xDEADBEEF_CAFEBABE, 64)));
        solver.assert(pre.get_register(Register::X1).eq(&zero));
        // Expected: bytes 0..=1 from the original 64-bit STR of x0 = 0xBABE
        // Then bytes 2..=3 from the low 16 bits of x0 stored by STRH at offset 2 = 0xBABE
        // Then bytes 4..=7 from the original 64-bit STR of x0 = 0xDEADBEEF
        let x2_post = post.get_register(Register::X2);
        let expected = BV::from_u64(0xDEAD_BEEF_BABE_BABE, 64);
        solver.assert(x2_post.eq(&expected));
        assert_eq!(solver.check(), SatResult::Sat);
    }
}

//! SMT constraint generation for AArch64 instructions

#![allow(dead_code)]

use crate::ir::{Instruction, Operand, Register};
use crate::semantics::live_out::LiveOutRegisters;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use z3::ast::BV;
use z3::{Params, Solver};

/// Monotonic counter used to generate unique names for fresh symbolic values
/// produced when modelling instructions whose result depends on state we do
/// not symbolically track (currently: the CSEL family, which reads NZCV).
static FRESH_BV_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_bv(prefix: &str) -> BV {
    let id = FRESH_BV_COUNTER.fetch_add(1, Ordering::Relaxed);
    BV::new_const(format!("{}_{}", prefix, id), 64)
}

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

        MachineState { registers }
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

    /// Evaluate an operand to get its value
    pub fn eval_operand(&self, operand: &Operand) -> BV {
        match operand {
            Operand::Register(reg) => self.get_register(*reg).clone(),
            Operand::Immediate(imm) => BV::from_i64(*imm, 64),
            Operand::ShiftedRegister { reg, kind, amount } => {
                let value = self.get_register(*reg).clone();
                let amt = BV::from_u64(*amount as u64, 64);
                match kind {
                    crate::ir::ShiftKind::LSL => value.bvshl(&amt),
                    crate::ir::ShiftKind::LSR => value.bvlshr(&amt),
                    crate::ir::ShiftKind::ASR => value.bvashr(&amt),
                    crate::ir::ShiftKind::ROR => bv_ror_64(&value, &amt),
                }
            }
        }
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
        // Comparison instructions set flags but don't modify registers
        // For now, we don't model flags in SMT - these are no-ops for register state
        Instruction::Cmp { .. } | Instruction::Cmn { .. } | Instruction::Tst { .. } => {
            // These only affect flags, which we don't model symbolically yet
            // No register state changes
        }
        // CSEL family depends on NZCV, which we don't model symbolically.
        // Emit a fresh, unconstrained BV per use site so the solver can never
        // prove equivalence across the conditional select. Sound (cannot
        // wrongly accept) but uninformative (cannot prove valid rewrites that
        // span CSEL chains). Flag-aware modelling is deferred.
        Instruction::Csel { rd, .. }
        | Instruction::Csinc { rd, .. }
        | Instruction::Csinv { rd, .. }
        | Instruction::Csneg { rd, .. } => {
            state.set_register(*rd, fresh_bv("csel_result"));
        }
        Instruction::Mvn { rd, rm } => {
            let value = state.get_register(*rm).bvnot();
            state.set_register(*rd, value);
        }
        Instruction::Neg { rd, rm } => {
            let value = state.get_register(*rm).bvneg();
            state.set_register(*rd, value);
        }
        // NEGS writes rd just like NEG; flag side-effects are not modelled
        // symbolically (matches CMP/CMN/TST). Soundness barrier: callers must
        // refuse to drop flag-writers when flags are live-out.
        Instruction::Negs { rd, rm } => {
            let value = state.get_register(*rm).bvneg();
            state.set_register(*rd, value);
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
        // BIC: rd = rn & !rm. BICS shares the SMT body — the flag effect is
        // not modelled (matches CMP/CMN/TST and ADDS/SUBS/ANDS). The
        // soundness barrier lives in `equivalence::flag_writers_diverge`,
        // which refuses any rewrite that drops a flag-writer the target had.
        Instruction::Bic { rd, rn, rm } | Instruction::Bics { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            let result = lhs.bvand(rhs.bvnot());
            state.set_register(*rd, result);
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
        // Flag-setting arith/logical: rd is modelled symbolically (same as
        // ADD/SUB/AND); flag side-effects are NOT modelled (matches CMP/CMN/TST).
        // Soundness barrier: callers must refuse to drop flag-writers when
        // flags are live-out (see `flags_live_out` and `modifies_flags`).
        Instruction::Adds { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            state.set_register(*rd, lhs.bvadd(&rhs));
        }
        Instruction::Subs { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            state.set_register(*rd, lhs.bvsub(&rhs));
        }
        Instruction::Ands { rd, rn, rm } => {
            let lhs = state.get_register(*rn).clone();
            let rhs = state.eval_operand(rm);
            state.set_register(*rd, lhs.bvand(&rhs));
        }
        // CSET / CSETM: depend on NZCV, which we don't model symbolically.
        // Emit a fresh symbolic value per use (matches CSEL family policy).
        Instruction::Cset { rd, .. } | Instruction::Csetm { rd, .. } => {
            state.set_register(*rd, fresh_bv("cset_result"));
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

/// Check if two machine states are not equal (for any register values)
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

    not_equal
}

/// Check if two machine states are not equal for the specified live-out registers
pub fn states_not_equal_for_live_out(
    state1: &MachineState,
    state2: &MachineState,
    live_out: &LiveOutRegisters,
) -> z3::ast::Bool {
    let mut not_equal = z3::ast::Bool::from_bool(false);

    for reg in live_out.iter() {
        let val1 = state1.get_register(*reg);
        let val2 = state2.get_register(*reg);
        let reg_not_equal = val1.eq(val2).not();
        not_equal = z3::ast::Bool::or(&[&not_equal, &reg_not_equal]);
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
                kind: crate::ir::ShiftKind::LSL,
                amount: 3,
            },
        }];

        let s1 = apply_sequence(initial.clone(), &seq_split);
        let s2 = apply_sequence(initial, &seq_fused);

        // Live-out is just X0; the split sequence clobbers X10 but X0 must match.
        let solver = Solver::new();
        solver.assert(
            &s1.get_register(Register::X0)
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
                kind: crate::ir::ShiftKind::ROR,
                amount: 4,
            },
        }];

        let s1 = apply_sequence(initial.clone(), &seq_split);
        let s2 = apply_sequence(initial, &seq_fused);

        let solver = Solver::new();
        solver.assert(
            &s1.get_register(Register::X0)
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
}

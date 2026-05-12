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
        // BIC: rd = rn & !rm. BICS shares the SMT body — the flag effect is
        // not modelled (matches CMP/CMN/TST and ADDS/SUBS/ANDS). The
        // soundness barrier lives in `equivalence::drops_target_flag_writer`,
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
        // ROR: no native bvror in z3-rust; compose
        // `(x lshr n) | (x shl (64 - n))`. For reg form, mask shift to 6 bits.
        //
        // Edge case at n == 0: `complement` evaluates to 64, and SMTLIB2
        // bit-vector semantics define `bvshl(x, 64) = 0` (any shift ≥ the
        // bit-width zeroes the value). So `hi = 0` and the result is just
        // `value lshr 0 = value`. Do **not** add a guard for n == 0 — it
        // would mis-handle the symbolic case where n is unknown.
        Instruction::Ror { rd, rn, shift } => {
            let value = state.get_register(*rn).clone();
            let n = state.eval_operand(shift);
            let mask = BV::from_u64(63, 64);
            let n_masked = n.bvand(&mask);
            let sixty_four = BV::from_u64(64, 64);
            let complement = sixty_four.bvsub(&n_masked);
            let lo = value.bvlshr(&n_masked);
            let hi = value.bvshl(&complement);
            state.set_register(*rd, lo.bvor(&hi));
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
}

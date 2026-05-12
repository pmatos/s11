//! Semantic equivalence checking for instruction sequences

#![allow(dead_code)]

use crate::ir::Instruction;
use crate::semantics::concrete::{
    apply_sequence_concrete, find_first_difference, states_equal_for_live_out,
};
use crate::semantics::live_out::LiveOut;
use crate::semantics::smt::{
    MachineState, SolverConfig, apply_sequence, create_solver_with_config, states_not_equal,
    states_not_equal_for_live_out,
};
use crate::semantics::state::ConcreteMachineState;
use crate::validation::random::{
    RandomInputConfig, generate_edge_case_inputs, generate_random_inputs,
};
use std::time::Duration;
use z3::SatResult;

/// Result of equivalence checking
#[derive(Debug, Clone, PartialEq)]
pub enum EquivalenceResult {
    /// The sequences are equivalent
    Equivalent,
    /// The sequences are not equivalent
    NotEquivalent,
    /// Not equivalent, found quickly by concrete testing (includes counterexample state)
    NotEquivalentFast(ConcreteMachineState),
    /// Could not determine (timeout, unknown, etc.)
    Unknown(String),
}

/// Configuration for equivalence checking
#[derive(Debug, Clone)]
pub struct EquivalenceConfig {
    /// Observable architectural state that must match after execution.
    pub live_out: LiveOut,
    /// Number of random tests to run before SMT
    pub random_test_count: usize,
    /// Timeout for SMT solver
    pub smt_timeout: Option<Duration>,
    /// Skip SMT verification (fast path only)
    pub fast_only: bool,
}

impl Default for EquivalenceConfig {
    fn default() -> Self {
        Self {
            live_out: LiveOut::all_registers(),
            random_test_count: 10,
            smt_timeout: Some(Duration::from_secs(30)),
            fast_only: false,
        }
    }
}

impl EquivalenceConfig {
    /// Create a config that only uses fast path (no SMT)
    pub fn fast_only() -> Self {
        Self {
            fast_only: true,
            ..Default::default()
        }
    }

    /// Create a config with a specific live-out contract.
    pub fn with_live_out(live_out: LiveOut) -> Self {
        Self {
            live_out,
            ..Default::default()
        }
    }

    /// Builder method to set live-out contract.
    pub fn live_out(mut self, live_out: LiveOut) -> Self {
        self.live_out = live_out;
        self
    }

    /// Builder method to set random test count
    pub fn random_tests(mut self, count: usize) -> Self {
        self.random_test_count = count;
        self
    }

    /// Builder method to set SMT timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.smt_timeout = Some(timeout);
        self
    }

    /// Builder method to disable SMT timeout
    pub fn no_timeout(mut self) -> Self {
        self.smt_timeout = None;
        self
    }

    /// Builder method to enable fast-only mode
    pub fn set_fast_only(mut self, fast_only: bool) -> Self {
        self.fast_only = fast_only;
        self
    }
}

/// Check if two instruction sequences are semantically equivalent
///
/// Returns true if for all possible initial states, both sequences
/// produce the same final state.
pub fn check_equivalence(seq1: &[Instruction], seq2: &[Instruction]) -> EquivalenceResult {
    let solver_config = SolverConfig::default();
    let solver = create_solver_with_config(&solver_config);

    let initial_state = MachineState::new_symbolic("init");

    let final_state1 = apply_sequence(initial_state.clone(), seq1);
    let final_state2 = apply_sequence(initial_state, seq2);

    solver.assert(states_not_equal(&final_state1, &final_state2));

    match solver.check() {
        SatResult::Unsat => EquivalenceResult::Equivalent,
        SatResult::Sat => EquivalenceResult::NotEquivalent,
        SatResult::Unknown => EquivalenceResult::Unknown("SMT solver returned unknown".to_string()),
    }
}

/// Optional per-call metrics from the equivalence pipeline.
#[derive(Debug, Default, Clone)]
pub struct EquivalenceMetrics {
    /// Whether the SMT solver was actually invoked. False when fast-path
    /// refuted the candidate, when fast_only is set, or when the candidate
    /// was rejected before reaching SMT for any other reason.
    pub smt_called: bool,
    /// Size of the SMT-LIB rendering of the loaded solver (assertions +
    /// declarations) at the moment `check()` was called. None if SMT was
    /// not called.
    pub smt_formula_bytes: Option<usize>,
}

/// Run the fast-path random + edge-case checks. Returns either a
/// `NotEquivalentFast` refutation, `None` if the fast path passed, or
/// `Some(Equivalent)` if `fast_only` short-circuits.
fn run_fast_path(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> Option<EquivalenceResult> {
    let live_out_registers = config.live_out.registers();
    let input_regs: Vec<_> = live_out_registers.iter().cloned().collect();

    let random_config = RandomInputConfig {
        count: config.random_test_count,
        registers: input_regs.clone(),
    };
    let random_inputs = generate_random_inputs(&random_config);

    for input in &random_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if !states_equal_for_live_out(&state1, &state2, live_out_registers) {
            return Some(EquivalenceResult::NotEquivalentFast(input.clone()));
        }
    }

    let edge_inputs = generate_edge_case_inputs(&input_regs);
    for input in &edge_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if !states_equal_for_live_out(&state1, &state2, live_out_registers) {
            return Some(EquivalenceResult::NotEquivalentFast(input.clone()));
        }
    }

    if config.fast_only {
        return Some(EquivalenceResult::Equivalent);
    }

    None
}

/// Check equivalence with configuration (fast path + optional SMT). No metrics.
pub fn check_equivalence_with_config(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> EquivalenceResult {
    if let Some(fast) = run_fast_path(seq1, seq2, config) {
        return fast;
    }

    let solver = build_smt_solver(seq1, seq2, config);
    interpret_smt_result(solver.check())
}

/// Like `check_equivalence_with_config`, but also reports per-call metrics
/// including the SMT formula size in bytes. Use this only when the metrics
/// are actually consumed — `solver.to_string()` is non-trivial work compared
/// to `solver.check()` on small problems.
///
/// Formula-size is captured **only when the solver returns `unsat`**
/// (i.e., the candidate was proven equivalent). For `sat` (counter-example)
/// or `unknown` (timeout) we skip the serialization — the size is
/// uninteresting in those cases and the cost would be paid on the slow paths.
pub fn check_equivalence_with_config_metrics(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> (EquivalenceResult, EquivalenceMetrics) {
    let metrics = EquivalenceMetrics::default();

    if let Some(fast) = run_fast_path(seq1, seq2, config) {
        return (fast, metrics);
    }

    let solver = build_smt_solver(seq1, seq2, config);
    let sat_result = solver.check();
    let smt_formula_bytes = if sat_result == SatResult::Unsat {
        Some(solver.to_string().len())
    } else {
        None
    };
    let result = interpret_smt_result(sat_result);
    (
        result,
        EquivalenceMetrics {
            smt_called: true,
            smt_formula_bytes,
        },
    )
}

/// Build a Z3 solver populated with the assertion that the two sequences
/// disagree on the live-out state. Caller invokes `check()` next.
fn build_smt_solver(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> z3::Solver {
    let solver_config = SolverConfig {
        timeout: config.smt_timeout,
    };
    let solver = create_solver_with_config(&solver_config);

    let initial_state = MachineState::new_symbolic("init");
    let final_state1 = apply_sequence(initial_state.clone(), seq1);
    let final_state2 = apply_sequence(initial_state, seq2);

    solver.assert(states_not_equal_for_live_out(
        &final_state1,
        &final_state2,
        config.live_out.registers(),
    ));
    solver
}

fn interpret_smt_result(result: SatResult) -> EquivalenceResult {
    match result {
        SatResult::Unsat => EquivalenceResult::Equivalent,
        SatResult::Sat => EquivalenceResult::NotEquivalent,
        SatResult::Unknown => {
            EquivalenceResult::Unknown("SMT solver returned unknown (possibly timeout)".to_string())
        }
    }
}

/// Find a counterexample showing two sequences are not equivalent
///
/// Returns Some((register, value1, value2)) if sequences differ,
/// where register is the first differing register and value1/value2
/// are the values in the respective final states.
#[allow(dead_code)]
pub fn find_counterexample(
    seq1: &[Instruction],
    seq2: &[Instruction],
) -> Option<(String, i64, i64)> {
    let solver_config = SolverConfig::default();
    let solver = create_solver_with_config(&solver_config);

    let initial_state = MachineState::new_symbolic("init");

    let final_state1 = apply_sequence(initial_state.clone(), seq1);
    let final_state2 = apply_sequence(initial_state, seq2);

    solver.assert(states_not_equal(&final_state1, &final_state2));

    if solver.check() == SatResult::Sat {
        let model = solver.get_model().unwrap();

        for i in 0..=30 {
            if let Some(reg) = crate::ir::Register::from_index(i) {
                let val1 = final_state1.get_register(reg);
                let val2 = final_state2.get_register(reg);

                let eval1 = model.eval(val1, true).unwrap();
                let eval2 = model.eval(val2, true).unwrap();

                if let (Some(v1), Some(v2)) = (eval1.as_i64(), eval2.as_i64())
                    && v1 != v2
                {
                    return Some((format!("x{}", i), v1, v2));
                }
            }
        }
    }

    None
}

/// Find a counterexample using concrete execution with configuration
#[allow(dead_code)]
pub fn find_counterexample_concrete(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> Option<(
    crate::ir::Register,
    crate::semantics::state::ConcreteValue,
    crate::semantics::state::ConcreteValue,
)> {
    let live_out_registers = config.live_out.registers();
    let input_regs: Vec<_> = live_out_registers.iter().cloned().collect();

    let random_config = RandomInputConfig {
        count: config.random_test_count,
        registers: input_regs.clone(),
    };
    let random_inputs = generate_random_inputs(&random_config);

    for input in &random_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if let Some(diff) = find_first_difference(&state1, &state2, live_out_registers) {
            return Some(diff);
        }
    }

    let edge_inputs = generate_edge_case_inputs(&input_regs);
    for input in &edge_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if let Some(diff) = find_first_difference(&state1, &state2, live_out_registers) {
            return Some(diff);
        }
    }

    None
}

// ============================================================================
// x86 equivalence checking
// ============================================================================

/// Equivalence-check configuration for the x86 backend. Carries the
/// bitvector width (64 for x86-64, 32 for x86-32) which threads through
/// to `MachineStateX86::new_symbolic` and the immediate lowering.
#[derive(Debug, Clone)]
pub struct X86EquivalenceConfig {
    pub live_out: crate::semantics::state::X86LiveOutMask,
    pub width: u32,
    pub random_test_count: usize,
    pub smt_timeout: Option<Duration>,
    pub fast_only: bool,
}

impl X86EquivalenceConfig {
    pub fn new_for_64() -> Self {
        Self {
            live_out: crate::semantics::state::X86LiveOutMask::empty(),
            width: 64,
            random_test_count: 10,
            smt_timeout: Some(Duration::from_secs(30)),
            fast_only: false,
        }
    }

    pub fn new_for_32() -> Self {
        Self {
            width: 32,
            ..Self::new_for_64()
        }
    }

    pub fn live_out(mut self, mask: crate::semantics::state::X86LiveOutMask) -> Self {
        self.live_out = mask;
        self
    }

    pub fn fast_only(mut self) -> Self {
        self.fast_only = true;
        self
    }
}

/// Check whether two x86 instruction sequences are equivalent under the
/// given live-out mask and operand width. Mirrors `check_equivalence_with_config`
/// for the AArch64 backend: fast path uses the concrete interpreter over
/// random inputs (and EFLAGS comparison when CMP is present or the mask
/// declares flags live); slow path lowers to Z3 BVs and checks UNSAT of the
/// not-equal assertion over live-out registers.
pub fn check_equivalence_x86(
    seq1: &[crate::isa::x86::X86Instruction],
    seq2: &[crate::isa::x86::X86Instruction],
    config: &X86EquivalenceConfig,
) -> EquivalenceResult {
    // Fast path: 10 random inputs.
    if let Some(refutation) = run_fast_path_x86(seq1, seq2, config) {
        return refutation;
    }
    if config.fast_only {
        return EquivalenceResult::Equivalent;
    }

    // SMT path.
    let solver_config = SolverConfig {
        timeout: config.smt_timeout,
    };
    let solver = create_solver_with_config(&solver_config);
    let initial = crate::semantics::smt_x86::MachineStateX86::new_symbolic("init", config.width);
    let final1 = crate::semantics::smt_x86::apply_sequence(initial.clone(), seq1);
    let final2 = crate::semantics::smt_x86::apply_sequence(initial, seq2);

    let mut disjuncts: Vec<z3::ast::Bool> = Vec::new();
    for reg in config.live_out.iter() {
        let v1 = final1.get_register(*reg);
        let v2 = final2.get_register(*reg);
        disjuncts.push(v1.eq(v2).not());
    }
    let any_diff = if disjuncts.is_empty() {
        z3::ast::Bool::from_bool(false)
    } else {
        z3::ast::Bool::or(&disjuncts.iter().collect::<Vec<_>>())
    };
    solver.assert(&any_diff);
    interpret_smt_result(solver.check())
}

fn run_fast_path_x86(
    seq1: &[crate::isa::x86::X86Instruction],
    seq2: &[crate::isa::x86::X86Instruction],
    config: &X86EquivalenceConfig,
) -> Option<EquivalenceResult> {
    use crate::isa::x86::X86Register;
    use crate::semantics::concrete_x86::apply_instruction_concrete_x86;
    use crate::semantics::state::X86ConcreteMachineState;

    // Detect any CMP in either sequence — that's the trigger to also
    // compare EFLAGS even if the caller didn't declare flags live.
    let cmp_present = seq1.iter().chain(seq2.iter()).any(|i| {
        matches!(
            i,
            crate::isa::x86::X86Instruction::CmpReg { .. }
                | crate::isa::x86::X86Instruction::CmpImm { .. }
        )
    });
    let flags_must_match = cmp_present || config.live_out.flags_live();

    // Deterministic seed sequence: the first four are hand-picked
    // boundary cases (zero, one, an asymmetric bit pattern, all-ones);
    // beyond that we mix the iteration index with a golden-ratio
    // multiplier to scatter through the u64 space without pulling in a
    // PRNG. The total number of seeds is `config.random_test_count`
    // (matching the AArch64 path's contract that the field actually
    // drives the fast-path coverage).
    let base_seeds: &[u64] = &[0, 1, 0xdead_beef, u64::MAX];
    for n in 0..config.random_test_count {
        let seed = if n < base_seeds.len() {
            base_seeds[n]
        } else {
            (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        };
        let mut state = X86ConcreteMachineState::new_zeroed(config.width);
        for i in 0..16u8 {
            if let Some(reg) = X86Register::from_index(i) {
                state.set_register(
                    reg,
                    crate::semantics::state::ConcreteValue::new(seed.wrapping_add(i as u64)),
                );
            }
        }
        let mut s1 = state.clone();
        for instr in seq1 {
            s1 = apply_instruction_concrete_x86(s1, instr);
        }
        let mut s2 = state.clone();
        for instr in seq2 {
            s2 = apply_instruction_concrete_x86(s2, instr);
        }
        for reg in config.live_out.iter() {
            if s1.get_register(*reg) != s2.get_register(*reg) {
                // We don't have an X86-typed counterexample state in the
                // EquivalenceResult yet; report a generic NotEquivalent.
                return Some(EquivalenceResult::NotEquivalent);
            }
        }
        if flags_must_match && s1.get_flags() != s2.get_flags() {
            return Some(EquivalenceResult::NotEquivalent);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::isa::x86::{X86Instruction, X86Register};
    use crate::semantics::state::X86LiveOutMask;

    #[test]
    fn x86_mov_zero_equivalent_to_xor_self_when_flags_dead() {
        let seq_mov = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let seq_xor = vec![X86Instruction::XorReg {
            rd: X86Register::RAX,
            rs: X86Register::RAX,
        }];
        let cfg = X86EquivalenceConfig::new_for_64()
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]));
        assert_eq!(
            check_equivalence_x86(&seq_mov, &seq_xor, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn x86_mov_zero_not_equivalent_to_xor_self_when_flags_live() {
        // XOR sets EFLAGS; MOV does not. So with flags_live=true, the two
        // sequences must NOT be considered equivalent.
        let seq_mov = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let seq_xor = vec![X86Instruction::XorReg {
            rd: X86Register::RAX,
            rs: X86Register::RAX,
        }];
        let cfg = X86EquivalenceConfig::new_for_64()
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]).with_flags(true))
            .fast_only();
        assert!(matches!(
            check_equivalence_x86(&seq_mov, &seq_xor, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_cmp_difference_caught_by_fast_path_eflags_auto_compare() {
        // Two CMPs that differ in operands -> different EFLAGS even when
        // no register is in live-out.
        let seq1 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let seq2 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RCX,
        }];
        let cfg = X86EquivalenceConfig::new_for_64()
            .live_out(X86LiveOutMask::empty())
            .fast_only();
        // CMP is present, so EFLAGS comparison auto-engages.
        assert!(matches!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_two_movs_with_same_immediate_are_equivalent() {
        let seq1 = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 42,
        }];
        let seq2 = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 42,
        }];
        let cfg = X86EquivalenceConfig::new_for_64()
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]));
        assert_eq!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_mov_zero_eor_equivalence() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_add_commutativity() {
        let seq1 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X2,
            rm: Operand::Register(Register::X1),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_sequence_optimization() {
        let seq1 = vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];

        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_non_equivalent_sequences() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 2,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::NotEquivalent
        );
    }

    #[test]
    fn test_xor_self_clearing() {
        for i in 0..5 {
            let reg = Register::from_index(i).unwrap();

            let seq1 = vec![Instruction::MovImm { rd: reg, imm: 0 }];

            let seq2 = vec![Instruction::Eor {
                rd: reg,
                rn: reg,
                rm: Operand::Register(reg),
            }];

            assert_eq!(
                check_equivalence(&seq1, &seq2),
                EquivalenceResult::Equivalent
            );
        }
    }

    #[test]
    fn test_and_with_zero() {
        let seq1 = vec![Instruction::And {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_or_with_zero() {
        let seq1 = vec![Instruction::Orr {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(0),
        }];

        let seq2 = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];

        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_counterexample() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 5,
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 10,
        }];

        let counter = find_counterexample(&seq1, &seq2);
        assert!(counter.is_some());
        if let Some((reg, v1, v2)) = counter {
            assert_eq!(reg, "x0");
            assert_eq!(v1, 5);
            assert_eq!(v2, 10);
        }
    }

    #[test]
    fn test_check_equivalence_with_config_equivalent() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];

        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        let config = EquivalenceConfig::default();
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert_eq!(result, EquivalenceResult::Equivalent);
    }

    #[test]
    fn test_check_equivalence_with_config_not_equivalent_fast() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 2,
        }];

        let config = EquivalenceConfig::default();
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        match result {
            EquivalenceResult::NotEquivalentFast(_) => {}
            _ => panic!("Expected NotEquivalentFast"),
        }
    }

    #[test]
    fn test_check_equivalence_with_config_live_out() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 2,
        }];

        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X1]));
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert_eq!(result, EquivalenceResult::Equivalent);
    }

    #[test]
    fn test_check_equivalence_with_config_fast_only() {
        let seq1 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];

        let seq2 = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X2,
            rm: Operand::Register(Register::X1),
        }];

        let config = EquivalenceConfig::fast_only();
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert_eq!(result, EquivalenceResult::Equivalent);
    }

    #[test]
    fn test_find_counterexample_concrete() {
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 5,
        }];

        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 10,
        }];

        let config = EquivalenceConfig::default();
        let counter = find_counterexample_concrete(&seq1, &seq2, &config);
        assert!(counter.is_some());
        let (reg, v1, v2) = counter.unwrap();
        assert_eq!(reg, Register::X0);
        assert_eq!(v1.as_u64(), 5);
        assert_eq!(v2.as_u64(), 10);
    }

    // --- Tier 1 algebraic identities --------------------------------------

    #[test]
    fn test_eor_self_equivalent_to_bic_self() {
        // EOR x0, x0, x0 ≡ BIC x0, x0, x0 (both produce 0)
        let seq1 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        let seq2 = vec![Instruction::Bic {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_orn_self_is_all_ones() {
        // ORN x0, x1, x1 = x1 | !x1 = all ones, matches MOVN x0, #0
        let seq1 = vec![Instruction::Orn {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X1),
        }];
        let seq2 = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 0,
            shift: 0,
        }];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_movn_zero_equivalent_to_csetm_al() {
        // MOVN x0, #0 = all ones.
        // We can't test CSETM with AL (it's rejected by is_encodable), but
        // we can prove MOVN x0,#0 ≡ EON x0,x1,x1.
        let seq1 = vec![Instruction::MovN {
            rd: Register::X0,
            imm: 0,
            shift: 0,
        }];
        let seq2 = vec![Instruction::Eon {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X1),
        }];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_mvn_twice_is_identity() {
        // MVN x0, x1; MVN x0, x0 ≡ MOV x0, x1
        let seq1 = vec![
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X1,
            },
            Instruction::Mvn {
                rd: Register::X0,
                rm: Register::X0,
            },
        ];
        let seq2 = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X1,
        }];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    /// BIC x0, x1, x2 ≡ MVN x3, x2; AND x0, x1, x3 (live-out X0)
    #[test]
    fn test_bic_lowered_to_mvn_and() {
        let seq1 = vec![Instruction::Bic {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let seq2 = vec![
            Instruction::Mvn {
                rd: Register::X3,
                rm: Register::X2,
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X3),
            },
        ];
        let config =
            EquivalenceConfig::with_live_out(LiveOutMask::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// ORN x0, x1, x2 ≡ MVN x3, x2; ORR x0, x1, x3 (live-out X0)
    #[test]
    fn test_orn_lowered_to_mvn_orr() {
        let seq1 = vec![Instruction::Orn {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let seq2 = vec![
            Instruction::Mvn {
                rd: Register::X3,
                rm: Register::X2,
            },
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X3),
            },
        ];
        let config =
            EquivalenceConfig::with_live_out(LiveOutMask::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// EON x0, x1, x2 ≡ MVN x3, x2; EOR x0, x1, x3 (live-out X0)
    #[test]
    fn test_eon_lowered_to_mvn_eor() {
        let seq1 = vec![Instruction::Eon {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let seq2 = vec![
            Instruction::Mvn {
                rd: Register::X3,
                rm: Register::X2,
            },
            Instruction::Eor {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Register(Register::X3),
            },
        ];
        let config =
            EquivalenceConfig::with_live_out(LiveOutMask::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn test_neg_equivalent_to_sub_from_zero() {
        // NEG x0, x1 ≡ MOV x2, #0; SUB x0, x2, x1
        let seq1 = vec![Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let seq2 = vec![
            Instruction::MovImm {
                rd: Register::X2,
                imm: 0,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X2,
                rm: Operand::Register(Register::X1),
            },
        ];
        // X2 differs between the two sequences (NEG doesn't touch X2 but the
        // 2-op form sets X2 to 0). Restrict equivalence to live-out X0.
        let config =
            EquivalenceConfig::with_live_out(LiveOutMask::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }
}

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
use crate::validation::live_out::flags_live_out;
use crate::validation::random::{
    RandomInputConfig, generate_edge_case_inputs, generate_random_inputs,
};
use std::time::Duration;
use z3::SatResult;

/// Soundness guard: SMT does not model NZCV, so any rewrite that disturbs
/// the flag-writing trace cannot be proved equivalent — a downstream
/// conditional branch (or CSEL chain) would observe different flags.
/// Equivalent in registers ≠ equivalent in flags.
///
/// This guard fires when the sub-sequence of flag-writing instructions in
/// `target` differs in any way from the sub-sequence in `candidate` — drop,
/// swap, reorder, or replace-with-different-flag-writer all count. The
/// comparison is `Instruction`-level structural equality, so a `CMP x2, #0`
/// in target vs `ADDS x0, x1, #1` in candidate (both modify NZCV but with
/// different operands and different flag-setting rules) is correctly
/// rejected — see the regression tests below.
///
/// Conservative on purpose: some valid rewrites that happen to produce
/// identical final NZCV from different flag-writers will be wrongly
/// rejected here. A symmetric incompleteness also remains — when both
/// sequences contain the same structural flag-writer but with different
/// upstream operands feeding it (e.g. `mov x1,#0; cmp x1,#0` vs
/// `mov x1,#5; cmp x1,#0`), the guard does not detect the divergence.
/// Closing either gap requires full NZCV modelling in SMT, tracked as
/// issue #92.
fn flag_writers_diverge(target: &[Instruction], candidate: &[Instruction]) -> bool {
    // Fast paths: most rewrites involve no flag writers at all.
    let tw = flags_live_out(target);
    let cw = flags_live_out(candidate);
    if !tw && !cw {
        return false;
    }
    if tw != cw {
        return true; // target writes flags, candidate doesn't (or vice versa)
    }
    let target_flag_writers: Vec<&Instruction> =
        target.iter().filter(|i| i.modifies_flags()).collect();
    let candidate_flag_writers: Vec<&Instruction> =
        candidate.iter().filter(|i| i.modifies_flags()).collect();
    target_flag_writers != candidate_flag_writers
}

/// Combined pre-SMT soundness guard. Single source of truth for the
/// short-circuit applied at every public entry point — returning `Some(r)`
/// here means callers must return `r` (or the metrics-wrapped equivalent)
/// before invoking the solver. Returning `None` means proceed to SMT.
///
/// Today this is just the flag-writer trace check, but the shape leaves
/// room to add more pre-SMT guards (e.g. memory ops, control flow) without
/// touching every call site.
fn pre_smt_guard(target: &[Instruction], candidate: &[Instruction]) -> Option<EquivalenceResult> {
    if flag_writers_diverge(target, candidate) {
        return Some(EquivalenceResult::NotEquivalent);
    }
    None
}

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
    if let Some(early) = pre_smt_guard(seq1, seq2) {
        return early;
    }

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
    if let Some(early) = pre_smt_guard(seq1, seq2) {
        return early;
    }

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

    if let Some(early) = pre_smt_guard(seq1, seq2) {
        return (early, metrics);
    }

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
    fn test_movn_zero_equivalent_to_eon_self() {
        // MOVN x0, #0 = all ones, which also equals `x1 XOR ~x1` for any x1.
        // (CSETM with AL would also produce all-ones but is_encodable rejects
        //  AL, so we use EON-with-self as the comparison sequence.)
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

    /// Issue #55 acceptance: MOVZ x0,#a; MOVK x0,#b,LSL #16 builds (b<<16)|a.
    /// We prove the materialised constant equals an explicit immediate by
    /// comparing it to a sequence that lifts the same bit pattern via shift +
    /// orr. With concrete values a=0x1234 and b=0x5678, the target constant is
    /// 0x56781234.
    #[test]
    fn test_movz_movk_materialises_32bit_constant() {
        let seq1 = vec![
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0x1234,
                shift: 0,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0x5678,
                shift: 16,
            },
        ];
        // Reference: build the same value via MovImm(low) + MovImm(high<<16
        // synthesised by a second MOVK from an empty MOVZ).
        let seq2 = vec![
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0x5678,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0x1234,
                shift: 0,
            },
        ];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    /// MOVZ with shift=0 collapses to MovImm — useful sanity check that the
    /// new variant is wired through SMT with the same semantics.
    #[test]
    fn test_movz_shift0_equivalent_to_mov_imm() {
        let seq1 = vec![Instruction::MovZ {
            rd: Register::X0,
            imm: 0xABCD,
            shift: 0,
        }];
        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0xABCD,
        }];
        assert_eq!(
            check_equivalence(&seq1, &seq2),
            EquivalenceResult::Equivalent
        );
    }

    /// MOVK preserves the upper 48 bits of rd: starting from x0=0xFFFF_FFFF
    /// (built via MOVZ #0xFFFF, lsl #16 + MOVK #0xFFFF), then MOVK #0,#0
    /// must leave the upper 16 bits intact (final value 0xFFFF_0000).
    #[test]
    fn test_movk_preserves_unwritten_lanes() {
        let seq1 = vec![
            Instruction::MovZ {
                rd: Register::X0,
                imm: 0xFFFF,
                shift: 16,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0xFFFF,
                shift: 0,
            },
            Instruction::MovK {
                rd: Register::X0,
                imm: 0,
                shift: 0,
            },
        ];
        // Equivalent: MOVZ x0, #0xFFFF, LSL #16 alone yields 0xFFFF_0000.
        let seq2 = vec![Instruction::MovZ {
            rd: Register::X0,
            imm: 0xFFFF,
            shift: 16,
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
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
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
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
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
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
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
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// Soundness regression for the flag-drop guard: ADDS x0, x1, #1 ≡ ADD
    /// x0, x1, #1 is unsound because the flag side-effect is silently
    /// dropped. SMT alone cannot rule this out (it models registers only).
    /// `check_equivalence_with_config` and `check_equivalence` must reject
    /// such rewrites before reaching the solver.
    #[test]
    fn test_adds_to_add_rewrite_rejected_even_with_register_live_out() {
        let adds = vec![Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let add = vec![Instruction::Add {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&adds, &add, &config),
            EquivalenceResult::NotEquivalent,
            "Dropping a flag-writer must not be certified as equivalent"
        );
        assert_eq!(
            check_equivalence(&adds, &add),
            EquivalenceResult::NotEquivalent,
            "Same guard must apply to the simple entry point"
        );
    }

    /// Soundness regression: `BICS x0, x1, x2` → `BIC x0, x1, x2` drops the
    /// NZCV side-effect. Must be rejected by the flag-writer guard.
    #[test]
    fn test_bics_to_bic_rewrite_rejected() {
        let bics = vec![Instruction::Bics {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let bic = vec![Instruction::Bic {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&bics, &bic, &config),
            EquivalenceResult::NotEquivalent
        );
        assert_eq!(
            check_equivalence(&bics, &bic),
            EquivalenceResult::NotEquivalent
        );
    }

    /// Soundness regression: `NEGS x0, x1` → `NEG x0, x1` drops NZCV.
    #[test]
    fn test_negs_to_neg_rewrite_rejected() {
        let negs = vec![Instruction::Negs {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let neg = vec![Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&negs, &neg, &config),
            EquivalenceResult::NotEquivalent
        );
        assert_eq!(
            check_equivalence(&negs, &neg),
            EquivalenceResult::NotEquivalent
        );
    }

    /// Soundness regression for the strengthened flag-writer guard:
    /// `ADD x0, x1, #1; CMP x2, #0` (writes flags from `CMP x2, #0`) vs
    /// `ADDS x0, x1, #1` (writes flags from `ADDS x0, x1, #1`). Both
    /// sequences write X0 to x1+1 and both have a flag-writer, so the SMT
    /// register check would pass and the old "any writer present" guard
    /// would also pass — but the post-sequence NZCV differs. The
    /// strengthened guard rejects on structural flag-writer-sequence
    /// inequality.
    #[test]
    fn test_swapped_flag_writer_rewrite_rejected() {
        let target = vec![
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Cmp {
                rn: Register::X2,
                rm: Operand::Immediate(0),
            },
        ];
        let candidate = vec![Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&target, &candidate, &config),
            EquivalenceResult::NotEquivalent,
            "Replacing one flag-writer with a different flag-writer changes NZCV"
        );
        assert_eq!(
            check_equivalence(&target, &candidate),
            EquivalenceResult::NotEquivalent
        );
    }

    /// ADDS ≡ ADDS (same op) must still succeed — the flag guard fires only
    /// when the flag-writer sequence diverges.
    #[test]
    fn test_adds_equivalent_to_adds() {
        let s1 = vec![Instruction::Adds {
            rd: Register::X0,
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let s2 = s1.clone();
        assert_eq!(check_equivalence(&s1, &s2), EquivalenceResult::Equivalent);
    }

    /// Issue #56 acceptance: `MUL t,a,b; NEG r,t` ≡ `MNEG r,a,b`
    /// (MNEG is `rd = -(rn*rm)`, the alias of `MSUB rd,rn,rm,XZR`).
    #[test]
    fn test_mneg_equivalent_to_neg_mul() {
        let seq1 = vec![
            Instruction::Mul {
                rd: Register::X3,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Neg {
                rd: Register::X0,
                rm: Register::X3,
            },
        ];
        let seq2 = vec![Instruction::Mneg {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// Issue #56 acceptance: `MUL t,a,b; SUB r,c,t` ≡ `MSUB r,a,b,c`
    /// when only `r` is live-out.
    #[test]
    fn test_msub_equivalent_to_sub_mul() {
        let seq1 = vec![
            Instruction::Mul {
                rd: Register::X3,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Sub {
                rd: Register::X0,
                rn: Register::X4,
                rm: Operand::Register(Register::X3),
            },
        ];
        let seq2 = vec![Instruction::Msub {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X4,
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// Issue #56 acceptance: `MUL t,a,b; ADD r,c,t` ≡ `MADD r,a,b,c`
    /// when only `r` is live-out (the temporary `t` is dead).
    #[test]
    fn test_madd_equivalent_to_mul_then_add() {
        let seq1 = vec![
            Instruction::Mul {
                rd: Register::X3,
                rn: Register::X1,
                rm: Register::X2,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X4,
                rm: Operand::Register(Register::X3),
            },
        ];
        let seq2 = vec![Instruction::Madd {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            ra: Register::X4,
        }];
        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&seq1, &seq2, &config),
            EquivalenceResult::Equivalent
        );
    }
}

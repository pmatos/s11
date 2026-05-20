//! Semantic equivalence checking for instruction sequences
//!
//! Issue #77 stage 2 step 19 plans to delete `X86EquivalenceConfig`,
//! `check_equivalence_x86`, and `run_fast_path_x86` once
//! `EquivalenceConfig<I>` is wired to consume `RegisterSet<I::Register>`
//! and the SearchAlgorithm<I> follow-up to step 11 lands. The CMP-presence
//! heuristic in `run_fast_path_x86` merges into the generic `run_fast_path`
//! as an `I::Flags`-aware optimisation (only triggers when `I::Flags != ()`).
//! Today the x86 path still owns its config + entry points; the AArch64
//! equivalence path consumes the generic surface via the trait route step 9
//! introduced.

#![allow(dead_code)]

use crate::ir::Instruction;
use crate::ir::instructions::split_terminator;
use crate::semantics::concrete::{
    apply_sequence_concrete, find_first_difference, states_equal_for_live_out,
};
use crate::semantics::live_out::LiveOut;
use crate::semantics::smt::{
    MachineState, SolverConfig, apply_sequence, create_solver_with_config, states_not_equal,
    states_not_equal_for_live_out,
};
use crate::semantics::state::ConcreteMachineState;
use crate::validation::live_out::reads_flags_before_writing;
use crate::validation::random::{
    RandomInputConfig, generate_edge_case_inputs, generate_random_inputs,
};
use std::time::Duration;
use z3::SatResult;

/// Cheap pre-SMT fast-path: rejects when only one sequence has flag-writers
/// AND flags are part of the comparison. Issue #92 closed the structural-
/// equality version of this guard — now that SMT models symbolic NZCV (see
/// `compute_flags_*` and `condition_to_smt` in `smt.rs`), any finer divergence
/// is settled by the solver. We keep the asymmetric writes-vs-no-writes check
/// because it short-circuits in O(n) without invoking Z3 and remains sound
/// *as long as flags are observable*. When the caller marks NZCV dead
/// (`flags_live = false`), the guard would otherwise reject sound rewrites
/// such as `cmp x0, #0` ≡ `<empty>` under a register-only live-out mask, so
/// the call site gates this check on flag liveness.
///
/// Issue #77 step 9: rather than reach for `Instruction::modifies_flags()` via
/// `flags_live_out`, we route through the `FlagsAnalysis<I>` trait (ADR-0004
/// decision 7). This lets the same guard ship for x86 in stage 2 without
/// accidentally substituting `InstructionType::has_side_effects` (which would
/// over-trigger — x86's impl returns `true` for everything except MOV).
fn flag_writers_diverge(target: &[Instruction], candidate: &[Instruction]) -> bool {
    use crate::isa::{AArch64, FlagsAnalysis};
    fn writes_any_flag(seq: &[Instruction]) -> bool {
        seq.iter()
            .any(<AArch64 as FlagsAnalysis<Instruction>>::modifies_flags)
    }
    writes_any_flag(target) != writes_any_flag(candidate)
}

/// Combined pre-SMT soundness guard. Single source of truth for the
/// short-circuit applied at every public entry point — returning `Some(r)`
/// here means callers must return `r` (or the metrics-wrapped equivalent)
/// before invoking the solver. Returning `None` means proceed to SMT.
///
/// `flags_live` is the caller's declaration that NZCV participates in the
/// comparison. When false, the flag-writer trace check is suppressed because
/// flag divergence is by definition unobservable.
///
/// Today this is just the flag-writer trace check, but the shape leaves
/// room to add more pre-SMT guards (e.g. memory ops, control flow) without
/// touching every call site.
fn pre_smt_guard(
    target: &[Instruction],
    candidate: &[Instruction],
    flags_live: bool,
) -> Option<EquivalenceResult> {
    if flags_live && flag_writers_diverge(target, candidate) {
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
    /// Per ADR-0004 decision 5, `flags_live` lives on the mask itself
    /// (`live_out.flags_live()`) rather than as a separate config field.
    pub live_out: LiveOut,
    /// Number of random tests to run before SMT
    pub random_test_count: usize,
    /// Timeout for SMT solver
    pub smt_timeout: Option<Duration>,
    /// Skip SMT verification (fast path only)
    pub fast_only: bool,
    /// Treat the entire memory image as live-out — every cell must agree
    /// between the two sequences' final states. Auto-derived in
    /// `check_equivalence_with_config` whenever either sequence touches
    /// memory (see ADR-0007).
    pub memory_live: bool,
}

impl Default for EquivalenceConfig {
    fn default() -> Self {
        Self {
            live_out: LiveOut::all_registers(),
            random_test_count: 10,
            smt_timeout: Some(Duration::from_secs(30)),
            fast_only: false,
            memory_live: false,
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
    ///
    /// Preserves any previously-set `flags_live` bit. Without this carry,
    /// `.with_flags(true).live_out(LiveOut::from_registers(...))` would
    /// silently drop NZCV-liveness because `from_registers` defaults
    /// `flags_live` to `false` — a regression footgun introduced when
    /// `flags_live` moved from `EquivalenceConfig` onto the mask (ADR-0004
    /// §5). The OR-merge makes the builder order-independent: flags are
    /// live if either the existing config OR the new mask says so.
    ///
    /// **One-way ratchet:** once a previous builder step set `flags_live`
    /// to true (via `.with_flags(true)` or a `LiveOut` with that bit
    /// already set), this method cannot clear it — callers who genuinely
    /// want a flags-dead replacement must mutate `config.live_out`
    /// directly. The trade-off is deliberate; silently *losing* flag
    /// liveness in a chained builder is a much more dangerous failure
    /// mode than retaining it.
    pub fn live_out(mut self, live_out: LiveOut) -> Self {
        let merged_flags = self.live_out.flags_live() || live_out.flags_live();
        self.live_out = live_out.with_flags(merged_flags);
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

    /// Builder method to mark NZCV as live-out — flag inequality then
    /// participates in both the fast-path concrete comparison and the SMT
    /// formula. Stores the bit on the live-out mask itself (ADR-0004 §5).
    pub fn with_flags(mut self, flags_live: bool) -> Self {
        self.live_out = self.live_out.with_flags(flags_live);
        self
    }

    /// Builder method to mark whole memory as live-out. Search algorithms
    /// pin `with_memory(true)` analogously to `with_flags(true)`; the
    /// `check_equivalence_with_config` entry point auto-derives this from
    /// `touches_memory()` on the candidate / target sequences. See
    /// ADR-0007.
    pub fn with_memory(mut self, memory_live: bool) -> Self {
        self.memory_live = memory_live;
        self
    }
}

/// Check if two instruction sequences are semantically equivalent
///
/// Returns true if for all possible initial states, both sequences
/// produce the same final state.
pub fn check_equivalence(seq1: &[Instruction], seq2: &[Instruction]) -> EquivalenceResult {
    // Issue #69: terminator-identity precheck. If either sequence ends in a
    // branch / control-flow instruction, both must end in the SAME terminator
    // (full struct equality including condition, register, bit, LabelId). The
    // prefix (everything before the terminator) is what the equivalence layer
    // semantically compares.
    let (prefix1, terminator1) = split_terminator(seq1);
    let (prefix2, terminator2) = split_terminator(seq2);
    if terminator1 != terminator2 {
        return EquivalenceResult::NotEquivalentFast(ConcreteMachineState::new_zeroed());
    }

    // Unmasked entry point compares full state including NZCV (see
    // `states_not_equal`); flags are always observable here.
    if let Some(early) = pre_smt_guard(prefix1, prefix2, true) {
        return early;
    }

    let solver_config = SolverConfig::default();
    let solver = create_solver_with_config(&solver_config);

    let initial_state = MachineState::new_symbolic("init");

    let final_state1 = apply_sequence(initial_state.clone(), prefix1);
    let final_state2 = apply_sequence(initial_state, prefix2);

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
    /// Wall-clock time spent inside `solver.check()`. `Duration::ZERO` when
    /// the solver was not invoked (fast path resolved the candidate or the
    /// pre-SMT guard fired).
    pub smt_elapsed: Duration,
}

/// Build the fast-path input randomization set.
///
/// Returns the union of `live_out_registers` and the source registers of every
/// instruction in `seq1` and `seq2`. Registers not in this set stay at the
/// `ConcreteMachineState::new_zeroed` default across all random/edge-case
/// inputs, which is a soundness gap for any sequence whose flag or register
/// output depends on a source register that is neither live-out nor a
/// destination of an earlier instruction in the sequence (e.g. `tst x1, #1`
/// vs `tst x1, #2` under a flag-only contract — see the regression test in
/// this module). The SMT path is unaffected; it operates on symbolic inputs.
fn fast_path_input_registers(
    live_out_registers: &crate::semantics::live_out::RegisterSet<crate::ir::Register>,
    seq1: &[Instruction],
    seq2: &[Instruction],
) -> Vec<crate::ir::Register> {
    use std::collections::HashSet;
    let mut regs: HashSet<crate::ir::Register> = HashSet::new();
    for r in live_out_registers.iter() {
        regs.insert(*r);
    }
    for instr in seq1.iter().chain(seq2.iter()) {
        for src in instr.source_registers() {
            regs.insert(src);
        }
    }
    // Sort by register index for deterministic input ordering (so test
    // failures and SMT-formula seeds are reproducible).
    let mut v: Vec<_> = regs.into_iter().collect();
    v.sort_by_key(|r| r.index().unwrap_or(u8::MAX));
    v
}

/// Build 16 inputs covering every initial NZCV combination with source
/// registers randomized. Used to plug a soundness gap when either sequence
/// reads flags before writing (e.g. CCMP, CSEL) and the contract treats
/// NZCV as live-out: the standard random/edge-case inputs leave initial
/// NZCV at `ConditionFlags::default()` (all zero), so a CCMP under a
/// condition predicate that depends on an incoming flag (e.g. `mi`) only
/// gets exercised on the condition-false branch.
fn fast_path_initial_nzcv_variants(
    input_regs: &[crate::ir::Register],
) -> Vec<ConcreteMachineState> {
    use crate::semantics::state::ConditionFlags;
    let variant_regs_config = RandomInputConfig {
        count: 16,
        registers: input_regs.to_vec(),
        memory_seed_size: 0,
    };
    let mut variants = generate_random_inputs(&variant_regs_config);
    for (i, input) in variants.iter_mut().enumerate() {
        input.set_flags(ConditionFlags {
            n: (i & 0b1000) != 0,
            z: (i & 0b0100) != 0,
            c: (i & 0b0010) != 0,
            v: (i & 0b0001) != 0,
        });
    }
    variants
}

/// Run the fast-path random + edge-case checks. Returns either a
/// `NotEquivalentFast` refutation, `None` if the fast path passed, or
/// `Some(Equivalent)` if `fast_only` short-circuits.
fn run_fast_path(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> Option<EquivalenceResult> {
    let live_out_registers = &config.live_out;
    // Under `fast_only`, the SMT path that would otherwise catch divergences
    // depending on source registers outside `live_out` is skipped — extend
    // the random-input mask to cover seq1+seq2 source registers so e.g.
    // `tst x1, #1` vs `tst x1, #2` is caught under `--live-out ';nzcv'
    // --fast-only`. Otherwise stay with the live-out-only mask: the SMT
    // path is authoritative (operates on symbolic inputs), and the larger
    // mask measurably increases per-call cost in search algorithms which
    // run check_equivalence on thousands of candidates.
    let input_regs: Vec<crate::ir::Register> = if config.fast_only {
        fast_path_input_registers(live_out_registers, seq1, seq2)
    } else {
        live_out_registers.iter().cloned().collect()
    };

    // Seed memory when either sequence touches it, so that LDR observations
    // during the fast-random pass return non-trivial values. See ADR-0007.
    let touches_mem = crate::validation::live_out::touches_memory(seq1)
        || crate::validation::live_out::touches_memory(seq2);
    let random_config = RandomInputConfig {
        count: config.random_test_count,
        registers: input_regs.clone(),
        memory_seed_size: if touches_mem {
            crate::validation::random::MEMORY_SEED_SIZE
        } else {
            0
        },
    };
    let random_inputs = generate_random_inputs(&random_config);

    for input in &random_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if !states_equal_for_live_out(
            &state1,
            &state2,
            live_out_registers,
            config.live_out.flags_live(),
            config.memory_live,
        ) {
            return Some(EquivalenceResult::NotEquivalentFast(input.clone()));
        }
    }

    let edge_inputs = generate_edge_case_inputs(&input_regs);
    for input in &edge_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if !states_equal_for_live_out(
            &state1,
            &state2,
            live_out_registers,
            config.live_out.flags_live(),
            config.memory_live,
        ) {
            return Some(EquivalenceResult::NotEquivalentFast(input.clone()));
        }
    }

    // Under `fast_only`, the SMT path that would otherwise catch initial-
    // NZCV divergence is skipped — for sequences that read flags before
    // writing them (CSEL family, CCMP, CCMN, ...), also test all 16 initial
    // NZCV combinations. Gated on `fast_only` because the SMT path already
    // handles this correctly via symbolic initial state, and adding 16
    // inputs to every search-algorithm candidate would burn significant
    // wall-clock time on a verifier that's normally SMT-authoritative.
    // NOT gated on `config.live_out.flags_live()` — a flag-reading sequence whose
    // *register* output depends on incoming NZCV (e.g. `csel x0, x1, x2, mi`
    // under `--live-out x0`) also needs the variants for the fast path to
    // catch divergence on the condition-true branch.
    if config.fast_only && (reads_flags_before_writing(seq1) || reads_flags_before_writing(seq2)) {
        for input in &fast_path_initial_nzcv_variants(&input_regs) {
            let state1 = apply_sequence_concrete(input.clone(), seq1);
            let state2 = apply_sequence_concrete(input.clone(), seq2);
            if !states_equal_for_live_out(
                &state1,
                &state2,
                live_out_registers,
                config.live_out.flags_live(),
                config.memory_live,
            ) {
                return Some(EquivalenceResult::NotEquivalentFast(input.clone()));
            }
        }
    }

    if config.fast_only {
        return Some(EquivalenceResult::Equivalent);
    }

    None
}

/// Check equivalence with configuration (fast path + optional SMT). No metrics.
///
/// Thin wrapper around `check_equivalence_with_config_metrics` that drops
/// the metrics. Callers that don't observe metrics pay the same
/// `solver.to_string()` cost on the unsat branch as the metrics-aware
/// caller; in practice that branch is rare (most candidates fail in the
/// fast path or return sat) and the serialization is microseconds.
pub fn check_equivalence_with_config(
    seq1: &[Instruction],
    seq2: &[Instruction],
    config: &EquivalenceConfig,
) -> EquivalenceResult {
    let (result, _) = check_equivalence_with_config_metrics(seq1, seq2, config);
    result
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

    // Issue #69: terminator-identity precheck — see `check_equivalence`.
    let (prefix1, terminator1) = split_terminator(seq1);
    let (prefix2, terminator2) = split_terminator(seq2);
    if terminator1 != terminator2 {
        return (
            EquivalenceResult::NotEquivalentFast(ConcreteMachineState::new_zeroed()),
            metrics,
        );
    }

    // ADR-0007: auto-derive memory_live and force fast_only off when memory
    // ops appear (see `check_equivalence_with_config` above for rationale).
    let memory_touched = crate::validation::live_out::touches_memory(prefix1)
        || crate::validation::live_out::touches_memory(prefix2);
    let mut config_owned;
    let config: &EquivalenceConfig = if memory_touched && (!config.memory_live || config.fast_only)
    {
        config_owned = config.clone();
        config_owned.memory_live = true;
        if config_owned.fast_only {
            config_owned.fast_only = false;
        }
        &config_owned
    } else {
        config
    };

    if let Some(early) = pre_smt_guard(prefix1, prefix2, config.live_out.flags_live()) {
        return (early, metrics);
    }

    if let Some(fast) = run_fast_path(prefix1, prefix2, config) {
        return (fast, metrics);
    }

    let solver = build_smt_solver(prefix1, prefix2, config);
    let smt_start = std::time::Instant::now();
    let sat_result = solver.check();
    let smt_elapsed = smt_start.elapsed();
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
            smt_elapsed,
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

    // Safety guard added in issue #77 step 6: catch any future caller that
    // splices states of mismatched width before Z3 panics on a BV-sort
    // mismatch deep inside `states_not_equal_for_live_out`.
    debug_assert_eq!(
        final_state1.width(),
        final_state2.width(),
        "build_smt_solver: width mismatch between sequence final states",
    );

    solver.assert(states_not_equal_for_live_out(
        &final_state1,
        &final_state2,
        &config.live_out,
        config.live_out.flags_live(),
        config.memory_live,
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
    let live_out_registers = &config.live_out;
    let input_regs: Vec<_> = live_out_registers.iter().cloned().collect();

    let touches_mem = crate::validation::live_out::touches_memory(seq1)
        || crate::validation::live_out::touches_memory(seq2);
    let random_config = RandomInputConfig {
        count: config.random_test_count,
        registers: input_regs.clone(),
        memory_seed_size: if touches_mem {
            crate::validation::random::MEMORY_SEED_SIZE
        } else {
            0
        },
    };
    let random_inputs = generate_random_inputs(&random_config);

    for input in &random_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if let Some(diff) = find_first_difference(
            &state1,
            &state2,
            live_out_registers,
            config.live_out.flags_live(),
        ) {
            return Some(diff);
        }
    }

    let edge_inputs = generate_edge_case_inputs(&input_regs);
    for input in &edge_inputs {
        let state1 = apply_sequence_concrete(input.clone(), seq1);
        let state2 = apply_sequence_concrete(input.clone(), seq2);

        if let Some(diff) = find_first_difference(
            &state1,
            &state2,
            live_out_registers,
            config.live_out.flags_live(),
        ) {
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
    /// Construct a baseline config. **Note:** `live_out` defaults to
    /// `X86LiveOutMask::empty()` — equivalence over an empty live-out
    /// set is vacuously true. Callers must populate the mask (typically
    /// via `live_out(x86_live_out_from_target(target))`) before using
    /// the config, or any two sequences will compare as equivalent.
    pub fn new(width: u32) -> Self {
        Self {
            live_out: crate::semantics::state::X86LiveOutMask::empty(),
            width,
            random_test_count: 10,
            smt_timeout: Some(Duration::from_secs(30)),
            fast_only: false,
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

/// Convenience wrapper used by both x86 search backends
/// (`stochastic/backend.rs` and `symbolic/backend.rs`). Builds an
/// `X86EquivalenceConfig` from the supplied mask + width + timeout
/// and invokes `check_equivalence_x86`. Two backends were each
/// inlining this same builder + call — a single helper here keeps
/// them from drifting.
pub fn check_equivalence_x86_for_search(
    target: &[crate::isa::x86::X86Instruction],
    proposal: &[crate::isa::x86::X86Instruction],
    live_out: &crate::semantics::state::X86LiveOutMask,
    width: u32,
    timeout: std::time::Duration,
) -> EquivalenceResult {
    let mut cfg = X86EquivalenceConfig::new(width);
    cfg.live_out = live_out.clone();
    cfg.smt_timeout = Some(timeout);
    check_equivalence_x86(target, proposal, &cfg)
}

/// Check whether two x86 instruction sequences are equivalent under the
/// given live-out mask and operand width. Mirrors `check_equivalence_with_config`
/// for the AArch64 backend: fast path uses the concrete interpreter over
/// random inputs (and EFLAGS comparison when CMP is present or the mask
/// declares flags live); slow path lowers to Z3 BVs and checks UNSAT of the
/// not-equal assertion over live-out registers, plus the five tracked
/// EFLAGS bits when `flags_live` is set.
pub fn check_equivalence_x86(
    seq1: &[crate::isa::x86::X86Instruction],
    seq2: &[crate::isa::x86::X86Instruction],
    config: &X86EquivalenceConfig,
) -> EquivalenceResult {
    // Peel matching Jcc terminators and require both sides to share the
    // exact same terminator (struct equality on the condition code).
    // Mirrors the AArch64 precheck in `check_equivalence`.
    let (prefix1, terminator1) = crate::ir::instructions::split_terminator_x86(seq1);
    let (prefix2, terminator2) = crate::ir::instructions::split_terminator_x86(seq2);
    if terminator1 != terminator2 {
        return EquivalenceResult::NotEquivalent;
    }

    // When a Jcc terminator is held fixed across both sides, its branch
    // outcome consumes the prefix's final EFLAGS. The caller-supplied
    // live-out mask may not declare flags live (e.g. when the target
    // contains only MOV/CMOV which `has_side_effects` reports as
    // flag-clean), so force `flags_live=true` for the prefix comparison
    // whenever a Jcc was peeled — otherwise a proposal that clobbers
    // EFLAGS before the branch would be accepted unsoundly.
    let effective_config = if matches!(
        terminator1,
        Some(crate::isa::x86::X86Instruction::Jcc { .. })
    ) && !config.live_out.flags_live()
    {
        let mut c = config.clone();
        c.live_out = c.live_out.with_flags(true);
        std::borrow::Cow::Owned(c)
    } else {
        std::borrow::Cow::Borrowed(config)
    };
    let config = effective_config.as_ref();

    // Fast path: 10 random inputs over the prefixes only.
    if let Some(refutation) = run_fast_path_x86(prefix1, prefix2, config) {
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
    let final1 = crate::semantics::smt_x86::apply_sequence(initial.clone(), prefix1);
    let final2 = crate::semantics::smt_x86::apply_sequence(initial, prefix2);

    let mut disjuncts: Vec<z3::ast::Bool> = Vec::new();
    for reg in config.live_out.iter() {
        let v1 = final1.get_register(*reg);
        let v2 = final2.get_register(*reg);
        disjuncts.push(v1.eq(v2).not());
    }
    // When flags are live (caller-declared or forced by a peeled Jcc),
    // any of the five tracked EFLAGS bits diverging refutes equivalence.
    if config.live_out.flags_live() {
        disjuncts.push(crate::semantics::smt_x86::flags_not_equal_x86(
            &final1, &final2,
        ));
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
        // Also randomize the five tracked input EFLAGS bits from the
        // same seed. Otherwise CMOV/Jcc-flag-reading instructions would
        // see ZF=CF=SF=OF=PF=0 across every trial and a proposal that
        // ignores incoming flags could pass the fast path (e.g.
        // `cmovne rax, rbx` accepted as equivalent to `mov rax, rbx`).
        let mut flags = crate::semantics::state::Eflags::new();
        flags.cf = (seed & 1) != 0;
        flags.pf = (seed & 2) != 0;
        flags.zf = (seed & 4) != 0;
        flags.sf = (seed & 8) != 0;
        flags.of = (seed & 16) != 0;
        state.set_flags(flags);
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
    fn aarch64_with_flags_writes_through_mask() {
        // After moving `flags_live` from `EquivalenceConfig` onto the mask,
        // `with_flags(true)` must make `config.live_out.flags_live()` true.
        let config = EquivalenceConfig::default().with_flags(true);
        assert!(config.live_out.flags_live());

        let config = EquivalenceConfig::default().with_flags(false);
        assert!(!config.live_out.flags_live());
    }

    #[test]
    fn aarch64_live_out_builder_preserves_flags_live() {
        // Regression: with `flags_live` on the mask, the builder order
        // `.with_flags(true).live_out(...)` used to silently drop the flag bit
        // because `LiveOut::from_registers(...)` defaults `flags_live` to
        // false. The builder must merge (OR) the prior flag state so flags
        // stay live regardless of builder order.
        let config = EquivalenceConfig::default()
            .with_flags(true)
            .live_out(LiveOut::from_registers(vec![Register::X0]));
        assert!(
            config.live_out.flags_live(),
            "live_out() must preserve flags_live set by an earlier with_flags()"
        );

        // Reverse order (already known-good) still works.
        let config = EquivalenceConfig::default()
            .live_out(LiveOut::from_registers(vec![Register::X0]))
            .with_flags(true);
        assert!(config.live_out.flags_live());

        // Explicit flags on the new mask propagate even with no prior with_flags.
        let config = EquivalenceConfig::default()
            .live_out(LiveOut::from_registers(vec![Register::X0]).with_flags(true));
        assert!(config.live_out.flags_live());
    }

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
        let cfg = X86EquivalenceConfig::new(64)
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
        let cfg = X86EquivalenceConfig::new(64)
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
        let cfg = X86EquivalenceConfig::new(64)
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
        let cfg = X86EquivalenceConfig::new(64)
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]));
        assert_eq!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    // --- SMT path catches flag-only divergence when flags_live ---

    #[test]
    fn x86_smt_path_distinguishes_cmps_with_different_operands_when_flags_live() {
        // `cmp rax, rbx` and `cmp rax, rcx` both write EFLAGS symbolically
        // (cycle 3) but their flag effects diverge whenever rbx != rcx.
        // The SMT flag disjunct (cycle 4) must let Z3 find that model and
        // refute equivalence under flags_live=true.
        //
        // Zero `random_test_count` to force-skip the fast path so the
        // assertion lands squarely on the SMT solver path.
        let seq1 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let seq2 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RCX,
        }];
        let mut cfg =
            X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty().with_flags(true));
        cfg.random_test_count = 0;
        assert!(matches!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_rejects_sequences_with_differing_jcc_terminators() {
        use crate::isa::x86::X86Condition;
        // Same prefix, different Jcc conditions => not equivalent.
        let prefix = X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let seq_je = vec![
            prefix,
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let seq_jne = vec![
            prefix,
            X86Instruction::Jcc {
                cond: X86Condition::NE,
            },
        ];
        let cfg = X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty());
        assert!(matches!(
            check_equivalence_x86(&seq_je, &seq_jne, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_accepts_sequences_with_matching_jcc_terminators() {
        use crate::isa::x86::X86Condition;
        let prefix = X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let jcc = X86Instruction::Jcc {
            cond: X86Condition::E,
        };
        let seq1 = vec![prefix, jcc];
        let seq2 = vec![prefix, jcc];
        let cfg = X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty());
        assert_eq!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn x86_fast_path_distinguishes_cmov_from_unconditional_mov_under_random_flags() {
        // Reviewer-supplied counterexample: `cmovne rax, rbx` should NOT
        // be accepted as equivalent to `mov rax, rbx` because the
        // original preserves rax when incoming ZF=1. The fast path must
        // randomize incoming EFLAGS — not just registers — for any trial
        // to hit a ZF=1 case and refute the rewrite.
        use crate::isa::x86::X86Condition;
        let target = vec![X86Instruction::Cmov {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
            cond: X86Condition::NE,
        }];
        let proposal = vec![X86Instruction::MovReg {
            rd: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let cfg = X86EquivalenceConfig::new(64)
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]))
            .fast_only();
        assert!(matches!(
            check_equivalence_x86(&target, &proposal, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_jcc_terminator_forces_flag_observability_on_prefix() {
        // Reviewer-supplied counterexample: a no-op `cmove rax, rax` prefix
        // versus `xor rcx, rcx` prefix, with a fixed `je` terminator on both
        // sides. Live-out is rax only (no caller-declared flags_live). The
        // prefixes leave rax untouched, but XOR clobbers ZF — which the
        // trailing `je` reads. Equivalence must reject; the Jcc terminator
        // forces the prefix's EFLAGS effect to be observable.
        use crate::isa::x86::X86Condition;
        let target = vec![
            X86Instruction::Cmov {
                rd: X86Register::RAX,
                rs: X86Register::RAX,
                cond: X86Condition::E,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let proposal = vec![
            X86Instruction::XorReg {
                rd: X86Register::RCX,
                rs: X86Register::RCX,
            },
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let cfg = X86EquivalenceConfig::new(64)
            .live_out(X86LiveOutMask::from_registers(vec![X86Register::RAX]));
        assert!(matches!(
            check_equivalence_x86(&target, &proposal, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_rejects_terminator_present_on_only_one_side() {
        use crate::isa::x86::X86Condition;
        let prefix = X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        };
        let seq_with_jcc = vec![
            prefix,
            X86Instruction::Jcc {
                cond: X86Condition::E,
            },
        ];
        let seq_without = vec![prefix];
        let cfg = X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty());
        assert!(matches!(
            check_equivalence_x86(&seq_with_jcc, &seq_without, &cfg),
            EquivalenceResult::NotEquivalent
        ));
    }

    #[test]
    fn x86_smt_path_treats_cmps_with_different_operands_as_equivalent_without_flags_live() {
        // Without flags_live=true, the same CMP pair must still pass on
        // the SMT path — the disjunct is gated on `flags_live`, and the
        // register-disjunct list is empty (no live-out registers), so
        // equivalence is vacuously true.
        let seq1 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let seq2 = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RCX,
        }];
        let mut cfg = X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty());
        cfg.random_test_count = 0;
        assert_eq!(
            check_equivalence_x86(&seq1, &seq2, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn x86_smt_path_equates_two_cmps_with_same_operands_under_flags_live() {
        // Identical CMPs must remain equivalent on the SMT path even with
        // flags_live=true — the flag-disjunct should be UNSAT.
        let cmp = vec![X86Instruction::CmpReg {
            rn: X86Register::RAX,
            rs: X86Register::RBX,
        }];
        let mut cfg =
            X86EquivalenceConfig::new(64).live_out(X86LiveOutMask::empty().with_flags(true));
        cfg.random_test_count = 0;
        assert_eq!(
            check_equivalence_x86(&cmp.clone(), &cmp, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    /// Issue #60 end-to-end discovery test: the enumerator's candidate set
    /// contains a length-1 instruction equivalent to the 2-instruction
    /// `UXTB t, X2 ; ADD X0, X1, t` target sequence — namely the
    /// extended-register form `ADD X0, X1, X2, UXTB #0`. This is the
    /// canonical acceptance criterion for issue #60.
    #[test]
    fn test_optimizer_discovers_extended_register_collapse() {
        use crate::ir::ExtendKind;
        use crate::search::candidate::generate_all_instructions;

        // Target sequence: UXTB X10, X2 ; ADD X0, X1, X10.
        let target = vec![
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

        // Live-out is just X0; the temp X10 is dead after the sequence.
        let config = EquivalenceConfig {
            live_out: LiveOut::from_registers(vec![Register::X0]),
            ..Default::default()
        };

        // Small pool keeps enumeration tractable for a unit test.
        let regs = vec![Register::X0, Register::X1, Register::X2, Register::X10];
        let imms = vec![0i64];
        let candidates = generate_all_instructions(&regs, &imms);

        let discovered = candidates.iter().find(|c| {
            matches!(
                c,
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ExtendedRegister {
                        reg: Register::X2,
                        kind: ExtendKind::Uxtb,
                        shift: 0,
                    },
                }
            ) && check_equivalence_with_config(&target, std::slice::from_ref(*c), &config)
                == EquivalenceResult::Equivalent
        });

        assert!(
            discovered.is_some(),
            "enumerative search must discover `ADD X0, X1, X2, UXTB #0` as equivalent to UXTB+ADD"
        );
    }

    /// Issue #59 end-to-end discovery test: the enumerator's candidate set
    /// contains a length-1 instruction equivalent to the 2-instruction
    /// `LSL t, X2, #3 ; ADD X0, X1, t` target sequence — namely the
    /// shifted-register form `ADD X0, X1, X2, LSL #3`.
    #[test]
    fn test_optimizer_discovers_shifted_register_collapse() {
        use crate::ir::ShiftKind;
        use crate::search::candidate::generate_all_instructions;

        // Target sequence: LSL X10, X2, #3 ; ADD X0, X1, X10.
        let target = vec![
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

        // Live-out is just X0; the temp X10 is dead after the sequence.
        let config = EquivalenceConfig {
            live_out: LiveOut::from_registers(vec![Register::X0]),
            ..Default::default()
        };

        // Use a small register/immediate pool so enumeration is fast.
        let regs = vec![Register::X0, Register::X1, Register::X2, Register::X10];
        let imms = vec![0i64];
        let candidates = generate_all_instructions(&regs, &imms);

        // Find a single-instruction candidate equivalent to the 2-instruction
        // target, restricted to ADD with a ShiftedRegister rm — that's the
        // collapse the optimizer is supposed to discover.
        let discovered = candidates.iter().find(|c| {
            matches!(
                c,
                Instruction::Add {
                    rd: Register::X0,
                    rn: Register::X1,
                    rm: Operand::ShiftedRegister {
                        reg: Register::X2,
                        kind: ShiftKind::Lsl,
                        amount: 3,
                    },
                }
            ) && check_equivalence_with_config(&target, std::slice::from_ref(*c), &config)
                == EquivalenceResult::Equivalent
        });

        assert!(
            discovered.is_some(),
            "enumerative search must discover `ADD X0, X1, X2, LSL #3` as equivalent to LSL+ADD"
        );
    }

    #[test]
    fn issue_57_acceptance_ccmp_branchless_equiv_to_cmp_csel() {
        // The issue 57 acceptance criterion: SMT proves a CCMP-based
        // branchless `(a==b) && (a<c)` ≡ the multi-instruction CMP+CSET
        // form, with the result deposited in X3.
        //
        // CCMP form (3 instructions):
        //   CMP x0, x1            ; flags from x0 - x1
        //   CCMP x0, x2, #0, EQ   ; if EQ: flags = x0 - x2; else flags = 0
        //   CSET x3, LT
        //
        // Multi-instruction form (5 instructions):
        //   CMP x0, x1
        //   CSET xtmp, EQ         ; (x0 == x1)
        //   CMP x0, x2
        //   CSET x3, LT           ; (x0 < x2 signed)
        //   AND x3, x3, xtmp
        let target = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Ccmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X2),
                nzcv: 0,
                cond: crate::ir::types::Condition::EQ,
            },
            Instruction::Cset {
                rd: Register::X3,
                cond: crate::ir::types::Condition::LT,
            },
        ];
        let candidate = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X1),
            },
            Instruction::Cset {
                rd: Register::X4,
                cond: crate::ir::types::Condition::EQ,
            },
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Cset {
                rd: Register::X3,
                cond: crate::ir::types::Condition::LT,
            },
            Instruction::And {
                rd: Register::X3,
                rn: Register::X3,
                rm: Operand::Register(Register::X4),
            },
        ];
        // Deliberately omit `.with_flags(true)`: the two forms produce
        // intentionally different post-window NZCV (the candidate has two
        // CMPs vs the target's one CMP + CCMP), so the proof only holds
        // when X3 is the sole observable. Search callers that need flag
        // preservation set `with_flags(true)` themselves — see
        // `mcmc.rs` / `synthesis.rs`.
        let cfg =
            EquivalenceConfig::default().live_out(LiveOut::from_registers(vec![Register::X3]));
        assert_eq!(
            check_equivalence_with_config(&target, &candidate, &cfg),
            EquivalenceResult::Equivalent,
            "Issue 57 acceptance: CCMP branchless ≡ CMP+CSET multi-instruction form"
        );
    }

    #[test]
    fn cmp_then_csel_is_flag_dependent() {
        // CMP x1, x2; CSEL x0, x3, x4, eq writes x0 = (x1==x2 ? x3 : x4),
        // which is not equivalent to MOV x0, x3 in general. With both
        // sequences as their own target, equivalence should hold.
        let cmp_csel = vec![
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Register(Register::X2),
            },
            Instruction::Csel {
                rd: Register::X0,
                rn: Register::X3,
                rm: Register::X4,
                cond: crate::ir::types::Condition::EQ,
            },
        ];
        let mov_only = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X3,
        }];
        let cfg =
            EquivalenceConfig::default().live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_ne!(
            check_equivalence_with_config(&cmp_csel, &mov_only, &cfg),
            EquivalenceResult::Equivalent,
            "CMP+CSEL outcome depends on x1==x2; cannot collapse to MOV"
        );
        // Self-equivalence: a sequence equals itself.
        assert_eq!(
            check_equivalence_with_config(&cmp_csel, &cmp_csel, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn csinc_wraps_on_max_input() {
        // CSINC x0, x1, x2, EQ with EQ=false sets x0 = x2 + 1 (wrapping).
        // Pin x1 = 0 and x2 = u64::MAX, then CMP x1, #1 leaves Z=0 so the
        // EQ predicate is false in both interpreters. CSINC's false branch
        // then writes x2 + 1 = 0 (wrap), matching the MovImm #0 candidate.
        let target = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 0,
            },
            Instruction::MovN {
                rd: Register::X2,
                imm: 0,
                shift: 0,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::Csinc {
                rd: Register::X0,
                rn: Register::X1,
                rm: Register::X2,
                cond: crate::ir::types::Condition::EQ,
            },
        ];
        let candidate = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 0,
            },
            Instruction::MovN {
                rd: Register::X2,
                imm: 0,
                shift: 0,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(1),
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
        ];
        let cfg =
            EquivalenceConfig::default().live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&target, &candidate, &cfg),
            EquivalenceResult::Equivalent,
            "CSINC with rm = u64::MAX must wrap to 0"
        );
    }

    #[test]
    fn cmp_equivalent_to_subs_xzr_with_flags_live() {
        // CMP x1, x2 and SUBS XZR, x1, x2 leave registers unchanged and
        // write identical NZCV. With flags as live-out, SMT must prove
        // equivalence — but only if the pre-SMT guard does not reject
        // them as having "different flag-writers" by structural equality.
        let seq_cmp = vec![Instruction::Cmp {
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let seq_subs = vec![Instruction::Subs {
            rd: Register::XZR,
            rn: Register::X1,
            rm: Operand::Register(Register::X2),
        }];
        let cfg = EquivalenceConfig::default().with_flags(true);
        assert_eq!(
            check_equivalence_with_config(&seq_cmp, &seq_subs, &cfg),
            EquivalenceResult::Equivalent
        );
    }

    #[test]
    fn issue_92_regression_mismatched_upstream_flags() {
        // Issue #92: two sequences with structurally identical flag-writers
        // but feeding them different upstream values produce different NZCV.
        // With flags live, SMT must reject the rewrite. The fast-path will
        // also catch it on random inputs (the constants -7 != +7).
        let target = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 0,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 7,
            },
        ];
        let candidate = vec![
            Instruction::MovImm {
                rd: Register::X1,
                imm: 5,
            },
            Instruction::Cmp {
                rn: Register::X1,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X0,
                imm: 7,
            },
        ];
        let cfg = EquivalenceConfig::default()
            .live_out(LiveOut::from_registers(vec![Register::X0]))
            .with_flags(true);
        assert_ne!(
            check_equivalence_with_config(&target, &candidate, &cfg),
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

    /// Soundness regression for the flag-drop guard: `ADDS x0, x1, #1` ≡
    /// `ADD x0, x1, #1` is only sound when NZCV is dead after the window.
    /// When the caller marks flags live (`with_flags(true)` or the unmasked
    /// `check_equivalence` path which always includes flags) the rewrite
    /// must be rejected. With flags dead, registers alone match and the
    /// rewrite is genuinely sound.
    #[test]
    fn test_adds_to_add_rewrite_rejected_when_flags_live() {
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
        let cfg_flags_live =
            EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]))
                .with_flags(true);
        assert_eq!(
            check_equivalence_with_config(&adds, &add, &cfg_flags_live),
            EquivalenceResult::NotEquivalent,
            "Dropping a flag-writer must not be certified as equivalent when flags are live"
        );
        // The unmasked path always treats NZCV as part of full state, so it
        // also rejects.
        assert_eq!(
            check_equivalence(&adds, &add),
            EquivalenceResult::NotEquivalent,
            "Unmasked entry point includes NZCV in comparison"
        );
    }

    /// Soundness regression: `BICS x0, x1, x2` → `BIC x0, x1, x2` drops the
    /// NZCV side-effect. Rejected when flags are observable.
    #[test]
    fn test_bics_to_bic_rewrite_rejected_when_flags_live() {
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
        let cfg_flags_live =
            EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]))
                .with_flags(true);
        assert_eq!(
            check_equivalence_with_config(&bics, &bic, &cfg_flags_live),
            EquivalenceResult::NotEquivalent
        );
        assert_eq!(
            check_equivalence(&bics, &bic),
            EquivalenceResult::NotEquivalent
        );
    }

    /// Completeness regression for the gated guard: dropping a flag-writer
    /// must NOT be rejected when the caller has marked flags dead. The
    /// pre-PR structural guard rejected this unconditionally, blocking a
    /// real class of sound rewrites. Covers both the non-metrics and
    /// metrics entry points since `pre_smt_guard` is now plumbed through
    /// both.
    #[test]
    fn test_dropping_flag_writer_allowed_when_flags_dead() {
        let target = vec![
            Instruction::Cmp {
                rn: Register::X0,
                rm: Operand::Immediate(0),
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 7,
            },
        ];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X1,
            imm: 7,
        }];
        // Explicit `.with_flags(false)` for parity with `cfg_flags_live`
        // elsewhere in this module — makes the intent self-documenting
        // even though `EquivalenceConfig::default()` already sets it.
        let cfg_flags_dead =
            EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X1]))
                .with_flags(false);
        assert_eq!(
            check_equivalence_with_config(&target, &candidate, &cfg_flags_dead),
            EquivalenceResult::Equivalent,
            "With flags marked dead, dropping a flag-only instruction is sound"
        );
        // Mirror the assertion for the metrics-returning entry point, which
        // shares the same pre_smt_guard plumbing.
        let (metrics_result, _metrics) =
            check_equivalence_with_config_metrics(&target, &candidate, &cfg_flags_dead);
        assert_eq!(
            metrics_result,
            EquivalenceResult::Equivalent,
            "Metrics entry point also accepts flag-only divergence when flags are dead"
        );
    }

    /// Soundness regression: `NEGS x0, x1` → `NEG x0, x1` drops NZCV.
    /// Rejected when flags are observable.
    #[test]
    fn test_negs_to_neg_rewrite_rejected_when_flags_live() {
        let negs = vec![Instruction::Negs {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let neg = vec![Instruction::Neg {
            rd: Register::X0,
            rm: Register::X1,
        }];
        let cfg_flags_live =
            EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]))
                .with_flags(true);
        assert_eq!(
            check_equivalence_with_config(&negs, &neg, &cfg_flags_live),
            EquivalenceResult::NotEquivalent
        );
        assert_eq!(
            check_equivalence(&negs, &neg),
            EquivalenceResult::NotEquivalent
        );
    }

    /// `ADD x0, x1, #1; CMP x2, #0` (writes flags from `CMP x2, #0`) vs
    /// `ADDS x0, x1, #1` (writes flags from `ADDS x0, x1, #1`). Both
    /// sequences write X0 to x1+1 and both have a flag-writer, so the
    /// pre-SMT guard now lets SMT settle it. With flags live-out the
    /// solver sees the NZCV divergence; with flags dead the rewrite is
    /// genuinely sound (registers alone match).
    #[test]
    fn test_swapped_flag_writer_rewrite_rejected_when_flags_live() {
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
        let cfg_flags_live =
            EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]))
                .with_flags(true);
        assert_ne!(
            check_equivalence_with_config(&target, &candidate, &cfg_flags_live),
            EquivalenceResult::Equivalent,
            "When NZCV is live, the two flag-writers produce different flags"
        );
        // Same with the no-config entry point, which now includes flags in
        // the unmasked full-state comparison.
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

    /// Acceptance criterion #2 from issue #61:
    /// SMT proves `BFI rd,rn,#lsb,#width` ≡ {
    ///   AND tmp_field, rn, #low_mask;       // isolate low `width` bits of rn
    ///   LSL tmp_shift, tmp_field, #lsb;     // shift them into position
    ///   AND tmp_clear, rd, #!shifted_mask;  // clear destination window in rd
    ///   ORR rd, tmp_clear, tmp_shift;       // merge
    /// }
    /// The issue's wording was "AND clear; AND mask; ORR" — this is the
    /// formal expansion. Verified for one representative (lsb, width).
    #[test]
    fn test_bfi_equivalent_to_and_and_or() {
        let lsb = 4u8;
        let width = 8u8;
        let low_mask = (1i64 << width) - 1;
        let shifted_mask = low_mask << lsb;
        let clear_mask = !shifted_mask;

        let bfi = vec![Instruction::Bfi {
            rd: Register::X0,
            rn: Register::X1,
            lsb,
            width,
        }];

        let expanded = vec![
            // tmp_field (X2) = rn & low_mask
            Instruction::And {
                rd: Register::X2,
                rn: Register::X1,
                rm: Operand::Immediate(low_mask),
            },
            // tmp_shift (X2) = tmp_field << lsb
            Instruction::Lsl {
                rd: Register::X2,
                rn: Register::X2,
                shift: Operand::Immediate(lsb as i64),
            },
            // tmp_clear (X3) = rd & !shifted_mask
            Instruction::And {
                rd: Register::X3,
                rn: Register::X0,
                rm: Operand::Immediate(clear_mask),
            },
            // rd = tmp_clear | tmp_shift
            Instruction::Orr {
                rd: Register::X0,
                rn: Register::X3,
                rm: Operand::Register(Register::X2),
            },
        ];

        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&bfi, &expanded, &config),
            EquivalenceResult::Equivalent
        );
    }

    /// Acceptance criterion #1 from issue #61:
    /// SMT proves `UBFX rd,rn,#lsb,#width` ≡ `LSR t,rn,#lsb; AND rd,t,#((1<<width)-1)`.
    #[test]
    fn test_ubfx_equivalent_to_lsr_and_mask() {
        let lsb = 8i64;
        let width = 16u8;
        let mask = (1i64 << width) - 1;

        let ubfx = vec![Instruction::Ubfx {
            rd: Register::X0,
            rn: Register::X1,
            lsb: lsb as u8,
            width,
        }];

        let lsr_and = vec![
            Instruction::Lsr {
                rd: Register::X2,
                rn: Register::X1,
                shift: Operand::Immediate(lsb),
            },
            Instruction::And {
                rd: Register::X0,
                rn: Register::X2,
                rm: Operand::Immediate(mask),
            },
        ];

        let config = EquivalenceConfig::with_live_out(LiveOut::from_registers(vec![Register::X0]));
        assert_eq!(
            check_equivalence_with_config(&ubfx, &lsr_and, &config),
            EquivalenceResult::Equivalent
        );
    }

    // ===== Issue #69: terminator-identity precheck =====

    use crate::ir::LabelId;
    use crate::ir::types::Condition;

    fn mov_imm(imm: i64) -> Instruction {
        Instruction::MovImm {
            rd: Register::X0,
            imm,
        }
    }

    #[test]
    fn check_equivalence_rejects_when_terminators_differ() {
        // Same prefix, different conditional-branch terminator → NotEquivalent.
        let seq1 = vec![
            mov_imm(1),
            Instruction::BCond {
                target: LabelId(0x1000),
                cond: Condition::EQ,
            },
        ];
        let seq2 = vec![
            mov_imm(1),
            Instruction::BCond {
                target: LabelId(0x1000),
                cond: Condition::NE,
            },
        ];
        let result = check_equivalence(&seq1, &seq2);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn check_equivalence_accepts_when_terminators_match() {
        // Same prefix + same terminator → Equivalent.
        let term = Instruction::Ret { rn: Register::X30 };
        let seq1 = vec![mov_imm(1), term];
        let seq2 = vec![mov_imm(1), term];
        let result = check_equivalence(&seq1, &seq2);
        assert!(
            matches!(result, EquivalenceResult::Equivalent),
            "got {:?}",
            result
        );
    }

    #[test]
    fn check_equivalence_rejects_one_terminator_one_none() {
        let seq1 = vec![mov_imm(1)];
        let seq2 = vec![mov_imm(1), Instruction::Ret { rn: Register::X30 }];
        let result = check_equivalence(&seq1, &seq2);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "got {:?}",
            result
        );
    }

    #[test]
    fn check_equivalence_accepts_two_bare_rets() {
        let term = Instruction::Ret { rn: Register::X30 };
        let result = check_equivalence(&[term], &[term]);
        assert!(
            matches!(result, EquivalenceResult::Equivalent),
            "got {:?}",
            result
        );
    }

    /// `tst x1, #1` and `tst x1, #2` differ on NZCV when bit 0 vs bit 1 of
    /// x1 is set, so a flag-aware live-out contract must classify them as
    /// non-equivalent. Prior to the source-register randomization fix, the
    /// fast path only varied registers in `config.live_out` —
    /// empty for a flag-only contract — so x1 stayed at zero across all
    /// random + edge-case inputs and both sequences reported flags as zero,
    /// returning `Equivalent` under `--fast-only`. The fix unions the source
    /// registers of both sequences into the random-input mask.
    #[test]
    fn fast_only_flags_only_contract_detects_tst_divergence() {
        let seq1 = vec![Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Immediate(1),
        }];
        let seq2 = vec![Instruction::Tst {
            rn: Register::X1,
            rm: Operand::Immediate(2),
        }];
        let config = EquivalenceConfig::fast_only()
            .live_out(LiveOut::from_registers(vec![]))
            .with_flags(true);
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "expected NotEquivalentFast for flags-only fast-only contract, got {:?}",
            result
        );
    }

    /// `ccmp x0, #0, #0, mi` and `ccmp x1, #1, #0, mi` both fall through to
    /// the immediate-NZCV `#0` branch when initial N is false, so all flags
    /// land at zero regardless of x0/x1. When initial N is true, the MI
    /// branch fires: seq1 computes `x0 cmp 0`, seq2 computes `x1 cmp 1` —
    /// flags then depend on x0/x1 and diverge for most randomized values.
    /// Prior to the initial-NZCV variants in `run_fast_path`, the fast path
    /// only tested with NZCV defaulted to zero, so this pair returned
    /// `Equivalent` under `--fast-only`. The fix is to also generate inputs
    /// with each of the 16 initial NZCV combinations when either sequence
    /// reads flags before writing.
    #[test]
    fn fast_only_flags_only_contract_detects_ccmp_initial_nzcv_divergence() {
        let seq1 = vec![Instruction::Ccmp {
            rn: Register::X0,
            rm: Operand::Immediate(0),
            nzcv: 0,
            cond: Condition::MI,
        }];
        let seq2 = vec![Instruction::Ccmp {
            rn: Register::X1,
            rm: Operand::Immediate(1),
            nzcv: 0,
            cond: Condition::MI,
        }];
        let config = EquivalenceConfig::fast_only()
            .live_out(LiveOut::from_registers(vec![]))
            .with_flags(true);
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "expected NotEquivalentFast for ccmp pair under flags-only fast-only, got {:?}",
            result
        );
    }

    /// `csel x0, x1, x2, mi` reads incoming N to decide whether x0 = x1
    /// (N=true) or x0 = x2 (N=false). With a register-live contract
    /// (`--live-out x0` but `flags_live=false`), the initial-NZCV variants
    /// were originally gated on `config.live_out.flags_live()` — so all fast-path
    /// inputs left N=false and the candidate `mov x0, x2` was accepted as
    /// equivalent even when x1 != x2 and N=true would differ. Broadening
    /// the gate to fire on any flag-reading sequence (regardless of whether
    /// flags themselves are observable) plugs the gap.
    #[test]
    fn fast_only_register_contract_detects_csel_initial_nzcv_divergence() {
        let seq1 = vec![Instruction::Csel {
            rd: Register::X0,
            rn: Register::X1,
            rm: Register::X2,
            cond: Condition::MI,
        }];
        let seq2 = vec![Instruction::MovReg {
            rd: Register::X0,
            rn: Register::X2,
        }];
        let config =
            EquivalenceConfig::fast_only().live_out(LiveOut::from_registers(vec![Register::X0]));
        // Deliberately NOT calling `.with_flags(true)` — this regression
        // exercises a register-only contract where the candidate's output
        // depends on incoming NZCV via CSEL.
        let result = check_equivalence_with_config(&seq1, &seq2, &config);
        assert!(
            matches!(result, EquivalenceResult::NotEquivalentFast(_)),
            "expected NotEquivalentFast for csel-vs-mov under --fast-only --live-out x0, got {:?}",
            result
        );
    }

    #[test]
    fn smt_elapsed_is_nonzero_when_solver_runs() {
        // MOV #0 vs EOR self — semantically equivalent under x0-only
        // live-out, fast-path forwards to SMT because random concrete
        // inputs all agree. Solver must run and report a nonzero
        // smt_elapsed.
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let seq2 = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];
        let cfg =
            EquivalenceConfig::default().live_out(LiveOut::from_registers(vec![Register::X0]));
        let (result, metrics) = check_equivalence_with_config_metrics(&seq1, &seq2, &cfg);
        assert_eq!(result, EquivalenceResult::Equivalent);
        assert!(metrics.smt_called, "solver should have been invoked");
        assert!(
            metrics.smt_elapsed > Duration::ZERO,
            "smt_elapsed must be nonzero when solver runs; got {:?}",
            metrics.smt_elapsed
        );
    }

    #[test]
    fn smt_elapsed_is_zero_when_fast_path_rejects() {
        // MOV #1 vs MOV #2 — the first random concrete input diverges,
        // so fast-path rejects before SMT is built. smt_elapsed must
        // be exactly zero.
        let seq1 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];
        let seq2 = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 2,
        }];
        let cfg =
            EquivalenceConfig::default().live_out(LiveOut::from_registers(vec![Register::X0]));
        let (result, metrics) = check_equivalence_with_config_metrics(&seq1, &seq2, &cfg);
        assert!(matches!(result, EquivalenceResult::NotEquivalentFast(_)));
        assert!(!metrics.smt_called, "fast path should reject before SMT");
        assert_eq!(
            metrics.smt_elapsed,
            Duration::ZERO,
            "smt_elapsed must be zero on fast-path rejection"
        );
    }
}

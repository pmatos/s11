//! ISA-dispatch trait for stochastic search.
//!
//! `StochasticSearch<I>` is generic over the `ISA` trait surface that
//! issue #77 already populated for AArch64, x86-64 and x86-32. The MCMC
//! body needs a handful of helpers that aren't part of the executor /
//! cost / assembler / mutator core traits — RNG-driven random-input
//! generation, sequence-level cost summation, sequence encodability
//! against the assembler — so we bundle those
//! into `StochasticBackend<I>`.
//!
//! Both AArch64 and x86 implement this trait by delegating to the
//! existing free helpers (`apply_sequence_concrete`, `check_equivalence_for`,
//! etc. for AArch64; `apply_sequence_concrete_x86` for x86).

use crate::isa::{CostModel, ISA, InstructionGenerator};
use crate::search::config::SearchConfig;
use crate::semantics::cost::CostMetric;
use crate::semantics::{EquivalenceMetrics, EquivalenceResult};
use rand::RngExt;
use std::time::Duration;

/// Per-ISA dispatch surface for `StochasticSearch`.
///
/// `I` is the ISA being searched. The trait carries an associated
/// `State` (the concrete machine state used for test execution) and
/// `LiveOut` (the live-out contract for equivalence). It exposes the
/// methods MCMC needs that aren't already in the `ISA` / executor /
/// cost / assembler trait bundle.
pub trait StochasticBackend<I: ISA>: Sized {
    /// Concrete machine state used for fast-path test execution.
    type State: Clone;
    /// Live-out contract type for equivalence checking.
    type LiveOut: Clone;

    /// Pull the register pool out of the search config. AArch64 reads
    /// `available_registers`; x86 reads `x86_available_registers`.
    fn registers_from_config(config: &SearchConfig) -> Vec<I::Register>;
    /// Pull the immediate pool out of the search config. Both ISAs
    /// share `available_immediates`.
    fn immediates_from_config(config: &SearchConfig) -> Vec<i64>;
    /// Build the per-ISA mutator from the search config (registers,
    /// immediates, mutation weights, mode-where-applicable).
    fn make_mutator(config: &SearchConfig) -> I::Mutator;

    /// Random test inputs covering `regs`. The width parameter sizes
    /// x86 register-write masking; AArch64 ignores it.
    fn make_test_inputs(regs: &[I::Register], width: u32, count: usize) -> Vec<Self::State>;
    /// Edge-case test inputs covering `regs`.
    fn make_edge_inputs(regs: &[I::Register], width: u32) -> Vec<Self::State>;

    /// Loop-execute a sequence against an initial state.
    fn apply_sequence(state: Self::State, seq: &[I::Instruction]) -> Self::State;
    /// Compare two states over the live-out contract.
    ///
    /// **Invariant:** any `flags_live` bit on the mask is honoured by the
    /// equivalence-checking layer (`semantics::equivalence`), not here.
    /// Implementations of this trait method **must** treat the comparison as
    /// register-only — the pre-SMT flag-writer guard upstream rejects
    /// flag-divergent candidates before stochastic comparison runs. If the
    /// call path is ever rearranged so stochastic compares states without
    /// passing through the upstream guard, this invariant has to be revisited.
    ///
    /// This is the only known caller in the codebase that intentionally
    /// passes `flags_live=false` to `concrete::states_equal_for_live_out`
    /// regardless of the mask's `flags_live()` value; the cleanup tracked in
    /// issue #282 must preserve this exception (e.g. by routing every other
    /// caller through `live_out.flags_live()` and leaving this one explicit).
    fn states_equal(s1: &Self::State, s2: &Self::State, live_out: &Self::LiveOut) -> bool;

    /// Sum the cost of every instruction in the sequence.
    fn sequence_cost(seq: &[I::Instruction], metric: &CostMetric, width: u32) -> u64;
    /// Sequence-level encodability against the ISA's assembler.
    fn is_encodable(seq: &[I::Instruction]) -> bool;

    /// Run the full equivalence check.
    fn check_equivalence(
        target: &[I::Instruction],
        proposal: &[I::Instruction],
        live_out: &Self::LiveOut,
        width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics);

    /// Generate a random sequence of length `len` from the supplied
    /// pools.
    fn random_sequence<R: RngExt>(
        rng: &mut R,
        len: usize,
        regs: &[I::Register],
        imms: &[i64],
        config: &SearchConfig,
    ) -> Vec<I::Instruction>;

    /// Return the target's trailing terminator if any. MCMC appends it
    /// to every `random_sequence` result so the equivalence check's
    /// terminator-equality precheck doesn't reject every random
    /// proposal against a Jcc-terminated target. Default returns
    /// `None`; x86 overrides to peel its `Jcc` terminator.
    fn target_terminator(_target: &[I::Instruction]) -> Option<I::Instruction> {
        None
    }

    /// Width parameter for cost + state masking. AArch64 returns 64;
    /// x86 reads `SearchConfig::x86_width` (32 or 64).
    fn width(config: &SearchConfig) -> u32;
}

// ---- AArch64 backend ----

impl StochasticBackend<crate::isa::AArch64> for crate::isa::AArch64 {
    type State = crate::semantics::state::ConcreteMachineState;
    type LiveOut = crate::semantics::live_out::LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::ir::Register> {
        config.available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn make_mutator(config: &SearchConfig) -> crate::search::stochastic::mutation::AArch64Mutator {
        crate::search::stochastic::mutation::AArch64Mutator::new(
            config.available_registers.clone(),
            config.available_immediates.clone(),
            config.stochastic.mutation_weights.clone(),
        )
    }

    fn make_test_inputs(
        regs: &[crate::ir::Register],
        _width: u32,
        count: usize,
    ) -> Vec<Self::State> {
        crate::validation::random::generate_random_inputs(
            &crate::validation::random::RandomInputConfig {
                count,
                registers: regs.to_vec(),
                memory_seed_size: 0,
            },
        )
    }

    fn make_edge_inputs(regs: &[crate::ir::Register], _width: u32) -> Vec<Self::State> {
        crate::validation::random::generate_edge_case_inputs(regs)
    }

    fn apply_sequence(state: Self::State, seq: &[crate::ir::Instruction]) -> Self::State {
        crate::semantics::concrete::apply_sequence_concrete(state, seq)
    }

    fn states_equal(s1: &Self::State, s2: &Self::State, live_out: &Self::LiveOut) -> bool {
        // Pass `flags_live = false` deliberately: the over-approximate
        // flag-writer guard in equivalence.rs pre-SMT already handles flag
        // divergence before stochastic comparison is reached. The mask may
        // carry `flags_live = true`, but it is honoured upstream, not here.
        // `memory_live = false` here for the same reason — equivalence.rs
        // force-enables it via `touches_memory()` before calling this path.
        // Mirrors mcmc.rs's existing call site.
        crate::semantics::concrete::states_equal_for_live_out(s1, s2, live_out, false, false)
    }

    fn sequence_cost(seq: &[crate::ir::Instruction], metric: &CostMetric, _width: u32) -> u64 {
        <crate::isa::AArch64 as CostModel<crate::ir::Instruction>>::sequence_cost(
            &crate::isa::AArch64,
            seq,
            metric,
        )
    }

    fn is_encodable(seq: &[crate::ir::Instruction]) -> bool {
        crate::search::candidate::is_sequence_encodable(seq)
    }

    fn check_equivalence(
        target: &[crate::ir::Instruction],
        proposal: &[crate::ir::Instruction],
        live_out: &Self::LiveOut,
        _width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        // Treat NZCV as live-out: the pre-refactor `mcmc.rs` body
        // built the EquivalenceConfig with `.with_flags(true)` so the
        // SMT solver cannot certify rewrites that diverge on flags
        // (e.g. `ADD;CMP` → `ADDS`). Symmetry with
        // `SymbolicBackend<AArch64>::check_equivalence`.
        let cfg = crate::semantics::EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(0)
            .timeout(timeout)
            .with_flags(true);
        crate::semantics::equivalence::check_equivalence_with_config_metrics(target, proposal, &cfg)
    }

    fn random_sequence<R: RngExt>(
        rng: &mut R,
        len: usize,
        regs: &[crate::ir::Register],
        imms: &[i64],
        _config: &SearchConfig,
    ) -> Vec<crate::ir::Instruction> {
        crate::search::candidate::generate_random_sequence(rng, len, regs, imms)
    }

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

// ---- x86 backends (x86-64 and x86-32) ----

/// Common helpers reused by both `X86_64` and `X86_32` backends. Inline
/// `fn`s rather than a trait so each ISA's `StochasticBackend` impl
/// stays the trait-required shape (no extra generic bounds).
fn x86_random_inputs(
    regs: &[crate::isa::x86::X86Register],
    width: u32,
    count: usize,
) -> Vec<crate::semantics::state::X86ConcreteMachineState> {
    crate::validation::random::generate_random_inputs_x86(
        &crate::validation::random::RandomInputConfigX86 {
            count,
            registers: regs.to_vec(),
            width,
        },
    )
}

fn x86_make_mutator(
    config: &SearchConfig,
    mode: crate::assembler::x86::X86Mode,
) -> crate::isa::x86::X86Mutator {
    crate::isa::x86::X86Mutator::new(
        config.x86_available_registers.clone(),
        config.available_immediates.clone(),
        config.stochastic.mutation_weights.clone(),
        mode,
    )
}

fn x86_random_sequence<R: RngExt>(
    rng: &mut R,
    len: usize,
    regs: &[crate::isa::x86::X86Register],
    imms: &[i64],
    mode: crate::assembler::x86::X86Mode,
) -> Vec<crate::isa::x86::X86Instruction> {
    let regs: Vec<_> = regs
        .iter()
        .copied()
        .filter(|r| {
            mode != crate::assembler::x86::X86Mode::Mode32 || matches!(r.index(), Some(i) if i < 8)
        })
        .collect();
    let regs = if regs.is_empty() {
        vec![crate::isa::x86::X86Register::RAX]
    } else {
        regs
    };
    let imms = if imms.is_empty() {
        vec![0]
    } else {
        imms.to_vec()
    };
    (0..len)
        .map(|_| crate::isa::x86::X86InstructionGenerator.generate_random(rng, &regs, &imms))
        .collect()
}

impl StochasticBackend<crate::isa::X86_64> for crate::isa::X86_64 {
    type State = crate::semantics::state::X86ConcreteMachineState;
    type LiveOut = crate::semantics::live_out::X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        config.x86_available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn make_mutator(config: &SearchConfig) -> crate::isa::x86::X86Mutator {
        x86_make_mutator(config, crate::assembler::x86::X86Mode::Mode64)
    }

    fn make_test_inputs(
        regs: &[crate::isa::x86::X86Register],
        width: u32,
        count: usize,
    ) -> Vec<Self::State> {
        x86_random_inputs(regs, width, count)
    }

    fn make_edge_inputs(regs: &[crate::isa::x86::X86Register], width: u32) -> Vec<Self::State> {
        crate::validation::random::generate_edge_case_inputs_x86(regs, width)
    }

    fn apply_sequence(state: Self::State, seq: &[crate::isa::x86::X86Instruction]) -> Self::State {
        crate::semantics::concrete_x86::apply_sequence_concrete_x86(state, seq)
    }

    fn states_equal(s1: &Self::State, s2: &Self::State, live_out: &Self::LiveOut) -> bool {
        crate::semantics::concrete_x86::states_equal_for_live_out_x86(s1, s2, live_out)
    }

    fn sequence_cost(
        seq: &[crate::isa::x86::X86Instruction],
        metric: &CostMetric,
        _width: u32,
    ) -> u64 {
        <crate::isa::X86_64 as CostModel<crate::isa::x86::X86Instruction>>::sequence_cost(
            &crate::isa::X86_64,
            seq,
            metric,
        )
    }

    fn is_encodable(seq: &[crate::isa::x86::X86Instruction]) -> bool {
        crate::search::candidate::is_sequence_encodable_for(seq, &crate::isa::X86_64)
    }

    fn check_equivalence(
        target: &[crate::isa::x86::X86Instruction],
        proposal: &[crate::isa::x86::X86Instruction],
        live_out: &Self::LiveOut,
        _width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let cfg =
            crate::semantics::equivalence::EquivalenceConfigFor::<crate::isa::X86_64>::default()
                .live_out(live_out.clone())
                .timeout(timeout);
        crate::semantics::equivalence::check_equivalence_for_metrics::<crate::isa::X86_64>(
            target, proposal, &cfg,
        )
    }

    fn random_sequence<R: RngExt>(
        rng: &mut R,
        len: usize,
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
        _config: &SearchConfig,
    ) -> Vec<crate::isa::x86::X86Instruction> {
        x86_random_sequence(rng, len, regs, imms, crate::assembler::x86::X86Mode::Mode64)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

impl StochasticBackend<crate::isa::X86_32> for crate::isa::X86_32 {
    type State = crate::semantics::state::X86ConcreteMachineState;
    type LiveOut = crate::semantics::live_out::X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        config.x86_available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn make_mutator(config: &SearchConfig) -> crate::isa::x86::X86Mutator {
        x86_make_mutator(config, crate::assembler::x86::X86Mode::Mode32)
    }

    fn make_test_inputs(
        regs: &[crate::isa::x86::X86Register],
        width: u32,
        count: usize,
    ) -> Vec<Self::State> {
        x86_random_inputs(regs, width, count)
    }

    fn make_edge_inputs(regs: &[crate::isa::x86::X86Register], width: u32) -> Vec<Self::State> {
        crate::validation::random::generate_edge_case_inputs_x86(regs, width)
    }

    fn apply_sequence(state: Self::State, seq: &[crate::isa::x86::X86Instruction]) -> Self::State {
        crate::semantics::concrete_x86::apply_sequence_concrete_x86(state, seq)
    }

    fn states_equal(s1: &Self::State, s2: &Self::State, live_out: &Self::LiveOut) -> bool {
        crate::semantics::concrete_x86::states_equal_for_live_out_x86(s1, s2, live_out)
    }

    fn sequence_cost(
        seq: &[crate::isa::x86::X86Instruction],
        metric: &CostMetric,
        _width: u32,
    ) -> u64 {
        <crate::isa::X86_32 as CostModel<crate::isa::x86::X86Instruction>>::sequence_cost(
            &crate::isa::X86_32,
            seq,
            metric,
        )
    }

    fn is_encodable(seq: &[crate::isa::x86::X86Instruction]) -> bool {
        crate::search::candidate::is_sequence_encodable_for(seq, &crate::isa::X86_32)
    }

    fn check_equivalence(
        target: &[crate::isa::x86::X86Instruction],
        proposal: &[crate::isa::x86::X86Instruction],
        live_out: &Self::LiveOut,
        _width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        let cfg =
            crate::semantics::equivalence::EquivalenceConfigFor::<crate::isa::X86_32>::default()
                .live_out(live_out.clone())
                .timeout(timeout);
        crate::semantics::equivalence::check_equivalence_for_metrics::<crate::isa::X86_32>(
            target, proposal, &cfg,
        )
    }

    fn random_sequence<R: RngExt>(
        rng: &mut R,
        len: usize,
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
        _config: &SearchConfig,
    ) -> Vec<crate::isa::x86::X86Instruction> {
        x86_random_sequence(rng, len, regs, imms, crate::assembler::x86::X86Mode::Mode32)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn width(config: &SearchConfig) -> u32 {
        config.x86_width
    }
}

#[cfg(test)]
mod tests {
    //! Direct unit tests for the x86 backend `check_equivalence` paths
    //! and helpers. These bypass the full MCMC loop so the SMT-side of
    //! `<X86_64 as StochasticBackend>::check_equivalence` and the
    //! width-32 branch of `x86_check_equivalence` are exercised
    //! deterministically (the stochastic tests in `mcmc.rs` only reach
    //! the SMT path when the search happens to find a shorter
    //! candidate, which depends on RNG and isn't a reliable coverage
    //! signal).
    use super::*;
    use crate::isa::x86::{X86Instruction, X86Register};
    use crate::semantics::live_out::X86LiveOut;

    #[test]
    fn x86_check_equivalence_helper_handles_width64() {
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mask = X86LiveOut::from_registers(vec![X86Register::RAX]);
        // Self-equivalent at width 64.
        let cfg =
            crate::semantics::equivalence::EquivalenceConfigFor::<crate::isa::X86_64>::default()
                .live_out(mask)
                .timeout(Duration::from_secs(2));
        let r = crate::semantics::equivalence::check_equivalence_for::<crate::isa::X86_64>(
            &target, &target, &cfg,
        );
        assert!(matches!(r, EquivalenceResult::Equivalent));
    }

    #[test]
    fn x86_check_equivalence_helper_handles_width32() {
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mask = X86LiveOut::from_registers(vec![X86Register::RAX]);
        // Self-equivalent at width 32 — exercises the width=32 path.
        let cfg =
            crate::semantics::equivalence::EquivalenceConfigFor::<crate::isa::X86_32>::default()
                .live_out(mask)
                .timeout(Duration::from_secs(2));
        let r = crate::semantics::equivalence::check_equivalence_for::<crate::isa::X86_32>(
            &target, &target, &cfg,
        );
        assert!(matches!(r, EquivalenceResult::Equivalent));
    }

    #[test]
    fn x86_64_backend_check_equivalence_routes_through_helper() {
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mask = X86LiveOut::from_registers(vec![X86Register::RAX]);
        let r = <crate::isa::X86_64 as StochasticBackend<crate::isa::X86_64>>::check_equivalence(
            &target,
            &target,
            &mask,
            64,
            Duration::from_secs(2),
        );
        assert!(matches!(r.0, EquivalenceResult::Equivalent));
    }

    #[test]
    fn x86_32_backend_check_equivalence_routes_through_helper() {
        let target = vec![X86Instruction::MovImm {
            rd: X86Register::RAX,
            imm: 0,
        }];
        let mask = X86LiveOut::from_registers(vec![X86Register::RAX]);
        let r = <crate::isa::X86_32 as StochasticBackend<crate::isa::X86_32>>::check_equivalence(
            &target,
            &target,
            &mask,
            32,
            Duration::from_secs(2),
        );
        assert!(matches!(r.0, EquivalenceResult::Equivalent));
    }
}

//! ISA-dispatch trait for symbolic (SMT-based) search.
//!
//! Mirrors `crate::search::stochastic::backend::StochasticBackend` but
//! with the smaller surface symbolic search needs: candidate
//! enumeration, sequence-cost summation, equivalence dispatch, and a
//! width getter. No mutator or random-input helpers.
//!
//! Both AArch64 and x86 implement this trait by delegating to the
//! existing free helpers and the generic equivalence checker.

use crate::isa::ISA;
use crate::search::config::SearchConfig;
use crate::semantics::cost::CostMetric;
use crate::semantics::{EquivalenceMetrics, EquivalenceResult};
use std::time::Duration;

/// Per-ISA dispatch surface for `SymbolicSearch`.
pub trait SymbolicBackend<I: ISA>: Sized {
    /// Live-out contract type for equivalence checking.
    type LiveOut: Clone;

    /// Pull the register pool out of the search config.
    fn registers_from_config(config: &SearchConfig) -> Vec<I::Register>;
    /// Pull the immediate pool out of the search config.
    fn immediates_from_config(config: &SearchConfig) -> Vec<i64>;

    /// Enumerate every encodable single-instruction variant covering
    /// the supplied register and immediate pools.
    fn enumerate_all(regs: &[I::Register], imms: &[i64]) -> Vec<I::Instruction>;

    /// Return the target's trailing terminator if any. The synthesis
    /// loop appends it to each candidate proposal so the equivalence
    /// check's terminator-equality precheck doesn't reject every
    /// candidate against a Jcc-terminated target. Default returns
    /// `None`; x86 overrides to peel its `Jcc` terminator.
    fn target_terminator(_target: &[I::Instruction]) -> Option<I::Instruction> {
        None
    }

    /// Sum the cost of every instruction in the sequence.
    fn sequence_cost(seq: &[I::Instruction], metric: &CostMetric, width: u32) -> u64;

    /// Run the full equivalence check.
    fn check_equivalence(
        target: &[I::Instruction],
        proposal: &[I::Instruction],
        live_out: &Self::LiveOut,
        width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics);

    /// Width parameter for cost + state masking. AArch64 returns 64;
    /// x86 reads `SearchConfig::x86_width` (32 or 64).
    fn width(config: &SearchConfig) -> u32;
}

// ---- AArch64 backend ----

impl SymbolicBackend<crate::isa::AArch64> for crate::isa::AArch64 {
    type LiveOut = crate::semantics::live_out::LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::ir::Register> {
        config.available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(regs: &[crate::ir::Register], imms: &[i64]) -> Vec<crate::ir::Instruction> {
        crate::search::candidate::generate_all_encodable_instructions(regs, imms)
    }

    fn sequence_cost(seq: &[crate::ir::Instruction], metric: &CostMetric, _width: u32) -> u64 {
        crate::semantics::cost::sequence_cost(seq, metric)
    }

    fn check_equivalence(
        target: &[crate::ir::Instruction],
        proposal: &[crate::ir::Instruction],
        live_out: &Self::LiveOut,
        _width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        // Treat NZCV as live-out so the solver cannot certify a
        // flag-divergent rewrite (see synthesis.rs's previous body).
        // `with_memory(true)` is informational here — the entry point in
        // `check_equivalence_with_config` re-derives it from
        // `touches_memory()` on the candidate / target. See ADR-0007.
        let cfg = crate::semantics::EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(5)
            .timeout(timeout)
            .with_flags(true)
            .with_memory(true);
        crate::semantics::equivalence::check_equivalence_with_config_metrics(target, proposal, &cfg)
    }

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

// ---- x86 backends ----

impl SymbolicBackend<crate::isa::X86_64> for crate::isa::X86_64 {
    type LiveOut = crate::semantics::live_out::X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        config.x86_available_registers.clone()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
    ) -> Vec<crate::isa::x86::X86Instruction> {
        crate::search::candidate_x86::generate_all_x86_instructions(regs, imms)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn sequence_cost(
        seq: &[crate::isa::x86::X86Instruction],
        metric: &CostMetric,
        width: u32,
    ) -> u64 {
        crate::semantics::cost_x86::sequence_cost(seq, metric, width)
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

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

impl SymbolicBackend<crate::isa::X86_32> for crate::isa::X86_32 {
    type LiveOut = crate::semantics::live_out::X86LiveOut;

    fn registers_from_config(config: &SearchConfig) -> Vec<crate::isa::x86::X86Register> {
        // Mode32 assembly rejects R8-R15 (`src/assembler/x86.rs:68-74`).
        // Filter the pool here so `enumerate_all` cannot emit candidates
        // that pass SMT verification but later fail at
        // `X86Assembler::new_32().assemble_instructions`. The stochastic
        // path filters at `X86Mutator::new`; this is the symbolic-search
        // equivalent.
        config
            .x86_available_registers
            .iter()
            .copied()
            .filter(|r| matches!(r.index(), Some(i) if i < 8))
            .collect()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
    ) -> Vec<crate::isa::x86::X86Instruction> {
        crate::search::candidate_x86::generate_all_x86_instructions(regs, imms)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn sequence_cost(
        seq: &[crate::isa::x86::X86Instruction],
        metric: &CostMetric,
        width: u32,
    ) -> u64 {
        crate::semantics::cost_x86::sequence_cost(seq, metric, width)
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

    fn width(config: &SearchConfig) -> u32 {
        config.x86_width
    }
}

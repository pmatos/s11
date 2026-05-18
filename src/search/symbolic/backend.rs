//! ISA-dispatch trait for symbolic (SMT-based) search.
//!
//! Mirrors `crate::search::stochastic::backend::StochasticBackend` but
//! with the smaller surface symbolic search needs: candidate
//! enumeration, sequence-cost summation, equivalence dispatch, and a
//! width getter. No mutator or random-input helpers.
//!
//! Both AArch64 and x86 implement this trait by delegating to the
//! existing free helpers. When `EquivalenceConfig<I>` is generified in
//! #77 stage 2 step 16, the `check_equivalence` method can be dropped.

use crate::isa::ISA;
use crate::search::config::SearchConfig;
use crate::semantics::EquivalenceResult;
use crate::semantics::cost::CostMetric;
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

    /// Sum the cost of every instruction in the sequence.
    fn sequence_cost(seq: &[I::Instruction], metric: &CostMetric, width: u32) -> u64;

    /// Run the full equivalence check.
    fn check_equivalence(
        target: &[I::Instruction],
        proposal: &[I::Instruction],
        live_out: &Self::LiveOut,
        width: u32,
        timeout: Duration,
    ) -> EquivalenceResult;

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
    ) -> EquivalenceResult {
        // Treat NZCV as live-out so the solver cannot certify a
        // flag-divergent rewrite (see synthesis.rs's previous body).
        let cfg = crate::semantics::EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(5)
            .timeout(timeout)
            .with_flags(true);
        crate::semantics::check_equivalence_with_config(target, proposal, &cfg)
    }

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

// ---- x86 backends ----

fn x86_check_equivalence(
    target: &[crate::isa::x86::X86Instruction],
    proposal: &[crate::isa::x86::X86Instruction],
    live_out: &crate::semantics::state::X86LiveOutMask,
    width: u32,
    timeout: Duration,
) -> EquivalenceResult {
    let mut cfg = if width == 32 {
        crate::semantics::equivalence::X86EquivalenceConfig::new_for_32()
    } else {
        crate::semantics::equivalence::X86EquivalenceConfig::new_for_64()
    };
    cfg.live_out = live_out.clone();
    cfg.smt_timeout = Some(timeout);
    crate::semantics::equivalence::check_equivalence_x86(target, proposal, &cfg)
}

impl SymbolicBackend<crate::isa::X86_64> for crate::isa::X86_64 {
    type LiveOut = crate::semantics::state::X86LiveOutMask;

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
        width: u32,
        timeout: Duration,
    ) -> EquivalenceResult {
        x86_check_equivalence(target, proposal, live_out, width, timeout)
    }

    fn width(_config: &SearchConfig) -> u32 {
        64
    }
}

impl SymbolicBackend<crate::isa::X86_32> for crate::isa::X86_32 {
    type LiveOut = crate::semantics::state::X86LiveOutMask;

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
        width: u32,
        timeout: Duration,
    ) -> EquivalenceResult {
        x86_check_equivalence(target, proposal, live_out, width, timeout)
    }

    fn width(config: &SearchConfig) -> u32 {
        config.x86_width
    }
}

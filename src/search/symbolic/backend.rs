//! ISA-dispatch trait for symbolic (SMT-based) search.
//!
//! Mirrors `crate::search::stochastic::backend::StochasticBackend` but
//! with the smaller surface symbolic search needs: candidate
//! enumeration, sequence-cost summation, equivalence dispatch, and a
//! width getter. No mutator or random-input helpers.
//!
//! Both AArch64 and x86 implement this trait by delegating to the
//! existing free helpers and the generic equivalence checker.

use crate::isa::{CostModel, ISA, InstructionGenerator};
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

    /// Whether this backend can find a strict metric improvement without
    /// reducing the number of rewritable instructions.
    fn can_improve_at_same_instruction_count(_metric: &CostMetric) -> bool {
        false
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

    /// Width parameter for cost + state masking. Architecture markers own
    /// this width so a mismatched config cannot silently change semantics.
    /// `config` is retained only for API symmetry; implementations are
    /// expected to return an architectural constant and must not read it.
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
        <crate::isa::AArch64 as CostModel<crate::ir::Instruction>>::sequence_cost(
            &crate::isa::AArch64,
            seq,
            metric,
        )
    }

    fn check_equivalence(
        target: &[crate::ir::Instruction],
        proposal: &[crate::ir::Instruction],
        live_out: &Self::LiveOut,
        _width: u32,
        timeout: Duration,
    ) -> (EquivalenceResult, EquivalenceMetrics) {
        // Honor the caller's live-out mask: ELF optimization derives
        // `flags_live` from the surrounding context, while CLI/test callers
        // can still opt into conservative NZCV comparison via the mask.
        // `with_memory(true)` is informational here — the entry point in
        // `check_equivalence_with_config` re-derives it from
        // `touches_memory()` on the candidate / target. See ADR-0007.
        let cfg = crate::semantics::EquivalenceConfig::with_live_out(live_out.clone())
            .random_tests(5)
            .timeout(timeout)
            .with_flags(live_out.flags_live())
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
        crate::isa::x86::X86InstructionGenerator.generate_all(regs, imms)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn can_improve_at_same_instruction_count(metric: &CostMetric) -> bool {
        matches!(metric, CostMetric::CodeSize)
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
        crate::isa::x86::X86InstructionGenerator.generate_all(regs, imms)
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn can_improve_at_same_instruction_count(metric: &CostMetric) -> bool {
        matches!(metric, CostMetric::CodeSize)
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

    fn width(_config: &SearchConfig) -> u32 {
        crate::isa::X86_32.register_width()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Instruction, Operand, Register};
    use crate::isa::AArch64;
    use crate::semantics::live_out::LiveOut;

    #[test]
    fn aarch64_backend_honors_flags_dead_live_out_mask() {
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
        let proposal = vec![Instruction::MovImm {
            rd: Register::X1,
            imm: 7,
        }];
        let live_out = LiveOut::from_registers(vec![Register::X1]);

        let result = <AArch64 as SymbolicBackend<AArch64>>::check_equivalence(
            &target,
            &proposal,
            &live_out,
            64,
            Duration::from_secs(2),
        );

        assert_eq!(result.0, EquivalenceResult::Equivalent);

        let flags_live_result = <AArch64 as SymbolicBackend<AArch64>>::check_equivalence(
            &target,
            &proposal,
            &live_out.with_flags(true),
            64,
            Duration::from_secs(2),
        );

        assert_ne!(flags_live_result.0, EquivalenceResult::Equivalent);
    }

    #[test]
    fn x86_32_symbolic_width_is_architectural_even_with_default_config() {
        let config = SearchConfig::default();
        assert_eq!(config.x86_width, 64);

        assert_eq!(
            <crate::isa::X86_32 as SymbolicBackend<crate::isa::X86_32>>::width(&config),
            32
        );

        // X86_64 was already correct; this cross-check guards against a
        // future regression and is not part of the x86-32 bug being fixed.
        assert_eq!(
            <crate::isa::X86_64 as SymbolicBackend<crate::isa::X86_64>>::width(
                &SearchConfig::default().with_x86_width(32),
            ),
            64
        );
    }
}

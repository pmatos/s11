//! ISA-dispatch trait for symbolic (SMT-based) search.
//!
//! Mirrors `crate::search::stochastic::backend::StochasticBackend` but
//! with the smaller surface symbolic search needs: candidate
//! enumeration, sequence-cost summation, equivalence dispatch, and a
//! width getter. No mutator or random-input helpers.
//!
//! Both AArch64 and x86 implement this trait by delegating to the
//! existing free helpers and the generic equivalence checker.

use crate::isa::{Assembler, CostModel, ISA, InstructionGenerator};
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

    /// Whether this backend may find a strict metric improvement without
    /// reducing the number of rewritable instructions for this target/config.
    ///
    /// For x86 code-size search, the config flag is a binary-patching guard:
    /// the current x86 IR collapses partial-register aliases to full-width
    /// registers, so the ELF frontend disables same-count rewrites when the
    /// original Capstone operands were not full-width for the binary mode.
    fn can_improve_at_same_instruction_count(
        _target: &[I::Instruction],
        _config: &SearchConfig,
    ) -> bool {
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
    /// this width so a mismatched config cannot silently change semantics;
    /// implementations return an architectural constant.
    fn width() -> u32;
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

    fn width() -> u32 {
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

    fn can_improve_at_same_instruction_count(
        _target: &[crate::isa::x86::X86Instruction],
        config: &SearchConfig,
    ) -> bool {
        matches!(config.cost_metric, CostMetric::CodeSize)
            && config.x86_same_count_code_size_allowed
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

    fn width() -> u32 {
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
            .filter(|r| r.is_available_in(crate::assembler::x86::X86Mode::Mode32))
            .collect()
    }

    fn immediates_from_config(config: &SearchConfig) -> Vec<i64> {
        config.available_immediates.clone()
    }

    fn enumerate_all(
        regs: &[crate::isa::x86::X86Register],
        imms: &[i64],
    ) -> Vec<crate::isa::x86::X86Instruction> {
        crate::isa::x86::X86InstructionGenerator
            .generate_all(regs, imms)
            .into_iter()
            .filter(|instruction| crate::isa::X86_32.can_assemble(instruction))
            .collect()
    }

    fn target_terminator(
        target: &[crate::isa::x86::X86Instruction],
    ) -> Option<crate::isa::x86::X86Instruction> {
        crate::ir::instructions::split_terminator_x86(target)
            .1
            .copied()
    }

    fn can_improve_at_same_instruction_count(
        _target: &[crate::isa::x86::X86Instruction],
        config: &SearchConfig,
    ) -> bool {
        matches!(config.cost_metric, CostMetric::CodeSize)
            && config.x86_same_count_code_size_allowed
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

    fn width() -> u32 {
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
    fn symbolic_width_is_architectural() {
        // Width is owned by the ISA marker, not configuration: each backend
        // returns its architectural constant from the no-arg `width()`.
        assert_eq!(
            <crate::isa::X86_32 as SymbolicBackend<crate::isa::X86_32>>::width(),
            32
        );
        assert_eq!(
            <crate::isa::X86_64 as SymbolicBackend<crate::isa::X86_64>>::width(),
            64
        );
        assert_eq!(
            <crate::isa::AArch64 as SymbolicBackend<crate::isa::AArch64>>::width(),
            64
        );
    }

    #[test]
    fn x86_32_symbolic_candidates_are_encodable() {
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::isa::{Assembler, X86_32};

        let candidates = <X86_32 as SymbolicBackend<X86_32>>::enumerate_all(
            &[X86Register::RAX, X86Register::RSI, X86Register::RDI],
            &[0],
        );

        assert!(
            candidates
                .iter()
                .all(|instruction| X86_32.can_assemble(instruction))
        );
        for rs in [X86Register::RSI, X86Register::RDI] {
            assert!(!candidates.contains(&X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs,
                src_width: 8,
            }));
            assert!(!candidates.contains(&X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs,
                src_width: 8,
            }));
            assert!(candidates.contains(&X86Instruction::Movzx {
                rd: X86Register::RAX,
                rs,
                src_width: 16,
            }));
            assert!(candidates.contains(&X86Instruction::Movsx {
                rd: X86Register::RAX,
                rs,
                src_width: 16,
            }));
        }
    }

    #[test]
    fn x86_32_symbolic_only_generates_assemblable_setcc_candidates() {
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::isa::{Assembler, X86_32};

        let regs = [
            X86Register::RAX,
            X86Register::RSP,
            X86Register::RBP,
            X86Register::RSI,
            X86Register::RDI,
        ];
        let candidates = <X86_32 as SymbolicBackend<X86_32>>::enumerate_all(&regs, &[0]);
        let setcc_count = candidates
            .iter()
            .filter(|instruction| matches!(instruction, X86Instruction::Setcc { .. }))
            .count();

        assert!(
            candidates
                .iter()
                .all(|instruction| X86_32.can_assemble(instruction)),
            "x86-32 symbolic search generated an unassemblable candidate"
        );
        assert_eq!(
            setcc_count,
            crate::isa::x86::X86Condition::ALL.len(),
            "symbolic search must retain every SETcc condition for EAX"
        );
        assert!(
            candidates.iter().any(|instruction| matches!(
                instruction,
                X86Instruction::MovImm {
                    rd: X86Register::RSI,
                    ..
                }
            )),
            "mode-specific SETcc filtering must not remove encodable ESI candidates"
        );
    }
}

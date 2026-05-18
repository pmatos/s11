//! Search algorithms for finding optimal instruction sequences
//!
//! This module provides multiple search algorithms for superoptimization:
//! - Enumerative: exhaustive search over instruction sequences
//! - Stochastic: MCMC-based search using Metropolis-Hastings acceptance
//! - Symbolic: SMT-based synthesis using Z3
//! - Hybrid: parallel execution combining symbolic + multiple stochastic workers

pub mod candidate;
pub mod candidate_x86;
pub mod config;
pub mod enumerative;
pub mod llm;
pub mod parallel;
pub mod result;
pub mod stochastic;
pub mod symbolic;

#[allow(unused_imports)]
pub use config::{Algorithm, SearchConfig, StochasticConfig, SymbolicConfig};
pub use enumerative::EnumerativeSearch;
#[allow(unused_imports)]
pub use parallel::{ParallelConfig, ParallelResult, run_parallel_search};
#[allow(unused_imports)]
pub use result::{SearchResult, SearchStatistics};
pub use stochastic::StochasticSearch;
pub use symbolic::SymbolicSearch;

use crate::isa::ISA;

/// Trait for search algorithms that find equivalent instruction sequences.
///
/// Parameterised on `<I: ISA>` so a single implementation surface covers
/// AArch64, x86-64 and x86-32 once the search bodies route through the
/// ISA-trait executors. `LiveOut` and `Result` are associated types so
/// the trait does not force a particular live-out representation or
/// result-carrier shape — implementors pick (AArch64 uses
/// `crate::semantics::live_out::LiveOut`; x86 will use
/// `crate::semantics::state::X86LiveOutMask` until `LiveOutMask<R>`
/// subsumes both in #77 stage 2 step 16).
#[allow(dead_code)]
pub trait SearchAlgorithm<I: ISA> {
    /// Live-out contract type this implementation accepts.
    type LiveOut;
    /// Result type returned by `search`.
    type Result;

    /// Search for an equivalent sequence that is cheaper than the target.
    fn search(
        &mut self,
        target: &[I::Instruction],
        live_out: &Self::LiveOut,
        config: &SearchConfig,
    ) -> Self::Result;

    /// Get statistics from the most recent search.
    fn statistics(&self) -> SearchStatistics;

    /// Reset the search state for a new search.
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time evidence that `SearchAlgorithm` is generic over ISA:
    /// every existing AArch64 search implementation satisfies
    /// `SearchAlgorithm<AArch64>`. If the trait ever silently regresses
    /// back to AArch64-typed, this test fails to compile.
    #[test]
    fn search_algorithm_is_generic_over_isa() {
        fn assert_impl<I: ISA, A: SearchAlgorithm<I>>() {}
        assert_impl::<crate::isa::AArch64, enumerative::EnumerativeSearch>();
        assert_impl::<crate::isa::AArch64, stochastic::StochasticSearch>();
        assert_impl::<crate::isa::AArch64, symbolic::SymbolicSearch>();
        assert_impl::<crate::isa::AArch64, llm::LlmSearch>();
    }
}

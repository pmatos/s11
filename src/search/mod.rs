//! Search algorithms for finding optimal instruction sequences
//!
//! This module provides multiple search algorithms for superoptimization:
//! - Enumerative: exhaustive search over instruction sequences
//! - Stochastic: MCMC-based search using Metropolis-Hastings acceptance
//! - Symbolic: SMT-based synthesis using Z3
//! - Hybrid: parallel execution combining symbolic + multiple stochastic workers

pub mod candidate;
pub mod config;
pub mod parallel;
pub mod result;
pub mod stochastic;
pub mod symbolic;

#[allow(unused_imports)]
pub use config::{Algorithm, SearchConfig, StochasticConfig, SymbolicConfig};
#[allow(unused_imports)]
pub use parallel::{ParallelConfig, ParallelResult, run_parallel_search};
pub use result::{SearchResult, SearchStatistics};
pub use stochastic::StochasticSearch;
pub use symbolic::SymbolicSearch;

use crate::ir::Instruction;
use crate::semantics::state::LiveOutMask;

/// Trait for search algorithms that find equivalent instruction sequences
#[allow(dead_code)]
pub trait SearchAlgorithm {
    /// Search for an equivalent sequence that is cheaper than the target
    ///
    /// # Arguments
    /// * `target` - The instruction sequence to optimize
    /// * `live_out` - Registers that must match after execution
    /// * `config` - Search configuration parameters
    ///
    /// # Returns
    /// A SearchResult containing the best found sequence (if any) and statistics
    fn search(
        &mut self,
        target: &[Instruction],
        live_out: &LiveOutMask,
        config: &SearchConfig,
    ) -> SearchResult;

    /// Get statistics from the most recent search
    fn statistics(&self) -> SearchStatistics;

    /// Reset the search state for a new search
    fn reset(&mut self);
}

//! Semantic analysis and equivalence checking for AArch64 instructions

#[cfg(feature = "z3")]
pub mod equivalence;
#[cfg(feature = "z3")]
pub mod smt;

pub mod simple_equiv;

// Re-export main functionality
#[cfg(feature = "z3")]
pub use equivalence::{check_equivalence, find_counterexample, EquivalenceResult};

#[cfg(not(feature = "z3"))]
pub use simple_equiv::check_equivalence_simple as check_equivalence;

#[cfg(not(feature = "z3"))]
#[derive(Debug, Clone, PartialEq)]
pub enum EquivalenceResult {
    Equivalent,
    NotEquivalent,
    Unknown(String),
}
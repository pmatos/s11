//! Semantic analysis and equivalence checking for AArch64 instructions

pub mod equivalence;
pub mod smt;

// Re-export main functionality
pub use equivalence::{check_equivalence, EquivalenceResult};
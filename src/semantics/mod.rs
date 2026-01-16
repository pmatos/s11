//! Semantic analysis and equivalence checking for AArch64 instructions

pub mod concrete;
pub mod cost;
pub mod equivalence;
pub mod smt;
pub mod state;

// Re-export main functionality
pub use equivalence::{
    EquivalenceConfig, EquivalenceResult, check_equivalence, check_equivalence_with_config,
};
pub use state::{ConcreteMachineState, ConcreteValue, LiveOutMask};

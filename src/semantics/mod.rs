//! Semantic analysis and equivalence checking (AArch64 + x86 backends).

pub mod concrete;
pub mod concrete_x86;
pub mod cost;
pub mod cost_x86;
pub mod equivalence;
pub mod live_out;
pub mod smt;
pub mod smt_x86;
pub mod state;

// Re-export main functionality. Some items are surfaced for external
// consumers (or to be discoverable from the public surface of the crate)
// and aren't called from within this binary, hence the targeted allow.
pub use concrete::apply_sequence_concrete;
pub use equivalence::{EquivalenceConfig, EquivalenceResult, check_equivalence_with_config};

#[allow(unused_imports)]
pub use equivalence::{EquivalenceMetrics, check_equivalence_with_config_metrics};
#[allow(unused_imports)]
pub use live_out::{LiveOut, LiveOutRegisters};
#[allow(unused_imports)]
pub use state::{ConcreteMachineState, ConcreteValue, ConditionFlags};

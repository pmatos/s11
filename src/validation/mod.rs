//! Validation utilities for fast equivalence checking

pub mod live_out;
pub mod random;

#[allow(unused_imports)]
pub use live_out::compute_written_registers;
#[allow(unused_imports)]
pub use random::{RandomInputConfig, generate_edge_case_inputs, generate_random_inputs};

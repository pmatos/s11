//! Validation utilities for fast equivalence checking

pub mod live_out;
pub mod random;

pub use live_out::compute_written_registers;
pub use random::{RandomInputConfig, generate_edge_case_inputs, generate_random_inputs};

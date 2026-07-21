//! Validation utilities for fast equivalence checking

pub mod downstream;
pub mod live_out;
pub mod random;

#[allow(unused_imports)]
pub use live_out::{ParseLiveOutError, compute_written_registers};
#[allow(unused_imports)]
pub use random::{RandomInputConfig, generate_edge_case_inputs, generate_random_inputs};

#[cfg(test)]
mod tests {
    #[test]
    fn parse_live_out_error_is_reexported_from_validation() {
        let _: crate::validation::ParseLiveOutError =
            super::live_out::parse_live_out_contract("x0;bogus").unwrap_err();
    }
}

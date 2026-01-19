//! Symbolic (SMT-based) search for superoptimization
//!
//! Uses Z3 SMT solver to synthesize optimal instruction sequences.
//! The approach:
//! 1. Create a symbolic "sketch" with Z3 variables for opcodes/operands
//! 2. Assert equivalence: ∀inputs. sketch_output = target_output (for live-out)
//! 3. Assert cost bound: sketch_cost < max_cost
//! 4. Use Z3 to find satisfying assignment or prove UNSAT

pub mod sketch;
pub mod synthesis;

pub use synthesis::SymbolicSearch;

//! Intermediate Representation (IR) for AArch64 instructions

pub mod instructions;
pub mod types;

// Re-export commonly used types
pub use instructions::Instruction;
pub use types::{Condition, Operand, Register};
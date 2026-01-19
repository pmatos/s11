//! ISA (Instruction Set Architecture) abstraction layer
//!
//! This module provides traits for abstracting over different instruction set architectures,
//! enabling the optimizer to work with multiple ISAs (AArch64, RISC-V, etc.)

pub mod aarch64;
mod traits;

pub use traits::{
    Assembler, ConcreteExecutor, CostModel, ISA, InstructionGenerator, InstructionType,
    OperandType, RegisterType, SymbolicExecutor,
};

pub use aarch64::AArch64;

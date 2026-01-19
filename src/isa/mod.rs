//! ISA (Instruction Set Architecture) abstraction layer
//!
//! This module provides traits for abstracting over different instruction set architectures,
//! enabling the optimizer to work with multiple ISAs (AArch64, RISC-V, etc.)

pub mod aarch64;
pub mod riscv;
mod traits;

#[allow(unused_imports)]
pub use traits::{
    Assembler, ConcreteExecutor, CostModel, InstructionGenerator, InstructionType, OperandType,
    RegisterType, SymbolicExecutor, ISA,
};

#[allow(unused_imports)]
pub use aarch64::AArch64;
#[allow(unused_imports)]
pub use riscv::{
    RiscV32, RiscV64, RiscVInstruction, RiscVInstructionGenerator, RiscVOperand, RiscVRegister,
};

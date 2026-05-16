//! ISA (Instruction Set Architecture) abstraction layer
//!
//! This module provides traits for abstracting over different instruction set architectures,
//! enabling the optimizer to work with multiple ISAs (AArch64, RISC-V, x86, etc.)

pub mod aarch64;
pub mod riscv;
mod traits;
pub mod x86;

#[allow(unused_imports)]
pub use traits::{
    Assembler, BVWidth, ConcreteExecutor, CostModel, FlagsAnalysis, ISA, InstructionGenerator,
    InstructionType, OperandType, RegisterType, SymbolicExecutor, U32, U64,
};

#[allow(unused_imports)]
pub use aarch64::AArch64;
#[allow(unused_imports)]
pub use riscv::{
    RiscV32, RiscV64, RiscVInstruction, RiscVInstructionGenerator, RiscVOperand, RiscVRegister,
};
#[allow(unused_imports)]
pub use x86::{X86_32, X86_64, X86Instruction, X86InstructionGenerator, X86Operand, X86Register};

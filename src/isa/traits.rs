//! Core traits for ISA abstraction
//!
//! These traits define the interface that any ISA implementation must provide.

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use rand::Rng;
/// Trait for register types
pub trait RegisterType:
    Clone + Copy + PartialEq + Eq + Hash + Debug + Display + Send + Sync
{
    /// Get the numeric index of this register (for iteration)
    fn index(&self) -> Option<u8>;

    /// Create a register from its numeric index
    fn from_index(idx: u8) -> Option<Self>;

    /// Returns true if this is a zero register (always reads as 0)
    fn is_zero_register(&self) -> bool;

    /// Returns true if this is a special register (e.g., SP, PC)
    fn is_special(&self) -> bool;
}

/// Trait for operand types
///
/// Note: The associated `Register` type here must match the register type used by this operand.
/// To avoid ambiguity when implementing this trait, use concrete types instead of `Self::Register`
/// in the method signatures.
pub trait OperandType:
    Clone + Copy + PartialEq + Eq + Hash + Debug + Display + Send + Sync
{
    /// The register type used by this operand
    type Register: RegisterType;

    /// Try to extract this operand as a register
    /// Note: Implementations should use concrete register types to avoid ambiguity
    fn as_register(&self) -> Option<Self::Register>;

    /// Try to extract this operand as an immediate value
    fn as_immediate(&self) -> Option<i64>;

    /// Returns true if this operand is an immediate
    fn is_immediate(&self) -> bool {
        self.as_immediate().is_some()
    }

    /// Returns true if this operand is a register
    fn is_register(&self) -> bool {
        self.as_register().is_some()
    }

    /// Create an operand from a register
    /// Note: Implementations should use concrete register types to avoid ambiguity
    fn from_register(reg: Self::Register) -> Self;

    /// Create an operand from an immediate value
    fn from_immediate(imm: i64) -> Self;
}

/// Trait for instruction types
pub trait InstructionType:
    Clone + Copy + PartialEq + Eq + Hash + Debug + Display + Send + Sync
{
    /// The register type used by this instruction
    type Register: RegisterType;
    /// The operand type used by this instruction
    type Operand: OperandType<Register = Self::Register>;

    /// Get the destination register of this instruction (if any)
    fn destination(&self) -> Self::Register;

    /// Get all source registers used by this instruction
    fn source_registers(&self) -> Vec<Self::Register>;

    /// Get a unique opcode identifier for this instruction type
    fn opcode_id(&self) -> u8;

    /// Get the mnemonic string for this instruction
    fn mnemonic(&self) -> &'static str;

    /// Returns true if this instruction has side effects beyond register writes
    /// (e.g., memory access, branches, condition code updates)
    fn has_side_effects(&self) -> bool {
        false
    }
}

/// High-level ISA trait that combines all ISA-specific types
pub trait ISA: Send + Sync + Clone {
    /// The register type for this ISA
    type Register: RegisterType;
    /// The operand type for this ISA
    type Operand: OperandType<Register = Self::Register>;
    /// The instruction type for this ISA
    type Instruction: InstructionType<Register = Self::Register, Operand = Self::Operand>;

    /// Name of this ISA (e.g., "AArch64", "RISC-V")
    fn name(&self) -> &'static str;

    /// Number of general-purpose registers
    fn register_count(&self) -> usize;

    /// Register bit width (e.g., 64 for AArch64, 32 for ARM)
    fn register_width(&self) -> u32;

    /// Instruction size in bytes (fixed-width ISAs like ARM)
    fn instruction_size(&self) -> Option<usize>;

    /// Get a list of all general-purpose registers
    fn general_registers(&self) -> Vec<Self::Register>;

    /// Get the zero register if this ISA has one
    fn zero_register(&self) -> Option<Self::Register>;
}

/// Trait for concrete (non-symbolic) instruction execution
pub trait ConcreteExecutor<I: InstructionType>: Send + Sync {
    /// The type of concrete values (e.g., u64, u32)
    type Value: Clone + PartialEq + Debug;
    /// The machine state type
    type State: Clone;

    /// Execute a single instruction on the given state
    fn execute_instruction(&self, state: Self::State, instruction: &I) -> Self::State;

    /// Execute a sequence of instructions
    fn execute_sequence(&self, state: Self::State, instructions: &[I]) -> Self::State {
        let mut s = state;
        for instr in instructions {
            s = self.execute_instruction(s, instr);
        }
        s
    }

    /// Create a new state with all registers set to zero
    fn new_zeroed_state(&self) -> Self::State;

    /// Create a state from a map of register values
    fn state_from_values(&self, values: HashMap<I::Register, Self::Value>) -> Self::State;

    /// Get a register value from a state
    fn get_register(&self, state: &Self::State, reg: I::Register) -> Self::Value;

    /// Set a register value in a state
    fn set_register(&self, state: &mut Self::State, reg: I::Register, value: Self::Value);
}

/// Trait for symbolic (SMT-based) instruction execution
///
/// This is a simplified trait interface. Actual SMT implementations may need
/// additional configuration (like Z3 context) that is provided separately.
pub trait SymbolicExecutor<I: InstructionType>: Send + Sync {
    /// The symbolic machine state type (typically containing Z3 bitvectors)
    type State: Clone;

    /// Execute a single instruction symbolically
    fn execute_instruction(&self, state: Self::State, instruction: &I) -> Self::State;

    /// Execute a sequence of instructions symbolically
    fn execute_sequence(&self, state: Self::State, instructions: &[I]) -> Self::State {
        let mut s = state;
        for instr in instructions {
            s = self.execute_instruction(s, instr);
        }
        s
    }

    /// Create a fresh symbolic state with symbolic register values
    fn new_symbolic_state(&self, prefix: &str) -> Self::State;
}

/// Trait for instruction cost models
pub trait CostModel<I: InstructionType>: Send + Sync {
    /// Calculate the cost of a single instruction
    fn instruction_cost(&self, instruction: &I) -> u64;

    /// Calculate the total cost of an instruction sequence
    fn sequence_cost(&self, instructions: &[I]) -> u64 {
        instructions.iter().map(|i| self.instruction_cost(i)).sum()
    }
}

/// Trait for instruction generation (used in search algorithms)
pub trait InstructionGenerator<I: InstructionType>: Send + Sync {
    /// Generate all possible instructions with the given registers and immediates
    fn generate_all(&self, registers: &[I::Register], immediates: &[i64]) -> Vec<I>;

    /// Generate a random instruction
    fn generate_random<R: Rng>(
        &self,
        rng: &mut R,
        registers: &[I::Register],
        immediates: &[i64],
    ) -> I;

    /// Mutate an existing instruction
    fn mutate<R: Rng>(
        &self,
        rng: &mut R,
        instruction: &I,
        registers: &[I::Register],
        immediates: &[i64],
    ) -> I;

    /// Get the total number of opcodes supported
    fn opcode_count(&self) -> u8;
}

/// Trait for instruction assembly (converting IR to machine code)
pub trait Assembler<I: InstructionType>: Send + Sync {
    /// Assemble a sequence of instructions into machine code
    fn assemble(&mut self, instructions: &[I]) -> Result<Vec<u8>, String>;

    /// Check if an instruction can be assembled
    fn can_assemble(&self, instruction: &I) -> bool;
}

//! Shared state types for concrete and symbolic execution

#![allow(dead_code)]

use crate::ir::Register;
use crate::ir::types::Condition;
use std::collections::HashMap;
use std::fmt;

/// NZCV condition flags (Negative, Zero, Carry, oVerflow)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConditionFlags {
    pub n: bool, // Negative: result is negative (MSB is 1)
    pub z: bool, // Zero: result is zero
    pub c: bool, // Carry: unsigned overflow occurred
    pub v: bool, // oVerflow: signed overflow occurred
}

impl ConditionFlags {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute flags from an arithmetic result (addition)
    pub fn from_add(lhs: u64, rhs: u64, result: u64) -> Self {
        let n = (result as i64) < 0;
        let z = result == 0;
        // Carry: unsigned overflow
        let c = result < lhs;
        // Overflow: signed overflow when signs of inputs match but differ from result
        let v = {
            let lhs_neg = (lhs as i64) < 0;
            let rhs_neg = (rhs as i64) < 0;
            let res_neg = (result as i64) < 0;
            (lhs_neg == rhs_neg) && (lhs_neg != res_neg)
        };
        Self { n, z, c, v }
    }

    /// Compute flags from a subtraction result (comparison)
    pub fn from_sub(lhs: u64, rhs: u64, result: u64) -> Self {
        let n = (result as i64) < 0;
        let z = result == 0;
        // Carry: no borrow occurred (lhs >= rhs unsigned)
        let c = lhs >= rhs;
        // Overflow: signed overflow
        let v = {
            let lhs_neg = (lhs as i64) < 0;
            let rhs_neg = (rhs as i64) < 0;
            let res_neg = (result as i64) < 0;
            (lhs_neg != rhs_neg) && (lhs_neg != res_neg)
        };
        Self { n, z, c, v }
    }

    /// Compute flags from a logical operation result (AND, ORR, EOR, TST)
    pub fn from_logical(result: u64) -> Self {
        Self {
            n: (result as i64) < 0,
            z: result == 0,
            c: false, // Logical ops clear C
            v: false, // Logical ops clear V
        }
    }

    /// Evaluate if a condition code is satisfied by these flags
    pub fn evaluate(&self, cond: Condition) -> bool {
        match cond {
            Condition::EQ => self.z,                        // Z==1
            Condition::NE => !self.z,                       // Z==0
            Condition::CS => self.c,                        // C==1 (unsigned >=)
            Condition::CC => !self.c,                       // C==0 (unsigned <)
            Condition::MI => self.n,                        // N==1
            Condition::PL => !self.n,                       // N==0
            Condition::VS => self.v,                        // V==1
            Condition::VC => !self.v,                       // V==0
            Condition::HI => self.c && !self.z,             // C==1 && Z==0 (unsigned >)
            Condition::LS => !self.c || self.z,             // C==0 || Z==1 (unsigned <=)
            Condition::GE => self.n == self.v,              // N==V (signed >=)
            Condition::LT => self.n != self.v,              // N!=V (signed <)
            Condition::GT => !self.z && (self.n == self.v), // Z==0 && N==V (signed >)
            Condition::LE => self.z || (self.n != self.v),  // Z==1 || N!=V (signed <=)
            Condition::AL => true,                          // Always
            Condition::NV => false,                         // Never (reserved, treat as false)
        }
    }
}

impl std::fmt::Display for ConditionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NZCV={}{}{}{}",
            if self.n { "N" } else { "n" },
            if self.z { "Z" } else { "z" },
            if self.c { "C" } else { "c" },
            if self.v { "V" } else { "v" },
        )
    }
}

/// Wrapper for concrete 64-bit values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConcreteValue(pub u64);

impl ConcreteValue {
    pub fn new(value: u64) -> Self {
        ConcreteValue(value)
    }

    pub fn from_i64(value: i64) -> Self {
        ConcreteValue(value as u64)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_i64(&self) -> i64 {
        self.0 as i64
    }
}

impl fmt::Display for ConcreteValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// Concrete machine state for fast validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteMachineState {
    registers: HashMap<Register, ConcreteValue>,
    flags: ConditionFlags,
}

impl ConcreteMachineState {
    /// Create a new state with all registers set to zero
    pub fn new_zeroed() -> Self {
        let mut registers = HashMap::new();

        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                registers.insert(reg, ConcreteValue::new(0));
            }
        }

        registers.insert(Register::XZR, ConcreteValue::new(0));
        registers.insert(Register::SP, ConcreteValue::new(0));

        ConcreteMachineState {
            registers,
            flags: ConditionFlags::new(),
        }
    }

    /// Create state from a map of register values
    pub fn from_values(values: HashMap<Register, u64>) -> Self {
        let mut state = Self::new_zeroed();
        for (reg, val) in values {
            state.set_register(reg, ConcreteValue::new(val));
        }
        state
    }

    /// Get the value of a register
    pub fn get_register(&self, reg: Register) -> ConcreteValue {
        if reg == Register::XZR {
            ConcreteValue::new(0)
        } else {
            *self.registers.get(&reg).unwrap_or(&ConcreteValue::new(0))
        }
    }

    /// Set the value of a register (XZR writes are ignored)
    pub fn set_register(&mut self, reg: Register, value: ConcreteValue) {
        if reg != Register::XZR {
            self.registers.insert(reg, value);
        }
    }

    /// Get all registers and their values
    pub fn registers(&self) -> &HashMap<Register, ConcreteValue> {
        &self.registers
    }

    /// Get the condition flags
    pub fn get_flags(&self) -> ConditionFlags {
        self.flags
    }

    /// Set the condition flags
    pub fn set_flags(&mut self, flags: ConditionFlags) {
        self.flags = flags;
    }
}

impl fmt::Display for ConcreteMachineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ConcreteMachineState {{")?;
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                let val = self.get_register(reg);
                if val.0 != 0 {
                    writeln!(f, "  {}: {}", reg, val)?;
                }
            }
        }
        let sp = self.get_register(Register::SP);
        if sp.0 != 0 {
            writeln!(f, "  sp: {}", sp)?;
        }
        writeln!(f, "  {}", self.flags)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_value_wrapping() {
        let v = ConcreteValue::new(u64::MAX);
        assert_eq!(v.as_u64(), u64::MAX);
        assert_eq!(v.as_i64(), -1);

        let v2 = ConcreteValue::from_i64(-1);
        assert_eq!(v2.as_u64(), u64::MAX);
    }

    #[test]
    fn test_machine_state_new_zeroed() {
        let state = ConcreteMachineState::new_zeroed();
        assert_eq!(state.get_register(Register::X0).as_u64(), 0);
        assert_eq!(state.get_register(Register::X30).as_u64(), 0);
        assert_eq!(state.get_register(Register::SP).as_u64(), 0);
        assert_eq!(state.get_register(Register::XZR).as_u64(), 0);
    }

    #[test]
    fn test_machine_state_from_values() {
        let mut values = HashMap::new();
        values.insert(Register::X0, 42);
        values.insert(Register::X1, 100);

        let state = ConcreteMachineState::from_values(values);
        assert_eq!(state.get_register(Register::X0).as_u64(), 42);
        assert_eq!(state.get_register(Register::X1).as_u64(), 100);
        assert_eq!(state.get_register(Register::X2).as_u64(), 0);
    }

    #[test]
    fn test_machine_state_set_get() {
        let mut state = ConcreteMachineState::new_zeroed();
        state.set_register(Register::X5, ConcreteValue::new(999));
        assert_eq!(state.get_register(Register::X5).as_u64(), 999);
    }

    #[test]
    fn test_xzr_always_zero() {
        let mut state = ConcreteMachineState::new_zeroed();
        state.set_register(Register::XZR, ConcreteValue::new(123));
        assert_eq!(state.get_register(Register::XZR).as_u64(), 0);
    }
}

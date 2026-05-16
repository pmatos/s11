//! Live-out contract for equivalence checking.
//!
//! `LiveOut` names the full observable architectural state contract. Today the
//! only populated slice is `LiveOutRegisters`; condition state, memory, and PC
//! can be added beside it without renaming the search/equivalence boundary.
//!
//! `LiveOutMask<R>` (added in #77 stage 1 step 7) is the per-ISA-register
//! generic shape that stage 1 step 9 wires into `EquivalenceConfig<I>` and
//! stage 2 step 16 lifts to subsume `X86LiveOutMask`. `flags_live` lives on
//! the mask per ADR-0004 decision 5.

use crate::ir::Register;
use crate::isa::RegisterType;
use std::collections::HashSet;
use std::fmt;

/// Generic live-out mask parameterised on register type.
///
/// Carries a `flags_live: bool` field so condition-state live-out is part of
/// the same contract object. Stage 1 step 9 migrates `EquivalenceConfig` to
/// `EquivalenceConfig<I>` and threads this type through every consumer; stage
/// 2 step 16 replaces the parallel `X86LiveOutMask` with
/// `LiveOutMask<X86Register>` and drops the duplicate type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOutMask<R: RegisterType> {
    regs: HashSet<R>,
    flags_live: bool,
}

impl<R: RegisterType> LiveOutMask<R> {
    /// Empty mask, flags not live.
    pub fn empty() -> Self {
        Self {
            regs: HashSet::new(),
            flags_live: false,
        }
    }

    /// Mask from a register slice, flags not live.
    pub fn from_registers(regs: Vec<R>) -> Self {
        Self {
            regs: regs.into_iter().collect(),
            flags_live: false,
        }
    }

    /// Add a register to the live-out set (zero registers are silently dropped).
    pub fn add(&mut self, reg: R) {
        if !reg.is_zero_register() {
            self.regs.insert(reg);
        }
    }

    /// Returns true if `reg` is live-out.
    pub fn contains(&self, reg: R) -> bool {
        self.regs.contains(&reg)
    }

    /// Iterate over live-out registers.
    pub fn iter(&self) -> impl Iterator<Item = &R> {
        self.regs.iter()
    }

    /// Number of live-out registers.
    pub fn len(&self) -> usize {
        self.regs.len()
    }

    /// True if the mask contains no registers (flag-only liveness still
    /// possible if `flags_live()` returns true).
    pub fn is_empty(&self) -> bool {
        self.regs.is_empty()
    }

    /// True if the condition flags are part of the live-out contract.
    #[allow(dead_code)] // wired in #77 stage 1 step 9
    pub fn flags_live(&self) -> bool {
        self.flags_live
    }

    /// Set whether the condition flags are live-out.
    #[allow(dead_code)] // wired in #77 stage 1 step 9
    pub fn set_flags_live(&mut self, live: bool) {
        self.flags_live = live;
    }
}

/// Observable architectural state that must match after executing a sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOut {
    registers: LiveOutRegisters,
}

impl LiveOut {
    /// Create a live-out contract containing all general-purpose registers.
    pub fn all_registers() -> Self {
        Self {
            registers: LiveOutRegisters::all_registers(),
        }
    }

    /// Create a live-out contract from the register slice.
    pub fn from_registers(regs: Vec<Register>) -> Self {
        Self {
            registers: LiveOutRegisters::from_registers(regs),
        }
    }

    /// Create a live-out contract from an already parsed register slice.
    pub fn from_register_set(registers: LiveOutRegisters) -> Self {
        Self { registers }
    }

    /// The register slice of this live-out contract.
    pub fn registers(&self) -> &LiveOutRegisters {
        &self.registers
    }

    /// Check whether a register is live-out.
    pub fn contains_register(&self, reg: Register) -> bool {
        self.registers.contains(reg)
    }
}

impl From<LiveOutRegisters> for LiveOut {
    fn from(registers: LiveOutRegisters) -> Self {
        Self::from_register_set(registers)
    }
}

impl fmt::Display for LiveOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "registers={}", self.registers)
    }
}

/// Register set specifying which registers are live-out (need to be preserved)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOutRegisters {
    registers: HashSet<Register>,
}

impl LiveOutRegisters {
    /// Create a register set with all general-purpose registers (X0-X30, SP)
    pub fn all_registers() -> Self {
        let mut registers = HashSet::new();
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                registers.insert(reg);
            }
        }
        registers.insert(Register::SP);
        LiveOutRegisters { registers }
    }

    /// Create a register set from a list of registers
    pub fn from_registers(regs: Vec<Register>) -> Self {
        LiveOutRegisters {
            registers: regs.into_iter().collect(),
        }
    }

    /// Create an empty register set
    pub fn empty() -> Self {
        LiveOutRegisters {
            registers: HashSet::new(),
        }
    }

    /// Add a register to the register set
    pub fn add(&mut self, reg: Register) {
        if reg != Register::XZR {
            self.registers.insert(reg);
        }
    }

    /// Remove a register from the register set
    #[allow(dead_code)]
    pub fn remove(&mut self, reg: Register) {
        self.registers.remove(&reg);
    }

    /// Check if a register is in the register set
    pub fn contains(&self, reg: Register) -> bool {
        self.registers.contains(&reg)
    }

    /// Iterate over registers in the register set
    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.registers.iter()
    }

    /// Get the number of registers in the register set
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Check if the register set is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }
}

impl fmt::Display for LiveOutRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut regs: Vec<_> = self.registers.iter().collect();
        regs.sort_by_key(|r| r.index().unwrap_or(255));
        let names: Vec<_> = regs.iter().map(|r| format!("{}", r)).collect();
        write!(f, "{{{}}}", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_out_registers_all_registers() {
        let mask = LiveOutRegisters::all_registers();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X30));
        assert!(mask.contains(Register::SP));
        assert!(!mask.contains(Register::XZR));
    }

    #[test]
    fn test_live_out_registers_from_registers() {
        let mask = LiveOutRegisters::from_registers(vec![Register::X0, Register::X1, Register::X2]);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
        assert_eq!(mask.len(), 3);
    }

    #[test]
    fn test_live_out_registers_empty() {
        let mask = LiveOutRegisters::empty();
        assert!(mask.is_empty());
        assert!(!mask.contains(Register::X0));
    }

    #[test]
    fn test_live_out_registers_add_remove() {
        let mut mask = LiveOutRegisters::empty();
        mask.add(Register::X0);
        assert!(mask.contains(Register::X0));

        mask.remove(Register::X0);
        assert!(!mask.contains(Register::X0));
    }

    #[test]
    fn test_live_out_registers_xzr_ignored() {
        let mut mask = LiveOutRegisters::empty();
        mask.add(Register::XZR);
        assert!(!mask.contains(Register::XZR));
        assert!(mask.is_empty());
    }

    #[test]
    fn test_live_out_wraps_register_slice() {
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        assert!(live_out.contains_register(Register::X0));
        assert_eq!(live_out.registers().len(), 1);
    }

    // Issue #77 stage 1 step 7: generic LiveOutMask coverage.
    #[test]
    fn test_live_out_mask_aarch64_basics() {
        let mut mask: LiveOutMask<Register> = LiveOutMask::empty();
        assert!(mask.is_empty());
        assert!(!mask.flags_live());

        mask.add(Register::X0);
        mask.add(Register::X1);
        mask.add(Register::XZR); // zero register is dropped
        assert_eq!(mask.len(), 2);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(!mask.contains(Register::XZR));

        mask.set_flags_live(true);
        assert!(mask.flags_live());
    }

    #[test]
    fn test_live_out_mask_from_registers() {
        let mask: LiveOutMask<Register> =
            LiveOutMask::from_registers(vec![Register::X0, Register::X5, Register::X30]);
        assert_eq!(mask.len(), 3);
        assert!(mask.contains(Register::X5));
        assert!(!mask.flags_live());
    }
}

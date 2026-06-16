//! Live-out and live-in register contracts for equivalence checking.
//!
//! `RegisterSet<R>` is the per-ISA generic carrier: a set of architectural
//! registers plus a `flags_live` bit. The same shape is reused for live-in
//! analyses (see `validation::live_out::compute_live_in_registers`) because
//! live-in and live-out are both register sets — hence the neutral name
//! (closes #85; supersedes the earlier `LiveOutMask<R>` / `LiveOutRegisters`
//! split).
//!
//! `LiveOut` is the AArch64 alias `RegisterSet<crate::ir::Register>` and is
//! the boundary type the search and equivalence layers use. `X86LiveOut` is
//! the same carrier specialised to x86 registers.

use crate::ir::Register;
use crate::isa::RegisterType;
use std::collections::HashSet;
use std::fmt;

/// Generic live-out mask parameterised on register type.
///
/// Carries a `flags_live: bool` field so condition-state live-out is part of
/// the same contract object. Stage 1 step 9 migrates `EquivalenceConfig` to
/// `EquivalenceConfig<I>` and threads this type through every consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterSet<R: RegisterType> {
    regs: HashSet<R>,
    flags_live: bool,
}

impl<R: RegisterType> RegisterSet<R> {
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

    /// Remove a register from the set.
    #[allow(dead_code)]
    pub fn remove(&mut self, reg: R) {
        self.regs.remove(&reg);
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
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.regs.len()
    }

    /// True if the mask contains no registers (flag-only liveness still
    /// possible if `flags_live()` returns true).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.regs.is_empty()
    }

    /// True if the condition flags are part of the live-out contract.
    pub fn flags_live(&self) -> bool {
        self.flags_live
    }

    /// Set whether the condition flags are live-out.
    #[allow(dead_code)]
    pub fn set_flags_live(&mut self, live: bool) {
        self.flags_live = live;
    }

    /// Builder form of `set_flags_live`.
    pub fn with_flags(mut self, flags_live: bool) -> Self {
        self.flags_live = flags_live;
        self
    }
}

impl RegisterSet<Register> {
    /// All general-purpose AArch64 registers (X0..X30, SP); excludes XZR.
    pub fn all_registers() -> Self {
        let mut mask = Self::empty();
        for i in 0..=30 {
            if let Some(reg) = Register::from_index(i) {
                mask.add(reg);
            }
        }
        mask.add(Register::SP);
        mask
    }

    /// AArch64-flavored alias for `contains`. Kept so call sites using the
    /// old `LiveOut::contains_register(reg)` (where `LiveOut` was a struct
    /// wrapping `LiveOutRegisters`) keep compiling against the
    /// `LiveOut = RegisterSet<Register>` alias.
    pub fn contains_register(&self, reg: Register) -> bool {
        self.contains(reg)
    }
}

/// Self-documenting Display: `LiveOut { registers={x0, x1} }`.
///
/// Format from PR #79: wrapping the register slice in a labelled outer
/// keeps the rendering forward-compatible with extra state slices
/// (flags_live today, memory/PC tomorrow) without breaking log readers.
impl fmt::Display for RegisterSet<Register> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut regs: Vec<_> = self.iter().collect();
        regs.sort_by_key(|r| r.index().unwrap_or(255));
        let names: Vec<_> = regs.iter().map(|r| format!("{}", r)).collect();
        write!(f, "LiveOut {{ registers={{{}}} }}", names.join(", "))
    }
}

/// AArch64 live-out / live-in carrier.
///
/// Type alias for `RegisterSet<Register>` per ADR-0004 decision 5. The
/// previous separate `LiveOut` wrapper struct and `LiveOutRegisters`
/// register-only set were collapsed onto this alias (closes #85).
pub type LiveOut = RegisterSet<Register>;

/// x86 live-out / live-in carrier.
///
/// Type alias for `RegisterSet<X86Register>` per ADR-0004 decision 5. x86
/// flags liveness represents EFLAGS observability.
pub type X86LiveOut = RegisterSet<crate::isa::x86::X86Register>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_out_registers_all_registers() {
        let mask = LiveOut::all_registers();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X30));
        assert!(mask.contains(Register::SP));
        assert!(!mask.contains(Register::XZR));
    }

    #[test]
    fn test_live_out_registers_from_registers() {
        let mask = LiveOut::from_registers(vec![Register::X0, Register::X1, Register::X2]);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
        assert_eq!(mask.len(), 3);
    }

    #[test]
    fn test_live_out_registers_empty() {
        let mask = LiveOut::empty();
        assert!(mask.is_empty());
        assert!(!mask.contains(Register::X0));
    }

    #[test]
    fn test_live_out_registers_add_remove() {
        let mut mask = LiveOut::empty();
        mask.add(Register::X0);
        assert!(mask.contains(Register::X0));

        mask.remove(Register::X0);
        assert!(!mask.contains(Register::X0));
    }

    #[test]
    fn test_live_out_registers_xzr_ignored() {
        let mut mask = LiveOut::empty();
        mask.add(Register::XZR);
        assert!(!mask.contains(Register::XZR));
        assert!(mask.is_empty());
    }

    #[test]
    fn test_live_out_alias_exposes_register_set_api() {
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        assert!(live_out.contains_register(Register::X0));
        assert_eq!(live_out.len(), 1);
    }

    // Issue #77 stage 1 step 7: generic RegisterSet coverage.
    #[test]
    fn test_live_out_mask_aarch64_basics() {
        let mut mask: RegisterSet<Register> = RegisterSet::empty();
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
    fn test_live_out_display_single_register() {
        let live_out = LiveOut::from_registers(vec![Register::X0]);
        assert_eq!(format!("{}", live_out), "LiveOut { registers={x0} }");
    }

    #[test]
    fn test_live_out_display_multiple_registers_sorted() {
        let live_out = LiveOut::from_registers(vec![Register::X1, Register::X0]);
        assert_eq!(format!("{}", live_out), "LiveOut { registers={x0, x1} }");
    }

    #[test]
    fn test_live_out_display_empty() {
        let live_out = LiveOut::from_registers(vec![]);
        assert_eq!(format!("{}", live_out), "LiveOut { registers={} }");
    }

    #[test]
    fn test_live_out_mask_from_registers() {
        let mask: RegisterSet<Register> =
            RegisterSet::from_registers(vec![Register::X0, Register::X5, Register::X30]);
        assert_eq!(mask.len(), 3);
        assert!(mask.contains(Register::X5));
        assert!(!mask.flags_live());
    }

    #[test]
    fn test_live_out_mask_with_flags_builder() {
        let mask: RegisterSet<Register> = RegisterSet::empty().with_flags(true);
        assert!(mask.flags_live());

        let mask: RegisterSet<Register> =
            RegisterSet::from_registers(vec![Register::X0]).with_flags(false);
        assert!(!mask.flags_live());
        assert!(mask.contains(Register::X0));
    }

    #[test]
    fn test_x86_live_out_uses_generic_register_set() {
        use crate::isa::x86::X86Register;

        let mask: X86LiveOut =
            RegisterSet::from_registers(vec![X86Register::RAX, X86Register::RBX]).with_flags(true);

        assert!(mask.contains(X86Register::RAX));
        assert!(mask.contains(X86Register::RBX));
        assert!(!mask.contains(X86Register::RCX));
        assert!(mask.flags_live());
    }

    #[test]
    fn test_live_out_mask_contains_register_alias() {
        let mask: RegisterSet<Register> = RegisterSet::from_registers(vec![Register::X3]);
        assert!(mask.contains_register(Register::X3));
        assert!(!mask.contains_register(Register::X4));
    }

    #[test]
    fn test_register_set_aarch64_all_registers() {
        let mask = RegisterSet::<Register>::all_registers();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X30));
        assert!(mask.contains(Register::SP));
        assert!(!mask.contains(Register::XZR));
    }

    #[test]
    fn test_register_set_aarch64_display_sorted() {
        let mask: RegisterSet<Register> =
            RegisterSet::from_registers(vec![Register::X5, Register::X1, Register::X3]);
        assert_eq!(format!("{}", mask), "LiveOut { registers={x1, x3, x5} }");
    }
}

//! Shared state types for concrete and symbolic execution

#![allow(dead_code)]

use crate::ir::Register;
use crate::ir::types::{AccessWidth, Condition};
use std::collections::{BTreeMap, HashMap};
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

    /// Compute flags from an add-with-carry result: `lhs + rhs + carry_in`.
    /// `carry_in` is 0 or 1. Uses 128-bit widening for exact carry-out (C)
    /// and signed overflow (V).
    pub fn from_adc(lhs: u64, rhs: u64, carry_in: u64) -> Self {
        let wide = lhs as u128 + rhs as u128 + carry_in as u128;
        let result = wide as u64;
        let v =
            (lhs as i64 as i128 + rhs as i64 as i128 + carry_in as i128) != result as i64 as i128;
        Self {
            n: (result as i64) < 0,
            z: result == 0,
            c: wide > u64::MAX as u128,
            v,
        }
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
            // NV (0b1111) is reserved in AArch64; per ARM ARM the encoding
            // still satisfies "condition holds = true" (it does NOT mean
            // "never"). Concrete and SMT both treat it as always-true.
            Condition::NV => true,
        }
    }
}

/// x86 EFLAGS bits relevant to the minimal core ISA (CMP, ADD, SUB, AND,
/// OR, XOR).
///
/// Distinct from `ConditionFlags` (AArch64 NZCV) because x86's CF
/// polarity on subtraction is inverted compared to AArch64 (x86 CF is
/// "borrow occurred", AArch64 C is "no-borrow"), and x86 has additional
/// bits (PF, AF) with their own semantics.
///
/// `af` is left as `false` for the initial scope — Intel documents it as
/// "undefined" after most logical ops, and the minimal instruction set
/// does not include any BCD or condition-code-reading instructions that
/// observe AF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Eflags {
    pub cf: bool, // Carry: unsigned overflow on add, borrow on sub
    pub pf: bool, // Parity: low byte has even parity
    pub af: bool, // Auxiliary carry (BCD); modelled as false for now
    pub zf: bool, // Zero
    pub sf: bool, // Sign (MSB of result)
    pub of: bool, // Overflow (signed)
}

impl Eflags {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parity of the low 8 bits of `result` (PF semantics).
    fn parity8(result: u64) -> bool {
        (result as u8).count_ones().is_multiple_of(2)
    }

    /// Flags from `lhs + rhs == result` at width `width`. CF is set on
    /// unsigned overflow (low-`width` bits wrap).
    pub fn from_add(lhs: u64, rhs: u64, result: u64, width: u32) -> Self {
        let lhs_w = mask_to_width(lhs, width);
        let rhs_w = mask_to_width(rhs, width);
        let result_w = mask_to_width(result, width);
        // Unsigned carry: result < either operand (mod width).
        let cf = result_w < lhs_w || result_w < rhs_w;
        let zf = result_w == 0;
        let sf = top_bit(result, width);
        // Signed overflow on addition: input signs match AND result sign differs.
        let of = {
            let l = top_bit(lhs, width);
            let r = top_bit(rhs, width);
            let res = top_bit(result, width);
            (l == r) && (l != res)
        };
        Self {
            cf,
            pf: Self::parity8(result),
            af: false,
            zf,
            sf,
            of,
        }
    }

    /// Flags from a logical op (AND/OR/XOR). CF and OF are always cleared
    /// per x86 spec; SF/ZF/PF reflect the result.
    pub fn from_logical(result: u64, width: u32) -> Self {
        Self {
            cf: false,
            pf: Self::parity8(result),
            af: false,
            zf: mask_to_width(result, width) == 0,
            sf: top_bit(result, width),
            of: false,
        }
    }

    /// Evaluate an x86 condition code against the current flag bits
    ///. Mirrors `ConditionFlags::evaluate` for AArch64.
    ///
    /// Intentionally does not read `self.af`; none of the 16 canonical
    /// x86 condition codes consult AF, and `MachineStateX86` does not
    /// model AF symbolically (see `src/semantics/smt_x86.rs`).
    pub fn evaluate(&self, cond: crate::isa::x86::X86Condition) -> bool {
        use crate::isa::x86::X86Condition;
        match cond {
            X86Condition::E => self.zf,
            X86Condition::NE => !self.zf,
            X86Condition::B => self.cf,
            X86Condition::AE => !self.cf,
            X86Condition::BE => self.cf || self.zf,
            X86Condition::A => !self.cf && !self.zf,
            X86Condition::L => self.sf != self.of,
            X86Condition::GE => self.sf == self.of,
            X86Condition::LE => self.zf || (self.sf != self.of),
            X86Condition::G => !self.zf && (self.sf == self.of),
            X86Condition::S => self.sf,
            X86Condition::NS => !self.sf,
            X86Condition::O => self.of,
            X86Condition::NO => !self.of,
            X86Condition::P => self.pf,
            X86Condition::NP => !self.pf,
        }
    }

    /// Flags from `lhs - rhs == result` (CMP and SUB at width `width`).
    /// CF is set if a borrow occurred (lhs < rhs at the operand width) —
    /// opposite of AArch64.
    pub fn from_sub(lhs: u64, rhs: u64, result: u64, width: u32) -> Self {
        let cf = mask_to_width(lhs, width) < mask_to_width(rhs, width);
        let zf = mask_to_width(result, width) == 0;
        let sf = top_bit(result, width);
        // Signed overflow on subtraction: signs differ AND lhs sign != result sign.
        let of = {
            let l = top_bit(lhs, width);
            let r = top_bit(rhs, width);
            let res = top_bit(result, width);
            (l != r) && (l != res)
        };
        Self {
            cf,
            pf: Self::parity8(result),
            af: false,
            zf,
            sf,
            of,
        }
    }
}

pub(crate) fn mask_to_width(value: u64, width: u32) -> u64 {
    match width {
        64 => value,
        32 => value & 0xffff_ffff,
        16 => value & 0xffff,
        8 => value & 0xff,
        _ => value,
    }
}

fn top_bit(value: u64, width: u32) -> bool {
    match width {
        64 => (value as i64) < 0,
        32 => (value & 0x8000_0000) != 0,
        16 => (value & 0x8000) != 0,
        8 => (value & 0x80) != 0,
        _ => (value as i64) < 0,
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

/// Concrete machine state for fast validation.
///
/// Per ADR-0004 decision 6, the state carries a width tag and masks writes
/// before storing (mask-on-write). AArch64 is always width=64, which makes
/// the mask a no-op; the field is there so stages 1+ can parameterise this
/// type and reuse the same struct for narrower widths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcreteMachineState {
    registers: HashMap<Register, ConcreteValue>,
    flags: ConditionFlags,
    width: u32,
    /// Sparse byte-addressed memory. Absent keys denote zero so that
    /// structural equality of two states matches semantic equality (see
    /// ADR-0007). `write_bytes` prunes zero entries to maintain that
    /// invariant.
    memory: BTreeMap<u64, u8>,
}

impl ConcreteMachineState {
    /// Create a new AArch64 (width=64) state with all registers set to zero.
    pub fn new_zeroed() -> Self {
        Self::new_zeroed_for_width(64)
    }

    /// Create a new state with the given register width, all registers zero.
    pub fn new_zeroed_for_width(width: u32) -> Self {
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
            width,
            memory: BTreeMap::new(),
        }
    }

    /// Register width this state was constructed with.
    pub fn width(&self) -> u32 {
        self.width
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

    /// Set the value of a register (XZR writes are ignored). Masks the value
    /// to the state's width per ADR-0004 decision 6.
    pub fn set_register(&mut self, reg: Register, value: ConcreteValue) {
        if reg != Register::XZR {
            let masked = mask_to_width(value.0, self.width);
            self.registers.insert(reg, ConcreteValue::new(masked));
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

    /// Borrow the sparse memory map. Used by `states_equal_for_live_out`
    /// to compare memory across two final states (see ADR-0007).
    pub fn memory(&self) -> &BTreeMap<u64, u8> {
        &self.memory
    }

    /// Read `width.bytes()` bytes starting at `addr`, little-endian, and
    /// zero-extend into a u64. Absent keys denote zero.
    pub fn read_bytes(&self, addr: u64, width: AccessWidth) -> u64 {
        let n = width.bytes() as usize;
        let mut value: u64 = 0;
        for i in 0..n {
            let byte = self
                .memory
                .get(&addr.wrapping_add(i as u64))
                .copied()
                .unwrap_or(0) as u64;
            value |= byte << (8 * i);
        }
        value
    }

    /// Write `width.bytes()` low bytes of `value` to memory at `addr`,
    /// little-endian. Zero bytes are pruned from the BTreeMap so that
    /// structural equality continues to match semantic equality (absent
    /// key = zero) — see ADR-0007.
    pub fn write_bytes(&mut self, addr: u64, value: u64, width: AccessWidth) {
        let n = width.bytes() as usize;
        for i in 0..n {
            let byte = ((value >> (8 * i)) & 0xff) as u8;
            let key = addr.wrapping_add(i as u64);
            if byte == 0 {
                self.memory.remove(&key);
            } else {
                self.memory.insert(key, byte);
            }
        }
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

/// Concrete machine state for the x86 backend.
///
/// Width-tagged: writes are masked to the low `width` bits so the same
/// struct can model both x86-64 (width=64) and x86-32 (width=32). All 16
/// GPRs are present in the backing map; x86-32 callers simply never
/// reference R8..R15.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86ConcreteMachineState {
    registers: HashMap<crate::isa::x86::X86Register, ConcreteValue>,
    flags: Eflags,
    width: u32,
}

impl X86ConcreteMachineState {
    pub fn new_zeroed(width: u32) -> Self {
        let mut registers = HashMap::new();
        for i in 0..16u8 {
            if let Some(r) = crate::isa::x86::X86Register::from_index(i) {
                registers.insert(r, ConcreteValue::new(0));
            }
        }
        X86ConcreteMachineState {
            registers,
            flags: Eflags::new(),
            width,
        }
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn get_register(&self, reg: crate::isa::x86::X86Register) -> ConcreteValue {
        *self.registers.get(&reg).unwrap_or(&ConcreteValue::new(0))
    }

    /// Set a register value, masking to the low `width` bits.
    pub fn set_register(&mut self, reg: crate::isa::x86::X86Register, value: ConcreteValue) {
        let masked = mask_to_width(value.as_u64(), self.width);
        self.registers.insert(reg, ConcreteValue::new(masked));
    }

    pub fn get_flags(&self) -> Eflags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: Eflags) {
        self.flags = flags;
    }

    pub fn registers(&self) -> &HashMap<crate::isa::x86::X86Register, ConcreteValue> {
        &self.registers
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

    #[test]
    fn condition_flags_evaluate_all_conditions() {
        let flags = ConditionFlags {
            n: true,
            z: false,
            c: true,
            v: false,
        };

        assert!(!flags.evaluate(Condition::EQ));
        assert!(flags.evaluate(Condition::NE));
        assert!(flags.evaluate(Condition::CS));
        assert!(!flags.evaluate(Condition::CC));
        assert!(flags.evaluate(Condition::MI));
        assert!(!flags.evaluate(Condition::PL));
        assert!(!flags.evaluate(Condition::VS));
        assert!(flags.evaluate(Condition::VC));
        assert!(flags.evaluate(Condition::HI));
        assert!(!flags.evaluate(Condition::LS));
        assert!(!flags.evaluate(Condition::GE));
        assert!(flags.evaluate(Condition::LT));
        assert!(!flags.evaluate(Condition::GT));
        assert!(flags.evaluate(Condition::LE));
        assert!(flags.evaluate(Condition::AL));
        // NV is reserved but ARM ARM specifies condition_holds = true, so it
        // is equivalent to AL — never the opposite of AL.
        assert!(flags.evaluate(Condition::NV));
    }

    #[test]
    fn aarch64_state_display_and_accessors_show_nonzero_parts() {
        let mut state = ConcreteMachineState::new_zeroed();
        state.set_register(Register::X0, ConcreteValue::new(0x2a));
        state.set_register(Register::SP, ConcreteValue::new(0x1000));
        state.set_flags(ConditionFlags {
            n: true,
            z: true,
            c: false,
            v: true,
        });

        assert!(state.registers().contains_key(&Register::X0));
        assert!(state.get_flags().z);
        assert_eq!(
            format!("{}", ConcreteValue::new(0x2a)),
            "0x000000000000002a"
        );

        let rendered = format!("{}", state);
        assert!(rendered.contains("ConcreteMachineState"));
        assert!(rendered.contains("x0: 0x000000000000002a"));
        assert!(rendered.contains("sp: 0x0000000000001000"));
        assert!(rendered.contains("NZCV=NZcV"));
    }

    #[test]
    fn width_helpers_cover_small_and_fallback_widths() {
        assert_eq!(mask_to_width(0x12345, 16), 0x2345);
        assert_eq!(mask_to_width(0x12345, 8), 0x45);
        assert_eq!(mask_to_width(0x12345, 24), 0x12345);

        assert!(top_bit(0x8000, 16));
        assert!(top_bit(0x80, 8));
        assert!(!top_bit(0x7f, 8));
        assert!(!top_bit(0x7f, 24));
    }

    #[test]
    fn x86_state_new_zeroed_has_all_gprs() {
        use crate::isa::x86::X86Register;
        let state = X86ConcreteMachineState::new_zeroed(64);
        for i in 0..16u8 {
            let r = X86Register::from_index(i).unwrap();
            assert_eq!(state.get_register(r).as_u64(), 0);
        }
        assert_eq!(state.get_flags(), Eflags::default());
        assert_eq!(state.width(), 64);
    }

    #[test]
    fn x86_state_register_get_set_round_trip() {
        use crate::isa::x86::X86Register;
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RDI, ConcreteValue::new(0xdead_beef));
        assert_eq!(state.get_register(X86Register::RDI).as_u64(), 0xdead_beef);
        assert_eq!(state.get_register(X86Register::RAX).as_u64(), 0);
    }

    #[test]
    fn x86_state_writes_mask_to_width_32() {
        use crate::isa::x86::X86Register;
        let mut state = X86ConcreteMachineState::new_zeroed(32);
        // Writing a 64-bit value when the ISA is 32-bit must truncate.
        state.set_register(X86Register::RAX, ConcreteValue::new(0x1234_5678_9abc_def0));
        assert_eq!(
            state.get_register(X86Register::RAX).as_u64(),
            0x9abc_def0,
            "32-bit ISA must truncate writes to low 32 bits"
        );
    }

    #[test]
    fn x86_state_flag_set_round_trip() {
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        let flags = Eflags {
            cf: true,
            pf: false,
            af: false,
            zf: true,
            sf: true,
            of: false,
        };
        state.set_flags(flags);
        assert_eq!(state.get_flags(), flags);
    }

    #[test]
    fn x86_state_registers_accessor_exposes_backing_map() {
        use crate::isa::x86::X86Register;
        let mut state = X86ConcreteMachineState::new_zeroed(64);
        state.set_register(X86Register::RBX, ConcreteValue::new(0xbeef));

        assert_eq!(
            state
                .registers()
                .get(&X86Register::RBX)
                .expect("rbx should be present")
                .as_u64(),
            0xbeef
        );
    }

    #[test]
    fn eflags_from_add_carry_on_unsigned_wrap() {
        // u64::MAX + 1 wraps to 0, CF=1.
        let lhs = u64::MAX;
        let rhs = 1u64;
        let result = lhs.wrapping_add(rhs);
        let f = Eflags::from_add(lhs, rhs, result, 64);
        assert!(f.cf, "carry expected on unsigned wrap");
        assert!(f.zf, "result is 0");
        assert!(!f.sf);
        assert!(!f.of, "0xff..ff + 1 = 0 is not a signed overflow");
    }

    #[test]
    fn eflags_from_add_no_carry() {
        let f = Eflags::from_add(1, 2, 3, 64);
        assert!(!f.cf);
        assert!(!f.zf);
        assert!(!f.sf);
        assert!(!f.of);
    }

    #[test]
    fn eflags_from_add_signed_overflow() {
        // INT64_MAX + 1 -> INT64_MIN ; signed overflow.
        let lhs = (1u64 << 63) - 1; // INT64_MAX
        let rhs = 1u64;
        let result = lhs.wrapping_add(rhs);
        let f = Eflags::from_add(lhs, rhs, result, 64);
        assert!(f.of, "signed overflow expected");
        assert!(!f.cf, "no unsigned overflow");
        assert!(f.sf, "result is negative");
    }

    #[test]
    fn eflags_from_logical_clears_cf_and_of() {
        let f = Eflags::from_logical(0, 64);
        assert!(!f.cf, "logical ops clear CF");
        assert!(!f.of, "logical ops clear OF");
        assert!(f.zf);
        assert!(!f.sf);
        // Result is 0, so PF for 0x00 is even parity → true.
        assert!(f.pf);
    }

    #[test]
    fn eflags_from_logical_nonzero_sign_set() {
        // High-bit set in 64-bit width.
        let f = Eflags::from_logical(1u64 << 63, 64);
        assert!(!f.zf);
        assert!(f.sf);
        assert!(!f.cf);
        assert!(!f.of);
    }

    #[test]
    fn eflags_from_sub_zero_result_sets_zf() {
        // 5 - 5 = 0 with no borrow, no overflow, sign 0, parity even.
        let f = Eflags::from_sub(5, 5, 0, 64);
        assert!(f.zf, "zf expected");
        assert!(!f.cf, "no borrow");
        assert!(!f.sf, "non-negative");
        assert!(!f.of, "no signed overflow");
        assert!(f.pf, "0x00 has even parity");
    }

    #[test]
    fn eflags_from_sub_borrow_sets_cf() {
        // 3 - 5 = -2 (wrap to 2^64 - 2). Unsigned: borrow occurred.
        let result = 3u64.wrapping_sub(5);
        let f = Eflags::from_sub(3, 5, result, 64);
        assert!(f.cf, "borrow expected");
        assert!(f.sf, "sign bit set (-2 in 64-bit signed)");
        assert!(!f.zf);
        // 3 (pos) - 5 (pos) = -2 with same input signs ⇒ no signed overflow.
        assert!(!f.of);
    }

    #[test]
    fn eflags_from_sub_signed_overflow() {
        // INT64_MIN - 1 overflows signed bounds.
        let lhs = 1u64 << 63;
        let rhs = 1u64;
        let result = lhs.wrapping_sub(rhs);
        let f = Eflags::from_sub(lhs, rhs, result, 64);
        assert!(f.of, "signed overflow expected");
        // INT64_MIN < 1 unsigned -> no borrow.
        assert!(!f.cf);
        assert!(!f.sf, "result is INT64_MAX, MSB clear");
    }

    #[test]
    fn eflags_from_sub_32bit_width_uses_low_32() {
        // In 32-bit mode, the borrow/overflow check uses the low 32 bits.
        // 0x0000_0001 - 0x0000_0002 = 0xFFFF_FFFF (treated as -1 in 32-bit).
        let result = 1u32.wrapping_sub(2) as u64;
        let f = Eflags::from_sub(1, 2, result, 32);
        assert!(f.cf, "borrow");
        assert!(f.sf, "32-bit MSB set");
        assert!(!f.zf);
    }

    // ---- Memory model ----

    #[test]
    fn read_bytes_returns_zero_on_fresh_state() {
        use crate::ir::types::AccessWidth;
        let state = ConcreteMachineState::new_zeroed();
        assert_eq!(state.read_bytes(0x1000, AccessWidth::Extended), 0);
        assert_eq!(state.read_bytes(0x1000, AccessWidth::Byte), 0);
    }

    #[test]
    fn write_then_read_round_trips_at_each_width() {
        use crate::ir::types::AccessWidth;
        let mut state = ConcreteMachineState::new_zeroed();
        state.write_bytes(0x1000, 0xDEADBEEF_CAFEBABE, AccessWidth::Extended);
        assert_eq!(
            state.read_bytes(0x1000, AccessWidth::Extended),
            0xDEADBEEF_CAFEBABE
        );

        state.write_bytes(0x2000, 0x1234_5678, AccessWidth::Word);
        assert_eq!(state.read_bytes(0x2000, AccessWidth::Word), 0x1234_5678);

        state.write_bytes(0x3000, 0xAB, AccessWidth::Byte);
        assert_eq!(state.read_bytes(0x3000, AccessWidth::Byte), 0xAB);
    }

    #[test]
    fn write_is_little_endian() {
        use crate::ir::types::AccessWidth;
        let mut state = ConcreteMachineState::new_zeroed();
        state.write_bytes(0x100, 0x0807_0605_0403_0201, AccessWidth::Extended);
        // Byte at +0 holds the low byte (0x01); byte at +7 holds the high byte (0x08).
        assert_eq!(state.read_bytes(0x100, AccessWidth::Byte), 0x01);
        assert_eq!(state.read_bytes(0x107, AccessWidth::Byte), 0x08);
    }

    #[test]
    fn overlapping_writes_resolve_per_byte() {
        use crate::ir::types::AccessWidth;
        let mut state = ConcreteMachineState::new_zeroed();
        state.write_bytes(0x100, 0x0807_0605_0403_0201, AccessWidth::Extended);
        // Overwrite bytes 2-3 with a half-word store.
        state.write_bytes(0x102, 0xCAFE, AccessWidth::Half);
        // The full 64-bit read sees the original bytes 0-1 and 4-7, plus the
        // patched bytes at 2-3 (little-endian).
        assert_eq!(
            state.read_bytes(0x100, AccessWidth::Extended),
            0x0807_0605_CAFE_0201
        );
    }

    #[test]
    fn write_of_zero_byte_prunes_entry() {
        use crate::ir::types::AccessWidth;
        let mut state = ConcreteMachineState::new_zeroed();
        state.write_bytes(0x100, 0x1234_5678, AccessWidth::Word);
        // Overwrite with zero — the BTreeMap entries should be removed so
        // structural equality matches semantic equality (absent key = zero).
        state.write_bytes(0x100, 0, AccessWidth::Word);
        assert!(state.memory().is_empty(), "zero writes must prune");
    }

    #[test]
    fn equality_of_states_is_structural_after_prune() {
        use crate::ir::types::AccessWidth;
        let mut a = ConcreteMachineState::new_zeroed();
        let b = ConcreteMachineState::new_zeroed();
        a.write_bytes(0x100, 0, AccessWidth::Word);
        assert_eq!(a, b, "writing zeroes must not perturb structural equality");
    }

    // --- Eflags::evaluate(X86Condition) ---

    #[test]
    fn eflags_evaluate_e_reads_zf() {
        use crate::isa::x86::X86Condition;
        let mut f = Eflags::new();
        f.zf = true;
        assert!(f.evaluate(X86Condition::E));
        assert!(!f.evaluate(X86Condition::NE));
        f.zf = false;
        assert!(!f.evaluate(X86Condition::E));
        assert!(f.evaluate(X86Condition::NE));
    }

    #[test]
    fn eflags_evaluate_b_reads_cf_unsigned_below() {
        use crate::isa::x86::X86Condition;
        let mut f = Eflags::new();
        f.cf = true;
        assert!(f.evaluate(X86Condition::B));
        assert!(!f.evaluate(X86Condition::AE));
        f.cf = false;
        assert!(!f.evaluate(X86Condition::B));
        assert!(f.evaluate(X86Condition::AE));
    }

    #[test]
    fn eflags_evaluate_l_compares_sf_vs_of_signed_less() {
        use crate::isa::x86::X86Condition;
        let mut f = Eflags::new();
        // L is true iff SF != OF.
        f.sf = true;
        f.of = false;
        assert!(f.evaluate(X86Condition::L));
        assert!(!f.evaluate(X86Condition::GE));
        f.of = true;
        assert!(!f.evaluate(X86Condition::L));
        assert!(f.evaluate(X86Condition::GE));
    }

    #[test]
    fn eflags_evaluate_ble_combines_zf_and_signed_less() {
        use crate::isa::x86::X86Condition;
        // BE: cf || zf; LE: zf || (sf != of).
        let mut f = Eflags::new();
        f.cf = true;
        assert!(f.evaluate(X86Condition::BE));
        f.cf = false;
        f.zf = true;
        assert!(f.evaluate(X86Condition::BE));
        assert!(f.evaluate(X86Condition::LE));
        f.zf = false;
        f.sf = true;
        f.of = false;
        assert!(f.evaluate(X86Condition::LE));
        assert!(!f.evaluate(X86Condition::G));
    }

    #[test]
    fn eflags_evaluate_p_reads_pf_only() {
        use crate::isa::x86::X86Condition;
        let mut f = Eflags::new();
        f.pf = true;
        assert!(f.evaluate(X86Condition::P));
        assert!(!f.evaluate(X86Condition::NP));
        f.pf = false;
        assert!(!f.evaluate(X86Condition::P));
        assert!(f.evaluate(X86Condition::NP));
    }

    #[test]
    fn eflags_evaluate_never_reads_af() {
        // x86 condition codes do not consult AF — enforce by toggling AF
        // across all 16 codes and asserting the result is invariant. Acts
        // as a tripwire if a future condition arm accidentally reads af.
        use crate::isa::x86::X86Condition;
        let mut f = Eflags::new();
        f.cf = true;
        f.pf = true;
        f.zf = true;
        f.sf = true;
        f.of = true;
        for cond in [
            X86Condition::E,
            X86Condition::NE,
            X86Condition::B,
            X86Condition::AE,
            X86Condition::BE,
            X86Condition::A,
            X86Condition::L,
            X86Condition::GE,
            X86Condition::LE,
            X86Condition::G,
            X86Condition::S,
            X86Condition::NS,
            X86Condition::O,
            X86Condition::NO,
            X86Condition::P,
            X86Condition::NP,
        ] {
            f.af = false;
            let v0 = f.evaluate(cond);
            f.af = true;
            let v1 = f.evaluate(cond);
            assert_eq!(v0, v1, "evaluate({:?}) must not depend on AF", cond);
        }
    }
}

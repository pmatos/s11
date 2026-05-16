//! Core types for the AArch64 IR representation

use std::fmt;

/// AArch64 general-purpose registers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum Register {
    // General purpose registers
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X18,
    X19,
    X20,
    X21,
    X22,
    X23,
    X24,
    X25,
    X26,
    X27,
    X28,
    X29,
    X30,
    // Special registers
    XZR, // Zero register
    SP,  // Stack pointer
}

impl Register {
    /// Get register index for X0-X30
    #[allow(dead_code)]
    pub fn index(&self) -> Option<u8> {
        match self {
            Register::X0 => Some(0),
            Register::X1 => Some(1),
            Register::X2 => Some(2),
            Register::X3 => Some(3),
            Register::X4 => Some(4),
            Register::X5 => Some(5),
            Register::X6 => Some(6),
            Register::X7 => Some(7),
            Register::X8 => Some(8),
            Register::X9 => Some(9),
            Register::X10 => Some(10),
            Register::X11 => Some(11),
            Register::X12 => Some(12),
            Register::X13 => Some(13),
            Register::X14 => Some(14),
            Register::X15 => Some(15),
            Register::X16 => Some(16),
            Register::X17 => Some(17),
            Register::X18 => Some(18),
            Register::X19 => Some(19),
            Register::X20 => Some(20),
            Register::X21 => Some(21),
            Register::X22 => Some(22),
            Register::X23 => Some(23),
            Register::X24 => Some(24),
            Register::X25 => Some(25),
            Register::X26 => Some(26),
            Register::X27 => Some(27),
            Register::X28 => Some(28),
            Register::X29 => Some(29),
            Register::X30 => Some(30),
            Register::XZR => Some(31),
            Register::SP => None,
        }
    }

    /// Create register from index (0-30 for X registers, 31 for XZR)
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Register::X0),
            1 => Some(Register::X1),
            2 => Some(Register::X2),
            3 => Some(Register::X3),
            4 => Some(Register::X4),
            5 => Some(Register::X5),
            6 => Some(Register::X6),
            7 => Some(Register::X7),
            8 => Some(Register::X8),
            9 => Some(Register::X9),
            10 => Some(Register::X10),
            11 => Some(Register::X11),
            12 => Some(Register::X12),
            13 => Some(Register::X13),
            14 => Some(Register::X14),
            15 => Some(Register::X15),
            16 => Some(Register::X16),
            17 => Some(Register::X17),
            18 => Some(Register::X18),
            19 => Some(Register::X19),
            20 => Some(Register::X20),
            21 => Some(Register::X21),
            22 => Some(Register::X22),
            23 => Some(Register::X23),
            24 => Some(Register::X24),
            25 => Some(Register::X25),
            26 => Some(Register::X26),
            27 => Some(Register::X27),
            28 => Some(Register::X28),
            29 => Some(Register::X29),
            30 => Some(Register::X30),
            31 => Some(Register::XZR),
            _ => None,
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Register::X0 => write!(f, "x0"),
            Register::X1 => write!(f, "x1"),
            Register::X2 => write!(f, "x2"),
            Register::X3 => write!(f, "x3"),
            Register::X4 => write!(f, "x4"),
            Register::X5 => write!(f, "x5"),
            Register::X6 => write!(f, "x6"),
            Register::X7 => write!(f, "x7"),
            Register::X8 => write!(f, "x8"),
            Register::X9 => write!(f, "x9"),
            Register::X10 => write!(f, "x10"),
            Register::X11 => write!(f, "x11"),
            Register::X12 => write!(f, "x12"),
            Register::X13 => write!(f, "x13"),
            Register::X14 => write!(f, "x14"),
            Register::X15 => write!(f, "x15"),
            Register::X16 => write!(f, "x16"),
            Register::X17 => write!(f, "x17"),
            Register::X18 => write!(f, "x18"),
            Register::X19 => write!(f, "x19"),
            Register::X20 => write!(f, "x20"),
            Register::X21 => write!(f, "x21"),
            Register::X22 => write!(f, "x22"),
            Register::X23 => write!(f, "x23"),
            Register::X24 => write!(f, "x24"),
            Register::X25 => write!(f, "x25"),
            Register::X26 => write!(f, "x26"),
            Register::X27 => write!(f, "x27"),
            Register::X28 => write!(f, "x28"),
            Register::X29 => write!(f, "x29"),
            Register::X30 => write!(f, "x30"),
            Register::XZR => write!(f, "xzr"),
            Register::SP => write!(f, "sp"),
        }
    }
}

/// AArch64 shift kind for the shifted-register operand form
/// (`add x0, x1, x2, lsl #3` etc.). Issue #59.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl fmt::Display for ShiftKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShiftKind::Lsl => write!(f, "lsl"),
            ShiftKind::Lsr => write!(f, "lsr"),
            ShiftKind::Asr => write!(f, "asr"),
            ShiftKind::Ror => write!(f, "ror"),
        }
    }
}

/// AArch64 extend kind for the extended-register operand form
/// (`add x0, x1, w2, uxtb #2` etc.). Issue #60.
///
/// The inner register is architecturally a W-register for byte/half/word
/// extends (UXTB/UXTH/UXTW, SXTB/SXTH/SXTW) and an X-register for the
/// 64-bit extends (UXTX/SXTX). The IR models the inner register as
/// 64-bit X and Display/encoder selectively project to the W form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendKind {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

impl ExtendKind {
    /// Returns true if this extend kind operates on a 64-bit (X-form)
    /// source register. UXTX/SXTX are the only such kinds.
    pub fn is_x_form(&self) -> bool {
        matches!(self, ExtendKind::Uxtx | ExtendKind::Sxtx)
    }
}

impl fmt::Display for ExtendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendKind::Uxtb => write!(f, "uxtb"),
            ExtendKind::Uxth => write!(f, "uxth"),
            ExtendKind::Uxtw => write!(f, "uxtw"),
            ExtendKind::Uxtx => write!(f, "uxtx"),
            ExtendKind::Sxtb => write!(f, "sxtb"),
            ExtendKind::Sxth => write!(f, "sxth"),
            ExtendKind::Sxtw => write!(f, "sxtw"),
            ExtendKind::Sxtx => write!(f, "sxtx"),
        }
    }
}

/// Operand for instructions: a register, an immediate, a shifted-register
/// (`reg, kind #amount` where amount is 0..=63 enforced by `is_encodable_aarch64`),
/// or an extended-register (`reg, extend-kind #shift` where shift is 0..=4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operand {
    Register(Register),
    Immediate(i64),
    ShiftedRegister {
        reg: Register,
        kind: ShiftKind,
        amount: u8,
    },
    ExtendedRegister {
        reg: Register,
        kind: ExtendKind,
        shift: u8,
    },
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Register(reg) => write!(f, "{}", reg),
            Operand::Immediate(imm) => write!(f, "#{}", imm),
            Operand::ShiftedRegister { reg, kind, amount } => {
                write!(f, "{}, {} #{}", reg, kind, amount)
            }
            Operand::ExtendedRegister { reg, kind, shift } => {
                // Byte/half/word extends print the inner register as W-form;
                // the 64-bit extends UXTX/SXTX print as X-form. The Display
                // matches what Capstone emits after a roundtrip.
                let inner = if kind.is_x_form() {
                    format!("{}", reg)
                } else {
                    match reg.index() {
                        Some(idx) => format!("w{}", idx),
                        // SP has no W-form; fall back to its canonical name
                        // (encodability gates SP out before any caller sees it).
                        None => format!("{}", reg),
                    }
                };
                write!(f, "{}, {} #{}", inner, kind, shift)
            }
        }
    }
}

/// Symbolic branch destination. Carries the absolute target address; the
/// assembler resolves it to a PC-relative immediate at encode time. For
/// identifier-style labels in `.s` source, the parser hashes the name into
/// the `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabelId(pub u64);

impl fmt::Display for LabelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Condition codes for AArch64
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Condition {
    EQ, // Equal
    NE, // Not equal
    CS, // Carry set (HS - unsigned higher or same)
    CC, // Carry clear (LO - unsigned lower)
    MI, // Minus (negative)
    PL, // Plus (positive or zero)
    VS, // Overflow set
    VC, // Overflow clear
    HI, // Unsigned higher
    LS, // Unsigned lower or same
    GE, // Signed greater than or equal
    LT, // Signed less than
    GT, // Signed greater than
    LE, // Signed less than or equal
    AL, // Always
    NV, // Never (reserved)
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::EQ => write!(f, "eq"),
            Condition::NE => write!(f, "ne"),
            Condition::CS => write!(f, "cs"),
            Condition::CC => write!(f, "cc"),
            Condition::MI => write!(f, "mi"),
            Condition::PL => write!(f, "pl"),
            Condition::VS => write!(f, "vs"),
            Condition::VC => write!(f, "vc"),
            Condition::HI => write!(f, "hi"),
            Condition::LS => write!(f, "ls"),
            Condition::GE => write!(f, "ge"),
            Condition::LT => write!(f, "lt"),
            Condition::GT => write!(f, "gt"),
            Condition::LE => write!(f, "le"),
            Condition::AL => write!(f, "al"),
            Condition::NV => write!(f, "nv"),
        }
    }
}

/// The 14 condition codes that are sensible operands for CSET / CSETM /
/// stochastic mutation. AL (always true) and NV (reserved) are excluded —
/// see `Condition::invert()` for the underlying AArch64 pairing rule.
pub const NORMAL_CONDITIONS: [Condition; 14] = [
    Condition::EQ,
    Condition::NE,
    Condition::CS,
    Condition::CC,
    Condition::MI,
    Condition::PL,
    Condition::VS,
    Condition::VC,
    Condition::HI,
    Condition::LS,
    Condition::GE,
    Condition::LT,
    Condition::GT,
    Condition::LE,
];

impl Condition {
    /// Returns the logical inverse of a condition code. AArch64 encodes the
    /// invert by toggling the low bit of the 4-bit condition field, so pairs
    /// are: EQ↔NE, CS↔CC, MI↔PL, VS↔VC, HI↔LS, GE↔LT, GT↔LE, AL↔NV.
    #[must_use]
    pub fn invert(self) -> Condition {
        match self {
            Condition::EQ => Condition::NE,
            Condition::NE => Condition::EQ,
            Condition::CS => Condition::CC,
            Condition::CC => Condition::CS,
            Condition::MI => Condition::PL,
            Condition::PL => Condition::MI,
            Condition::VS => Condition::VC,
            Condition::VC => Condition::VS,
            Condition::HI => Condition::LS,
            Condition::LS => Condition::HI,
            Condition::GE => Condition::LT,
            Condition::LT => Condition::GE,
            Condition::GT => Condition::LE,
            Condition::LE => Condition::GT,
            Condition::AL => Condition::NV,
            Condition::NV => Condition::AL,
        }
    }

    /// Pick a random condition code from [`NORMAL_CONDITIONS`] (excludes
    /// AL / NV — those are encoder-rejected by `is_encodable_aarch64` for
    /// CSET / CSETM and have no real meaning for stochastic mutation).
    #[must_use]
    pub fn random_normal<R: rand::RngExt>(rng: &mut R) -> Condition {
        NORMAL_CONDITIONS[rng.random_range(0..NORMAL_CONDITIONS.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_index() {
        assert_eq!(Register::X0.index(), Some(0));
        assert_eq!(Register::X30.index(), Some(30));
        assert_eq!(Register::XZR.index(), Some(31));
        assert_eq!(Register::SP.index(), None);
    }

    #[test]
    fn test_register_from_index() {
        assert_eq!(Register::from_index(0), Some(Register::X0));
        assert_eq!(Register::from_index(30), Some(Register::X30));
        assert_eq!(Register::from_index(31), Some(Register::XZR));
        assert_eq!(Register::from_index(32), None);
    }

    #[test]
    fn test_register_display() {
        assert_eq!(format!("{}", Register::X0), "x0");
        assert_eq!(format!("{}", Register::XZR), "xzr");
        assert_eq!(format!("{}", Register::SP), "sp");
    }

    #[test]
    fn test_operand_display() {
        assert_eq!(format!("{}", Operand::Register(Register::X5)), "x5");
        assert_eq!(format!("{}", Operand::Immediate(42)), "#42");
        assert_eq!(format!("{}", Operand::Immediate(-1)), "#-1");
    }

    #[test]
    fn test_extended_register_display_widths() {
        // Issue #60: byte/half/word extend kinds print the inner register as
        // a W-form; UXTX/SXTX print it as X-form. The shift always uses a
        // `#<amount>` immediate.
        assert_eq!(
            format!(
                "{}",
                Operand::ExtendedRegister {
                    reg: Register::X2,
                    kind: ExtendKind::Uxtb,
                    shift: 2,
                }
            ),
            "w2, uxtb #2"
        );
        assert_eq!(
            format!(
                "{}",
                Operand::ExtendedRegister {
                    reg: Register::X5,
                    kind: ExtendKind::Sxth,
                    shift: 0,
                }
            ),
            "w5, sxth #0"
        );
        assert_eq!(
            format!(
                "{}",
                Operand::ExtendedRegister {
                    reg: Register::X10,
                    kind: ExtendKind::Sxtx,
                    shift: 3,
                }
            ),
            "x10, sxtx #3"
        );
        assert_eq!(
            format!(
                "{}",
                Operand::ExtendedRegister {
                    reg: Register::X1,
                    kind: ExtendKind::Uxtx,
                    shift: 4,
                }
            ),
            "x1, uxtx #4"
        );
    }

    #[test]
    fn test_condition_invert_pairs() {
        let pairs = [
            (Condition::EQ, Condition::NE),
            (Condition::CS, Condition::CC),
            (Condition::MI, Condition::PL),
            (Condition::VS, Condition::VC),
            (Condition::HI, Condition::LS),
            (Condition::GE, Condition::LT),
            (Condition::GT, Condition::LE),
            (Condition::AL, Condition::NV),
        ];
        for (a, b) in pairs {
            assert_eq!(a.invert(), b, "{:?}.invert() should be {:?}", a, b);
            assert_eq!(b.invert(), a, "{:?}.invert() should be {:?}", b, a);
        }
    }

    #[test]
    fn test_condition_invert_is_involution() {
        for c in [
            Condition::EQ,
            Condition::NE,
            Condition::CS,
            Condition::CC,
            Condition::MI,
            Condition::PL,
            Condition::VS,
            Condition::VC,
            Condition::HI,
            Condition::LS,
            Condition::GE,
            Condition::LT,
            Condition::GT,
            Condition::LE,
            Condition::AL,
            Condition::NV,
        ] {
            assert_eq!(
                c.invert().invert(),
                c,
                "{:?}.invert().invert() != {:?}",
                c,
                c
            );
        }
    }

    #[test]
    fn all_registers_display_and_index_round_trip() {
        for idx in 0..=30 {
            let reg = Register::from_index(idx).unwrap();
            assert_eq!(reg.index(), Some(idx));
            assert_eq!(format!("{}", reg), format!("x{}", idx));
        }
        assert_eq!(Register::XZR.index(), Some(31));
        assert_eq!(format!("{}", Register::XZR), "xzr");
        assert_eq!(Register::SP.index(), None);
        assert_eq!(format!("{}", Register::SP), "sp");
    }

    #[test]
    fn all_conditions_display_and_normal_set_are_covered() {
        let cases = [
            (Condition::EQ, "eq"),
            (Condition::NE, "ne"),
            (Condition::CS, "cs"),
            (Condition::CC, "cc"),
            (Condition::MI, "mi"),
            (Condition::PL, "pl"),
            (Condition::VS, "vs"),
            (Condition::VC, "vc"),
            (Condition::HI, "hi"),
            (Condition::LS, "ls"),
            (Condition::GE, "ge"),
            (Condition::LT, "lt"),
            (Condition::GT, "gt"),
            (Condition::LE, "le"),
            (Condition::AL, "al"),
            (Condition::NV, "nv"),
        ];
        for (cond, display) in cases {
            assert_eq!(format!("{}", cond), display);
        }
        assert_eq!(NORMAL_CONDITIONS.len(), 14);
        assert!(!NORMAL_CONDITIONS.contains(&Condition::AL));
        assert!(!NORMAL_CONDITIONS.contains(&Condition::NV));
    }
}

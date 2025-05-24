//! Core types for the AArch64 IR representation

use std::fmt;

/// AArch64 general-purpose registers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    // General purpose registers
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30,
    // Special registers
    XZR, // Zero register
    SP,  // Stack pointer
}

impl Register {
    /// Get register index for X0-X30
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

/// Operand for instructions - either a register or immediate value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operand {
    Register(Register),
    Immediate(i64),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Register(reg) => write!(f, "{}", reg),
            Operand::Immediate(imm) => write!(f, "#{}", imm),
        }
    }
}

/// Condition codes for AArch64
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}
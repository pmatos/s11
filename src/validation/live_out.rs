//! Live-out register computation and parsing

use crate::ir::{Instruction, Register};
use crate::semantics::state::LiveOutMask;
use std::str::FromStr;

/// Error type for parsing LiveOutMask
#[derive(Debug, Clone, PartialEq)]
pub struct ParseLiveOutError {
    pub message: String,
}

impl std::fmt::Display for ParseLiveOutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParseLiveOutError: {}", self.message)
    }
}

impl std::error::Error for ParseLiveOutError {}

/// Parse a register name like "x0", "X1", "sp", "SP"
fn parse_register(s: &str) -> Result<Register, ParseLiveOutError> {
    let s = s.trim().to_lowercase();

    if s == "sp" {
        return Ok(Register::SP);
    }
    if s == "xzr" {
        return Ok(Register::XZR);
    }

    if let Some(num_str) = s.strip_prefix('x') {
        if let Ok(num) = num_str.parse::<u8>() {
            if let Some(reg) = Register::from_index(num) {
                return Ok(reg);
            }
        }
    }

    Err(ParseLiveOutError {
        message: format!("invalid register name: '{}'", s),
    })
}

impl FromStr for LiveOutMask {
    type Err = ParseLiveOutError;

    /// Parse a comma or space-separated list of register names
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Ok(LiveOutMask::empty());
        }

        let separator = if s.contains(',') { ',' } else { ' ' };

        let mut mask = LiveOutMask::empty();
        for part in s.split(separator) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let reg = parse_register(part)?;
            mask.add(reg);
        }

        Ok(mask)
    }
}

/// Compute the set of registers written by a sequence of instructions
pub fn compute_written_registers(instructions: &[Instruction]) -> LiveOutMask {
    let mut mask = LiveOutMask::empty();
    for instr in instructions {
        if let Some(dest) = instr.destination() {
            mask.add(dest);
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Operand;

    #[test]
    fn test_parse_register_x0() {
        assert_eq!(parse_register("x0"), Ok(Register::X0));
        assert_eq!(parse_register("X0"), Ok(Register::X0));
    }

    #[test]
    fn test_parse_register_x30() {
        assert_eq!(parse_register("x30"), Ok(Register::X30));
        assert_eq!(parse_register("X30"), Ok(Register::X30));
    }

    #[test]
    fn test_parse_register_sp() {
        assert_eq!(parse_register("sp"), Ok(Register::SP));
        assert_eq!(parse_register("SP"), Ok(Register::SP));
    }

    #[test]
    fn test_parse_register_xzr() {
        assert_eq!(parse_register("xzr"), Ok(Register::XZR));
        assert_eq!(parse_register("XZR"), Ok(Register::XZR));
    }

    #[test]
    fn test_parse_register_invalid() {
        assert!(parse_register("r0").is_err());
        assert!(parse_register("x32").is_err());
        assert!(parse_register("foo").is_err());
    }

    #[test]
    fn test_live_out_mask_from_str_comma_separated() {
        let mask: LiveOutMask = "x0, x1, x2".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
    }

    #[test]
    fn test_live_out_mask_from_str_space_separated() {
        let mask: LiveOutMask = "x0 x1 x2".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
    }

    #[test]
    fn test_live_out_mask_from_str_mixed_case() {
        let mask: LiveOutMask = "X0, x1, SP".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::SP));
    }

    #[test]
    fn test_live_out_mask_from_str_empty() {
        let mask: LiveOutMask = "".parse().unwrap();
        assert!(mask.is_empty());
    }

    #[test]
    fn test_live_out_mask_from_str_whitespace() {
        let mask: LiveOutMask = "  x0  ,  x1  ".parse().unwrap();
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
    }

    #[test]
    fn test_live_out_mask_from_str_invalid() {
        let result: Result<LiveOutMask, _> = "x0, invalid, x1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_written_registers_empty() {
        let mask = compute_written_registers(&[]);
        assert!(mask.is_empty());
    }

    #[test]
    fn test_compute_written_registers_single() {
        let instructions = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert!(!mask.contains(Register::X1));
    }

    #[test]
    fn test_compute_written_registers_multiple() {
        let instructions = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 42,
            },
            Instruction::Add {
                rd: Register::X1,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
            Instruction::MovReg {
                rd: Register::X2,
                rn: Register::X1,
            },
        ];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert!(mask.contains(Register::X1));
        assert!(mask.contains(Register::X2));
        assert!(!mask.contains(Register::X3));
    }

    #[test]
    fn test_compute_written_registers_same_register_multiple_times() {
        let instructions = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ];
        let mask = compute_written_registers(&instructions);
        assert!(mask.contains(Register::X0));
        assert_eq!(mask.len(), 1);
    }

    #[test]
    fn test_compute_written_registers_xzr_not_included() {
        let instructions = vec![Instruction::MovImm {
            rd: Register::XZR,
            imm: 42,
        }];
        let mask = compute_written_registers(&instructions);
        assert!(!mask.contains(Register::XZR));
        assert!(mask.is_empty());
    }
}

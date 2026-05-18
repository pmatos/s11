//! Random input generation for fast validation

use crate::ir::Register;
use crate::semantics::state::ConcreteMachineState;
use rand::RngExt;
use std::collections::HashMap;

/// Configuration for random input generation
#[derive(Debug, Clone)]
pub struct RandomInputConfig {
    /// Number of random inputs to generate
    pub count: usize,
    /// Registers to randomize (others will be zero)
    pub registers: Vec<Register>,
}

impl Default for RandomInputConfig {
    fn default() -> Self {
        RandomInputConfig {
            count: 10,
            registers: vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
            ],
        }
    }
}

/// Generate random concrete machine states for testing
pub fn generate_random_inputs(config: &RandomInputConfig) -> Vec<ConcreteMachineState> {
    let mut rng = rand::rng();
    let mut inputs = Vec::with_capacity(config.count);

    for _ in 0..config.count {
        let mut values = HashMap::new();
        for reg in &config.registers {
            values.insert(*reg, rng.random::<u64>());
        }
        inputs.push(ConcreteMachineState::from_values(values));
    }

    inputs
}

/// Generate edge case inputs for thorough testing
pub fn generate_edge_case_inputs(registers: &[Register]) -> Vec<ConcreteMachineState> {
    let edge_values: Vec<u64> = vec![
        0,
        1,
        u64::MAX,
        i64::MAX as u64,
        i64::MIN as u64,
        0x8000_0000_0000_0000,
        0x7FFF_FFFF_FFFF_FFFF,
        0x0000_0000_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
    ];

    let mut inputs = Vec::new();

    for &edge_val in &edge_values {
        let mut values = HashMap::new();
        for reg in registers {
            values.insert(*reg, edge_val);
        }
        inputs.push(ConcreteMachineState::from_values(values));
    }

    if registers.len() >= 2 {
        for &val1 in &edge_values[..5] {
            for &val2 in &edge_values[..5] {
                let mut values = HashMap::new();
                if let Some(reg) = registers.first() {
                    values.insert(*reg, val1);
                }
                if let Some(reg) = registers.get(1) {
                    values.insert(*reg, val2);
                }
                inputs.push(ConcreteMachineState::from_values(values));
            }
        }
    }

    inputs
}

// ---- x86 random-input helpers (issue #73 Phase C) ----

/// Configuration for x86 random-input generation. Parallels
/// `RandomInputConfig` for AArch64. `width` controls how assigned
/// values are masked by the x86 concrete state on write.
#[derive(Debug, Clone)]
pub struct RandomInputConfigX86 {
    pub count: usize,
    pub registers: Vec<crate::isa::x86::X86Register>,
    pub width: u32,
}

impl Default for RandomInputConfigX86 {
    fn default() -> Self {
        Self {
            count: 10,
            registers: vec![
                crate::isa::x86::X86Register::RAX,
                crate::isa::x86::X86Register::RCX,
                crate::isa::x86::X86Register::RDX,
                crate::isa::x86::X86Register::RBX,
            ],
            width: 64,
        }
    }
}

/// Generate random x86 concrete machine states. Each state initialises
/// the listed registers with random values; other registers stay zero.
pub fn generate_random_inputs_x86(
    config: &RandomInputConfigX86,
) -> Vec<crate::semantics::state::X86ConcreteMachineState> {
    let mut rng = rand::rng();
    let mut inputs = Vec::with_capacity(config.count);
    for _ in 0..config.count {
        let mut state = crate::semantics::state::X86ConcreteMachineState::new_zeroed(config.width);
        for reg in &config.registers {
            state.set_register(
                *reg,
                crate::semantics::state::ConcreteValue::new(rng.random()),
            );
        }
        inputs.push(state);
    }
    inputs
}

/// Generate edge-case x86 inputs. Mirrors `generate_edge_case_inputs`
/// for AArch64.
pub fn generate_edge_case_inputs_x86(
    registers: &[crate::isa::x86::X86Register],
    width: u32,
) -> Vec<crate::semantics::state::X86ConcreteMachineState> {
    let edge_values: Vec<u64> = vec![
        0,
        1,
        u64::MAX,
        i64::MAX as u64,
        i64::MIN as u64,
        0x8000_0000_0000_0000,
        0x7FFF_FFFF_FFFF_FFFF,
        0x0000_0000_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
    ];

    let mut inputs = Vec::new();
    for &edge_val in &edge_values {
        let mut state = crate::semantics::state::X86ConcreteMachineState::new_zeroed(width);
        for reg in registers {
            state.set_register(*reg, crate::semantics::state::ConcreteValue::new(edge_val));
        }
        inputs.push(state);
    }
    if registers.len() >= 2 {
        for &v1 in &edge_values[..5] {
            for &v2 in &edge_values[..5] {
                let mut state = crate::semantics::state::X86ConcreteMachineState::new_zeroed(width);
                if let Some(reg) = registers.first() {
                    state.set_register(*reg, crate::semantics::state::ConcreteValue::new(v1));
                }
                if let Some(reg) = registers.get(1) {
                    state.set_register(*reg, crate::semantics::state::ConcreteValue::new(v2));
                }
                inputs.push(state);
            }
        }
    }
    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_inputs_count() {
        let config = RandomInputConfig {
            count: 5,
            registers: vec![Register::X0, Register::X1],
        };
        let inputs = generate_random_inputs(&config);
        assert_eq!(inputs.len(), 5);
    }

    #[test]
    fn test_generate_random_inputs_default() {
        let config = RandomInputConfig::default();
        let inputs = generate_random_inputs(&config);
        assert_eq!(inputs.len(), 10);
    }

    #[test]
    fn test_generate_random_inputs_varies() {
        let config = RandomInputConfig {
            count: 10,
            registers: vec![Register::X0],
        };
        let inputs = generate_random_inputs(&config);

        let values: Vec<_> = inputs
            .iter()
            .map(|s| s.get_register(Register::X0).as_u64())
            .collect();

        let unique_count = values
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count > 1);
    }

    #[test]
    fn test_generate_edge_case_inputs_not_empty() {
        let inputs = generate_edge_case_inputs(&[Register::X0, Register::X1]);
        assert!(!inputs.is_empty());
    }

    #[test]
    fn test_generate_edge_case_inputs_contains_zero() {
        let inputs = generate_edge_case_inputs(&[Register::X0]);
        let has_zero = inputs
            .iter()
            .any(|s| s.get_register(Register::X0).as_u64() == 0);
        assert!(has_zero);
    }

    #[test]
    fn test_generate_edge_case_inputs_contains_max() {
        let inputs = generate_edge_case_inputs(&[Register::X0]);
        let has_max = inputs
            .iter()
            .any(|s| s.get_register(Register::X0).as_u64() == u64::MAX);
        assert!(has_max);
    }

    #[test]
    fn test_generate_edge_case_inputs_single_register() {
        let inputs = generate_edge_case_inputs(&[Register::X0]);
        assert!(!inputs.is_empty());
        for input in &inputs {
            assert_eq!(input.get_register(Register::X1).as_u64(), 0);
        }
    }

    // ---- x86 random-input helpers ----

    #[test]
    fn generate_random_inputs_x86_respects_count_and_width() {
        let config = RandomInputConfigX86 {
            count: 5,
            registers: vec![crate::isa::x86::X86Register::RAX],
            width: 32,
        };
        let inputs = generate_random_inputs_x86(&config);
        assert_eq!(inputs.len(), 5);
        for input in &inputs {
            assert_eq!(input.width(), 32);
            // Mode32 masks writes to low 32 bits.
            let v = input
                .get_register(crate::isa::x86::X86Register::RAX)
                .as_u64();
            assert!(v <= u32::MAX as u64, "value {} not masked to width", v);
        }
    }

    #[test]
    fn generate_edge_case_inputs_x86_includes_zero_and_all_ones() {
        let inputs = generate_edge_case_inputs_x86(&[crate::isa::x86::X86Register::RAX], 64);
        // Width-64: the edge_values set includes 0 and u64::MAX.
        let rax_vals: std::collections::HashSet<u64> = inputs
            .iter()
            .map(|s| s.get_register(crate::isa::x86::X86Register::RAX).as_u64())
            .collect();
        assert!(rax_vals.contains(&0));
        assert!(rax_vals.contains(&u64::MAX));
    }
}

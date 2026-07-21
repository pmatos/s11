//! Random input generation for fast validation

use crate::ir::Register;
use crate::ir::types::AccessWidth;
use crate::semantics::state::ConcreteMachineState;
use rand::RngExt;

/// Base address of the random-input memory seed region. See ADR-0007.
pub const MEMORY_SEED_BASE: u64 = 0x1000_0000;

/// Size of the random-input memory seed region in bytes. 4 KiB matches a
/// page; large enough to exercise meaningful overlap patterns yet small
/// enough that filling it stays cheap.
pub const MEMORY_SEED_SIZE: usize = 4096;

/// Configuration for random input generation
#[derive(Debug, Clone)]
pub struct RandomInputConfig {
    /// Number of random inputs to generate
    pub count: usize,
    /// Registers to randomize (others will be zero)
    pub registers: Vec<Register>,
    /// If non-zero, seed each generated state's memory with this many
    /// random bytes starting at `MEMORY_SEED_BASE`. Default 0 (no seed).
    /// Set to `MEMORY_SEED_SIZE` for memory-bearing windows so memory
    /// loads return non-trivial values during fast / counterexample
    /// random testing.
    pub memory_seed_size: usize,
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
            memory_seed_size: 0,
        }
    }
}

/// Generate random concrete machine states for testing
pub fn generate_random_inputs(config: &RandomInputConfig) -> Vec<ConcreteMachineState> {
    let mut rng = rand::rng();
    let mut inputs = Vec::with_capacity(config.count);

    for _ in 0..config.count {
        let mut state = ConcreteMachineState::new_zeroed();
        for reg in &config.registers {
            match reg {
                Register::Vector(vector) => state.set_vector(
                    *vector,
                    (u128::from(rng.random::<u64>()) << 64) | u128::from(rng.random::<u64>()),
                ),
                _ => state.set_register(
                    *reg,
                    crate::semantics::state::ConcreteValue::new(rng.random::<u64>()),
                ),
            }
        }
        if config.memory_seed_size > 0 {
            for i in 0..config.memory_seed_size {
                let byte = rng.random::<u8>();
                state.write_bytes(
                    MEMORY_SEED_BASE.wrapping_add(i as u64),
                    byte as u64,
                    AccessWidth::Byte,
                );
            }
        }
        inputs.push(state);
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
        let mut state = ConcreteMachineState::new_zeroed();
        for reg in registers {
            match reg {
                Register::Vector(vector) => {
                    state.set_vector(*vector, (u128::from(edge_val) << 64) | u128::from(edge_val));
                }
                _ => {
                    state.set_register(*reg, crate::semantics::state::ConcreteValue::new(edge_val))
                }
            }
        }
        inputs.push(state);
    }

    if registers.len() >= 2 {
        for &val1 in &edge_values[..5] {
            for &val2 in &edge_values[..5] {
                let mut state = ConcreteMachineState::new_zeroed();
                if let Some(reg) = registers.first() {
                    match reg {
                        Register::Vector(vector) => {
                            state.set_vector(*vector, (u128::from(val1) << 64) | u128::from(val1))
                        }
                        _ => state
                            .set_register(*reg, crate::semantics::state::ConcreteValue::new(val1)),
                    }
                }
                if let Some(reg) = registers.get(1) {
                    match reg {
                        Register::Vector(vector) => {
                            state.set_vector(*vector, (u128::from(val2) << 64) | u128::from(val2))
                        }
                        _ => state
                            .set_register(*reg, crate::semantics::state::ConcreteValue::new(val2)),
                    }
                }
                inputs.push(state);
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
            memory_seed_size: 0,
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
            memory_seed_size: 0,
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
    fn random_inputs_populate_full_vector_registers() {
        let inputs = generate_random_inputs(&RandomInputConfig {
            count: 8,
            registers: vec![Register::Vector(crate::ir::VectorRegister::V0)],
            memory_seed_size: 0,
        });
        assert!(
            inputs
                .iter()
                .any(|state| { state.get_vector(crate::ir::VectorRegister::V0) >> 64 != 0 })
        );
    }

    #[test]
    fn memory_seed_populates_region_when_size_nonzero() {
        let config = RandomInputConfig {
            count: 4,
            registers: vec![Register::X0],
            memory_seed_size: MEMORY_SEED_SIZE,
        };
        let inputs = generate_random_inputs(&config);
        // At least one input must have a non-empty memory map (the random
        // bytes might all be zero, but with 4 KiB of random bytes and four
        // independent draws the probability of every byte being zero is
        // 256^-(4*4096) — vastly below 2^-256, indistinguishable from zero).
        let any_populated = inputs.iter().any(|s| !s.memory().is_empty());
        assert!(any_populated, "memory seed produced no entries");
        // Every populated byte must lie inside [MEMORY_SEED_BASE,
        // MEMORY_SEED_BASE + MEMORY_SEED_SIZE).
        for s in &inputs {
            for &addr in s.memory().keys() {
                assert!(
                    (MEMORY_SEED_BASE..MEMORY_SEED_BASE + MEMORY_SEED_SIZE as u64).contains(&addr),
                    "address 0x{:x} outside seed region",
                    addr
                );
            }
        }
    }

    #[test]
    fn memory_seed_default_zero_leaves_memory_empty() {
        let config = RandomInputConfig {
            count: 4,
            registers: vec![Register::X0],
            memory_seed_size: 0,
        };
        let inputs = generate_random_inputs(&config);
        for s in &inputs {
            assert!(s.memory().is_empty(), "memory must stay empty without seed");
        }
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

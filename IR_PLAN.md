# AArch64 IR and Semantic Equivalence Plan

## Overview

This document outlines the plan for implementing an Intermediate Representation (IR) for AArch64 instructions and a semantic equivalence checker using SMT solving.

## Architecture Design

### 1. Module Structure

```
src/
├── main.rs          # Existing entry point
├── ir/
│   ├── mod.rs       # IR module exports
│   ├── types.rs     # Core IR types (registers, immediates, conditions)
│   ├── instructions.rs  # Instruction enum and display traits
│   └── state.rs     # Machine state representation
├── semantics/
│   ├── mod.rs       # Semantics module exports
│   ├── smt.rs       # SMT constraint generation
│   └── equivalence.rs   # Equivalence checking logic
└── tests/
    ├── ir_tests.rs      # IR construction tests
    ├── semantics_tests.rs   # Instruction semantics tests
    └── equivalence_tests.rs # Equivalence checking tests
```

### 2. IR Design

#### Core Types
```rust
// Registers
pub enum Register {
    X0, X1, ..., X30,  // General purpose
    XZR,               // Zero register
    SP,                // Stack pointer
}

// Operands
pub enum Operand {
    Register(Register),
    Immediate(i64),
}

// Condition codes
pub enum Condition {
    EQ, NE, CS, CC, MI, PL, VS, VC,
    HI, LS, GE, LT, GT, LE, AL, NV,
}
```

#### Instructions (Phase 1 - Basic Set)
```rust
pub enum Instruction {
    // Data movement
    MovReg { rd: Register, rn: Register },
    MovImm { rd: Register, imm: i64 },
    
    // Arithmetic
    Add { rd: Register, rn: Register, rm: Operand },
    Sub { rd: Register, rn: Register, rm: Operand },
    
    // Logical
    And { rd: Register, rn: Register, rm: Operand },
    Orr { rd: Register, rn: Register, rm: Operand },
    Eor { rd: Register, rn: Register, rm: Operand },
    
    // Shifts
    Lsl { rd: Register, rn: Register, shift: Operand },
    Lsr { rd: Register, rn: Register, shift: Operand },
    Asr { rd: Register, rn: Register, shift: Operand },
}
```

### 3. SMT Integration

#### SMT Solver Choice
- **Primary**: z3 (via z3 crate) - mature, well-documented, good Rust bindings
- **Alternative**: smt2 crate for generic SMT-LIB2 output

#### State Representation
```rust
pub struct MachineState {
    registers: HashMap<Register, BitVec>,  // 64-bit bitvectors
    flags: Flags,  // N, Z, C, V (optional for phase 1)
}
```

#### Constraint Generation
Each instruction will generate SMT constraints:
```rust
// Example for MOV X0, #0
// post.x0 = 0

// Example for EOR X0, X0, X0  
// post.x0 = pre.x0 XOR pre.x0 = 0
```

### 4. Equivalence Checking Algorithm

```rust
fn check_equivalence(seq1: &[Instruction], seq2: &[Instruction]) -> bool {
    let solver = z3::Solver::new(&ctx);
    
    // Create symbolic initial state
    let pre_state = create_symbolic_state();
    
    // Apply seq1 constraints
    let post_state1 = apply_sequence(pre_state.clone(), seq1);
    
    // Apply seq2 constraints  
    let post_state2 = apply_sequence(pre_state, seq2);
    
    // Assert states are NOT equal
    solver.assert(&states_not_equal(post_state1, post_state2));
    
    // If UNSAT, states are always equal
    match solver.check() {
        SatResult::Unsat => true,   // Equivalent
        SatResult::Sat => false,     // Not equivalent
        SatResult::Unknown => false, // Timeout/unknown
    }
}
```

## Implementation Plan

### Phase 1: Basic IR and Simple Equivalences (Week 1)
1. Set up module structure
2. Implement basic IR types (registers, immediates)
3. Implement core instructions (MOV, ADD, EOR)
4. Integrate z3 crate
5. Implement simple equivalence checker
6. Test cases: `MOV X0, #0` ≡ `EOR X0, X0, X0`

### Phase 2: Extended Instruction Set (Week 2)
1. Add arithmetic instructions (SUB, MUL)
2. Add logical instructions (AND, ORR)
3. Add shift instructions (LSL, LSR, ASR)
4. Extend SMT constraint generation
5. More complex equivalence tests

### Phase 3: Advanced Features (Week 3)
1. Add condition flags modeling (optional)
2. Add conditional instructions
3. Performance optimizations
4. Integration with existing disassembler

## Testing Strategy

### Unit Tests
1. **IR Construction**: Test that IR correctly represents instructions
2. **SMT Translation**: Verify SMT constraints match instruction semantics
3. **Known Equivalences**: Test well-known equivalent sequences
4. **Non-Equivalences**: Verify non-equivalent sequences are detected

### Example Test Cases
```rust
#[test]
fn test_mov_zero_equivalence() {
    // MOV X0, #0 ≡ EOR X0, X0, X0
    let seq1 = vec![Instruction::MovImm { rd: X0, imm: 0 }];
    let seq2 = vec![Instruction::Eor { rd: X0, rn: X0, rm: Register(X0) }];
    assert!(check_equivalence(&seq1, &seq2));
}

#[test]
fn test_add_commutativity() {
    // ADD X0, X1, X2 ≡ ADD X0, X2, X1
    let seq1 = vec![Instruction::Add { rd: X0, rn: X1, rm: Register(X2) }];
    let seq2 = vec![Instruction::Add { rd: X0, rn: X2, rm: Register(X1) }];
    assert!(check_equivalence(&seq1, &seq2));
}

#[test]
fn test_non_equivalence() {
    // MOV X0, #1 ≢ MOV X0, #2
    let seq1 = vec![Instruction::MovImm { rd: X0, imm: 1 }];
    let seq2 = vec![Instruction::MovImm { rd: X0, imm: 2 }];
    assert!(!check_equivalence(&seq1, &seq2));
}
```

## CI Integration

### GitHub Actions Updates
1. Install z3 solver:
   ```yaml
   - name: Install Z3
     run: |
       sudo apt-get update
       sudo apt-get install -y z3 libz3-dev
   ```

2. Run unit tests:
   ```yaml
   - name: Run unit tests
     run: cargo test --verbose --all-features
   ```

## Dependencies to Add

```toml
[dependencies]
z3 = "0.12"  # or latest version

[dev-dependencies]
proptest = "1.0"  # For property-based testing
```

## Success Criteria

1. IR can represent basic AArch64 instructions
2. SMT solver correctly identifies equivalent sequences
3. Unit tests pass for known equivalences
4. CI runs all tests successfully on ARM64
5. Performance is reasonable (< 1s for small sequences)

## Future Extensions

1. Support for memory operations (LDR, STR)
2. SIMD instructions
3. Condition flags and conditional execution
4. Multi-instruction pattern matching
5. Cost models for optimization decisions
# S10 → S11 Port Status

This document tracks the porting progress from s10 (Racket superoptimizer) to s11 (Rust port).

## Overview

| Aspect | S10 (Racket) | S11 (Rust) | Status |
|--------|--------------|------------|--------|
| Primary ISA | RISC-V 32-bit | AArch64 64-bit | ✅ Changed by design |
| Code Size | ~6,946 LOC | ~2,318 LOC | MVP |
| Search Algorithms | Symbolic + Stochastic + Hybrid | Enumerative + Stochastic + Symbolic | ✅ Implemented |
| Parallelism | Multi-core (loci framework) | Multi-threaded (rayon/crossbeam) | ✅ Implemented |
| SMT Solver | Rosette/Z3 | Z3 direct | ✅ Implemented |
| Binary Input | Assembly text files | ELF binaries | ✅ Enhanced |

---

## Detailed Component Comparison

### 1. Search Algorithms

#### 1.1 Symbolic Search (IMPLEMENTED)

S10's `symbolic.rkt` implements SMT-based synthesis:

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Window decomposition | ✅ L, 2L, 3L, 4L windows | ❌ | Medium |
| Cost bounding | ✅ SMT constraints | ✅ sequence_cost() | ✅ |
| Linear cost search | ✅ Incrementally increase bounds | ✅ --search-mode linear | ✅ |
| Binary cost search | ✅ Binary search on cost space | ✅ --search-mode binary | ✅ |
| Mixed synthesis | ✅ Guess opcodes, solve operands | Partial (enumerate+verify) | Medium |
| Early termination | ✅ UNSAT proves optimality | ✅ | ✅ |
| Len-limit tuning | ✅ 3 instructions/minute | ❌ | Low |

**Implementation**: `src/search/symbolic/` (~400 LOC)

#### 1.2 Stochastic Search (IMPLEMENTED)

S10's `stochastic.rkt` implements Metropolis-Hastings:

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Simulated annealing | ✅ Temperature-based acceptance | ✅ --beta (inverse temp) | ✅ |
| Mutation operators | ✅ opcode/operand/swap/instruction | ✅ All 4 operators | ✅ |
| Mutation distribution | ✅ Configurable (16/50/16/16%) | ✅ (50/16/16/18%) | ✅ |
| Synthesis mode | ✅ Start from random | ✅ | ✅ |
| Optimization mode | ✅ Start from original | ✅ | ✅ |
| Tracker mode | ✅ Restart from symbolic best | ❌ (needs hybrid) | Medium |
| Test-based filtering | ✅ 16 random inputs | ✅ Fast validation | ✅ |

**Implementation**: `src/search/stochastic/` (~500 LOC)

#### 1.3 Hybrid Search (IMPLEMENTED)

S10's `driver.rkt` coordinates multi-algorithm search:

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Algorithm selection | ✅ --symbolic/--stochastic/--hybrid | ✅ --algorithm hybrid | ✅ |
| Core distribution | ✅ 1 symbolic + (N-1) stochastic | ✅ --cores/-j | ✅ |
| Best program broadcast | ✅ Cross-worker propagation | ✅ SharedBest + channels | ✅ |
| Solution merging | ✅ Master aggregation | ✅ Coordinator | ✅ |

**Implementation**: `src/search/parallel/` (~400 LOC)

#### 1.4 Enumerative Search (PARTIAL)

| Feature | S10 | S11 | Status |
|---------|-----|-----|--------|
| Length-1 search | N/A | ✅ | Implemented |
| Length-N search | N/A | ❌ | Missing |
| Register set expansion | N/A | ❌ | Only X0-X2 |
| Immediate range | N/A | ❌ | Only 0, 1 |

---

### 2. Parallelism & Job Management (IMPLEMENTED)

S10 uses the `loci` framework for distributed computation:

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Locus spawning | ✅ jobs.rkt | ✅ std::thread + rayon | ✅ |
| Message passing | ✅ messaging.rkt | ✅ crossbeam-channel | ✅ |
| Worker coordination | ✅ Master/worker protocol | ✅ Coordinator pattern | ✅ |
| Core allocation | ✅ -j/--cores option | ✅ --cores/-j | ✅ |
| Dynamic locus creation | ✅ Runtime spawning | ❌ (not needed) | Low |

**Implementation**: `src/search/parallel/` using rayon, crossbeam-channel, num_cpus

---

### 3. IR (Intermediate Representation)

#### 3.1 Core Types (IMPLEMENTED)

| Feature | S10 | S11 | Status |
|---------|-----|-----|--------|
| Register enum | ✅ x0-x31 (RISC-V) | ✅ X0-X30, XZR, SP (AArch64) | ✅ |
| Operand abstraction | ✅ Register/Immediate | ✅ | ✅ |
| Condition codes | ✅ | ✅ (defined, not used) | Partial |
| Instruction struct | ✅ rv-insn | ✅ Instruction enum | ✅ |

#### 3.2 Instruction Coverage

**AArch64 Instructions Implemented in S11**:
- ✅ MOV (register, immediate)
- ✅ ADD/SUB (register, immediate)
- ✅ AND/ORR/EOR (register, immediate)
- ✅ LSL/LSR/ASR (register, immediate)

**AArch64 Instructions Missing** (for parity with RISC-V capabilities):
- ❌ MUL/SDIV/UDIV (multiplication, division)
- ❌ MADD/MSUB (multiply-add/subtract)
- ❌ CMP/CMN/TST (comparison)
- ❌ CSEL/CSINC/CSINV/CSNEG (conditional select)
- ❌ B/BL/BR/BLR/RET (branches)
- ❌ LDR/STR variants (memory operations)
- ❌ SXTB/SXTH/SXTW/UXTB/UXTH (sign/zero extend)
- ❌ REV/REV16/REV32 (byte reversal)
- ❌ CLZ/CLS (count leading zeros/sign bits)
- ❌ RBIT (reverse bits)

#### 3.3 Program Abstraction (PARTIAL)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Instruction sequences | ✅ | ✅ Vec<Instruction> | ✅ |
| Register compression | ✅ Map unused to minimal set | ❌ | Medium |
| Register decompression | ✅ Restore original names | ❌ | Medium |
| Live-out metadata | ✅ Observable outputs | ✅ LiveOutMask | ✅ |
| Live-in computation | ✅ Backward propagation | ❌ | High |

**Files to port**: `s10/program.rkt`, `riscv-program.rkt` (~200 LOC)

---

### 4. Machine Model

#### 4.1 Machine Configuration (MISSING)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Bitwidth config | ✅ 32-bit configurable | ❌ 64-bit hardcoded | Medium |
| Byte ordering | ✅ Little/big endian | ❌ Assumed little | Low |
| Register count | ✅ Configurable (default 4) | ❌ Fixed 32 | Low |
| Memory size | ✅ 1MB configurable | N/A | Low |
| Address width | ✅ Configurable | N/A | Low |

**Files to port**: `s10/machine.rkt`, `riscv-machine-config.rkt` (~150 LOC)

#### 4.2 Program State (PARTIAL)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Register bank | ✅ | ✅ MachineState HashMap | ✅ |
| Memory model | ✅ Concrete + symbolic | ❌ | High |
| Random input generation | ✅ For validation | ✅ validation/random.rs | ✅ |

**Files to port**: `s10/progstate.rkt`, `s10/registerbank.rkt`, `s10/memory-*.rkt` (~400 LOC)

---

### 5. Simulation

#### 5.1 Concrete Interpreter (IMPLEMENTED)

S10 has `simulator-racket.rkt` for actual execution:

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Concrete execution | ✅ Run with real values | ✅ concrete.rs | ✅ |
| Step-by-step execution | ✅ | ✅ apply_instruction_concrete() | ✅ |
| Memory read/write | ✅ | ❌ | Medium |
| State inspection | ✅ | ✅ ConcreteMachineState | ✅ |

**Files to port**: `s10/simulator-racket.rkt`, `riscv-simulator-racket.rkt` (~300 LOC)

#### 5.2 Symbolic Interpreter (IMPLEMENTED)

| Feature | S10 | S11 | Status |
|---------|-----|-----|--------|
| Symbolic state | ✅ Rosette bitvectors | ✅ Z3 bitvectors | ✅ |
| Instruction execution | ✅ | ✅ apply_instruction() | ✅ |
| Sequence execution | ✅ | ✅ apply_sequence() | ✅ |
| Constraint collection | ✅ | ✅ | ✅ |

---

### 6. Validation & Equivalence Checking

#### 6.1 SMT-based Validation (IMPLEMENTED)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Basic equivalence check | ✅ | ✅ are_sequences_equivalent() | ✅ |
| Fast validation (random) | ✅ generate-input-states-fast | ✅ check_equivalence_with_config() | ✅ |
| Slow validation (thorough) | ✅ generate-input-states-slow | ❌ | Medium |
| Counterexample extraction | ✅ | ✅ NotEquivalentFast variant | ✅ |
| Live-out aware checking | ✅ Only check observable outputs | ✅ LiveOutMask | ✅ |

**Files to port**: `s10/validator.rkt`, `riscv-validator.rkt` (~350 LOC)

#### 6.2 Cost Model (IMPLEMENTED)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Instruction costs | ✅ Per-opcode costs | ✅ cost.rs instruction_cost() | ✅ |
| Sequence cost | ✅ Sum of instruction costs | ✅ sequence_cost() | ✅ |
| Unused register penalty | ✅ 0.16 weight | ❌ | Low |
| Cost-bounded synthesis | ✅ SMT constraint | ❌ | High |

**Files to port**: `riscv-simulator-rosette-cost.rkt` (~100 LOC)

---

### 7. Input/Output

#### 7.1 Input Parsing

| Feature | S10 | S11 | Status |
|---------|-----|-----|--------|
| Assembly text parsing | ✅ Lexer/parser | ❌ | Different approach |
| ELF binary reading | ❌ | ✅ | ✅ Enhanced |
| Live-out extraction | ✅ From .info files | ❌ | Missing |
| Disassembly | ❌ | ✅ Capstone | ✅ Enhanced |

#### 7.2 Output Generation

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Assembly text output | ✅ Pretty print | ❌ | Medium |
| Binary patching | ❌ | ✅ | ✅ Enhanced |
| Solution reporting | ✅ Optimized program | Partial | Medium |

---

### 8. CLI & Configuration

#### 8.1 Command-Line Options (PARTIAL)

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| Binary input | ❌ | ✅ --binary | ✅ |
| Disassembly | ❌ | ✅ disasm subcommand | ✅ |
| Address window | ❌ | ✅ --start-addr/--end-addr | ✅ |
| Algorithm selection | ✅ --symbolic/--stochastic/--hybrid | ✅ --algorithm | ✅ |
| Core count | ✅ -j/--cores | ✅ --cores/-j | ✅ |
| Timeout | ✅ -t/--timeout | ✅ --timeout | ✅ |
| Verbose mode | ✅ --verbose | ✅ --verbose | ✅ |
| Statistics output | ✅ --statistics | Partial (printed) | Low |
| Profiling | ✅ --profile | ❌ | Low |

---

### 9. Testing Infrastructure

| Feature | S10 | S11 | Status |
|---------|-----|-----|--------|
| Unit tests | ✅ rackunit inline | ✅ #[test] | ✅ |
| Integration tests | ✅ all-tests.rkt | ✅ tests/ dir | ✅ |
| Benchmark programs | ✅ Hacker's Delight (25) | ❌ | Missing |
| Test binaries | ❌ | ✅ binaries/ dir | ✅ |
| CI script | ✅ Makefile | ✅ ci_check.sh | ✅ |

---

### 10. Documentation

| Feature | S10 | S11 | Priority |
|---------|-----|-----|----------|
| User guide | ✅ s10-guide.scrbl | ❌ | Medium |
| Tool reference | ✅ s10-tool.scrbl | ❌ | Medium |
| Design concepts | ✅ s10-ideas.scrbl | ❌ | Low |
| API docs | ✅ Scribble | ❌ | Low |
| CLAUDE.md | ❌ | ✅ | ✅ |
| README | ❌ | ❌ | Medium |

---

## ISA Abstraction Requirements

For s11 to become ISA-agnostic and support both AArch64 (primary) and RISC-V (secondary):

### Required Abstractions

```rust
// Proposed trait-based abstraction
pub trait ISA {
    type Register: Clone + Eq + Hash;
    type Instruction: Clone;

    fn registers() -> &'static [Self::Register];
    fn zero_register() -> Option<Self::Register>;
    fn register_bitwidth() -> u32;

    fn instruction_cost(insn: &Self::Instruction) -> u32;
    fn encode(insn: &Self::Instruction) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Option<Self::Instruction>;

    fn to_smt_constraints(
        insn: &Self::Instruction,
        state: &mut MachineState<Self::Register>
    );
}
```

### Module Reorganization

| Current | Proposed |
|---------|----------|
| `ir/types.rs` | `arch/mod.rs` (trait definitions) |
| `ir/instructions.rs` | `arch/aarch64/instructions.rs` |
| `semantics/smt.rs` | `arch/aarch64/smt.rs` |
| `assembler/mod.rs` | `arch/aarch64/assembler.rs` |
| - | `arch/riscv/` (new backend) |

---

## Priority Implementation Order

### Phase 1: Core Infrastructure (High Priority) ✅ COMPLETE
1. [x] Concrete interpreter for fast validation
2. [x] Live-out metadata support
3. [x] Random input generation for testing
4. [x] Cost model for instructions
5. [x] Timeout mechanism

### Phase 2: Search Algorithms (High Priority) ✅ COMPLETE
1. [x] Stochastic search with mutation operators (MCMC with Metropolis-Hastings)
2. [x] Symbolic search with SMT-based synthesis (linear cost search)
3. [x] CLI options for algorithm selection (--algorithm, --beta, --iterations, etc.)

### Phase 3: Parallelism (Medium Priority) ✅ COMPLETE
1. [x] Multi-threaded execution framework (rayon + crossbeam-channel)
2. [x] Worker coordination (Coordinator pattern with SharedBest)
3. [x] Core allocation CLI (--cores/-j, --no-symbolic)

### Phase 4: ISA Abstraction (Medium Priority)
1. [x] Trait-based ISA abstraction
2. [ ] RISC-V backend implementation
3. [ ] Backend selection CLI

### Phase 5: Extended Instructions (Medium Priority)
1. [ ] Multiplication/division
2. [ ] Conditional operations
3. [ ] Memory operations (if needed)

### Phase 6: Polish (Low Priority)
1. [ ] Documentation
2. [ ] Benchmark suite
3. [ ] Statistics/profiling
4. [ ] Verbose mode

---

## Summary Statistics

| Category | S10 Features | S11 Implemented | S11 Missing |
|----------|--------------|-----------------|-------------|
| Search Algorithms | 3 | 4 (enumerative, stochastic, symbolic, hybrid) | - |
| Parallelism | Full | Full (rayon + crossbeam) | - |
| IR/Instructions | ~20 opcodes | 10 opcodes | ~10 |
| Validation | 3 modes | 2 modes (fast+SMT) | 1 mode |
| CLI Options | ~15 | ~14 | ~1 |
| Documentation | 5 guides | 1 file | 4 guides |

**Overall Port Progress**: ~75% (Phase 1-3 complete, ISA abstraction and extended instructions remaining)

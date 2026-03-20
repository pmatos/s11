# s11 Project Status & Next Steps

## Current Project Status

### What's Working
- **Concrete interpreter**: All 20 AArch64 instructions fully implemented with correct semantics
- **Equivalence checking**: Two-phase verification (16 random tests + Z3 SMT proof)
- **Stochastic search (MCMC)**: Metropolis-Hastings with 4 mutation operators (operand, opcode, swap, instruction)
- **Cost model**: Three metrics (instruction count, latency, code size)
- **AArch64 ISA backend**: Complete for all 20 instructions at IR level
- **Parallel search coordinator**: Multi-threaded with worker communication via crossbeam channels
- **CLI**: `disasm`, `opt`, and `equiv` commands functional
- **CI/CD**: GitHub Actions with formatting, build, test, Clippy, CodeQL
- **Test infrastructure**: ~180 unit tests, integration tests, 15 cross-compiled AArch64 ELF binaries

### Critical Gaps (Blocking Real-World Use)

| Gap | Impact | Effort |
|-----|--------|--------|
| **Capstone-to-IR conversion** — only MOV and ADD of 20 opcodes | `s11 opt` skips 18/20 instruction types on real binaries | Medium |
| **SMT flag modeling** — CMP/CMN/TST are no-ops, CSEL always returns `rn` | Cannot reason about conditional code in SMT | Very High |
| **Assembler encoding** — CSEL/CSINC/CSINV/CSNEG and logical immediates missing | Cannot emit optimized sequences using these instructions | High |
| **Random instruction generation** — only 10/20 opcodes | Stochastic search can't explore half the instruction space | Low |
| **Enumerative search** — length-1 only, 3 registers | Not a real enumerative search | Medium |

### Secondary Gaps
- **RISC-V backend**: Skeleton only (~30% — just register definitions)
- **No memory operations**: LDR/STR/LDP/STP not supported
- **No branches/control flow**: Limited to straight-line code
- **Symbolic search**: Hybrid enumeration, not true symbolic synthesis

---

## Recommended Next Steps (Priority Order)

### 1. Complete Capstone-to-IR Conversion (Phase 1 in PLAN.md)
- Highest impact, unblocks real binary optimization
- Already has a detailed plan in PLAN.md with parse function patterns
- Extend `convert_to_ir()` in `src/main.rs` to handle all 18 missing mnemonics

### 2. Expand Random Instruction Generation
- Low effort, improves stochastic search effectiveness
- Add MUL, SDIV, UDIV, CMP, CMN, TST, CSEL variants to `src/search/candidate.rs`

### 3. Complete Assembler Encoding
- CSEL family needs raw AArch64 encoding (dynasm workaround for condition code operands)
- Logical immediates need bitmask encoder
- Blocking for outputting optimized binaries with these instructions

### 4. SMT Flag Modeling
- Most complex remaining task
- Requires full NZCV modeling in Z3 bitvectors
- Enables formal verification of conditional sequences

### 5. Benchmarking Infrastructure (see below)

---

## Superoptimization Benchmarks

### A. Classic Superoptimizer Benchmarks (Applicable Now)

**1. Hacker's Delight Sequences**
- Source: Henry Warren's "Hacker's Delight" book
- Classic bit-manipulation idioms perfect for register-only superoptimization
- Examples: abs(x), max(x,y), min(x,y), population count, next power of 2, sign extension
- Many are 2-5 instruction sequences — ideal for s11's current capability
- Used by STOKE, Optgen, and most superoptimizer papers

**2. STOKE Benchmark Suite**
- Stanford's stochastic superoptimizer (x86, but patterns transfer to AArch64)
- Includes ~60+ benchmark programs from Hacker's Delight
- Straight-line code, register-only — matches s11's constraints
- Paper: "Stochastic Superoptimization" (Schkufza et al., ASPLOS 2013)

**3. Souper Benchmarks**
- LLVM IR-level superoptimizer from Google
- Harvests optimization candidates from real LLVM IR
- Could extract AArch64-relevant patterns from LLVM's test suite

**4. GNU Superoptimizer (GSO) Test Cases**
- Original superoptimizer by Torbjörn Granlund (1992)
- Focus: synthesizing optimal sequences for GCC's machine-dependent code
- Small arithmetic/logical sequences that map directly to s11's instruction set

### B. Real-World AArch64 Benchmarks

**5. SPEC CPU 2017 (AArch64)**
- Industry-standard CPU benchmarks
- Cross-compile for AArch64, extract hot basic blocks
- Provides realistic instruction mixes for peephole optimization

**6. LLVM Test Suite**
- `llvm-project/llvm/test/CodeGen/AArch64/` — thousands of AArch64 codegen tests
- Many are small straight-line sequences with known optimal forms
- Free, well-maintained, directly relevant

**7. Embench**
- Embedded benchmark suite (embench.org)
- Small programs that compile to compact AArch64 code
- Good for measuring real optimization impact

### C. Micro-Benchmarks to Build for s11

**8. Algebraic Identity Suite**
- Commutative rewrites: `add x0, x1, x2` → `add x0, x2, x1`
- Identity elimination: `add x0, x1, #0` → `mov x0, x1`
- Strength reduction: `mul x0, x1, #2` → `lsl x0, x1, #1`
- Zero idioms: `mov x0, #0` → `eor x0, x0, x0`
- Constant folding: `mov x0, #3; add x0, x0, #5` → `mov x0, #8`

**9. Instruction Fusion Patterns**
- MOV+binop fusion: `mov x0, x1; add x0, x0, #1` → `add x0, x1, #1`
- Redundant MOV elimination
- Dead code removal

**10. AArch64-Specific Patterns**
- Conditional select optimizations (once CSEL is fully supported)
- Shifted operand folding (future: `add x0, x1, x2, lsl #3`)
- Address computation optimization

### D. Metrics to Track

For any benchmark suite, measure:
- **Search time**: Wall-clock time to find optimal sequence
- **Speedup**: Latency reduction (using cost model)
- **Code size reduction**: Instruction count delta
- **Verification time**: SMT solver time for equivalence proof
- **Success rate**: % of benchmarks where a shorter/faster sequence is found

---

## Summary

The project has solid architecture but is bottlenecked by the Capstone-to-IR conversion gap — fixing that single issue would make `s11 opt` functional on real binaries. For benchmarking, start with **Hacker's Delight sequences** (they're small, register-only, and the gold standard for superoptimizer evaluation), then expand to **LLVM AArch64 codegen tests** for real-world coverage.

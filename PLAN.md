# s11 Development Plan

This plan outlines the phased development of s11, the AArch64 superoptimizer. Each phase builds on prior phases, addressing the most impactful gaps first to transform s11 from a prototype into a practically useful tool.

---

## Current State Summary

s11 has a clean architecture with four search algorithms, two-phase equivalence checking (random testing + SMT), ~180 unit tests, and support for 20 AArch64 opcodes in the IR. However, several critical gaps limit practical use:

- **Capstone-to-IR conversion** (`main.rs:convert_to_ir`) only handles `mov` and `add` of 20 supported opcodes
- **SMT flag modeling** (`smt.rs`) is stubbed — CMP/CMN/TST are no-ops, CSEL variants always return `rn`
- **Assembler encoding** (`assembler/mod.rs`) is missing for AND/ORR/EOR/TST immediates and CSEL/CSINC/CSINV/CSNEG
- **Random instruction generation** (`candidate.rs:generate_random_instruction`) only covers 10 of 20 opcodes
- **Enumerative search** in `main.rs` only handles length-1 sequences with 3 registers

---

## Phase 1: Complete Capstone-to-IR Conversion

**Goal:** Make `s11 opt` work on real-world AArch64 binaries containing all 20 supported instructions.

**Dependencies:** None (standalone)

### What to implement

Extend `convert_to_ir()` in `src/main.rs` (currently lines 595-627) to handle all 18 missing mnemonics from Capstone disassembly output:

| Mnemonic | IR Instruction | Operand pattern |
|----------|---------------|-----------------|
| `sub`    | `Sub`         | `rd, rn, rm/imm` |
| `and`    | `And`         | `rd, rn, rm/imm` |
| `orr`    | `Orr`         | `rd, rn, rm/imm` |
| `eor`    | `Eor`         | `rd, rn, rm/imm` |
| `lsl`    | `Lsl`         | `rd, rn, rm/imm` |
| `lsr`    | `Lsr`         | `rd, rn, rm/imm` |
| `asr`    | `Asr`         | `rd, rn, rm/imm` |
| `mul`    | `Mul`         | `rd, rn, rm` |
| `sdiv`   | `Sdiv`        | `rd, rn, rm` |
| `udiv`   | `Udiv`        | `rd, rn, rm` |
| `cmp`    | `Cmp`         | `rn, rm/imm` |
| `cmn`    | `Cmn`         | `rn, rm/imm` |
| `tst`    | `Tst`         | `rn, rm/imm` |
| `csel`   | `Csel`        | `rd, rn, rm, cond` |
| `csinc`  | `Csinc`       | `rd, rn, rm, cond` |
| `csinv`  | `Csinv`       | `rd, rn, rm, cond` |
| `csneg`  | `Csneg`       | `rd, rn, rm, cond` |

For each, write a `parse_<mnemonic>_instruction()` function following the pattern of the existing `parse_mov_instruction()` and `parse_add_instruction()` (lines 629-688). The general pattern for each:

1. Split `op_str` by commas
2. Parse destination register (or first operand for CMP/CMN/TST)
3. Parse source registers and/or immediate operands
4. For CSEL/CSINC/CSINV/CSNEG: parse the condition code string (eq/ne/cs/cc/etc.) into `Condition` enum
5. Construct the appropriate `Instruction` variant

**Specific implementation details:**
- The existing `parse_register()` function (line 690) already handles all X registers, XZR, and SP — reuse it
- Need a new `parse_condition()` function to map strings like "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al" to `Condition` variants
- For instructions with 3 operands (SUB, AND, ORR, EOR, LSL, LSR, ASR): follow the `parse_add_instruction` pattern — check if third operand starts with `#` for immediate, otherwise parse as register
- For MUL/SDIV/UDIV: all three operands are always registers (no immediate form)
- For CMP/CMN/TST: only 2 operands (no destination register), second can be register or immediate
- For CSEL/CSINC/CSINV/CSNEG: 4 operands — 3 registers + 1 condition code

### User-visible changes

- `s11 opt --binary <file> --start-addr <hex> --end-addr <hex>` will now convert all 20 instruction types from disassembled binaries instead of printing "Warning: Skipping unsupported instruction" for everything except MOV and ADD
- Users can optimize code regions containing SUB, AND, shifts, multiply, divide, comparisons, and conditional selects

### Testing and verification

1. **Unit tests for each new parse function:**
   - `test_parse_sub_reg`: `"x0, x1, x2"` → `Sub { rd: X0, rn: X1, rm: Register(X2) }`
   - `test_parse_sub_imm`: `"x0, x1, #5"` → `Sub { rd: X0, rn: X1, rm: Immediate(5) }`
   - Same pattern for AND, ORR, EOR, LSL, LSR, ASR
   - `test_parse_mul`: `"x0, x1, x2"` → `Mul { rd: X0, rn: X1, rm: X2 }`
   - `test_parse_sdiv`/`test_parse_udiv`: similar
   - `test_parse_cmp_reg`: `"x0, x1"` → `Cmp { rn: X0, rm: Register(X1) }`
   - `test_parse_cmp_imm`: `"x0, #10"` → `Cmp { rn: X0, rm: Immediate(10) }`
   - Same for CMN, TST
   - `test_parse_csel`: `"x0, x1, x2, eq"` → `Csel { rd: X0, rn: X1, rm: X2, cond: EQ }`
   - Same for CSINC, CSINV, CSNEG with different condition codes
   - `test_parse_condition`: Test all 16 condition code strings

2. **Integration round-trip test:**
   - Create test assembly files containing each instruction type
   - Assemble them with `aarch64-linux-gnu-as` into ELF objects
   - Run `s11 opt` on the resulting binary
   - Verify the instructions are correctly parsed into IR (check output for instruction count and display strings)

3. **Negative tests:**
   - Invalid register names
   - Missing operands
   - Invalid condition codes
   - Hex immediates (`#0xff`)

4. **Verify command:**
   ```bash
   # Build a test binary with diverse instructions
   # Run: s11 opt --binary test_diverse --start-addr 0x... --end-addr 0x... --verbose
   # Expected: all instructions converted without "Warning: Skipping" messages
   ```

---

## Phase 2: Complete Assembler Encoding

**Goal:** Enable end-to-end binary patching by encoding all instruction forms that the optimizer can produce.

**Dependencies:** None (standalone, but most useful after Phase 1)

### What to implement

#### 2a: CSEL/CSINC/CSINV/CSNEG encoding

The `condition_to_dynasm()` function already exists in `assembler/mod.rs` (line 379) but is unused. The CSEL family instructions need raw encoding since dynasm may not directly support condition code operands.

AArch64 encoding for CSEL: `[sf=1][op=0][S=0][11010100][Rm][cond][0][0][Rn][Rd]`
- sf = 1 (64-bit)
- Bits 31:21 = `1_00_11010100`
- Bits 20:16 = Rm
- Bits 15:12 = cond (4-bit condition code)
- Bit 11 = 0
- Bit 10 = 0 (CSEL), 1 (CSINC)
- Bits 9:5 = Rn
- Bits 4:0 = Rd

For CSINV/CSNEG, bit 30 (op) = 1:
- Bits 31:21 = `1_10_11010100`
- Bit 10 = 0 (CSINV), 1 (CSNEG)

Implementation: Use `dynasm!(ops ; .arch aarch64 ; .bytes ...)` to emit raw 4-byte encodings, or use `DynasmApi::push_u32()` to write the encoded instruction directly.

#### 2b: AND/ORR/EOR/TST immediate encoding (bitmask immediates)

AArch64 logical immediates use a complex encoding scheme with `N`, `immr`, `imms` fields that represent repeating bit patterns. Implementing a full encoder requires:

1. Write `encode_bitmask_immediate(value: u64) -> Option<(u8, u8, u8)>` returning `(N, immr, imms)`:
   - Check if value is a valid bitmask immediate (repeating pattern of 2, 4, 8, 16, 32, or 64 bits)
   - Determine element size and rotation
   - Encode as N/immr/imms triple
   - Return `None` for values that aren't valid bitmask immediates

2. Instruction encoding layout for AND immediate:
   - `[sf=1][opc=00][100100][N][immr][imms][Rn][Rd]`
   - ORR: opc=01, EOR: opc=10
   - TST is ANDS with Rd=XZR (register 31): `[sf=1][opc=11][100100][N][immr][imms][Rn][11111]`

3. Fallback: If the immediate is not a valid bitmask, the assembler should return `Err` (matching current behavior but with a more descriptive message).

### User-visible changes

- `s11 opt` can now produce patched binaries containing CSEL, CSINC, CSINV, CSNEG instructions
- `s11 opt` can produce patched binaries containing AND/ORR/EOR with common bitmask immediate patterns (e.g., `AND X0, X1, #0xFF` for masking)
- Previously, finding an optimization using these forms would fail at the assembly stage with "encoding not yet supported"

### Testing and verification

1. **CSEL family encoding tests:**
   - Encode `CSEL X0, X1, X2, EQ` → 4 bytes → disassemble with Capstone → verify mnemonic, operands, condition
   - Test all 16 condition codes with CSEL
   - Encode CSINC, CSINV, CSNEG with various registers and conditions
   - Verify round-trip: encode → Capstone disassemble → re-parse → same instruction

2. **Bitmask immediate tests:**
   - `encode_bitmask_immediate(0xFF)` → valid
   - `encode_bitmask_immediate(0xFFFF)` → valid
   - `encode_bitmask_immediate(0x5555555555555555)` → valid (alternating bits)
   - `encode_bitmask_immediate(0x3)` → invalid for 64-bit (not a repeating pattern... actually this might be valid)
   - `encode_bitmask_immediate(0)` → invalid (all-zeros not allowed)
   - `encode_bitmask_immediate(0xFFFFFFFFFFFFFFFF)` → invalid (all-ones not allowed)
   - AND/ORR/EOR/TST immediate encoding → Capstone round-trip verification

3. **End-to-end binary patching test:**
   ```bash
   # Create a binary with: MOV X0, X1; AND X0, X0, X2
   # Run s11 opt, verify patched binary is valid AArch64
   # Disassemble patched binary, verify instructions are correct
   ```

---

## Phase 3: Complete Random Instruction Generation

**Goal:** Enable the stochastic and symbolic search algorithms to explore the full instruction space.

**Dependencies:** None (standalone, but most impactful after Phases 1-2)

### What to implement

Extend `generate_random_instruction()` in `src/search/candidate.rs` (lines 103-181) to cover all 20 opcodes. Currently it generates 10 (MovImm, MovReg, Add, Sub, And, Orr, Eor, Lsl, Lsr, Asr). Add cases for:

1. **MUL** (case 10): Pick `rd`, `rn`, `rm` from registers
2. **SDIV** (case 11): Pick `rd`, `rn`, `rm` from registers
3. **UDIV** (case 12): Pick `rd`, `rn`, `rm` from registers
4. **CMP** (case 13): Pick `rn`, `rm` (register or immediate)
5. **CMN** (case 14): Pick `rn`, `rm` (register or immediate)
6. **TST** (case 15): Pick `rn`, `rm` (register only — immediate not encodable without bitmask support)
7. **CSEL** (case 16): Pick `rd`, `rn`, `rm`, random condition
8. **CSINC** (case 17): Same as CSEL
9. **CSINV** (case 18): Same as CSEL
10. **CSNEG** (case 19): Same as CSEL

Change `rng.random_range(0..10)` to `rng.random_range(0..20)`.

Add a helper `random_condition()` that picks uniformly from the 14 useful conditions (EQ through LE, excluding AL and NV).

Also extend `generate_all_instructions()` (lines 25-100) to include MUL, SDIV, UDIV, CMP, CMN, TST, CSEL, CSINC, CSINV, CSNEG in the instruction space for exhaustive generation.

### User-visible changes

- Stochastic search (`--algorithm stochastic`) will explore MUL, SDIV, UDIV, CMP, CMN, TST, and conditional select instructions as candidate optimizations
- Symbolic search (`--algorithm symbolic`) will consider the full instruction set when enumerating candidates
- More diverse optimizations found (e.g., replacing `LSL X0, X1, #1; ADD X0, X0, X1` with `MUL X0, X1, #3`... though that would need MUL by immediate which isn't supported — better example: replacing a branch-heavy sequence with CSEL)

### Testing and verification

1. **Coverage test:**
   ```rust
   #[test]
   fn test_random_generation_covers_all_opcodes() {
       let mut rng = rand::rng();
       let regs = vec![Register::X0, Register::X1, Register::X2];
       let imms = vec![0, 1, 2, 4095];
       let mut seen_opcodes = std::collections::HashSet::new();
       for _ in 0..10000 {
           let instr = generate_random_instruction(&mut rng, &regs, &imms);
           seen_opcodes.insert(opcode_id(&instr));
       }
       // All 20 opcodes should be generated
       assert_eq!(seen_opcodes.len(), 20);
   }
   ```

2. **Encodability test:**
   ```rust
   #[test]
   fn test_random_instructions_mostly_encodable() {
       // With register-only operands, most instructions should be encodable
       let mut rng = rand::rng();
       let regs = vec![Register::X0, Register::X1, Register::X2];
       let imms = vec![0, 1, 100, 4095]; // all within 12-bit range
       let mut encodable = 0;
       let total = 1000;
       for _ in 0..total {
           let instr = generate_random_instruction(&mut rng, &regs, &imms);
           if instr.is_encodable_aarch64() { encodable += 1; }
       }
       // Majority should be encodable
       assert!(encodable > total / 2);
   }
   ```

3. **All-instructions generation test:**
   ```rust
   #[test]
   fn test_generate_all_includes_mul_div() {
       let regs = vec![Register::X0, Register::X1];
       let imms = vec![0, 1];
       let instrs = generate_all_instructions(&regs, &imms);
       assert!(instrs.iter().any(|i| matches!(i, Instruction::Mul { .. })));
       assert!(instrs.iter().any(|i| matches!(i, Instruction::Sdiv { .. })));
       assert!(instrs.iter().any(|i| matches!(i, Instruction::Cmp { .. })));
       assert!(instrs.iter().any(|i| matches!(i, Instruction::Csel { .. })));
   }
   ```

---

## Phase 4: SMT Flag Modeling

**Goal:** Enable formal verification of equivalences involving NZCV flags (comparisons and conditional selects).

**Dependencies:** Phase 3 (conditional instructions in candidate generation are useless without flag semantics)

### What to implement

Extend the SMT `MachineState` in `src/semantics/smt.rs` to include NZCV flags as symbolic bitvectors.

#### 4a: Add flags to MachineState

```rust
pub struct MachineState {
    pub registers: HashMap<Register, BV>,
    // NZCV flags as 1-bit bitvectors
    pub flag_n: BV,  // Negative
    pub flag_z: BV,  // Zero
    pub flag_c: BV,  // Carry
    pub flag_v: BV,  // Overflow
}
```

Initialize as symbolic 1-bit bitvectors in `new_symbolic()`:
```rust
flag_n: BV::new_const(format!("{}_flag_n", prefix), 1),
flag_z: BV::new_const(format!("{}_flag_z", prefix), 1),
// etc.
```

#### 4b: Implement flag computation for CMP/CMN/TST

**CMP (SUBS with Rd=XZR):** Computes `rn - rm` and sets:
- N = bit 63 of result
- Z = (result == 0) ? 1 : 0
- C = NOT borrow (i.e., unsigned rn >= rm)
- V = signed overflow detection

In Z3 bitvector arithmetic:
```
result = rn.bvsub(rm)
N = result.extract(63, 63)       // bit 63
Z = result.eq(zero).ite(one, zero)
C = rn.bvuge(rm).ite(one, zero)  // unsigned greater-or-equal = no borrow
V = ((rn XOR rm) AND (rn XOR result)).extract(63, 63)  // overflow
```

**CMN (ADDS with Rd=XZR):** Computes `rn + rm`:
```
result = rn.bvadd(rm)
N = result.extract(63, 63)
Z = result.eq(zero).ite(one, zero)
C = result.bvult(rn).ite(one, zero)  // carry = unsigned overflow
V = ((NOT (rn XOR rm)) AND (rn XOR result)).extract(63, 63)
```

**TST (ANDS with Rd=XZR):** Computes `rn AND rm`:
```
result = rn.bvand(rm)
N = result.extract(63, 63)
Z = result.eq(zero).ite(one, zero)
C = zero  // always cleared
V = zero  // always cleared
```

#### 4c: Implement condition evaluation for CSEL/CSINC/CSINV/CSNEG

Write `evaluate_condition(state: &MachineState, cond: &Condition) -> z3::ast::Bool`:
```
EQ: flag_z == 1
NE: flag_z == 0
CS: flag_c == 1
CC: flag_c == 0
MI: flag_n == 1
PL: flag_n == 0
VS: flag_v == 1
VC: flag_v == 0
HI: flag_c == 1 AND flag_z == 0
LS: NOT (flag_c == 1 AND flag_z == 0)
GE: flag_n == flag_v
LT: flag_n != flag_v
GT: flag_z == 0 AND flag_n == flag_v
LE: NOT (flag_z == 0 AND flag_n == flag_v)
AL: true
NV: true (architecturally same as AL)
```

Then update CSEL handler:
```
cond_true = evaluate_condition(&state, cond)
CSEL: rd = cond_true.ite(rn, rm)
CSINC: rd = cond_true.ite(rn, rm + 1)
CSINV: rd = cond_true.ite(rn, NOT rm)
CSNEG: rd = cond_true.ite(rn, NEG rm)
```

#### 4d: Update states_not_equal to include flags

`states_not_equal()` and `states_not_equal_for_live_out()` should also compare flags when flag-producing/consuming instructions are in the sequence. Add a `LiveOutMask` option for "flags are live-out" or always compare flags when present.

### User-visible changes

- `s11 equiv` with assembly files containing CMP/CSEL will now give correct results instead of potentially false equivalences
- `s11 opt` can formally verify optimizations involving conditional code, e.g.:
  - `CMP X0, #0; CSEL X1, X2, X3, EQ` with equivalent sequences
  - `CMP X0, X1; CSINC X2, XZR, XZR, LT` ≡ `CMP X0, X1; CSET X2, LT` (alias)
- The SMT verifier will no longer silently treat CMP as a no-op

### Testing and verification

1. **Flag computation correctness:**
   ```rust
   #[test]
   fn test_cmp_flags_smt() {
       // CMP X0, X1 where X0 > X1 (unsigned)
       // Should set C=1 (no borrow), Z=0
       // Verify with concrete values via SMT model extraction
   }

   #[test]
   fn test_cmp_equal_sets_z_flag() {
       // CMP X0, X0 should always set Z=1
       // Assert via SMT that flag_z == 1 is always true
   }
   ```

2. **Conditional select with flags:**
   ```rust
   #[test]
   fn test_cmp_csel_equivalence() {
       // CMP X0, #0; CSEL X1, X2, X3, EQ
       // ≡ CMP X0, #0; CSEL X1, X2, X3, EQ (identity — verify framework works)

       // CMP X0, #0; CSEL X1, X2, X3, EQ
       // ≢ CMP X0, #0; CSEL X1, X2, X3, NE (should be not equivalent)
   }
   ```

3. **Known equivalences involving flags:**
   ```rust
   #[test]
   fn test_cset_alias_equivalence() {
       // CSINC X0, XZR, XZR, cond ≡ CSET X0, cond
       // (CSET is an alias — test that the CSINC form works correctly)
   }
   ```

4. **Cross-validation with concrete interpreter:**
   - Run the same CMP+CSEL sequences through both concrete and SMT interpreters
   - For randomly generated inputs, verify both agree on register outputs

---

## Phase 5: Assembly Text Optimization (`opt --asm`)

**Goal:** Allow users to optimize assembly text files directly without compiling to ELF first.

**Dependencies:** Phases 1, 2 (need complete IR conversion and assembler encoding)

### What to implement

Add a new CLI variant to the `Opt` subcommand that accepts assembly files:

```rust
Commands::Opt {
    // Existing: binary + start_addr + end_addr
    // New alternative:
    /// Assembly file to optimize (alternative to binary+addresses)
    #[arg(long, conflicts_with_all = ["binary", "start_addr", "end_addr"])]
    asm: Option<PathBuf>,
    // ... rest unchanged
}
```

Or, add a new subcommand `OptAsm`:
```rust
Commands::OptAsm {
    /// Assembly file to optimize
    file: PathBuf,
    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Registers that must match (comma-separated)
    #[arg(long, default_value = "x0,x1,x2,x3,x4,x5,x6,x7")]
    live_out: String,
    // ... algorithm options same as Opt ...
}
```

Implementation:
1. Use the existing `parser::parse_assembly_file()` to parse the input `.s` file
2. Feed the parsed `Vec<Instruction>` to `run_optimization()`
3. Output the optimized sequence as assembly text (using `Instruction::Display`)
4. Optionally write to an output file

### User-visible changes

- New command: `s11 opt-asm input.s --live-out x0,x1 --algorithm stochastic`
- Output: optimized assembly to stdout or file
- No need to compile assembly to ELF, specify addresses, or deal with binary formats
- Much more accessible for experimentation and learning
- Can pipe output: `s11 opt-asm input.s | diff - input.s`

### Testing and verification

1. **Basic round-trip:**
   ```bash
   # Create test.s with: mov x0, x1; add x0, x0, #1
   # Run: s11 opt-asm test.s --live-out x0
   # Expected output: add x0, x1, #1
   ```

2. **Equivalence preservation:**
   ```bash
   # Optimize, then verify equivalence of input and output
   s11 opt-asm input.s --live-out x0 > output.s
   s11 equiv input.s output.s --live-out x0
   # Should report EQUIVALENT
   ```

3. **All algorithm variants:**
   ```bash
   s11 opt-asm test.s --algorithm enumerative --live-out x0
   s11 opt-asm test.s --algorithm stochastic --timeout 5 --live-out x0
   s11 opt-asm test.s --algorithm symbolic --live-out x0
   s11 opt-asm test.s --algorithm hybrid --cores 4 --timeout 5 --live-out x0
   ```

4. **Unit tests:**
   - Test that the command parses correctly
   - Test that file-not-found gives a clear error
   - Test that invalid assembly gives a parse error

---

## Phase 6: Peephole Optimization Database

**Goal:** Provide instant results for common optimization patterns without expensive search.

**Dependencies:** Phase 1 (need full IR conversion), Phase 2 (need full encoding)

### What to implement

Create `src/peephole/mod.rs` with a pattern-matching optimization pass:

```rust
pub struct PeepholeOptimizer {
    rules: Vec<PeepholeRule>,
}

pub struct PeepholeRule {
    name: &'static str,
    pattern_length: usize,
    apply: fn(&[Instruction]) -> Option<Vec<Instruction>>,
}
```

Implement these well-known AArch64 peephole optimizations:

1. **MOV+binop fusion:** `MOV Xd, Xn; ADD Xd, Xd, Xm` → `ADD Xd, Xn, Xm`
   - Also for SUB, AND, ORR, EOR
2. **Zeroing idiom:** `MOV Xd, #0` → `EOR Xd, Xd, Xd` (saves code size — MOVZ is 4 bytes but so is EOR, however MOVZ uses the literal pool on some assemblers for larger constants)
3. **Identity removal:** `ADD Xd, Xn, #0` → `MOV Xd, Xn` (or delete if Xd == Xn)
4. **Sub of negative:** `SUB Xd, Xn, #-k` → `ADD Xd, Xn, #k` (when k > 0 and fits)
5. **Double negation:** `SUB Xd, XZR, Xn; SUB Xe, XZR, Xd` → `MOV Xe, Xn` (when Xd not live-out)
6. **Strength reduction:** `MUL Xd, Xn, Xm` where one operand is known power-of-2 → `LSL` (requires constant propagation or specific pattern like `MOV Xm, #4; MUL Xd, Xn, Xm`)
7. **Redundant MOV:** `MOV Xd, Xd` → deleted (no-op)
8. **MOV chain:** `MOV Xd, Xn; MOV Xe, Xd` → `MOV Xe, Xn` (when Xd not live-out)
9. **Self-XOR after write:** `MOV Xd, #k; EOR Xd, Xd, Xd` → `MOV Xd, #0` (or just `EOR Xd, Xd, Xd`)

Integration: Run peephole pass before invoking search algorithms. If peephole finds improvements, report them. If further optimization desired, feed peephole result to search.

### User-visible changes

- `s11 opt` and `s11 opt-asm` run a fast peephole pass first, reporting instant wins
- Output shows: "Peephole optimization: applied <rule-name>, saved <N> instructions"
- New flag: `--no-peephole` to skip the peephole pass
- Peephole results are verified by equivalence checking before being applied

### Testing and verification

1. **Per-rule unit tests:**
   ```rust
   #[test]
   fn test_peephole_mov_add_fusion() {
       let input = vec![
           Instruction::MovReg { rd: X0, rn: X1 },
           Instruction::Add { rd: X0, rn: X0, rm: Operand::Immediate(1) },
       ];
       let output = peephole.optimize(&input, &live_out);
       assert_eq!(output, vec![
           Instruction::Add { rd: X0, rn: X1, rm: Operand::Immediate(1) },
       ]);
   }
   ```

2. **Equivalence verification for each rule:**
   ```rust
   #[test]
   fn test_peephole_rules_are_sound() {
       // For each rule, verify input and output are equivalent via SMT
       for rule in peephole.rules() {
           let (input, expected_output) = rule.example();
           let result = check_equivalence(&input, &expected_output);
           assert_eq!(result, EquivalenceResult::Equivalent);
       }
   }
   ```

3. **No-regression test:** Applying peephole to already-optimal code should produce no changes.

---

## Phase 7: W-Register (32-bit) Support

**Goal:** Support AArch64 32-bit register operations (W0-W30), which are extremely common in real binaries.

**Dependencies:** Phases 1, 2, 4 (need complete IR/assembler/SMT foundation first)

### What to implement

This is a significant cross-cutting change affecting IR, semantics, SMT, assembler, and parser.

#### 7a: IR type changes

Add a `Width` enum and modify `Register`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width {
    W32,  // Wn registers (32-bit)
    W64,  // Xn registers (64-bit)
}
```

Option A (minimal): Add width field to each instruction variant:
```rust
Instruction::Add { width: Width, rd: Register, rn: Register, rm: Operand }
```

Option B (separate W-register enum): Add W0-W30 to the Register enum. This is more disruptive but cleaner semantically.

Recommended: Option A — adding a `width` field keeps the register enum simple and matches how AArch64 actually works (W0 and X0 are the same physical register, just different views).

#### 7b: Semantics changes

- **Concrete interpreter:** For W32 operations, mask results to 32 bits (zero-extend to 64 bits), matching AArch64 behavior where 32-bit results zero the upper 32 bits of the 64-bit register
- **SMT interpreter:** Use 32-bit bitvectors for computation, then zero-extend to 64 bits when writing back
- **Flag computation:** Use 32-bit operands for W32 CMP/CMN/TST (bit 31 for N flag, etc.)

#### 7c: Assembler changes

- Use `W(reg)` instead of `X(reg)` in dynasm macros for 32-bit instructions
- Immediate ranges may differ (e.g., MOVZ for W registers: 0-0xFFFF same range, but shift is 0 or 16 only)

#### 7d: Parser and disassembly

- Parse `w0`-`w30`, `wzr` in addition to `x0`-`x30`, `xzr`
- `convert_to_ir()` must detect W-register variants from Capstone output

### User-visible changes

- `s11 opt` handles W-register instructions from real binaries (extremely common in compiled C/C++ code for `int` and `unsigned int` operations)
- `s11 equiv` can check equivalence of 32-bit instruction sequences
- `s11 opt-asm` accepts W-register syntax in assembly files

### Testing and verification

1. **32-bit arithmetic correctness:**
   ```rust
   #[test]
   fn test_w_register_add_wraps_32bit() {
       // ADD W0, W1, #1 where W1 = 0xFFFFFFFF
       // Result should be 0x00000000 (32-bit wrap), X0 upper bits = 0
   }
   ```

2. **Zero-extension verification:**
   ```rust
   #[test]
   fn test_w_register_zero_extends() {
       // ADD W0, W1, W2 should zero upper 32 bits of X0
   }
   ```

3. **Cross-width equivalence tests:**
   ```rust
   #[test]
   fn test_w_add_not_equivalent_to_x_add() {
       // ADD W0, W1, W2 ≢ ADD X0, X1, X2 (different overflow behavior)
   }
   ```

4. **Assembler round-trip:** Encode W-register instructions, disassemble, verify correctness.

---

## Phase 8: Expand Instruction Set (MADD/MSUB/MOVZ/MOVK/MOVN)

**Goal:** Support high-value optimization targets: multiply-accumulate and large constant materialization.

**Dependencies:** Phase 7 (W-register support makes these more useful), Phase 4 (SMT for verification)

### What to implement

#### 8a: MADD/MSUB/MNEG

Add to IR:
```rust
Madd { rd: Register, rn: Register, rm: Register, ra: Register },  // rd = ra + rn*rm
Msub { rd: Register, rn: Register, rm: Register, ra: Register },  // rd = ra - rn*rm
Mneg { rd: Register, rn: Register, rm: Register },                // rd = -(rn*rm)
```

Note: `MUL Xd, Xn, Xm` is an alias for `MADD Xd, Xn, Xm, XZR`. Converting to MADD may let us find optimizations like `MUL X0, X1, X2; ADD X0, X0, X3` → `MADD X0, X1, X2, X3`.

Concrete semantics: straightforward multiply-add/sub/neg.
SMT semantics: `bvmul` + `bvadd`/`bvsub`/`bvneg`.

#### 8b: MOVZ/MOVK/MOVN

Add to IR:
```rust
Movz { rd: Register, imm: u16, shift: u8 },  // rd = imm << shift (shift = 0, 16, 32, 48)
Movk { rd: Register, imm: u16, shift: u8 },  // rd[shift+15:shift] = imm (keep other bits)
Movn { rd: Register, imm: u16, shift: u8 },  // rd = NOT(imm << shift)
```

These are critical for constant materialization. A 64-bit constant may take up to 4 instructions:
```
MOVZ X0, #0x1234, LSL #48
MOVK X0, #0x5678, LSL #32
MOVK X0, #0x9ABC, LSL #16
MOVK X0, #0xDEF0
```

Optimization potential: Some constants can be expressed more efficiently with MOVN (for values near all-ones) or with ORR bitmask immediates.

### User-visible changes

- `s11 opt` finds multiply-accumulate fusions: `MUL X0, X1, X2; ADD X0, X0, X3` → `MADD X0, X1, X2, X3` (saves one instruction)
- `s11 opt` can optimize constant materialization sequences
- New instructions available in assembly files for `equiv` and `opt-asm` commands

### Testing and verification

1. **MADD fusion:**
   ```rust
   #[test]
   fn test_mul_add_to_madd_equivalence() {
       let seq1 = vec![
           Instruction::Mul { rd: X0, rn: X1, rm: X2 },
           Instruction::Add { rd: X0, rn: X0, rm: Operand::Register(X3) },
       ];
       let seq2 = vec![
           Instruction::Madd { rd: X0, rn: X1, rm: X2, ra: X3 },
       ];
       assert_eq!(check_equivalence(&seq1, &seq2), EquivalenceResult::Equivalent);
   }
   ```

2. **Constant materialization:**
   ```rust
   #[test]
   fn test_movz_movk_constant() {
       // MOVZ X0, #0x1234, LSL #16; MOVK X0, #0x5678
       // Should produce X0 = 0x12345678
   }
   ```

---

## Phase 9: Optimization Report and Diff Output

**Goal:** Generate structured reports showing what was optimized, the savings, and verification status.

**Dependencies:** Phase 5 (assembly text mode), Phase 6 (peephole for rule names)

### What to implement

Add a `--report` flag that generates a structured optimization report:

```rust
struct OptimizationReport {
    original_instructions: Vec<Instruction>,
    optimized_instructions: Vec<Instruction>,
    original_cost: CostMetrics,
    optimized_cost: CostMetrics,
    verification_result: EquivalenceResult,
    algorithm_used: Algorithm,
    search_time: Duration,
    peephole_rules_applied: Vec<String>,
}

struct CostMetrics {
    instruction_count: u64,
    latency: u64,
    code_size: u64,
}
```

Output formats:
- `--report text` (default): Human-readable diff-style output
- `--report json`: Machine-readable JSON for integration with other tools

Example text output:
```
=== s11 Optimization Report ===

Original (3 instructions, latency 5, 12 bytes):
  mov x0, x1
  mul x0, x0, x2
  add x0, x0, x3

Optimized (1 instruction, latency 3, 4 bytes):
  madd x0, x1, x2, x3

Savings: 2 instructions, latency -2, 8 bytes
Verification: EQUIVALENT (SMT verified)
Algorithm: stochastic (MCMC)
Search time: 0.342s
```

### User-visible changes

- `--report` flag on `opt`, `opt-asm` commands
- `--report json` for CI integration and tooling
- Clear before/after comparison with cost metrics

### Testing and verification

1. Verify JSON output parses correctly
2. Verify cost metrics match `sequence_cost()` computations
3. Verify report is generated even when no optimization is found (shows "no improvement found")

---

## Phase 10: Basic Block Extraction

**Goal:** Automatically identify basic blocks in binaries for batch optimization.

**Dependencies:** Phase 1 (complete IR conversion), Phase 9 (reporting per-block results)

### What to implement

Add basic block detection to the ELF analysis pipeline:

1. **Branch detection:** Identify branch instructions (B, BL, BR, BLR, RET, B.cond, CBZ, CBNZ, TBZ, TBNZ) as basic block terminators
2. **Fall-through analysis:** Consecutive instructions without branches form a single basic block
3. **Target detection:** Branch target addresses start new basic blocks

New subcommand or enhancement:
```
s11 opt --binary <file> --function <name_or_addr>  # optimize all blocks in a function
s11 opt --binary <file> --all                       # optimize all detected basic blocks
```

Output: For each basic block, run optimization and report results. Show total savings across all blocks.

### User-visible changes

- No longer need to manually specify `--start-addr` and `--end-addr`
- Can optimize entire functions or binaries in one command
- Summary shows per-block and total savings

### Testing and verification

1. Build test binaries with known basic block structures
2. Verify detected blocks match manual analysis
3. Verify optimizations are applied only within block boundaries (not across branches)

---

## Phase Dependency Graph

```
Phase 1 (Capstone-to-IR)  ──────────────────────┐
                                                  │
Phase 2 (Assembler encoding) ────────────────────┤
                                                  ├── Phase 5 (opt-asm) ──┐
Phase 3 (Candidate generation) ──┐               │                       ├── Phase 9 (Reports)
                                  ├── Phase 4 ───┤                       │
                                  │   (SMT flags) │                       │
                                  │               ├── Phase 6 (Peephole) ─┘
                                  │               │
                                  │               ├── Phase 7 (W-registers) ── Phase 8 (MADD/MOVZ)
                                  │               │
                                  │               └── Phase 10 (Basic blocks)
                                  │
                                  └── (standalone)
```

**Independent phases** (can be done in any order):
- Phase 1, Phase 2, Phase 3 are all independent of each other

**Dependencies:**
- Phase 4 depends on Phase 3 (flag-based instructions need to be in candidate set)
- Phase 5 depends on Phases 1 and 2 (needs complete IR conversion and encoding)
- Phase 6 depends on Phases 1 and 2
- Phase 7 depends on Phases 1, 2, and 4
- Phase 8 depends on Phase 7 (W-register support makes these more valuable) and Phase 4
- Phase 9 depends on Phases 5 and 6
- Phase 10 depends on Phases 1 and 9

**Recommended implementation order:**
1. Phases 1, 2, 3 (in parallel — all independent)
2. Phase 4 (SMT flags — unlocks formal verification for conditional code)
3. Phase 5 (opt-asm — major usability improvement)
4. Phase 6 (peephole — instant results for common patterns)
5. Phase 7 (W-registers — real-world binary support)
6. Phases 8, 9, 10 (can be done in any order)

---

## Summary Table

| Phase | Effort | Impact | Key Deliverable |
|-------|--------|--------|-----------------|
| 1. Capstone-to-IR | Medium | Critical | `opt` works on real binaries |
| 2. Assembler encoding | Medium | Critical | End-to-end binary patching |
| 3. Candidate generation | Small | High | Full instruction space search |
| 4. SMT flags | Large | High | Formal verification of conditional code |
| 5. opt-asm | Small | High | Optimize assembly files directly |
| 6. Peephole | Medium | Medium | Instant results for known patterns |
| 7. W-registers | Large | High | 32-bit instruction support |
| 8. MADD/MOVZ/MOVK | Medium | Medium | Multiply-accumulate and constants |
| 9. Reports | Small | Medium | Structured optimization output |
| 10. Basic blocks | Medium | Medium | Batch optimization without addresses |

Phases 1-5 together transform s11 from a prototype into a practically useful tool. Phases 6-10 add polish, broader coverage, and ergonomic improvements.

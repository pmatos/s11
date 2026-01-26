# s11 Tutorial

s11 is an AArch64 superoptimizer that finds shorter or faster instruction sequences that are semantically equivalent to the original code. This tutorial walks through all available features with working examples.

## Prerequisites

Build s11 in release mode for best performance:

```bash
just release
# or: cargo build --release
```

## Test Binary

This tutorial uses a simple test binary. Create it with:

```bash
cat > tests/tutorial_test.s << 'EOF'
.global _start

_start:
    // Pattern 1: MOV + ADD that can be optimized to single ADD
    mov x0, x1
    add x0, x0, #1

    // Pattern 2: Zero register
    mov x2, #0

    // Pattern 3: Redundant addition
    add x3, x3, #0

    // Pattern 4: Shift operations
    lsl x4, x5, #2

    // Pattern 5: Bitwise operations
    and x6, x7, x8
    orr x9, x10, x11
    eor x12, x13, x14

    // Exit syscall
    mov x0, #0
    mov x8, #93
    svc #0
EOF

aarch64-linux-gnu-as tests/tutorial_test.s -o tests/tutorial_test.o
aarch64-linux-gnu-ld tests/tutorial_test.o -o binaries/tutorial_test
```

---

## Command 1: Disassembly (`disasm`)

The `disasm` command shows all instructions in an ELF binary with their addresses and machine code.

### Basic Usage

```bash
./target/release/s11 disasm binaries/tutorial_test
```

**Output:**
```
0x400078: e00301aa mov x0, x1
0x40007c: 00040091 add x0, x0, #1
0x400080: 020080d2 mov x2, #0
0x400084: 63000091 add x3, x3, #0
0x400088: a4f47ed3 lsl x4, x5, #2
0x40008c: e600088a and x6, x7, x8
0x400090: 49010baa orr x9, x10, x11
0x400094: ac010eca eor x12, x13, x14
0x400098: 000080d2 mov x0, #0
0x40009c: a80b80d2 mov x8, #0x5d
0x4000a0: 010000d4 svc #0
```

Each line shows: `address: machine_code assembly_mnemonic operands`

### Disassembling Existing Binaries

You can disassemble any AArch64 ELF binary:

```bash
./target/release/s11 disasm binaries/functions_debug
```

---

## Command 2: Optimization (`opt`)

The `opt` command optimizes a window of instructions in a binary using semantic equivalence checking.

### Required Options

- `--start-addr <ADDR>`: Start address of the window (hex)
- `--end-addr <ADDR>`: End address of the window (hex)

### Basic Example: Enumerative Search

The default algorithm is enumerative search, which exhaustively tries all possible shorter sequences:

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --verbose
```

**Output:**
```
Original code: 8 bytes
Disassembled 2 instructions:
  0x400078: mov x0, x1
  0x40007c: add x0, x0, #1
Converted 2 instructions to IR:
  mov x0, x1
  add x0, x0, #1

Running enumerative search...
Searching for equivalent sequences of length 1...
  Testing candidate: add x0, x1, #1; Found equivalent!
Optimized to 1 instructions:
  add x0, x1, #1

Created optimized binary: binaries/tutorial_test_optimized
```

The optimizer found that `mov x0, x1; add x0, x0, #1` (2 instructions) is equivalent to `add x0, x1, #1` (1 instruction).

Verify the optimization:

```bash
./target/release/s11 disasm binaries/tutorial_test_optimized
```

**Output:**
```
0x400078: 20040091 add x0, x1, #1
0x40007c: 1f2003d5 nop
...
```

The second instruction became a NOP to maintain binary size/alignment.

---

## Command 3: Equivalence Checking (`equiv`)

The `equiv` command checks if two assembly files are semantically equivalent using SMT-based verification.

### Basic Usage

```bash
./target/release/s11 equiv tests/asm/seq1.s tests/asm/seq2.s --verbose
```

**Output:**
```
Parsing tests/asm/seq1.s...
  Parsed 2 instructions:
    mov x0, x1
    add x0, x0, #1
Parsing tests/asm/seq2.s...
  Parsed 1 instructions:
    add x0, x1, #1
Live-out registers: x0, x1, x2, x3, x4, x5, x6, x7

Checking equivalence...
  Mode: random testing + SMT verification
  Timeout: 30s
EQUIVALENT: The two sequences are semantically equivalent.
```

### Options

- `--live-out <REGS>`: Registers that must match (comma-separated). Default: `x0,x1,x2,x3,x4,x5,x6,x7`
- `--timeout <SECS>`: SMT solver timeout in seconds. Default: 30
- `--fast-only`: Use random testing only, skip SMT verification
- `-v, --verbose`: Show detailed output

### Example: Specifying Live-Out Registers

If you only care about specific output registers:

```bash
./target/release/s11 equiv tests/asm/seq1.s tests/asm/seq2.s --live-out "x0" --verbose
```

This is useful when intermediate registers are used differently but final outputs match.

### Example: Non-Equivalent Sequences

When sequences are not equivalent, `equiv` shows a counterexample:

```bash
./target/release/s11 equiv tests/asm/seq1.s tests/asm/seq3.s --verbose
```

**Output:**
```
Parsing tests/asm/seq1.s...
  Parsed 2 instructions:
    mov x0, x1
    add x0, x0, #1
Parsing tests/asm/seq3.s...
  Parsed 1 instructions:
    add x0, x1, #2
...
NOT EQUIVALENT: The two sequences produce different results.

Counterexample found:
  Input state:
    x1 = 0xb5a308b226faa80e
    ...
  Output from sequence 1:
    x0 = 0xb5a308b226faa80f
  Output from sequence 2:
    x0 = 0xb5a308b226faa810
```

### Example: Zero Register Patterns

Check if `mov x0, #0` and `eor x0, x0, x0` are equivalent:

```bash
# Create test files
echo "mov x0, #0" > /tmp/zero1.s
echo "eor x0, x0, x0" > /tmp/zero2.s

./target/release/s11 equiv /tmp/zero1.s /tmp/zero2.s --live-out "x0"
```

**Output:**
```
EQUIVALENT: The two sequences are semantically equivalent.
```

### Example: Commutativity

Verify that addition is commutative:

```bash
echo "add x0, x1, x2" > /tmp/add1.s
echo "add x0, x2, x1" > /tmp/add2.s

./target/release/s11 equiv /tmp/add1.s /tmp/add2.s --live-out "x0"
```

**Output:**
```
EQUIVALENT: The two sequences are semantically equivalent.
```

### Example: Fast Mode

For quick checks without SMT verification:

```bash
./target/release/s11 equiv tests/asm/seq1.s tests/asm/seq2.s --fast-only --verbose
```

This runs random testing only, which is faster but may not catch all differences.

### Assembly File Format

Assembly files support:
- GNU assembler syntax
- Comments: `//`, `;`, or `@`
- Directives: `.text`, `.global`, etc. (ignored)
- Labels: `_start:`, `loop:`, etc. (ignored)
- Case-insensitive opcodes and registers

Example file:
```asm
// my_sequence.s - Example assembly file
    .text
    .global _start
_start:
    mov x0, x1          // copy x1 to x0
    add x0, x0, #1      ; increment by 1
```

---

## Search Algorithms

s11 provides four search algorithms, each with different tradeoffs.

### 1. Enumerative Search (Default)

Exhaustively searches all possible instruction sequences up to a given length. Guarantees finding the optimal solution within the search space.

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --algorithm enumerative \
    --verbose
```

**Best for:** Small windows (1-3 instructions) where exhaustive search is feasible.

### 2. Stochastic Search (MCMC)

Uses Markov Chain Monte Carlo to randomly explore the search space. Can handle larger windows but may not find optimal solutions.

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --algorithm stochastic \
    --iterations 100000 \
    --beta 1.0 \
    --seed 42 \
    --verbose
```

Options:
- `--iterations <N>`: Number of MCMC iterations (default: 1000000)
- `--beta <FLOAT>`: Inverse temperature - higher values make search more greedy (default: 1.0)
- `--seed <N>`: Random seed for reproducibility

**Best for:** Larger windows where exhaustive search is impractical.

### 3. Symbolic Search (SMT)

Uses an SMT solver to synthesize optimal instruction sequences. More principled than stochastic but can be slow.

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --algorithm symbolic \
    --search-mode linear \
    --solver-timeout 5 \
    --verbose
```

Options:
- `--search-mode <linear|binary>`: How to search for cost bounds
- `--solver-timeout <SECS>`: Timeout per SMT query (default: 5)

**Best for:** Finding provably optimal solutions when SMT queries succeed.

### 4. Hybrid Parallel Search

Runs symbolic and multiple stochastic workers in parallel, combining the strengths of both approaches.

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --algorithm hybrid \
    -j 4 \
    --timeout 10 \
    --verbose
```

Options:
- `-j, --cores <N>`: Number of worker threads
- `--timeout <SECS>`: Total search timeout
- `--no-symbolic`: Disable symbolic worker (all workers run stochastic)

**Best for:** General use when you want the best of both worlds.

---

## Cost Metrics

s11 can optimize for different goals using the `--cost-metric` option:

### Instruction Count (Default)

Minimize the number of instructions:

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --cost-metric instruction-count
```

### Latency

Minimize estimated execution cycles (accounts for slow instructions like MUL/DIV):

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --cost-metric latency
```

### Code Size

Minimize code size in bytes (4 bytes per AArch64 instruction):

```bash
./target/release/s11 opt \
    --start-addr 0x400078 \
    --end-addr 0x400080 \
    binaries/tutorial_test \
    --cost-metric code-size
```

---

## Supported Instructions

s11 currently supports these AArch64 instructions:

**Arithmetic:**
- `ADD`, `SUB` (register and immediate)
- `MUL`, `SDIV`, `UDIV`

**Logical:**
- `AND`, `ORR`, `EOR` (register and immediate)

**Shifts:**
- `LSL`, `LSR`, `ASR` (register and immediate)

**Move:**
- `MOV` (register and immediate)

**Comparison (flag-setting):**
- `CMP`, `CMN`, `TST`

**Conditional Select:**
- `CSEL`, `CSINC`, `CSINV`, `CSNEG`

Unsupported instructions (memory operations, branches, etc.) are skipped with a warning.

---

## Tips for Best Results

1. **Start with small windows** (1-3 instructions) where optimization is most likely
2. **Use enumerative search** for small windows - it's fast and complete
3. **Use hybrid search** for larger windows when you have time
4. **Check the verbose output** to understand what the optimizer found
5. **Use a consistent seed** with stochastic search for reproducibility

---

## Known Limitations

- Memory operations (LDR, STR) are not supported
- Branch instructions are not supported
- Some immediate values may not be encodable in optimized forms
- Condition flags are approximated in SMT mode

---

## Example Workflow

1. **Disassemble** to identify optimization targets:
   ```bash
   ./target/release/s11 disasm mybinary
   ```

2. **Choose a window** of instructions to optimize

3. **Run optimization**:
   ```bash
   ./target/release/s11 opt \
       --start-addr 0x1000 \
       --end-addr 0x1010 \
       mybinary \
       --algorithm enumerative \
       --verbose
   ```

4. **Verify the result**:
   ```bash
   ./target/release/s11 disasm mybinary_optimized
   ```

5. **(Optional) Check equivalence** of two sequences you're curious about:
   ```bash
   ./target/release/s11 equiv original.s optimized.s --live-out "x0,x1"
   ```

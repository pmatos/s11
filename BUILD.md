# Build Documentation

This document explains how to build and run s11, the AArch64 / x86
superoptimizer. For the up-to-date list of supported instructions and
search algorithms, see [`README.md`](README.md); this file only covers
build, run, and test mechanics.

## Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Just**: Install the `just` command runner (optional but recommended)
  ```bash
  cargo install just
  ```

## Building with Just (Recommended)

This project uses `just` as a task runner for common operations:

### Basic Commands

```bash
# Build in debug mode (fast compilation, unoptimized)
just build

# Build in release mode (slower compilation, optimized)
just release

# Check code for errors without building
just check

# Format code according to Rust standards
just fmt

# Clean build artifacts
just clean
```

### Running the Application

```bash
# Build and run in debug mode (prints clap help when given no subcommand)
just run

# Build and run in release mode (recommended for performance testing)
just run-release
```

### Testing

```bash
# Run all tests
just test
```

### Help

```bash
# List all available commands
just list

# Show detailed help
just help
```

## Building with Cargo

If you don't have `just` installed, you can use standard Cargo commands:

### Basic Commands

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release

# Check code for errors
cargo check

# Format code
cargo fmt

# Clean build artifacts
cargo clean
```

### Running the Application

```bash
# Run in debug mode (prints clap help when given no subcommand)
cargo run

# Run in release mode
cargo run --release
```

### Testing

```bash
# Run all tests
cargo test
```

## Build Outputs

- **Debug builds**: Located in `target/debug/`
- **Release builds**: Located in `target/release/`
- **Executable name**: `s11`

## Performance Notes

- Use **debug builds** (`just run`) for development — they compile faster
- Use **release builds** (`just run-release`) for performance testing — they are significantly faster at runtime

## Example Session

```bash
# Check that everything compiles
just check

# Show the available subcommands (s11 with no args prints help)
just run

# Build optimized version
just release
```

## Usage Examples

s11 is a subcommand-driven CLI. Run `s11 --help` (or `cargo run -- --help`)
for the full list; the common entry points are `disasm`, `opt`, and
`equiv`. See [`README.md`](README.md) for an overview of the algorithm
and flag surface.

### Disassemble an ELF binary

```bash
# Pretty-print .text for an AArch64 or x86 ELF
cargo run -- disasm /path/to/binary

# Or using just
just run -- disasm /path/to/binary
```

`disasm` auto-detects the architecture from the ELF header; pass
`--arch x86-64` (etc.) if you want to override.

### Optimize a window of instructions

```bash
# Search for a cheaper equivalent of the instructions between two
# addresses (hex, inside .text). Use `disasm` first to find the
# boundaries you care about.
cargo run -- opt /path/to/binary \
    --start-addr 0x740 --end-addr 0x758 \
    --algorithm hybrid --cores 4 --timeout 30
```

The `opt` subcommand has many more flags (cost metric, MCMC tuning, SMT
timeout, …) — see `cargo run -- opt --help` and `README.md` for the
full table.

### Example Output

`disasm` prints one instruction per line as `addr: bytes mnemonic operands`:

```
0x598: 3f2303d5 paciasp
0x59c: fd7bbfa9 stp x29, x30, [sp, #-0x10]!
0x5a0: fd030091 mov x29, sp
0x5a4: 34000094 bl #0x674
0x5a8: fd7bc1a8 ldp x29, x30, [sp], #0x10
0x5ac: bf2303d5 autiasp
0x5b0: c0035fd6 ret
...
```

## Testing

The repository includes a comprehensive test suite with C programs compiled for AArch64 (and x86 where the host toolchain supports it):

### Build Test Binaries
```bash
# Build all test programs with different optimization levels
./build_tests.sh
```

This creates binaries in the `binaries/` directory:
- `simple_*`: Basic arithmetic operations
- `functions_*`: Function calls and loops
- `loops_*`: Control flow and loops
- `optimizable_*`: Code with obvious optimization opportunities
- `arrays_*`: Array operations

Each test has three versions: `_debug` (O0), `_opt` (O2), and `_opt3` (O3).

### Run All Tests
```bash
# Run the complete test suite
./test_all.sh
```

### Individual Tests
```bash
# Disassemble a specific binary
just analyze binaries/simple_debug
just analyze binaries/simple_opt

# Compare debug vs optimized versions
cargo run -- disasm binaries/functions_debug
cargo run -- disasm binaries/functions_opt
```

### Expected Results

The test suite demonstrates that s11 can:
- Disassemble AArch64 and x86 ELF binaries across optimization levels.
- Find shorter or cheaper equivalent instruction windows via `opt`
  (enumerative, stochastic, symbolic, and — on AArch64 — hybrid / LLM
  search).
- Prove equivalence of two assembly sequences via `equiv` and an
  explicit live-out set.

See `README.md` for worked examples of the kinds of rewrites s11 finds.

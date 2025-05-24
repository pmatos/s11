# Build Documentation

This document explains how to build and run the AArch64 Super-Optimizer MVP.

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
# Build and run in debug mode
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
# Run in debug mode
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
- **Executable name**: `aarch64_superoptimizer_mvp`

## Performance Notes

- Use **debug builds** (`just run`) for development - they compile faster
- Use **release builds** (`just run-release`) for performance testing - they are significantly faster at runtime

## Example Session

```bash
# Check that everything compiles
just check

# Run the application
just run

# Build optimized version and run
just run-release
```

## Current Functionality

The MVP demonstrates:
1. **ELF Binary Analysis**: Read and disassemble AArch64 ELF binaries
2. **IR Representation**: Basic AArch64 instructions (ADD, MOV with register/immediate variants)
3. **Pattern Recognition**: Hardcoded equivalence patterns for demonstration
4. **Enumerative Search**: Searches for shorter equivalent instruction sequences

### Usage Examples

#### Analyze AArch64 ELF Binary
```bash
# Analyze a binary file
cargo run -- --binary /path/to/aarch64_binary

# Or using just
just run -- --binary /path/to/aarch64_binary
```

#### Run Optimization Demo
```bash
# Run demo mode (default)
cargo run

# Explicitly run demo
cargo run -- --demo
```

### Example Output

**Demo Mode:**
```
AArch64 Super-Optimizer MVP
=== Running Optimization Demo ===
Original sequence: MOV X0, X1; ADD X0, X0, #1; 

Searching for optimizations...
  Testing candidate: ADD X0, X1, #1; Found equivalent!
Found shorter equivalent sequence: ADD X0, X1, #1; 
```

**Binary Analysis:**
```
AArch64 Super-Optimizer MVP
Analyzing ELF binary: test_binary
ELF Header:
  Architecture: AArch64
  Entry point: 0x600
  Type: Shared object

Text sections:
Section: .text (offset: 0x600, size: 328 bytes)
Disassembly:
  0x00000724: mov	w0, #5
  0x00000728: str	w0, [sp, #0xc]
  0x0000072c: ldr	w0, [sp, #0xc]
  0x00000730: add	w0, w0, #1
  ...
```

## Testing

The repository includes a comprehensive test suite with C programs compiled for AArch64:

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
# Test specific binaries
just analyze binaries/simple_debug
just analyze binaries/simple_opt

# Compare debug vs optimized versions
cargo run -- --binary binaries/functions_debug
cargo run -- --binary binaries/functions_opt
```

### Expected Results

The test suite demonstrates:
- **Simple arithmetic**: `5+3` optimized from multiple instructions to `mov w0, #8`
- **Function inlining**: Complex function calls optimized to single constants
- **Loop unrolling**: Multiplication loops replaced with `mul` instructions
- **Dead code elimination**: Unused variables completely removed
- **Constant folding**: Compile-time arithmetic evaluation
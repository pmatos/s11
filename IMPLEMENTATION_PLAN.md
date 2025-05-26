# Implementation Plan for s11 Features

## Overview

This document outlines the implementation plan for two new features in the s11 AArch64 optimizer:

1. **`--disasm` flag**: Print addresses and code of every instruction in .text sections
2. **`--opt` flag**: Optimize instructions within an address window and patch the ELF file

## Current Architecture Analysis

### Existing Components
- **CLI**: Uses `clap` for argument parsing with `--binary` and `--demo` options
- **ELF Analysis**: Already reads AArch64 ELF files and disassembles executable sections
- **Disassembly**: Uses Capstone for AArch64 instruction disassembly
- **IR System**: Supports subset of AArch64 instructions (MOV, ADD, SUB, AND, ORR, EOR, shifts)
- **SMT Equivalence**: Uses z3 for semantic equivalence checking
- **Optimization**: Basic enumerative search for shorter equivalent sequences

### Key Functions
- `analyze_elf_binary()`: Parses ELF and disassembles text sections
- `check_equivalence()`: SMT-based equivalence verification
- `find_shorter_equivalent()`: Enumerative optimization search

## Feature 1: --disasm Implementation

### Requirements
- Print address and raw bytes for each instruction in executable sections
- Format: `<address>: <raw_bytes> <mnemonic> <operands>`

### Implementation Steps

1. **CLI Modification**
   ```rust
   #[derive(Parser)]
   struct Args {
       #[arg(short, long)]
       binary: Option<PathBuf>,
       
       #[arg(short, long)]
       demo: bool,
       
       /// Disassemble all instructions in text sections
       #[arg(long)]
       disasm: bool,
   }
   ```

2. **Enhanced Disassembly Output**
   - Modify `analyze_elf_binary()` to check for `disasm` flag
   - When flag is set, print raw instruction bytes alongside disassembly
   - Use Capstone's `bytes()` method to get raw instruction data

3. **Output Format**
   ```
   0x00001234: 91 00 00 00    add x0, x0, #0
   0x00001238: d2 80 00 01    mov x1, #0x1
   ```

### Effort Estimate: 2-3 hours
- CLI modification: 30 minutes
- Enhanced output formatting: 1-2 hours
- Testing: 30 minutes

## Feature 2: --opt Implementation

### Requirements
- Accept ELF file and two addresses defining optimization window
- Convert instructions to IR, optimize, reassemble, and patch ELF
- Create modified copy of the ELF file

### Implementation Steps

1. **CLI Modification**
   ```rust
   #[derive(Parser)]
   struct Args {
       // ... existing fields ...
       
       /// Optimize instructions within address window
       #[arg(long)]
       opt: bool,
       
       /// Start address for optimization window (hex)
       #[arg(long, value_parser = parse_hex_address)]
       start_addr: Option<u64>,
       
       /// End address for optimization window (hex)
       #[arg(long, value_parser = parse_hex_address)]
       end_addr: Option<u64>,
   }
   ```

2. **Address Window Validation**
   - Ensure start < end
   - Verify addresses are within executable sections
   - Check alignment (AArch64 instructions are 4-byte aligned)

3. **Instruction Extraction and IR Conversion**
   - Extract instructions within window using Capstone
   - Convert supported instructions to IR representation
   - Handle unsupported instructions (skip optimization or error)

4. **Optimization Pipeline**
   - Use existing `find_shorter_equivalent()` for each sequence
   - Consider instruction dependencies and register liveness
   - Preserve program semantics

5. **AArch64 Assembly/Encoding**

   **Recommended Approach: dynasmrt**
   - Pros: Pure Rust, well-maintained, supports AArch64 up to ARMv8.4
   - Cons: Learning curve, designed for JIT but can be used for static assembly
   
   **Alternative Options**:
   - **Keystone**: Full-featured but requires C library dependency
   - **Manual encoding**: Implement subset of instruction encoding (complex but no dependencies)
   - **Inline assembly + object extraction**: Hacky but could work for MVP

   **Decision**: Use dynasmrt for its Rust-native approach and good AArch64 support

6. **ELF Patching Strategy**
   - Read original ELF into memory
   - Locate section containing optimization window
   - Replace instruction bytes with optimized sequence
   - Handle size differences:
     - If optimized < original: NOP padding
     - If optimized > original: Fail (or implement code relocation)
   - Update section headers if needed
   - Write modified ELF to new file

### Key Implementation Functions

```rust
fn parse_hex_address(s: &str) -> Result<u64, String> {
    // Parse hex addresses like "0x1234" or "1234"
}

fn validate_address_window(elf: &ElfBytes, start: u64, end: u64) -> Result<(), Error> {
    // Ensure addresses are valid and within executable sections
}

fn extract_instructions_in_window(
    cs: &Capstone,
    section_data: &[u8],
    base_addr: u64,
    start: u64,
    end: u64
) -> Vec<capstone::Insn> {
    // Extract instructions within address window
}

fn convert_to_ir(instructions: &[capstone::Insn]) -> Result<Vec<Instruction>, Error> {
    // Convert Capstone instructions to IR
    // Return error for unsupported instructions
}

fn ir_to_machine_code(instructions: &[Instruction]) -> Result<Vec<u8>, Error> {
    // Use dynasmrt to assemble IR back to machine code
}

fn patch_elf(
    original_elf: &[u8],
    section_offset: u64,
    window_offset: u64,
    original_code: &[u8],
    new_code: &[u8]
) -> Result<Vec<u8>, Error> {
    // Create patched ELF with new code
}
```

### Effort Estimate: 2-3 days
- CLI and address parsing: 2 hours
- Address validation: 2 hours
- IR conversion expansion: 4-6 hours
- dynasmrt integration: 8-12 hours
- ELF patching: 6-8 hours
- Testing and debugging: 4-6 hours

## Dependencies to Add

```toml
[dependencies]
# Existing dependencies...
dynasmrt = "2.0"  # For AArch64 assembly
dynasm = "2.0"    # Macro support for dynasmrt
```

## Testing Strategy

1. **Unit Tests**
   - Address parsing and validation
   - IR conversion for various instructions
   - Assembly/disassembly round-trip tests

2. **Integration Tests**
   - Test binaries with known optimization opportunities
   - Verify patched ELFs still execute correctly
   - Compare optimized vs original behavior

3. **Edge Cases**
   - Empty address windows
   - Windows spanning multiple sections
   - Unsupported instructions
   - Size constraint violations

## Risk Mitigation

1. **Instruction Coverage**: Start with subset of instructions already in IR
2. **Safety**: Always create new ELF file, never modify original
3. **Validation**: Extensive checks before patching
4. **Fallback**: If optimization fails, report why and skip

## Future Enhancements

1. Support more AArch64 instructions in IR
2. Multi-instruction pattern matching
3. Control flow graph analysis
4. Register allocation optimization
5. Profile-guided optimization hints
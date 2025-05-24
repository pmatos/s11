# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an AArch64 super-optimizer MVP written in Rust that demonstrates:
- ELF binary reading and disassembly for AArch64 binaries using Capstone engine
- IR representation for a subset of AArch64 instructions (ADD, MOV with register/immediate variants)
- Simplified equivalence checking with hardcoded patterns (SMT integration planned for future)
- Basic enumerative search for shorter equivalent instruction sequences

## Development Commands

This project uses `just` as the task runner. Common commands:

- `just build` - Build in debug mode
- `just release` - Build in release mode (optimized)
- `just run` - Build and run in debug mode
- `just run-release` - Build and run in release mode
- `just test` - Run tests
- `just check` - Check code without building
- `just fmt` - Format code
- `just clean` - Clean build artifacts

Standard Cargo commands also work:
- `cargo build`
- `cargo run`
- `cargo test`
- `cargo fmt`

### CI Checks

**IMPORTANT**: Before committing and pushing, always run `./ci_check.sh` to ensure your code will pass CI. This script runs:
1. Code formatting check (`cargo fmt -- --check`)
2. Clippy linting (`cargo clippy -- -D warnings`)
3. Project build
4. Unit tests
5. Test binary builds
6. Full test suite

This prevents pushing code that will fail CI checks.

## Dependencies

The project requires:
- Rust toolchain with 2021 edition support
- External crates: `elf`, `capstone`, `clap`, `z3`
- Capstone engine (usually installed via system package manager)
- Z3 SMT solver and development libraries (for semantic equivalence checking)
- `just` command runner for running build tasks (required by test_all.sh)

## Architecture

### Core Components

- **Command Line Interface** (`main.rs`): Uses `clap` for argument parsing with `--binary` and `--demo` options
- **ELF Binary Analysis** (`main.rs`): Reads AArch64 ELF files and disassembles executable sections using Capstone
- **IR Definition** (`ir/` module): 
  - `types.rs`: Defines `Register` enum (X0-X30, XZR, SP), `Operand`, and `Condition` types
  - `instructions.rs`: Defines `Instruction` enum covering AArch64 operations (MOV, ADD, SUB, AND, ORR, EOR, shifts)
- **SMT-based Equivalence Checking** (`semantics/` module):
  - `smt.rs`: Translates IR to SMT constraints using z3 bitvectors
  - `equivalence.rs`: Checks semantic equivalence of instruction sequences using SMT solving
- **Enumerative Search** (`main.rs`): Searches for shorter equivalent sequences (currently limited to length-1 candidates)

### Key Functions

- `analyze_elf_binary()` - Parses ELF files and disassembles text sections
- `are_sequences_equivalent()` - Pattern-based equivalence verification with hardcoded rules
- `generate_all_instructions()` - Generates all possible single instructions for search
- `find_shorter_equivalent()` - Enumerative optimization search
- `run_demo()` - Demonstrates IR optimization capabilities

The application has two modes: binary analysis (reads and disassembles AArch64 ELF files) and demo mode (shows IR-level optimization). The optimizer uses z3 SMT solver to verify semantic equivalence between instruction sequences. For example, it can prove that:
- `MOV X0, X1; ADD X0, X0, #1` is equivalent to `ADD X0, X1, #1`
- `MOV X0, #0` is equivalent to `EOR X0, X0, X0` (register clearing)
- `ADD X0, X1, X2` is equivalent to `ADD X0, X2, X1` (commutativity)
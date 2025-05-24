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

## Dependencies

The project requires:
- Rust toolchain with 2021 edition support
- External crates: `elf`, `capstone`, `clap`
- Capstone engine (usually installed via system package manager)

## Architecture

### Core Components

- **Command Line Interface** (`main.rs:10-22`): Uses `clap` for argument parsing with `--binary` and `--demo` options
- **ELF Binary Analysis** (`main.rs:26-95`): Reads AArch64 ELF files and disassembles executable sections using Capstone
- **IR Definition** (`main.rs:97-135`): Defines `Register` enum (X0, X1, X2) and `Instruction` enum covering basic AArch64 operations  
- **Equivalence Checker** (`main.rs:141-167`): Simplified pattern-based equivalence checking (hardcoded known optimizations)
- **Enumerative Search** (`main.rs:169-267`): Searches for shorter equivalent sequences (currently limited to length-1 candidates)

### Key Functions

- `analyze_elf_binary()` - Parses ELF files and disassembles text sections
- `are_sequences_equivalent()` - Pattern-based equivalence verification with hardcoded rules
- `generate_all_instructions()` - Generates all possible single instructions for search
- `find_shorter_equivalent()` - Enumerative optimization search
- `run_demo()` - Demonstrates IR optimization capabilities

The application has two modes: binary analysis (reads and disassembles AArch64 ELF files) and demo mode (shows IR-level optimization). The optimizer currently works with hardcoded equivalence patterns. For example, it recognizes that `MOV X0, X1; ADD X0, X0, #1` is equivalent to `ADD X0, X1, #1`.
# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

s11 is a superoptimizer written in Rust. It finds shorter or faster equivalent instruction sequences using multiple search strategies and SMT-based equivalence checking. Primary target is AArch64; x86-64 and x86-32 are supported through the shared ISA trait-backed optimization path; RISC-V is scaffold-only with no supported RISC-V opt path because machine-code emission is not yet implemented.

See [docs/capability.md](docs/capability.md) for the canonical instruction and ISA support matrix.

**Key Features:**
- ELF binary reading and disassembly using Capstone engine (auto-detects e_machine)
- **AArch64**: see [docs/capability.md](docs/capability.md) for the canonical mnemonic matrix. Full pipeline including stochastic/symbolic/hybrid/LLM search. Supported control-flow terminators are parsed, held fixed, and the search rewrites only the straight-line prefix.
- **x86-64 + x86-32**: see [docs/capability.md](docs/capability.md) for the canonical mnemonic matrix. Enumerative, stochastic (MCMC), and symbolic (SMT) search are supported. Hybrid and LLM remain AArch64-only.
- SMT-based equivalence checking using Z3 (width-parameterised for x86-32 vs x86-64)
- Multi-threaded parallel search with worker coordination
- ISA abstraction supporting AArch64 (primary), x86-64/x86-32, RISC-V (scaffolded)
- Binary patching for applying optimizations (per-arch alignment + NOP padding)

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
2. Project build
3. Unit tests
4. Test binary builds
5. Full test suite

This prevents pushing code that will fail CI checks.

Note: Clippy linting is run separately in the `rust-clippy.yml` workflow which performs security analysis and uploads results to GitHub's security tab.

### Code Coverage

Source-based coverage uses [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov). Install once with:

```
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

Local recipes:

- `just coverage` — HTML report at `target/llvm-cov/html/index.html`.
- `just coverage-lcov` — LCOV at `target/llvm-cov/lcov.info` (CI format).

Both recipes depend on `build-tests` so that AArch64 integration-test binaries are present.

In CI, `.github/workflows/coverage.yml` runs on PRs and pushes to `main`, collects LCOV across unit + integration tests, and uploads to [Codecov](https://codecov.io/) using the `CODECOV_TOKEN` repo secret. Project/patch thresholds live in `codecov.yml`.

### Benchmark suite (issue #70)

Criterion-driven benchmarks live under `benches/`. Three phases —
Hacker's Delight micro-suite (Phase 1), LLVM AArch64 codegen sample
(Phase 2), and an algebraic-identities catalog (Phase 3). The shared
harness (`load_sequence`, `run_bench`, `append_json`,
`discover_specs_in`) lives in `src/bench_support.rs` because criterion
benchmarks built with `harness = false` cannot run `#[test]` blocks
— the lib-test path is the only way to unit-test the helpers.

Each criterion sample emits one JSON-Lines record to
`benches/results/results.jsonl`. See `benches/README.md` for the schema
and how to add a fixture.

- `just bench` / `just bench-phase1` / `just bench-clean` are the entry
  points.
- Benchmarks are **not** wired into CI — full runs are tens of minutes
  and would burn through GitHub Actions budget.
- Reproducibility depends on a seeded `StochasticConfig`. The bench
  harness sets `spec.seed + sample_index` per record so runs are
  deterministic given the pair.
- Phase 2 fixtures are not committed; run
  `scripts/harvest_llvm_codegen.sh` to populate them.

### Mutation Testing (informational, local-only)

Mutation testing runs via [cargo-mutants](https://mutants.rs/) and is **informational only** — it does not gate merges. It is **not** wired into CI to keep GitHub Actions minutes for the test/clippy/CodeQL workflows.

- `just mutants` — full run via `scripts/run-mutants.sh` (slow; expect >30 min).
- `just mutants -- --diff` — mutants only on the local diff vs `origin/main`.
- `just mutants -- --shard 0/8` — one shard of an 8-way split for parallel local runs.
- Configuration lives in `.cargo/mutants.toml` (cargo-mutants reads this path automatically).
- The wrapper prints a caught/missed/timeout/unviable summary via `scripts/mutants_summary.py`.

## Dependencies

The project requires:
- Rust toolchain with 2024 edition support
- External crates: `elf`, `capstone`, `clap`, `z3`, `rayon`, `crossbeam-channel`, `dynasmrt`/`dynasm` (both ship aarch64 + x64 + x86 backends in default features)
- Capstone engine (usually installed via system package manager) — auto-detects x86 and arm64 modes
- Z3 SMT solver and development libraries (for semantic equivalence checking)
- `just` command runner for running build tasks (required by test_all.sh)
- For building x86 test binaries via `build_tests.sh`:
  - Host `gcc` for x86-64 (produced into `binaries/x86_64/`)
  - `gcc -m32` for x86-32 (requires `gcc-multilib`; gracefully skipped if absent)

## Architecture

### Module Structure

```
src/
├── main.rs              # CLI; shared AArch64 + x86 opt driver with per-arch hooks
├── ir/                  # AArch64 IR (Register, Operand, Condition, Instruction)
│   ├── types.rs
│   └── instructions.rs
├── isa/                 # ISA Abstraction Layer
│   ├── traits.rs        # ISA trait definitions used by AArch64/x86 consumers
│   ├── aarch64.rs       # AArch64 backend
│   ├── riscv.rs         # RISC-V backend (trait scaffolding only, no opt path)
│   └── x86.rs           # x86 backend (X86_64 + X86_32; full vertical slice)
├── semantics/           # Execution semantics
│   ├── concrete.rs      # AArch64 concrete interpreter
│   ├── concrete_x86.rs  # x86 concrete interpreter (width-aware)
│   ├── smt.rs           # AArch64 SMT lowering (64-bit BVs)
│   ├── smt_x86.rs       # x86 SMT lowering (width-parameterised BVs)
│   ├── cost.rs          # AArch64 cost model
│   ├── cost_x86.rs      # x86 cost model (variable-length CodeSize)
│   ├── equivalence.rs   # Generic equivalence entry points (AArch64 + x86)
│   └── state.rs         # Machine state: ConditionFlags (NZCV), Eflags, concrete/symbolic states. RegisterSet<R> lives in live_out.rs.
├── search/              # Search algorithms generic over ISA where supported
│   ├── candidate.rs     # Candidate and encodability helpers
│   ├── enumerative/     # Exhaustive search up to target.len()-1 (AArch64 + x86)
│   ├── stochastic/      # MCMC with Metropolis-Hastings (AArch64 + x86)
│   ├── symbolic/        # SMT-based synthesis (AArch64 + x86)
│   ├── parallel/        # Multi-threaded coordination (AArch64)
│   └── llm/             # LLM-assisted search via Codex CLI (AArch64)
├── validation/          # Input validation
│   ├── live_out.rs      # Live-out register tracking (AArch64 + x86)
│   └── random.rs        # Random input generation (AArch64)
├── assembler/           # Machine code generation (dynasm)
│   ├── mod.rs           # AArch64Assembler
│   └── x86.rs           # X86Assembler (Mode64 / Mode32)
└── elf_patcher/         # ELF read/patch with DetectedArch (AArch64/X86_64/X86_32)
```

### Adding a new AArch64 instruction

There are two text-to-IR entry points and they MUST cover the same mnemonic set:

- `src/parser/mod.rs::parse_line` — GNU assembler syntax (drives `s11 equiv`, `.s` inputs, round-trip tests).
- `src/main.rs::convert_to_ir` — Capstone disassembly of ELF binaries (drives `s11 opt <elf>`).

To prevent drift, `convert_to_ir` does NOT maintain its own mnemonic switch — it formats `"{mnemonic} {op_str}"` and delegates to `parser::parse_line`. **Adding a new mnemonic means adding it to the parser only**; the binary path picks it up automatically. Do not reintroduce a parallel match-on-mnemonic in `convert_to_ir`.

The regression test `convert_capstone_op_handles_all_supported_aarch64_mnemonics` in `src/main.rs` pins one canonical operand string per supported mnemonic — extend it whenever you add an opcode so a future Capstone-syntax regression on that mnemonic fails loudly.

For instructions with multiple destinations (LDP, pre/post-index writeback), use `Instruction::destinations() -> Vec<Register>` rather than the singleton `destination() -> Option<Register>`. Memory ops are non-terminator, do not modify NZCV, and have observable memory side effects — `has_side_effects()` and `EquivalenceConfig::memory_live` model the latter. See ADR-0007 for the design.

### Search Algorithms

1. **Enumerative**: Exhaustively enumerate candidate sequences
2. **Stochastic**: MCMC with mutation operators (opcode, operand, swap, instruction)
3. **Symbolic**: SMT-based synthesis with cost bounding
4. **Hybrid**: Parallel combination of symbolic + stochastic workers

### Key CLI Options

```bash
# Disassemble a binary (auto-detects arch from ELF; --arch is optional)
s11 disasm <file>
s11 disasm --arch x86-64 <file>

# Optimize a code region
s11 opt <file> --start-addr <hex> --end-addr <hex>

# Architecture selection
s11 opt ... --arch [aarch64|x86-64|x86-32]    # riscv32/64 still rejected

# Algorithm selection
s11 opt ... --algorithm [enumerative|stochastic|symbolic|hybrid|llm]

# x86 supports enumerative, stochastic, and symbolic. Hybrid and LLM
# remain AArch64-only.

# Parallel execution
s11 opt ... --cores <n> --timeout <seconds>

# Stochastic parameters
s11 opt ... --beta <inverse-temp> --iterations <n>
```

### Equivalence Checking

The optimizer verifies semantic equivalence using:
1. **Fast validation**: Random input testing (16 test cases)
2. **SMT verification**: Z3 bitvector constraints for formal proof

Example equivalences the optimizer can prove:
- `MOV X0, X1; ADD X0, X0, #1` ≡ `ADD X0, X1, #1`
- `MOV X0, #0` ≡ `EOR X0, X0, X0`
- `ADD X0, X1, X2` ≡ `ADD X0, X2, X1` (commutativity)

## Commit Guidelines

- Do not mention code being co-authored or generated by Claude in commits.

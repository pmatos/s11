# s11

An AArch64 superoptimizer written in Rust. Given a window of machine
instructions inside an ELF binary, s11 searches for a shorter or faster
sequence that is provably equivalent under SMT.

> Research / experiment. APIs and CLI flags change without notice.

## What it does

- Reads an ELF binary, disassembles it with [Capstone], and lifts a window
  into an internal IR.
- Searches for a cheaper instruction sequence using one of four
  algorithms: enumerative, stochastic (MCMC / Metropolis–Hastings),
  symbolic (SMT synthesis with Z3), or a hybrid of the symbolic and
  stochastic workers running in parallel.
- Verifies each candidate first with random-input testing for a quick
  reject, then with [Z3] over bitvector constraints for a formal proof.
- Patches the verified replacement back into the binary.

The IR currently covers 20 AArch64 integer instructions: `MOV`, `ADD`,
`SUB`, `AND`, `ORR`, `EOR`, `LSL`, `LSR`, `ASR`, `MUL`, `SDIV`, `UDIV`,
`CMP`, `CMN`, `TST`, `CSEL`, `CSINC`, `CSINV`, `CSNEG`. There is also a
RISC-V (rv32 / rv64) backend behind the same ISA trait.

[Capstone]: https://www.capstone-engine.org/
[Z3]: https://github.com/Z3Prover/z3

## Building

System dependencies (Debian / Ubuntu names):

```
libcapstone-dev gcc-aarch64-linux-gnu z3 libz3-dev
```

Plus a stable Rust toolchain (2024 edition) and [`just`].

[`just`]: https://just.systems/

```
just build         # debug build
just release       # optimized build
just test          # cargo test
just check         # cargo check, no codegen
just fmt           # cargo fmt
```

Before pushing, run `./ci_check.sh` to mirror the test workflow locally:
fmt check, build, AArch64 test binaries, full test suite.

## Using it

```
s11 <COMMAND>
```

`disasm` — pretty-print an ELF binary's `.text`:

```
s11 disasm path/to/binary
```

`opt` — search for a cheaper equivalent of a window:

```
s11 opt path/to/binary \
    --start-addr 0x1000 --end-addr 0x1100 \
    --algorithm hybrid \
    --cores 8 --timeout 60
```

Useful flags on `opt`:

| flag | meaning |
| --- | --- |
| `--algorithm enumerative\|stochastic\|symbolic\|hybrid\|llm` | search strategy (default: `enumerative`) |
| `--cost-metric instruction-count\|latency\|code-size` | what to minimize (default: `instruction-count`) |
| `--cores N` | worker threads for `hybrid` |
| `--timeout SECS` | wall-clock budget for the search |
| `--beta`, `--iterations`, `--seed` | MCMC tuning for `stochastic` |
| `--search-mode linear\|binary`, `--solver-timeout SECS` | SMT synthesis tuning |
| `--no-symbolic` | run hybrid as all-stochastic workers |

`equiv` — check whether two assembly files are semantically equivalent
on a chosen live-out set:

```
s11 equiv a.s b.s --live-out x0,x1 --timeout 30
```

`llm-opt` — experimental driver that asks an LLM (via the `codex` CLI) to
propose candidates that are then verified the same way as any other
search result.

## Repository layout

```
src/
├── main.rs           # CLI, ELF I/O, top-level orchestration
├── ir/               # Register, Operand, Condition, Instruction
├── isa/              # ISA trait + AArch64 / RISC-V backends
├── semantics/        # Concrete + symbolic interpreters, equivalence,
│                     # cost model, machine state
├── search/           # enumerative / stochastic / symbolic / parallel
├── validation/       # live-out tracking, random-input generator
└── assembler/        # dynasm-based code emission
```

`tests/` contains C sources that are cross-compiled by `build_tests.sh`
into AArch64 test binaries under `binaries/`, plus Rust integration
tests that exercise `disasm` / `opt` end-to-end.

## Testing

```
just test            # cargo test (unit + integration)
just build-tests     # cross-compile the AArch64 test binaries
just test-all        # build + run ./test_all.sh end-to-end demo
./ci_check.sh        # what CI runs before push
```

### Mutation testing (informational, local-only)

s11 uses [cargo-mutants] to surface tests that are too weak to detect
deliberate code mutations. It is **informational only** and is not
wired into CI — running it on every PR was burning more GitHub Actions
minutes than the project can afford.

[cargo-mutants]: https://mutants.rs/

```
cargo install --locked cargo-mutants

just mutants                     # full run, expect >30 min
just mutants -- --diff           # only mutants in the local diff vs origin/main
just mutants -- --diff main      # diff vs an explicit base ref
just mutants -- --shard 0/8      # one shard of an 8-way split
just mutants -- -- --foo         # forward extra flags to cargo-mutants
```

The wrapper lives at `scripts/run-mutants.sh` and prints a
caught/missed/timeout/unviable summary at the end via
`scripts/mutants_summary.py`. Configuration lives in
`.cargo/mutants.toml`.

## License

Licensed under [MIT](LICENSE).

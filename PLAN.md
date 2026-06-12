# Plan - issue #175: Add `test_generate_random_reaches_madd_family`

## 1. Problem Restated

Issue #175 asks for a focused regression test proving that the AArch64 random candidate generator still reaches the multiply-accumulate instruction family after the dispatch slot that used to be the catch-all became an explicit `29 =>` arm. The existing exhaustive generator already covers `Madd`, `Msub`, `Mneg`, `Smulh`, and `Umulh`, but the stochastic path needs its own fixed-seed 5000-draw guard over `generate_random_instruction` so future refactors cannot silently make opcode IDs `42..=46` unreachable.

## 2. Files To Touch

- `src/search/candidate.rs` - add one unit test in the existing `#[cfg(test)] mod tests`, near the current random reachability tests and reusing `random_opcode_ids(seed, draws)`.

No production code should change unless the new test unexpectedly exposes a real mismatch in the current generator. There are no `crates/` or `compiler/` directories in this repository, so this is not a Rust-stage/self-hosted cross-cutting change. There is no `docs/spec/` tree; `docs/capability.md` and the ADRs do not need updates because this PR adds coverage for already-documented AArch64 support rather than changing syntax, semantics, CLI flags, contracts, or supported mnemonics.

## 3. TDD Slices

1. Add the regression test skeleton in `src/search/candidate.rs`, immediately after `test_generate_random_reaches_csel_family` (currently around lines 1211-1258). Name it `test_generate_random_reaches_madd_family`. It should call `let ids = random_opcode_ids(0x66, 5_000);`, matching the nearby fixed-seed random reach tests.

2. In that test, assert that `ids` contains `opcode_id` for representative instructions for each family member:
   - `Instruction::Madd { rd: X0, rn: X1, rm: X2, ra: X0 }` -> opcode ID 42
   - `Instruction::Msub { rd: X0, rn: X1, rm: X2, ra: X0 }` -> opcode ID 43
   - `Instruction::Mneg { rd: X0, rn: X1, rm: X2 }` -> opcode ID 44
   - `Instruction::Smulh { rd: X0, rn: X1, rm: X2 }` -> opcode ID 45
   - `Instruction::Umulh { rd: X0, rn: X1, rm: X2 }` -> opcode ID 46
   Use the same `(label, instr)` loop and failure message shape as `test_generate_random_reaches_mul_div_family`, `test_generate_random_reaches_compare_family`, and `test_generate_random_reaches_csel_family` (lines 1140-1258).

3. Red-check the test as a regression guard without committing sabotage: temporarily alter the random dispatch locally so slot 29 no longer emits the MADD family, for example by making arm `29` emit only an existing non-MADD instruction, then run:
   ```bash
   cargo test search::candidate::tests::test_generate_random_reaches_madd_family -- --exact
   ```
   Confirm the new test fails with a "random never produced ..." assertion, then immediately revert the temporary production-code mutation.

4. Green-check against the real code. The production implementation that should satisfy the test already exists at `src/search/candidate.rs:804-821`: slot `29` samples `rng.random_range(0..5)` and emits `Madd`, `Msub`, `Mneg`, `Smulh`, or `Umulh`. Run the targeted test again and expect it to pass.

5. Refactor only if the test body duplicates enough local boilerplate to be worth a tiny cleanup. Prefer keeping the test parallel to the three existing random reachability tests over introducing a new abstraction. Do not change opcode numbering, random dispatch probabilities, candidate generation behavior, or documentation.

## 4. Verification Surface

- No ESBMC proof work is needed. This does not touch contracts, codegen, the C model, SMT lowering, concrete semantics, parser behavior, or the binary patching path.
- No `tests/run/`, `tests/asm/`, `tests/integration/`, `examples/`, or benchmark fixtures should grow.
- Minimum verification:
  ```bash
  cargo test search::candidate::tests::test_generate_random_reaches_madd_family -- --exact
  ```
- Broader local verification before PR/commit:
  ```bash
  cargo test search::candidate
  cargo fmt -- --check
  ```
- Full pre-push verification remains the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- Fixed-seed brittleness: `0x66` with 5000 draws is already used by nearby random reach tests and should have an extremely large margin for a 1-in-33 outer slot and 1-in-5 subslot, but if `rand_chacha` or the dispatch ordering changes later this test may fail honestly because the fixed trace changed.
- Test runtime: 5000 draws are cheap and already match nearby tests, so keep the new test at the requested size and avoid expanding it into a statistical stress test.
- Opcode ID coupling: the assertions intentionally use `opcode_id(&instr)` rather than hard-coded numbers in the test body. The issue's expected range is still documented in this plan and pinned by the representative instruction variants.
- Clippy/format gate: the added test should not introduce unused imports or dead helper functions. Reuse existing imports from `super::*`, `default_registers`, `default_immediates`, and `random_opcode_ids`.
- Parse/print/parse idempotency and binary fixed point are unaffected because no parser, printer, codegen, ordering-sensitive maps, stack-slot layout, or `vow-clif-shim`-style component exists in this repo slice.

## 6. Out Of Scope

- Changing `generate_random_instruction` dispatch weights, slot count, or sub-multiplexer structure.
- Adding exhaustive-generator tests for the MADD family; `generate_all_instructions` already emits these variants at `src/search/candidate.rs:249-259`.
- Adding docs or capability-matrix entries for `madd`, `msub`, `mneg`, `smulh`, or `umulh`; `docs/capability.md` already lists multiply-accumulate support.
- Renumbering `opcode_id`, synchronizing with `src/isa/aarch64.rs`, or broadening the opcode-ID uniqueness tests.
- Refactoring the existing random reach tests into a table-driven helper.
- Running or modifying benchmark, integration, x86, RISC-V, parser, assembler, semantics, or LLM search code.

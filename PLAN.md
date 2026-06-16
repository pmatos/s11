# Plan: Consolidate AArch64 opcode IDs

## 1. Problem Restated

`src/search/candidate.rs` defines a free `opcode_id(&Instruction) -> u8` match table that mirrors the canonical `InstructionType::opcode_id` implementation for `Instruction` in `src/isa/aarch64.rs`. This hand-synchronised duplicate makes each new AArch64 IR variant a two-site update and required an extra drift test. The implementation should remove the search-layer copy and route every `candidate.rs` opcode-ID use through the existing `InstructionType` trait method.

## 2. Files To Touch

- `src/search/candidate.rs`: update same-file test/helper call sites from the free `opcode_id` function to `InstructionType::opcode_id` or `.opcode_id()`, remove the free function at lines 999-1081, and remove or rewrite the now-obsolete drift test at lines 1690-1742.
- `src/isa/aarch64.rs`: no production change expected; this remains the canonical opcode-ID table in `impl InstructionType for Instruction` at lines 182-270. Use existing tests here as the backend safety net.
- `src/isa/traits.rs`: no change expected; `InstructionType::opcode_id` already exists at lines 112-113.
- No `crates/` or `compiler/` paths exist in this repository, so there is no cross-compiler update.
- No `docs/spec/*.md` updates are required because this is an internal Rust refactor with no syntax, semantics, builtin, operator, effect, or CLI behavior change. This repository also has no `docs/spec/` directory.

## 3. TDD Slices

1. **Compile-fail consumer audit**
   - Test/location: `src/search/candidate.rs` unit tests that currently call the free function, especially `test_generate_all_instructions_covers_issue_66_opcodes` at lines 1201-1221, `random_opcode_ids` at lines 1223-1232, `test_opcode_id_unique` at lines 1630-1688, and `test_bitfield_opcode_id_matches_isa_backend` at lines 1690-1742.
   - Red: remove or temporarily hide `candidate::opcode_id`; `cargo test candidate::` should fail at every remaining free-function call.
   - Green: update those call sites to use `InstructionType::opcode_id` or `.opcode_id()`. Keep stable literal checks such as `10u8..=19`; only change the source of the ID value.
   - Production code: no behavior change yet beyond call-site routing.

2. **Remove the duplicated table**
   - Test/location: same `src/search/candidate.rs` unit test module plus repository search.
   - Red: after deleting the free function at lines 999-1081, `rg -n "map\\(opcode_id\\)|opcode_id\\(&|candidate::opcode_id|fn opcode_id" src/search` should show no AArch64 candidate helper references.
   - Green: rely on `InstructionType::opcode_id` from the existing import at `src/search/candidate.rs:5`; add a local `use crate::isa::InstructionType;` inside the test module only if method resolution stops being obvious after edits.
   - Production code: delete `pub fn opcode_id` entirely, including `#[allow(dead_code)]` and comments that say the table mirrors `src/isa/aarch64.rs`.

3. **Retire the drift test without losing useful coverage**
   - Test/location: `src/search/candidate.rs::test_bitfield_opcode_id_matches_isa_backend` at lines 1690-1742.
   - Red: once the free function is gone, the old assertion would become `instr.opcode_id() == instr.opcode_id()` and no longer catches anything.
   - Green: either delete this sync test as redundant, or convert it into a stable-value guard for the bitfield aliases using literal expected IDs `49..=54`. Prefer deletion if `src/isa/aarch64.rs::all_instruction_families_cover_trait_methods` and candidate bitfield generation tests already give enough coverage.
   - Production code: none.

4. **Regression and formatting pass**
   - Test/location: affected unit tests in `src/search/candidate.rs` and `src/isa/aarch64.rs`.
   - Red: run the narrow tests before and after cleanup to catch accidental ID or import changes.
   - Green: run `cargo test candidate::`, `cargo test isa::aarch64::tests::all_instruction_families_cover_trait_methods`, and `cargo fmt -- --check`. If time permits in implementation, run `just check` or the full `./ci_check.sh` before opening the PR.
   - Production code: only formatting required by Rustfmt.

## 4. Verification Surface

- Contracts, codegen, the C model, and ESBMC properties are not touched. No Vow `.vow` contracts or ESBMC proofs apply to this s11 Rust refactor.
- No `tests/run/` or `examples/` fixtures need to grow; this does not affect parse, print, assembly, disassembly, equivalence, or CLI output.
- Verification should focus on Rust compile/test coverage and static search:
  - `rg -n "opcode_id" src/search/` should show only legitimate trait test method calls or comments, not a search-layer helper table.
  - `cargo test candidate::` should keep candidate generator behavior intact.
  - `cargo test isa::aarch64::tests::all_instruction_families_cover_trait_methods` should keep the canonical opcode-count invariant intact.

## 5. Risk Areas

- Method-call trait resolution: `.opcode_id()` requires `InstructionType` in scope; `candidate.rs` already imports it at line 5, but tests should be checked after deleting the helper.
- Test tautology: the old drift test must not survive as a self-comparison after the free function is removed.
- Stable opcode ID expectations: tests around issue #66 intentionally use literal range `10..=19`; do not rewrite these to derive the values from representatives, because that would hide renumbering.
- Search comments: remove or update comments that claim `candidate.rs` owns or mirrors an opcode table so future contributors do not reintroduce the duplicate.
- `cargo clippy --all -- -D warnings`: deleting the free function should remove one `#[allow(dead_code)]`, but new imports must not be unused.
- Binary fixed point, parse-print-parse idempotency, codegen ordering, map ordering, and stack-slot layout are not involved.

## 6. Out Of Scope

- Renumbering opcode IDs or changing `AArch64InstructionGenerator::opcode_count`.
- Consolidating `generate_all_instructions` with `AArch64InstructionGenerator::generate_all`; those are broader duplicated candidate-generation paths.
- Refactoring x86, RISC-V, symbolic sketch opcode constants, or stochastic mutation opcode-selection tables.
- Changing instruction semantics, parser behavior, assembler encodability, CLI flags, docs capability tables, or benchmark fixtures.
- Running `sudo`, modifying `symphony/` if present, or editing anything under gitignored `build/`.

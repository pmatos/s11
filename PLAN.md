# Plan: Reconcile AArch64 Random-Generator Slot Notes

## 1. Problem Restated

The issue is a reader-confusion/documentation problem, not a requested behavior change. The two AArch64 random-instruction generators cover overlapping instruction families but use independent 33-slot dispatch tables: in the current tree, `src/isa/aarch64.rs::AArch64InstructionGenerator::generate_random` has `ANDS` at slot 23 and `CSET`/`CSETM`/`ROR` at slots 30/31/32 after issue #93 removed the old slot-23 sub-multiplexer, while `src/search/candidate.rs::generate_random_instruction` has `ROR` at slot 23 and places `ANDS`/`CSET`/`CSETM` at slots 20/21/22. The implementation should add paired cross-reference comments that make this parallel-but-not-slot-identical relationship explicit and should not change random sampling behavior.

## 2. Files to Touch

- `src/isa/aarch64.rs` around `AArch64InstructionGenerator::generate_random` at lines 689-706: add a short note that this slot table is local to the ISA trait generator and is not slot-number-aligned with `src/search/candidate.rs::generate_random_instruction`.
- `src/search/candidate.rs` around `generate_random_instruction` at lines 605-620, or immediately above the slot-23 `ROR` arm at lines 763-767: add the reciprocal note that this search candidate sampler has its own slot layout and that slot 23 is `ROR` here.
- No `crates/` or `compiler/` paths exist in this s11 workspace, so there is no cross-compiler update.
- No `docs/spec/*.md` directory exists. `docs/capability.md` and `docs/adr/*.md` do not need updates because this plan does not change syntax, semantics, capabilities, CLI flags, contracts, or architecture decisions.
- Do not touch `src/ir/*`, `src/semantics/*`, `src/main.rs`, x86/RISC-V code, `build/`, or any submodule.

## 3. TDD Slices

1. Characterize the current behavior before comments.
   - Test location: existing `src/isa/aarch64.rs` test `slot_23_sub_multiplexer_removed_for_issue_93` near lines 2474-2525; existing `src/search/candidate.rs` tests `test_generate_random_instruction` near lines 1546-1556 and `candidate_pool_excludes_terminators` near lines 1594-1617.
   - Behavior under test: random generation still emits valid/non-terminator AArch64 instructions, and the ISA generator keeps the issue #93 invariant that `ANDS`, `CSET`, `CSETM`, and `ROR` are no longer hidden behind one low-probability sub-multiplexer.
   - Production code to make it pass: none; these are existing characterization checks. Do not add a synthetic failing test for comments.
2. Add the cross-reference comments.
   - Test location: same focused tests as slice 1; comments have no runtime behavior to test directly.
   - Behavior under test: unchanged random-generation behavior.
   - Production code to make it pass: comment-only edits in `src/isa/aarch64.rs` and `src/search/candidate.rs` explaining that the two slot tables are parallel sources, not synchronized layouts.
3. Refactor/readability pass.
   - Test location: no new test file.
   - Behavior under test: no behavior change; comments remain accurate when checked against the adjacent `match` arms.
   - Production code to make it pass: keep comments concise, avoid restating stale issue text that says the ISA generator still has a 4-way slot-23 sub-mux, and avoid unrelated formatting churn.

## 4. Verification Surface

- Run the narrow existing checks after the comment edit:
  - `cargo test slot_23_sub_multiplexer_removed_for_issue_93`
  - `cargo test test_generate_random_instruction`
  - `cargo test candidate_pool_excludes_terminators`
- Run `cargo fmt -- --check` to catch accidental formatting churn. Before a PR, follow repo policy and run `./ci_check.sh` if time/resources allow.
- No contracts, codegen, C model, Vow files, or ESBMC properties are touched. No `tests/run/` or `examples/` fixture growth is needed.

## 5. Risk Areas

- The issue body is stale in one detail: the current `isa/aarch64.rs` generator no longer uses a 4-way slot-23 sub-multiplexer. Comments must describe the current layout, not the old one.
- Renumbering slots or trying to make the two generators layout-identical would change stochastic sampling behavior and is out of scope for this documentation pass.
- Adding a probabilistic test just to prove comment accuracy would add flake risk. Use the existing focused tests unless implementation accidentally changes behavior.
- `cargo clippy --all -- -D warnings` should be unaffected by comment-only edits, but avoid adding unused helpers or test-only code.
- Parse/print idempotency, binary fixed points, `BTreeMap`/`HashMap` ordering, stack-slot layout, and codegen ordering are not affected because no parser, compiler, or codegen path changes.

## 6. Out of Scope

- Consolidating the two random generators into one shared `InstructionGenerator` or shared slot-table abstraction.
- Changing opcode IDs, slot counts, probability weights, random seeds, or instruction-family coverage.
- Adding/removing AArch64 instruction semantics, parser support, assembler support, or capability documentation.
- Refactoring stochastic mutation, enumerative generation, x86/RISC-V generation, or unrelated comments.

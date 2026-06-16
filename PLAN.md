# Plan: CCMP/CCMN Follow-Up Coverage

## 1. Problem Restated

Issue #137 is a narrow test-hardening pass for CCMP/CCMN support: directly pin the `find_first_difference` flag-difference sentinel when NZCV is live, expand the bounded CCMP/CCMN NZCV sample set to include the N-only literal `8`, and clarify the parser/encodability contract for `ccmp` with `al`/`nv` condition strings. The current repository is Rust-only `s11`; there is no `crates/`, `compiler/`, or `docs/spec/` tree to update, so this is not a cross-compiler or language-spec change.

## 2. Files To Touch

- `src/semantics/concrete.rs`
  - Add a unit test near existing `test_find_first_difference` at lines 1253-1275.
  - Existing production surface: `find_first_difference` at lines 782-807 already supports the `Register::XZR` flag sentinel and packed `N<<3 | Z<<2 | C<<1 | V` values.
- `src/search/candidate.rs`
  - Update `CCMP_NZCV_SAMPLES` at line 368 from `[0, 1, 7, 15]` to `[0, 1, 7, 8, 15]`.
  - Add a focused generator test in the existing `#[cfg(test)]` module after the compare-family coverage around lines 1437-1478.
- `src/isa/aarch64.rs`
  - Update the mirrored `CCMP_NZCV_SAMPLES` at line 537 from `[0, 1, 7, 15]` to `[0, 1, 7, 8, 15]` because the surrounding comment says it mirrors `candidate.rs::generate_all_instructions`.
  - No separate test is required unless an existing AArch64 generator test already provides a natural place for the same assertion.
- `src/parser/mod.rs`
  - Add a parser unit test near existing CCMP parser tests at lines 2509-2521.
  - Existing production surfaces: `parse_ccmp_like` parses the condition token at lines 1481-1504; `parse_line` applies the final `is_encodable_aarch64` gate at lines 1939-1944.
- `src/ir/instructions.rs`
  - No intended edit, but the parser test should rely on the existing contract at lines 920-942: `Instruction::Ccmp`/`Instruction::Ccmn` with `Condition::AL` or `Condition::NV` are rejected by `is_encodable_aarch64`.
- No `docs/spec/*.md` updates: `docs/spec/` is absent and the change does not alter syntax, CLI, semantics, or documented capability.
- No `tests/run/`, `examples/`, `crates/`, or `compiler/` updates: those paths are absent or unrelated in this repo.

## 3. TDD Slices

1. Add the `find_first_difference` flag-sentinel test.
   - Test location: `src/semantics/concrete.rs`, adjacent to `test_find_first_difference`.
   - Red test: create two `ConcreteMachineState`s with identical live-out registers and divergent `ConditionFlags`, call `find_first_difference(&state1, &state2, &live_out, true)`, and assert `Some((Register::XZR, ConcreteValue(8), ConcreteValue(4)))` for N-only vs Z-only flags.
   - Production code to make it pass: none expected; if it fails, fix only `find_first_difference` packing/sentinel logic at lines 795-807.
   - Keep an adjacent negative assertion optional but useful: same divergent flags with `flags_live=false` returns `None` when registers match.

2. Pin the N-only CCMP/CCMN candidate sample in `search::candidate`.
   - Test location: `src/search/candidate.rs`, inside the existing tests module after `test_generate_all_instructions_contains_plain_compare_family`.
   - Red test: call `generate_all_instructions(&[Register::X0, Register::X1], &[0])` and assert it contains both `Instruction::Ccmp { rn: X0, rm: Operand::Register(X1), nzcv: 8, cond: Condition::MI }` and `Instruction::Ccmn { rn: X0, rm: Operand::Immediate(0), nzcv: 8, cond: Condition::PL }`.
   - Production code to make it pass: change `const CCMP_NZCV_SAMPLES` in `src/search/candidate.rs` to `[0, 1, 7, 8, 15]`.
   - Refactor/consistency step: update the mirrored constant in `src/isa/aarch64.rs` to the same five-entry array so trait-based generation stays aligned with the primary candidate generator.

3. Pin the CCMP AL/NV parser boundary.
   - Test location: `src/parser/mod.rs`, adjacent to `parse_ccmp_rejects_out_of_range_nzcv` and `parse_ccmp_rejects_out_of_range_imm5`.
   - Red test: for `ccmp x1, x2, #0, al` and `ccmp x1, x2, #0, nv`, assert `parse_line` returns `Err(ParseLineError::Other(msg))` where `msg` contains `instruction cannot be encoded in AArch64`.
   - Contract to document in the test name/comment: `parse_condition` accepts `al`/`nv` syntactically, but `parse_line` rejects these CCMP forms at the final `is_encodable_aarch64` boundary. Do not change `parse_line` to return an unencodable instruction.
   - Production code to make it pass: none expected; if it fails as an unknown condition, fix only condition-token plumbing; if it succeeds, restore the existing encodability rejection in `src/ir/instructions.rs`.

4. Optional CCMN parity only if the implementation remains tiny.
   - Test location: same parser test in `src/parser/mod.rs`.
   - Red test: include `ccmn x1, x2, #0, al` and `ccmn x1, x2, #0, nv` in the same rejection table.
   - Production code to make it pass: none expected, because `Instruction::Ccmp` and `Instruction::Ccmn` share the `is_encodable_aarch64` arm.

## 4. Verification Surface

- Run focused tests first:
  - `cargo test semantics::concrete::tests::test_find_first_difference`
  - `cargo test search::candidate::tests::test_generate_all_instructions`
  - `cargo test parser::tests::parse_ccmp`
- Then run the project gate recommended by `CLAUDE.md` before handoff/PR:
  - `./ci_check.sh`
- No ESBMC properties are needed: this repository is Rust `s11`, not the Vow compiler/C model workspace described by the generic run template.
- No contract/codegen changes are planned. The only production changes are bounded sample-table updates in candidate generators.
- No `tests/run/` or `examples/` fixtures need to grow; existing unit tests are the right granularity for this coverage issue.

## 5. Risk Areas

- `parse_line` idempotency: do not make `parse_line` return unencodable CCMP/CCMN instructions just to satisfy the phrase "round-trip"; its final encodability validation is a repository contract at `src/parser/mod.rs:1939`.
- AL/NV ambiguity: current source rejects CCMP/CCMN `AL`/`NV` in `is_encodable_aarch64`; tests should pin rejection at that boundary, not at condition-token parsing.
- Candidate-count drift: adding one NZCV sample increases the CCMP/CCMN product space. Keep the change to the single N-only literal and avoid expanding imm/register/condition domains.
- Mirror drift: `src/isa/aarch64.rs` says its sample table mirrors `src/search/candidate.rs`; update both or explicitly remove that claim.
- Clippy gate: avoid needless allocations or brittle full-vector scans beyond simple `.iter().any(...)` assertions; keep imports minimal and use existing test style.
- Binary fixed point / codegen ordering: not applicable here because no self-hosted compiler, stack-slot layout, `BTreeMap` ordering, or codegen path is touched.

## 6. Out Of Scope

- No refactor of `find_first_difference`, `states_equal_for_live_out`, or the TODO #282 redundant `flags_live` parameter.
- No change to CCMP/CCMN AL/NV policy in `is_encodable_aarch64`, assembler lowering, concrete semantics, or SMT semantics.
- No expansion of `CCMP_IMM5_SAMPLES`, register pools, condition pools, stochastic mutation probabilities, or benchmark fixtures.
- No documentation edits beyond the local test comment/name, because capability and ADR documents already cover CCMP/CCMN and flag-live semantics at the right level.
- No formatting-only churn outside files touched by these tests and sample constants.

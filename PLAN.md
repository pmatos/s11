# Plan - issue #135: Audit `OperandType::as_register` callers for `ShiftedRegister` awareness

## 1. Problem Restated

`src/isa/aarch64.rs::impl OperandType for Operand` correctly returns `None` for `Operand::ShiftedRegister` because the trait method means "plain register operand", not "operand containing a register". The issue is to audit whether any caller uses `as_register().is_some()` or `is_register()` as a broader "register-capable" predicate, which would accidentally classify `ShiftedRegister` as immediate-like and drop valid AArch64 shifted-register candidates. The live caller graph shows no AArch64 production caller currently does this; implementation should preserve that behavior, add focused characterization coverage, and document the audit result in the PR body rather than changing search semantics.

## 2. Files to Touch

Implementation edits:

- `src/isa/aarch64.rs` - extend the existing `tests::test_operand_traits` at lines 1969-1982 with `ShiftedRegister` and `ExtendedRegister` assertions. This is test-only coverage for the trait contract.
- `src/isa/traits.rs` - clarify the doc comments for `OperandType::as_register` and `OperandType::is_register` at lines 66-80 so future generic callers know this means a plain register operand, not any operand shape that contains a register.

Audit-only files to inspect, but not edit unless the audit proves the current premise wrong:

- `src/ir/instructions.rs` - `is_encodable_aarch64` handles shifted-register legality at lines 720-769 and 796-806; `source_registers` extracts inner shifted registers at lines 988-1039; `test_source_registers_shifted_register` starts at line 2185.
- `src/search/candidate.rs` - candidate enumeration already creates shifted-register forms at lines 100-128 and has a regression test at lines 1325-1341.
- `src/search/stochastic/mutation.rs` - mutation bridges directly pattern-match shifted/extended register operands at lines 39-47 and can generate shifted-register operands at lines 1007-1039, with coverage at lines 1174-1201.
- `docs/adr/0004-isa-trait-collapse.md` - decision 4 at lines 34-38 already says `OperandType` is the lowest-common-denominator operand surface and should not grow to losslessly carry richer AArch64 operand grammar.

No `crates/`, `compiler/`, or `docs/spec/` paths exist in this s11 checkout, so there is no Rust/self-hosted compiler split and no spec document update for this audit. No `docs/capability.md` update is required because this does not change supported instructions.

## 3. TDD Slices

1. Characterize the AArch64 operand-trait contract.
   - Test file/location: `src/isa/aarch64.rs::tests::test_operand_traits`.
   - Behavior under test: `Operand::ShiftedRegister { reg: X3, kind: Lsl, amount: 4 }` and `Operand::ExtendedRegister { reg: X3, kind: Uxtx, shift: 0 }` both return `None` from `as_register()` and `as_immediate()`, and both return `false` from `is_register()` and `is_immediate()`.
   - Production code: no change expected. If this unexpectedly fails, restore the existing `OperandType for Operand` behavior in `src/isa/aarch64.rs` so both compound operand forms remain distinct from plain registers/immediates.

2. Clarify the shared trait wording without broadening the trait.
   - Test file/location: same `src/isa/aarch64.rs::tests::test_operand_traits` characterization from slice 1 remains the guard.
   - Behavior under test: the trait-level helpers still expose only plain register/immediate operand shapes.
   - Production code: update only comments in `src/isa/traits.rs` for `as_register()` and `is_register()` to say "plain register operand" and warn that ISA-specific compound operands that contain registers need ISA-specific matching.

3. Re-run the caller audit and keep the result out of production code.
   - Test file/location: no new test; this is the source audit that closes the investigation request.
   - Behavior under test: `rg -n "as_register\\(|is_register\\(" src tests benches docs` should show no AArch64 production caller that uses the predicate to decide candidate register capability. The expected non-test production hits are the trait method/default helper and ISA implementations; shifted-register-aware behavior is handled by direct `Operand::ShiftedRegister` pattern matches in the audit-only files above.
   - Production code: none. Put the grep result summary in the PR body so reviewers can see the audit was deliberate.

4. Regression-check the existing shifted-register surfaces.
   - Test file/location: existing tests `test_source_registers_shifted_register`, `test_generate_all_instructions_contains_shifted_register_add`, and `test_mutate_operand_can_produce_shifted_register`.
   - Behavior under test: the live-out/source-register path, enumerative candidate generation, and stochastic mutation continue to see `ShiftedRegister` through explicit operand-shape matching rather than through `as_register()`.
   - Production code: none expected. If any of these fail after slice 2, fix only the local doc/test edit that caused the failure; do not refactor candidate generation or mutation as part of this audit PR.

## 4. Verification Surface

- No ESBMC, contract, codegen, or C-model verification is involved. This issue is a Rust trait-caller audit and test/doc clarification.
- No `tests/run/` or `examples/` fixtures need to grow; those directories are absent in this checkout.
- Targeted checks for the implementation stage:
  - `cargo test test_operand_traits`
  - `cargo test test_source_registers_shifted_register`
  - `cargo test test_generate_all_instructions_contains_shifted_register_add`
  - `cargo test test_mutate_operand_can_produce_shifted_register`
- Before publishing a PR, follow the repository policy and run `./ci_check.sh`. If time is tight, at minimum run `cargo test --workspace` plus `cargo fmt -- --check`, but the PR body should say if the full CI script was not run.

## 5. Risk Areas

- Do not replace existing `Operand::ShiftedRegister` pattern matches with `as_register()` or `is_register()` during cleanup; that would recreate the exact bug the audit is guarding against.
- Keep `OperandType` as a lowest-common-denominator trait. Extending it to return inner registers from compound operands conflicts with ADR-0004 and would blur the plain-register contract for x86/RISC-V too.
- Avoid parser, display, or Capstone conversion edits. This audit does not touch parse-print-parse idempotency or the `convert_to_ir -> parser::parse_line` delegation contract.
- Avoid search refactors. Candidate generation and mutation already have shifted-register-specific paths; moving those through generic trait helpers risks dropping shift kind/amount information.
- Clippy risk is low, but new test code should avoid unused imports. Prefer fully qualified `crate::ir::ShiftKind::Lsl` and `crate::ir::ExtendKind::Uxtx` or add imports only if they are used.
- Binary fixed point, codegen ordering, stack-slot layout, and `BTreeMap` versus `HashMap` concerns are not applicable because this PR should not touch compiler/codegen/data-structure ordering paths.

## 6. Out of Scope

- Changing `OperandType::as_register` to return the inner register from `ShiftedRegister` or `ExtendedRegister`.
- Adding a generic "contains register" trait method or visitor.
- Refactoring AArch64 candidate generation, stochastic mutation, assembler lowering, concrete semantics, SMT semantics, or parser support.
- Updating `docs/capability.md`, ADRs, CLI docs, benchmarks, or integration fixtures.
- Any formatting churn outside the two touched files.

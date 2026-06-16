# Plan: remove shifted-register macro turbofish

## Problem Restated

The AArch64 shifted-register dynasm wrapper macros in `src/assembler/mod.rs` use two different `Ok` styles: arithmetic macros return plain `Ok(())`, while logical macros return `Ok::<(), String>(())` in every arm. A local inference check showed that `cargo check` succeeds with the logical annotations removed, so the smallest safe fix is to drop the redundant turbofish and make the shifted-register macros consistent.

## Files To Touch

- `src/assembler/mod.rs` lines 68-95 and 124-149: replace `Ok::<(), String>(())` with plain `Ok(())` in `emit_shifted_reg_3op_logical` and `emit_shifted_reg_2op_logical`.
- `src/search/symbolic/synthesis.rs`: if the full cargo gate exposes the pre-existing cooperative-cancel test race, make the synthetic test backend flip its stop flag deterministically after the first equivalence check.
- No `crates/` or `compiler/` paths: this repository does not contain those directories, and this issue is not cross-cutting.
- No `docs/spec/*.md` updates: this repository does not contain `docs/spec/`, and the change does not alter syntax, semantics, operators, effects, or CLI flags.
- No new assembler tests should be added: existing assembler coverage in `src/assembler/mod.rs` lines 4242-4380 already exercises shifted-register logical/arithmetic encodings and arithmetic ROR rejection.

## TDD Slices

1. Style-only slice for the logical shifted-register macros.
   - Test file/location: no new test; use existing `src/assembler/mod.rs::tests::test_assemble_shifted_register_round_trip` at lines 4245-4363, which covers logical shifted-register `ORR ... ROR` and `TST ... ROR`.
   - Behavior under test: shifted-register logical encodings still assemble and disassemble exactly as before; arithmetic shifted-register ROR remains rejected by `test_assemble_shifted_arith_rejects_ror` at lines 4369-4380.
   - Production code: remove the logical macro turbofish annotations only; do not change any `dynasm!` invocation, match arm, or `Err(...)` expression.
   - Red/green/refactor framing: because the requested fix is style-only, there is no meaningful new red behavioral test. Treat the temporary inference check, existing targeted assembler tests, and `cargo check` as verification; skip refactoring.

2. Verification-stability slice, only if needed.
   - Test file/location: `src/search/symbolic/synthesis.rs`.
   - Behavior under test: cooperative cancellation is still observed from inside length-2 and length-3 symbolic-search loops.
   - Test harness: avoid depending on a helper thread being scheduled before the synthetic search performs several equivalence checks; have the synthetic backend set the shared stop flag immediately after the first check.
   - Production code: no production search behavior changes.

## Verification Surface

- Run `cargo check` to confirm the macro-expanded code still type-checks after the explicit `Ok::<(), String>(())` annotations are removed.
- Run `cargo test assembler::tests::test_assemble_shifted_register_round_trip` and `cargo test assembler::tests::test_assemble_shifted_arith_rejects_ror` as separate targeted checks.
- Run `cargo fmt --all`, `cargo clippy --all -- -D warnings`, `./build_tests.sh`, `cargo test --all`, and `./ci_check.sh` per the run contract and `CLAUDE.md`.
- `scripts/full_test.sh` is absent in this repository; `./ci_check.sh` runs the available `test_all.sh` wrapper instead.
- No ESBMC properties are required: this Rust repository has no C model in scope for this issue, and the change does not touch contracts, semantics, code generation behavior, or verification logic.
- No `tests/run/` or `examples/` fixtures need to grow; the observable assembler behavior is unchanged.

## Risk Areas

- Removing the turbofish could reintroduce `Result` error-type inference ambiguity in success-only logical macro arms; the local `cargo check` inference check guards this before committing the change.
- Accidentally editing the macro bodies would touch AArch64 machine-code emission; restrict the implementation to the `Ok` return spelling.
- The symbolic cancellation harness change should remain test-only and should not relax the cancellation assertions.
- `cargo clippy --all -- -D warnings` should remain unaffected.
- Binary fixed-point risks are not applicable: there is no `compiler/` tree here, and this plan changes no codegen ordering, map type, stack-slot layout, or generated binary.
- `parse -> print -> parse` idempotency is not applicable because the parser, printer/display code, and Capstone conversion path are untouched.

## Out Of Scope

- Do not normalize other `Ok::<(), String>(())` occurrences in memory or pair encoding macros.
- Do not refactor the shifted-register macros, extract helpers, or alter dynasm token dispatch.
- Do not add assembler tests for a style-only fix.
- Do not update `docs/capability.md`, ADRs, CLI docs, or absent `docs/spec/` files.
- Do not bundle any broader AArch64 shifted-register support or W-register logical work into this PR.

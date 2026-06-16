# Plan - issue #181: Pin reversed-order `--live-out` error

## 1. Problem Restated

Issue #181 asks for a narrow regression test documenting the current malformed-order behavior for `--live-out "nzcv;x0"`. The accepted grammar is `<regs>` or `<regs>;<flags>` with `nzcv` valid only in the flags half, so the reversed input currently splits into register half `nzcv` and flag half `x0`, then fails through the register parser with `invalid register name: 'nzcv'`. The PR should pin that exact diagnostic so future parser-message changes fail with an actionable test failure, without changing parser behavior.

## 2. Files To Touch

- `src/validation/live_out.rs` - add one unit test in the existing `#[cfg(test)] mod tests`, near the `parse_live_out_contract` malformed-input tests around lines 677-727.

No production files should change. There are no `crates/` or `compiler/` directories in this repository, so this is not a Rust-stage/self-hosted compiler cross-cutting change. There is no `docs/spec/` tree in this checkout; the relevant accepted design source is `docs/adr/0006-live-out-cli-grammar.md`, and no ADR/spec update is needed because the grammar and behavior stay unchanged.

## 3. TDD Slices

1. Add a focused regression test in `src/validation/live_out.rs`, immediately after `test_parse_live_out_contract_bareword_nzcv_rejected` or before `test_parse_live_out_contract_unknown_flag_rejected`. Name it `test_parse_live_out_contract_reversed_order_nzcv_x0_error`.

2. In that test, call `let err = parse_live_out_contract("nzcv;x0").unwrap_err();` and assert the exact rendered message:
   ```rust
   assert_eq!(err.to_string(), "invalid register name: 'nzcv'");
   ```
   Prefer `err.to_string()` over substring matching so the test pins the user-visible `Display` body already covered by `display_renders_message_without_type_prefix` at `src/validation/live_out.rs:267-271`.

3. Red-check the guard without committing sabotage: temporarily change the expected string in the new test, or temporarily mutate the local parser diagnostic at `src/validation/live_out.rs:49-50`, then run:
   ```bash
   cargo test validation::live_out::tests::test_parse_live_out_contract_reversed_order_nzcv_x0_error -- --exact
   ```
   Confirm the test fails on the message mismatch, then immediately revert the temporary mutation.

4. Green-check against the real code. The production path that should satisfy the test already exists: `parse_live_out_contract` counts one semicolon at `src/validation/live_out.rs:94-115`, parses `regs_part` via `RegisterSet::<Register>::from_str`, and `parse_register` emits `invalid register name: 'nzcv'` at `src/validation/live_out.rs:49-50`. No production code should be edited.

5. Refactor only if formatting requires it. Keep the test local and explicit; do not introduce helper functions or convert the surrounding parse-live-out tests to table-driven form for this small coverage addition.

## 4. Verification Surface

- No ESBMC proof work is needed. This change does not touch contracts, codegen, the C model, SMT lowering, concrete semantics, assembler output, or binary patching.
- No fixtures under `tests/run/`, `tests/asm/`, `tests/integration/`, `examples/`, or benchmark directories should grow.
- Minimum verification:
  ```bash
  cargo test validation::live_out::tests::test_parse_live_out_contract_reversed_order_nzcv_x0_error -- --exact
  ```
- Broader local verification before PR/commit:
  ```bash
  cargo test validation::live_out
  cargo fmt -- --check
  ```
- Full pre-push verification remains the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- Error-message coupling is intentional here: use an exact assertion because the issue specifically asks to pin the diagnostic text for `nzcv;x0`.
- Test placement should stay in the parser/error-test cluster so future maintainers understand this as CLI grammar coverage, not live-in/live-out dataflow coverage.
- Do not change `parse_live_out_contract` to special-case reversed order unless a separate issue asks for a friendlier diagnostic; that would widen the behavioral scope and may require ADR/help-text updates.
- `parse -> print -> parse` idempotency is unaffected because this is a CLI live-out contract parser test, not assembly IR parsing or formatting.
- Binary fixed-point risks are absent: no `compiler/` tree exists here, and the plan does not touch codegen ordering, map iteration, stack-slot layout, assembler encoding, or `vow-clif-shim`-style components.
- The `cargo clippy --all -- -D warnings` gate should be unaffected; the added test must avoid unused imports or dead helper functions.

## 6. Out Of Scope

- Changing the grammar for reversed-order input or adding a bespoke "wrong order" diagnostic.
- Changing any `run_equiv` or `run_llm_opt` error-prefix behavior in `src/main.rs`.
- Adding docs/spec/ADR updates; this PR documents existing behavior through a regression test only.
- Refactoring `ParseRegisterSetError`, `parse_register`, or the surrounding `parse_live_out_contract` tests.
- Running benchmarks, mutation tests, x86/RISC-V flows, LLM search, assembler tests, or integration fixtures for this unit-test-only issue.

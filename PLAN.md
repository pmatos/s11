# Plan: Contract-Scoped Live-Out Parse Error

## 1. Problem Restated

`parse_live_out_contract` now parses the whole `--live-out` contract, including the optional `;nzcv` flag-liveness suffix, so a register-only error name is misleading when diagnostics can say things like `unknown flag token 'bogus'`. In this checkout the original `ParseLiveOutRegistersError` symbol is already gone and the shared wrapper is named `ParseRegisterSetError`, but the contract parser still exposes that register-set-flavored name in its signature and ADR-0006 still has one stale reference to the old name. The implementation should add a contract-facing error name for `parse_live_out_contract` without breaking existing `RegisterSet<Register>::from_str` users.

## 2. Files To Touch

- `src/validation/live_out.rs`
  - Lines 9-21: keep `ParseRegisterSetError` as the underlying shared `{ message: String }` wrapper used by `RegisterSet<Register>::from_str`, but broaden its doc comment to cover live-out contract parsing too.
  - After line 21: add `pub type ParseLiveOutError = ParseRegisterSetError;` with a doc comment explaining it is the contract-facing error name for `parse_live_out_contract`.
  - Line 94: change `parse_live_out_contract(s: &str) -> Result<LiveOut, ParseRegisterSetError>` to return `Result<LiveOut, ParseLiveOutError>`.
  - Lines 266-272 and 694-702: adjust or add tests so the contract parser path names `ParseLiveOutError` while preserving display output and flag-token diagnostics.
- `docs/adr/0006-live-out-cli-grammar.md`
  - Line 18: update the documented signature to `Result<LiveOut, ParseLiveOutError>`.
  - Line 48: replace the stale `ParseLiveOutRegistersError` reference with the current contract-facing `ParseLiveOutError` name and mention that it aliases the shared `ParseRegisterSetError` wrapper.
- `src/main.rs`
  - Lines 1520-1521 and 1585-1586 are call sites to verify; no edit is expected unless the implementation needs an import cleanup. Both should continue mapping errors through `"invalid live-out: {}"`.
- No `crates/`, `compiler/`, or `docs/spec/*.md` files exist in this repository checkout, so there is no cross-compiler or spec-doc update for this Rust-only hygiene change.

## 3. TDD Slices

1. Add the contract-facing compile check.
   - Test location: `src/validation/live_out.rs` test module near `display_renders_message_without_type_prefix` at lines 266-272.
   - Red behavior: introduce or adjust a unit test that binds a parsed contract error as `ParseLiveOutError`, for example from `parse_live_out_contract("x0;bogus").unwrap_err()`, and asserts `err.to_string()` is still the bare message body.
   - Production code: add `pub type ParseLiveOutError = ParseRegisterSetError;`, update the `parse_live_out_contract` return type, and keep `Display` implemented only on `ParseRegisterSetError` so the alias inherits the existing behavior.

2. Pin flag-token diagnostics through the contract-facing name.
   - Test location: `src/validation/live_out.rs` around `test_parse_live_out_contract_unknown_flag_rejected` at lines 694-702.
   - Red behavior: make the test explicitly type the error as `ParseLiveOutError` and assert it still contains `unknown flag token`.
   - Production code: no new parsing behavior should be needed beyond the signature/alias from slice 1; this slice guards against accidentally narrowing the contract parser back to register-only terminology.

3. Align the accepted architecture record.
   - Test/static check location: repository-wide `rg -n "ParseLiveOutRegistersError" docs src`.
   - Red behavior: before the doc edit, ADR-0006 still mentions `ParseLiveOutRegistersError`.
   - Production/docs code: update `docs/adr/0006-live-out-cli-grammar.md` so the documented parser signature and resolution note use `ParseLiveOutError` for the contract parser and `ParseRegisterSetError` only for the shared underlying register-set wrapper.

## 4. Verification Surface

- Run targeted tests after the implementation:
  - `cargo test validation::live_out::tests::display_renders_message_without_type_prefix`
  - `cargo test validation::live_out::tests::test_parse_live_out_contract_unknown_flag_rejected`
  - `cargo test validation::live_out::tests::test_parse_live_out_contract_per_flag_tokens_reserved`
- Run `cargo check` or `just check` to catch any public signature/import fallout.
- Before a final PR, follow repository guidance and run `./ci_check.sh`; if time is tight, at minimum run `cargo test validation::live_out`.
- This change does not touch contracts in the Vow/ESBMC sense, codegen, the C model, or machine semantics. There are no ESBMC properties to prove, and no `tests/run/` or `examples/` fixtures exist or need to grow.

## 5. Risk Areas

- Public API blast radius: removing or renaming `ParseRegisterSetError` would break users of `RegisterSet<Register>::from_str`; use a `ParseLiveOutError` alias for the contract-facing path instead.
- Stale terminology: `ParseLiveOutRegistersError` should not remain in docs or code after the implementation.
- Rustdoc readability: the `parse_live_out_contract` signature should show the contract-facing alias, while the shared wrapper can remain documented as the register-set/parser error carrier.
- `cargo clippy --all -- -D warnings`: avoid unused imports or dead aliases; the public alias should be used in the parser signature and tests.
- Parse/print/parse idempotency and binary fixed-point behavior are unaffected because no grammar, IR, search, assembler, or codegen ordering changes are planned.

## 6. Out Of Scope

- Do not change the `--live-out` grammar, accepted flag tokens, or error message text beyond type/doc names.
- Do not split the error into multiple structs with conversions; the existing `{ message: String }` wrapper is sufficient.
- Do not add compatibility aliases for the removed `ParseLiveOutRegistersError` name; reintroducing the old register-only symbol would dilute the cleanup.
- Do not refactor `RegisterSet`, `LiveOut`, x86 live-out masks, or ADR-0004 migration work.
- Do not modify `symphony/`, `build/`, unrelated docs, formatting across untouched files, or generated artifacts.

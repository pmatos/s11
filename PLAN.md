# Plan - issue #124: reject SP for AArch64 multiply-family encodability

## 1. Problem Restated

`Instruction::is_encodable_aarch64()` currently returns `true` for the AArch64 multiply/divide and multiply-accumulate register-only family, so IR values and parsed assembly such as `madd sp, x1, x2, x3` pass the parser/search encodability boundary and fail only later when the dynasm register lowering rejects `Register::SP`. The implementation should make the IR encodability gate match the architectural register class for all eight affected variants: `mul`, `sdiv`, `udiv`, `madd`, `msub`, `mneg`, `smulh`, and `umulh` reject `SP` in every register operand slot while still accepting `XZR`, because register number 31 in these slots denotes the zero register, not the stack pointer.

## 2. Files To Touch

- `src/ir/instructions.rs` - production change in `Instruction::is_encodable_aarch64()` around lines 815-823; add table-driven unit coverage in the existing `#[cfg(test)] mod tests` near `test_is_encodable_bit_manip_rejects_sp` around lines 2647-2697 and the existing multiply-family positive assertions around lines 3160-3226.
- `src/parser/mod.rs` - add a parser-boundary regression near `test_parse_line_encoding_validation` around lines 2264-2286 or `parse_line_covers_all_core_mnemonics` around lines 2560-2602, proving parser rejection flows through the tightened IR gate.

No `crates/` or `compiler/` directories exist in this repository, so there is no Rust-stage/self-hosted compiler mirror to update. `docs/spec/` is absent. `docs/capability.md` lists supported mnemonics, not per-slot operand legality, so no documentation update is required unless the implementation chooses to add operand-level notes elsewhere.

## 3. TDD Slices

1. Add the red IR regression in `src/ir/instructions.rs`. Name it `test_is_encodable_multiply_family_rejects_sp_all_slots`. Cover all eight variants, with one assertion for every register slot that can contain `SP`: `rd/rn/rm` for `Mul`, `Sdiv`, `Udiv`, `Mneg`, `Smulh`, `Umulh`; `rd/rn/rm/ra` for `Madd` and `Msub`. In the same test, assert that the corresponding XZR forms remain encodable, preferably with all operand slots set to `Register::XZR` for each variant.

2. Add a parser-boundary red test in `src/parser/mod.rs`. Name it `parse_line_rejects_sp_in_multiply_family`. Use representative text forms that exercise every affected mnemonic and every distinct slot shape, for example `mul sp, x1, x2`, `sdiv x0, sp, x2`, `udiv x0, x1, sp`, `madd x0, x1, x2, sp`, plus `msub`, `mneg`, `smulh`, and `umulh`. Assert `parse_line(text).is_err()` rather than pinning the exact error string, because the contract is rejection at the parser boundary. Add XZR accept cases for the eight mnemonics, such as `madd xzr, xzr, xzr, xzr`.

3. Green the IR gate in `src/ir/instructions.rs`. Replace the unconditional arms at lines 815-823 with explicit `Register::SP` checks:
   - `Mul | Sdiv | Udiv | Mneg | Smulh | Umulh`: return `rd != SP && rn != SP && rm != SP`.
   - `Madd | Msub`: return `rd != SP && rn != SP && rm != SP && ra != SP`.
   Keep `Register::XZR` accepted; do not use `Register::index()` as the predicate, because `XZR.index() == Some(31)` is exactly the valid architectural encoding for this family.

4. Run the focused red/green tests:
   ```bash
   cargo test ir::instructions::tests::test_is_encodable_multiply_family_rejects_sp_all_slots -- --exact
   cargo test parser::tests::parse_line_rejects_sp_in_multiply_family -- --exact
   ```

5. Run the local impact tests for search/filter behavior without adding new production paths:
   ```bash
   cargo test search::candidate::tests::test_generate_all_instructions_contains_mul_div_family -- --exact
   cargo test search::candidate::tests::test_generate_random_reaches_mul_div_family -- --exact
   cargo test search::candidate::tests::test_generate_random_reaches_madd_family -- --exact
   cargo test isa::aarch64::tests::random_generator_handles_sp_only_register_pool -- --exact
   ```
   If any random-generator test exposes a stale assumption that multiply can fall back with `SP`, keep the fix minimal: adjust only the affected sampler/fallback to choose a non-SP register or a different always-encodable fallback, and add/adjust the smallest test needed to pin finite termination.

6. Refactor only for clarity after green. If the two match arms become noisy, a tiny private helper such as `fn no_sp(regs: &[Register]) -> bool` can be introduced inside `src/ir/instructions.rs`, but prefer direct slot checks unless duplication starts obscuring the rule.

## 4. Verification Surface

- No ESBMC proof work is needed. This Rust repository has no Vow contracts, C model, `tests/run/`, `examples/`, or self-hosted compiler/codegen mirror involved in this operand-legality change.
- No SMT or concrete-semantics property changes are required; invalid SP-bearing multiply-family instructions should now be refused before semantics, equivalence, and assembly.
- No test fixtures under `tests/asm/`, `tests/integration/`, `benches/`, or docs examples need to grow.
- Minimum verification after implementation:
  ```bash
  cargo test ir::instructions::tests::test_is_encodable_multiply_family_rejects_sp_all_slots -- --exact
  cargo test parser::tests::parse_line_rejects_sp_in_multiply_family -- --exact
  cargo test search::candidate
  cargo fmt -- --check
  ```
- Full pre-push verification remains the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- `SP` and `XZR` both correspond to architectural register number 31 in different register classes. The multiply family uses the plain X register class, so reject only `Register::SP`; rejecting `Register::XZR` would be a behavioral regression.
- `parse_line` calls `instruction.is_encodable_aarch64()` at `src/parser/mod.rs:1939-1945`; no separate parser-level operand filter should be introduced unless needed for better diagnostics.
- `search::candidate::generate_all_encodable_instructions()` filters via `is_encodable_aarch64()` at `src/search/candidate.rs:36-39`; avoid changing broad enumeration loops just to pre-filter SP, because the existing architecture intentionally centralizes legality in the encodability gate.
- `src/isa/aarch64.rs` and `src/search/candidate.rs` random generators have comments/fallbacks that may assume multiply tolerates any register. If tests fail, update only those assumptions and preserve bounded behavior for degenerate pools such as `[SP]`.
- `parse -> print -> parse` idempotency should stay intact for valid XZR and normal-register multiply-family forms; the parser test should assert valid XZR forms still parse.
- `cargo clippy --all -- -D warnings` should be unaffected if new tests avoid unused helper closures/imports and keep table types simple enough for inference.

## 6. Out Of Scope

- Refactoring the broader AArch64 register-class model or adding a general operand-slot type system.
- Changing assembler lowering in `src/assembler/mod.rs`; its `register_to_dynasm()` failure remains useful defense in depth for callers that bypass `is_encodable_aarch64()`.
- Changing Capstone bridge tests in `src/main.rs`; no new mnemonic is being added and valid canonical multiply-family operands already exist there.
- Changing semantics, SMT lowering, cost model, live-out analysis, candidate opcode IDs, docs/capability mnemonic lists, benchmarks, or x86/RISC-V code.
- Bundling unrelated SP/XZR legality fixes for conditional select, unary arithmetic, inverted logical, or other register-only families; this PR is only the multiply/divide and multiply-accumulate family named in issue #124.

# Plan - issue #125: Tighten SMULH `wrapping_mul` comment

## 1. Problem Restated

Issue #125 asks for a wording-only refinement in the AArch64 concrete interpreter's `SMULH` arm. The current comment above the `i128::wrapping_mul` call is correct, but it frames `i64::MIN * i64::MIN` as an exceptional case instead of stating the general bound: every signed 64-bit by signed 64-bit product fits in `i128`, so `wrapping_mul` cannot actually wrap here. The implementation stage should make that invariant clearer without changing SMULH behavior, tests, parser support, SMT lowering, assembler output, or CLI-visible semantics.

## 2. Files To Touch

- `src/semantics/concrete.rs` - replace the three-line comment in the `Instruction::Smulh` arm at lines 176-178 with a clearer bound-based explanation. The executable line `let result = (a.wrapping_mul(b) >> 64) as i64;` at line 179 should stay unchanged.

No `crates/` or `compiler/` paths exist in this repository, so there is no Rust-stage/self-hosted compiler cross-cutting change. No `docs/spec/` tree exists in this checkout, and no spec or ADR update is required because this is a comment-only clarification of existing concrete semantics.

## 3. TDD Slices

1. Baseline the existing behavior guard in `src/semantics/concrete.rs`.
   - Test location: `src/semantics/concrete.rs`, `test_smulh_matches_rust_i128` at lines 1371-1406.
   - Behavior under test: `SMULH` matches Rust's signed `i128` high-half product across zero, signed boundaries, `i64::MIN * i64::MIN`, and `i64::MIN * -1`.
   - Production code involved: `Instruction::Smulh` in `apply_instruction_concrete` at lines 173-180.
   - Red/green note: no new red test is appropriate for a non-behavioral comment rewrite. Run this existing test before and after the comment change to prove the implementation was not disturbed.

2. Rewrite only the SMULH justification comment.
   - Test location: same existing `test_smulh_matches_rust_i128` regression test.
   - Behavior under test: unchanged; the slice is documentation-only.
   - Production code to edit: comment lines 176-178 in `src/semantics/concrete.rs`.
   - Recommended wording:
     ```rust
     // wrapping_mul for i128 cannot wrap here: the signed product of two
     // 64-bit values has max magnitude 2^63 * 2^63 = 2^126, which is
     // less than i128::MAX.
     ```
   - Keep the code expression as `a.wrapping_mul(b)` so the comment explains the existing implementation rather than introducing a mechanical code change.

3. Refactor slice: none.
   - Do not add helper constants, replace `wrapping_mul` with `*`, or restructure the SMULH arm. Those would be behavior-equivalent cleanups, but they are outside the issue's wording-only scope and would increase review surface.

## 4. Verification Surface

- No contracts, codegen, C model, ESBMC proofs, SMT formulas, assembler encodings, or binary patching paths are touched.
- No fixtures under `tests/run/`, `examples/`, benchmark directories, or integration-test binaries need to grow.
- Minimum targeted verification after the comment edit:
  ```bash
  cargo test semantics::concrete::tests::test_smulh_matches_rust_i128 -- --exact
  cargo fmt -- --check
  ```
- Before committing/pushing an implementation PR, follow the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- Keep the mathematical statement precise: the maximum magnitude is `2^126`, and that is below the positive `i128` bound. Avoid implying only `i64::MIN * i64::MIN` is safe.
- The suggested `less than i128::MAX` phrase is acceptable for the bound argument, but an implementer may choose `fits within i128` if they want to avoid comparing exactly against `2^127 - 1`.
- Do not change the `wrapping_mul` call just because the comment says it cannot wrap; replacing it with `*` would alter the implementation surface and might invite unnecessary debug-overflow discussion.
- `parse -> print -> parse` idempotency is unaffected because no parser, formatter, or IR display code changes.
- Binary fixed-point risks are absent: no `compiler/` tree exists, and this plan does not touch codegen ordering, `BTreeMap`/`HashMap` iteration, stack-slot layout, assembler emission, or any `vow-clif-shim`-style component.
- The `cargo clippy --all -- -D warnings` gate should be unaffected because comments do not introduce lints; still run formatting/check gates per project convention.

## 6. Out Of Scope

- Changing SMULH semantics, edge-case tests, SMT lowering, or equivalence checking.
- Adding or removing AArch64 instruction support.
- Updating `docs/capability.md`, ADRs, nonexistent `docs/spec/` files, or CLI documentation.
- Refactoring adjacent multiply instructions (`MADD`, `MSUB`, `MNEG`, `UMULH`) or their comments.
- Running benchmarks, mutation tests, LLM search, x86/RISC-V flows, assembler integration tests, or fixture generation for this comment-only issue.

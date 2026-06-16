# Plan - issue #133: Pre-filter SP from shifted-register candidates

## 1. Problem Restated

`src/search/candidate.rs::generate_all_instructions` currently constructs AArch64 shifted-register `ADD`/`SUB`/`AND`/`ORR`/`EOR` candidates for every `(rd, rn, rm)` tuple, including tuples where one of those slots is `Register::SP`. `Instruction::is_encodable_aarch64` later rejects all shifted-register forms involving SP, so `generate_all_encodable_instructions` stays correct, but the raw candidate pool does unnecessary allocation and filtering work. The fix should pre-filter those known-invalid shifted-register tuples at enumeration time while preserving all valid shifted-register candidates and leaving the broader post-hoc encodability filter in place.

## 2. Files To Touch

- `src/search/candidate.rs` - add a focused regression test in the existing `#[cfg(test)] mod tests` near the shifted-register enumeration tests around lines 1476-1543, then update the shifted-register enumeration block around lines 130-189 to skip any tuple where `rd == Register::SP`, `rn == Register::SP`, or `rm == Register::SP`.

No `crates/` or `compiler/` paths exist in this repository, so this is not a Rust-stage/self-hosted compiler cross-cutting change. No `docs/spec/` tree exists in this checkout. `docs/capability.md` and `docs/adr/` do not need updates because the accepted instruction set, syntax, CLI, equivalence contract, and user-visible semantics are unchanged.

## 3. TDD Slices

1. Add a red unit test in `src/search/candidate.rs` after `test_generate_all_instructions_arith_excludes_ror`. Name it `test_generate_all_instructions_shifted_register_prefilters_sp`. Use `registers = vec![Register::X0, Register::X1, Register::SP]` and `immediates = vec![]`, call `generate_all_instructions`, filter to `Instruction::Add`, `Sub`, `And`, `Orr`, and `Eor` whose `rm` is `Operand::ShiftedRegister`, and assert that the filtered set is non-empty and no shifted-register instruction has `rd`, `rn`, or inner `reg` equal to `Register::SP`. This fails on the current implementation because the raw enumerator emits those SP-bearing shifted-register candidates.

2. Make the minimal production change in `src/search/candidate.rs::generate_all_instructions`. In the shifted-register block, replace the stale comment saying SP is filtered later with an enumeration-time guard. Keep the guard scoped to shifted-register candidate construction: either wrap the shifted-register pushes in `if rd != Register::SP && rn != Register::SP` plus `continue` for `rm == Register::SP`, or use an equivalent local predicate. Do not remove the later `.filter(|instr| instr.is_encodable_aarch64())` in `generate_all_encodable_instructions`.

3. Green-check the new test and existing shifted-register coverage. Verify that the new SP pre-filter test passes, and that the existing tests still prove valid shifted-register coverage is retained: `test_generate_all_instructions_contains_shifted_register_add`, `test_generate_all_instructions_includes_all_shifted_kinds_for_logical`, and `test_generate_all_instructions_arith_excludes_ror`.

4. Refactor only if the guard makes the block harder to read. If introducing a helper, keep it private to `src/search/candidate.rs` and name it around the AArch64 shifted-register slot rule, not around a generic "encodable" concept; the authoritative full encodability rule remains `Instruction::is_encodable_aarch64` in `src/ir/instructions.rs`.

## 4. Verification Surface

- No ESBMC proof work is needed. This repository is the Rust `s11` project, and this change does not touch contracts, codegen, a C model, SMT lowering, concrete semantics, assembler encoding, parser behavior, or binary patching.
- No fixtures under `tests/`, `examples/`, or `benches/` need to grow; this is covered by unit tests in `src/search/candidate.rs`.
- Minimum verification:
  ```bash
  cargo test test_generate_all_instructions_shifted_register_prefilters_sp
  cargo test test_generate_all_instructions_contains_shifted_register_add
  cargo test test_generate_all_instructions_includes_all_shifted_kinds_for_logical
  cargo test test_generate_all_instructions_arith_excludes_ror
  ```
- Broader local verification before PR/commit:
  ```bash
  cargo test search::candidate
  cargo fmt -- --check
  cargo clippy --all -- -D warnings
  ```
- Full pre-push verification remains the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- Do not pre-filter `Register::XZR` from shifted-register forms. `src/ir/instructions.rs:749-798` rejects `Register::SP` for shifted-register operands but does not reject `Register::XZR`; filtering XZR would silently shrink valid search space.
- Do not broaden this issue into plain `Operand::Register` cleanup. Register-form AArch64 slot rules are more nuanced in `is_encodable_aarch64`, and changing them would be a separate behavior/performance audit.
- Do not remove the final encodability filter in `generate_all_encodable_instructions`; many other deliberately broad enumerations still rely on it for immediates and other forms.
- Keep the test behavior-oriented. Avoid asserting the total candidate-pool size, which would make future instruction-family additions fail for the wrong reason.
- `parse -> print -> parse` idempotency is unaffected because the parser and formatter are not touched.
- Binary fixed-point risks are absent: no `compiler/` tree exists here, and the plan does not touch codegen ordering, map iteration, stack-slot layout, assembler encoding, or `vow-clif-shim`-style components.
- The `cargo clippy --all -- -D warnings` gate should stay clean; avoid adding unused helpers/imports while moving the `ShiftKind` use or introducing a local predicate.

## 6. Out Of Scope

- Changing `Instruction::is_encodable_aarch64` or assembler slot rules.
- Filtering XZR or SP from unrelated plain-register, immediate, extended-register, memory, bitfield, compare, or conditional-select candidate families.
- Changing stochastic mutation, symbolic synthesis, x86/RISC-V candidate generation, parser behavior, or CLI behavior.
- Adding docs/spec, ADR, capability-matrix, benchmark, mutation-test, or integration-fixture updates.

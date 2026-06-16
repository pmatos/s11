# Plan - issue #114: Targeted swap_opcode move-wide peer tests

## 1. Problem Restated

Issue #114 asks for targeted unit coverage of the AArch64 stochastic opcode-mutator topology added around the move-wide family: `MOVN`, `MOVZ`, and `MOVK` should be able to propose their declared peer opcodes, and `MOVZ` should be the only direct bridge to `MovImm`. The current MCMC integration tests exercise these arms indirectly, but they do not fail loudly if an individual `mutate_opcode` arm loses a peer, gains the wrong bridge, or stops producing the documented self/peer distribution.

## 2. Files To Touch

- `src/search/stochastic/mutation.rs` - add test-only helper code and a focused unit test in the existing `#[cfg(test)] mod tests`; the relevant implementation arms are `Mutator::mutate_opcode` lines 738-775, and nearby opcode-mutator tests start around lines 1457 and 1622.
- `src/search/stochastic/mutation.rs` - production code should change only if the new tests expose drift from the intended topology; any such fix should stay inside the `Instruction::MovN`, `Instruction::MovZ`, and `Instruction::MovK` `mutate_opcode` arms at lines 750-775.

No `crates/` or `compiler/` paths exist in this repository, so there is no Rust-stage/self-hosted compiler split to update. No `docs/spec/` tree exists in this checkout. The issue is test-only for AArch64 stochastic search, so `docs/capability.md` and `docs/adr/*.md` do not need updates.

## 3. TDD Slices

1. Add a test-local opcode classifier in `src/search/stochastic/mutation.rs` inside the existing tests module near `default_mutator()` at lines 1270-1275. The helper should classify only `Instruction::MovN`, `Instruction::MovZ`, `Instruction::MovK`, and `Instruction::MovImm`; all other opcodes should panic or return an explicit unexpected marker so accidental non-move-wide outputs are visible.

2. Add a small deterministic histogram helper in the same test module. It should create `let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(<fixed seed>);`, call `default_mutator().mutate_opcode(&mut rng, &mut seq)` 5000 times from a one-instruction sequence, and count opcode classes. Use fixed-size counters or a deterministic `BTreeMap`, not a `HashMap`, so failure output is stable. Assert reachability only: every expected class has count greater than zero, and every observed class is in the expected set. Do not assert exact frequencies.

3. Red slice for `MOVN`: add a table row or dedicated test case named from `test_move_wide_opcode_mutation_reaches_declared_peers`, starting with `Instruction::MovN { rd: Register::X0, imm: 0x1234, shift: 16 }`. Expected reachable classes are `MovN`, `MovZ`, and `MovK`; `MovImm` must not appear directly. Red-check by temporarily deleting or mis-expecting one peer locally, then revert the temporary change.

4. Red slice for `MOVZ`: extend the same test with `Instruction::MovZ { rd: Register::X0, imm: 0x1234, shift: 16 }`. Expected reachable classes are `MovZ`, `MovN`, `MovK`, and `MovImm`. When classifying a `MovImm` bridge, also assert it preserves `rd` and uses the raw `u16` immediate as `imm as i64`, not `imm << shift`, matching the current bridge comment at lines 758-768.

5. Red slice for `MOVK`: extend the same test with `Instruction::MovK { rd: Register::X0, imm: 0x1234, shift: 16 }`. Expected reachable classes are `MovK`, `MovN`, and `MovZ`; `MovImm` must not appear directly.

6. Green/fix slice: if any row fails against current code, edit only the corresponding `mutate_opcode` move-wide arm at `src/search/stochastic/mutation.rs:750-775` to restore the documented topology: `MovN -> {MovN, MovZ, MovK}`, `MovZ -> {MovZ, MovN, MovK, MovImm}`, and `MovK -> {MovK, MovN, MovZ}`. Do not change mutation weights, MCMC acceptance, candidate generation, parsing, semantics, or encodability rules.

7. Refactor slice: keep helper names local and narrow, remove any temporary red-check edits, and run formatting only if the added test code needs it. Avoid broad table-driven rewrites of unrelated opcode-mutator tests.

## 4. Verification Surface

- No ESBMC proof work is needed. This repository does not have the Vow C-model/codegen surface referenced by the generic run template, and this issue does not touch contracts, codegen, SMT lowering, concrete semantics, assembler output, or binary patching.
- No fixtures under `tests/run/`, `tests/asm/`, `tests/integration/`, `examples/`, or benchmark directories should grow.
- Minimum targeted verification:
  ```bash
  cargo test search::stochastic::mutation::tests::test_move_wide_opcode_mutation_reaches_declared_peers -- --exact
  ```
- Broader local verification for the touched module:
  ```bash
  cargo test search::stochastic::mutation
  cargo fmt -- --check
  ```
- Full pre-push verification remains the repository gate from `CLAUDE.md`:
  ```bash
  ./ci_check.sh
  ```

## 5. Risk Areas

- Deterministic sampling can create false negatives if the chosen seed/sample count misses a valid low-probability arm. With the current 1-in-3 and 1-in-4 arms, 5000 samples makes that practically impossible, but the implementation stage should run the exact test after choosing the seed and keep the seed fixed in the test.
- The test should not assert exact frequencies; doing so would overfit implementation detail and make harmless future weight changes painful.
- `mutate_opcode` is private, but the existing unit tests live in the same module and already call it directly. Do not widen visibility or add new public API for this test.
- `MovZ -> MovImm` intentionally discards `shift`. The test should protect this payload behavior only for the bridge output, while keeping the main assertion about opcode reachability.
- `parse -> print -> parse` idempotency is unaffected because no parser/display code changes are planned.
- Binary fixed-point risks are absent: there is no `compiler/` tree here, and this plan does not touch codegen ordering, map iteration in production, stack-slot layout, or any `vow-clif-shim`-style component.
- The `cargo clippy --all -- -D warnings` gate should remain clean; avoid unused imports such as `ChaCha8Rng` if the final test uses `StdRng` instead, and avoid dead helper functions.

## 6. Out Of Scope

- Changing the stochastic proposal topology beyond restoring the documented move-wide peers if drift is found.
- Adding exact statistical/frequency assertions, chi-squared checks, or acceptance-rate tests.
- Adding integration, MCMC end-to-end, parser, encoder, concrete-semantics, SMT, or capability-matrix tests.
- Refactoring the full `mutate_opcode` match, moving tests out of `mutation.rs`, or replacing existing stochastic test patterns.
- Updating docs or ADRs for a test-only coverage addition.

# Plan - issue #127: Complete the MNEG <-> MADD/MSUB mutation graph

## 1. Problem Restated

The AArch64 stochastic opcode mutation graph currently lets `MADD` and `MSUB` collapse to `MNEG`, but `MNEG` can only mutate to `MUL` or remain unchanged. That asymmetry does not create wrong code because candidates are still validated by random testing and SMT, and whole-instruction reset can still discover `MADD`/`MSUB`; however, it slows MCMC walks that start near `MNEG` and need to explore multiply-accumulate candidates. The minimal fix is to add direct `MNEG -> MADD` and `MNEG -> MSUB` opcode transitions, choosing a fresh `ra` from the mutator register pool because `MNEG` has no accumulator register to preserve.

## 2. Files To Touch

- `src/search/stochastic/mutation.rs`
  - Add focused unit coverage in the existing `#[cfg(test)] mod tests` near the opcode-mutation tests at `src/search/stochastic/mutation.rs:1622`.
  - Update the `Instruction::Mneg` arm in `Mutator::mutate_opcode` at `src/search/stochastic/mutation.rs:929` to include `Madd` and `Msub` outcomes with `ra: self.random_register(rng)`.
  - Update the nearby multiply-accumulate comment at `src/search/stochastic/mutation.rs:915`/`src/search/stochastic/mutation.rs:926` so it documents the deliberate `ra` introduction exception.

No `crates/` or `compiler/` directories exist in this checkout, so there is no Rust-stage/self-hosted compiler split to update. No `docs/spec/*.md` files exist. `docs/capability.md:30` already lists `mul`, `madd`, `msub`, and `mneg`; no syntax, semantics, CLI, or capability documentation changes are required.

## 3. TDD Slices

1. Add a red unit test for the missing reverse edges.
   - Test file/location: `src/search/stochastic/mutation.rs`, in `mod tests` after `test_opcode_mutation_changes_opcode` or near the bitfield opcode-mutation test.
   - Behavior under test: starting from `Instruction::Mneg { rd: X0, rn: X1, rm: X2 }`, repeated calls to `Mutator::mutate_opcode` with a deterministic `StdRng` must eventually produce both `Instruction::Madd { rd: X0, rn: X1, rm: X2, ra }` and `Instruction::Msub { rd: X0, rn: X1, rm: X2, ra }`.
   - Test shape: construct `Mutator::new(vec![Register::X3], vec![0], MutationWeights::default())` so any newly introduced `ra` is expected to be `Register::X3`; loop with a fixed seed for enough iterations, assert every output remains encodable with `is_encodable_aarch64()`, and assert `seen_madd && seen_msub`.
   - Expected red result before production code: the test fails because `MNEG` never reaches `MADD` or `MSUB`.
   - Production code that will make it pass: `Mutator::mutate_opcode`'s `Instruction::Mneg` arm.

2. Implement the minimal `MNEG` arm widening.
   - Production file/location: `src/search/stochastic/mutation.rs:929`.
   - Change: replace the current `rng.random_range(0..2)` branch with a 4-way branch: one outcome keeps the existing `Mul { rd, rn, rm }` bridge, one creates `Madd { rd, rn, rm, ra: self.random_register(rng) }`, one creates `Msub { rd, rn, rm, ra: self.random_register(rng) }`, and one preserves `Mneg { rd, rn, rm }`.
   - Preserve the existing `rd`, `rn`, and `rm` fields exactly. Only the new `ra` field may be fresh.
   - Reuse `Mutator::random_register` at `src/search/stochastic/mutation.rs:1075`, rather than indexing `self.registers` directly, so empty register pools keep the existing `Register::X0` fallback behavior.

3. Refactor only the local comment/documentation for the exception.
   - Production file/location: `src/search/stochastic/mutation.rs:915`.
   - Change: update the multiply-accumulate comment to say `MADD/MSUB` preserve/collapse `ra`, while `MNEG -> MADD/MSUB` introduces a fresh `ra` from the mutator register pool.
   - Do not introduce a new multiply-family mutation strategy in this PR; this issue can close with the local graph-completion change.

4. Green-check the focused test, then the containing module.
   - Focused command:
     ```bash
     cargo test search::stochastic::mutation::tests::mneg_opcode_mutation_reaches_madd_and_msub -- --exact
     ```
   - Module command:
     ```bash
     cargo test search::stochastic::mutation
     ```

5. Final cleanup and formatting check.
   - Run:
     ```bash
     cargo fmt -- --check
     ```
   - Before pushing from the implementation stage, run the repository-required:
     ```bash
     ./ci_check.sh
     ```

## 4. Verification Surface

- No ESBMC proof work is needed. This change does not touch contracts, codegen, the C model, SMT lowering, concrete semantics, assembler output, binary patching, or parser behavior.
- No fixtures under `tests/run/` need to grow; that directory is absent in this checkout. No `examples/` fixtures need to grow; `examples/` is absent.
- The useful verification surface is the stochastic mutation unit layer:
  ```bash
  cargo test search::stochastic::mutation::tests::mneg_opcode_mutation_reaches_madd_and_msub -- --exact
  cargo test search::stochastic::mutation
  cargo fmt -- --check
  ./ci_check.sh
  ```
- `src/search/candidate.rs:314` and `src/search/candidate.rs:893` already generate `MADD`, `MSUB`, and `MNEG`; no candidate-generation test changes are needed.

## 5. Risk Areas

- The existing `mutate_opcode` documentation says opcode mutation keeps operand structure. This fix intentionally adds one exception because `MNEG` has no `ra`; keep the exception local and documented so future reviewers do not mistake it for accidental invariant drift.
- Avoid flaky tests: use `StdRng::seed_from_u64(...)`, not `rand::rng()`, and loop enough times to cover the 4-way branch deterministically in local runs.
- Do not change the `MADD` and `MSUB` arms unless a test proves it is necessary. Their existing reverse edges to `MNEG` are the behavior this issue builds on.
- Do not direct-index `self.registers` for `ra`; that could panic with an empty register pool. `random_register` already handles the fallback.
- `parse -> print -> parse` idempotency is unaffected because no parser or `Display` implementation changes are planned.
- Binary fixed-point risks are absent in this repository layout: no `compiler/` tree exists, and the change does not touch codegen ordering, `BTreeMap`/`HashMap` iteration, stack-slot layout, assembler encoding, or binary patching.
- The `cargo clippy --all -- -D warnings` gate should stay quiet if the new test avoids unused helpers/imports and the comment-only refactor remains local.

## 6. Out Of Scope

- Creating a dedicated multiply-family mutation strategy.
- Retuning `MutationWeights` or changing stochastic operator selection probabilities.
- Editing `src/search/candidate.rs`, parser support, assembler support, SMT/concrete semantics, or `docs/capability.md`.
- Adding broad mutation-topology graph tests for every opcode family.
- Refactoring existing stochastic mutation tests into table-driven helpers.
- Running benchmarks, mutation testing, x86/RISC-V flows, LLM search, or unrelated integration fixtures.

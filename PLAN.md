# Plan: Tune Shifted-Register Mutation Probability

## 1. Problem Restated

The AArch64 stochastic mutator currently samples shifted-register operands with a duplicated hard-coded `0.15` probability in `random_operand_3op` and in the X64 `Tst` operand-mutation path. That low rate was a reasonable initial heuristic, but shifted-register collapses such as `lsl x3, x2, #2; add x0, x1, x3` -> `add x0, x1, x2, lsl #2` depend on this shape appearing often enough in MCMC proposals. The first implementation slice should make the heuristic explicit, raise it modestly, and pin the proposal distribution with deterministic tests without widening the public CLI/config surface.

## 2. Files To Touch

- `src/search/stochastic/mutation.rs`: add one private probability constant near the existing mutator constants at lines 24-30; replace the hard-coded `0.15` in the `Instruction::Tst` arm at lines 238-251 and in `random_operand_3op` at lines 1130-1140; add deterministic unit tests in the existing `#[cfg(test)]` module starting at line 1282.
- No `src/search/config.rs` change: do not add a public `StochasticConfig` field or CLI flag for this first slice. The current public knobs are `beta`, `iterations`, `test_count`, mutation operator weights, and seed at lines 89-141; this issue is about an internal operand-shape heuristic.
- No `src/search/stochastic/backend.rs` change expected: `AArch64Mutator::new` is constructed from registers, immediates, and mutation weights at lines 132-137. Keep that signature stable unless implementation discovers the probability truly needs to be configurable.
- No benchmark fixture change expected: `benches/algebraic_fusion/shift_fuse_lsl.s` already covers the shifted-register fusion target at lines 1-6. Use it for manual evidence, not as a source edit.
- No `crates/` or `compiler/` paths exist in this Rust repository, so there is no cross-compiler update.
- No `docs/spec/*.md` updates are required; this repository has no `docs/spec/` directory, and the change does not alter syntax, semantics, builtins, operators, effects, or CLI flags. `docs/capability.md` is unchanged because supported instructions do not change.

Chosen heuristic: start with `SHIFTED_REGISTER_OPERAND_PROBABILITY: f64 = 0.30`. This doubles the previous 15% heat while preserving a 70% fallback to the existing register/immediate distribution. Alternatives considered and rejected for the first PR: `0.25` is safer but may be too small to materially affect discovery; exposing a config/CLI knob adds API and docs surface before there is enough evidence that users need per-run control.

## 3. TDD Slices

1. **Pin the three-operand shifted-register distribution**
   - Test/location: add a unit test in `src/search/stochastic/mutation.rs` near `test_mutate_operand_can_produce_shifted_register` at lines 1324-1351.
   - Behavior under test: with `StdRng::seed_from_u64(134)` and 10,000 calls to `default_mutator().random_operand_3op(&mut rng, false)`, `Operand::ShiftedRegister` appears in a broad 25%-35% band and shifted samples never use `ShiftKind::Ror`.
   - Red: the current hard-coded `0.15` should produce about 15% shifted operands and fail the lower bound.
   - Green production code: add a private `SHIFTED_REGISTER_OPERAND_PROBABILITY` constant set to `0.30` and use it in `random_operand_3op` instead of the literal at line 1136.

2. **Pin the TST-specific distribution to the same heuristic**
   - Test/location: add a second unit test in `src/search/stochastic/mutation.rs` beside the distribution test.
   - Behavior under test: using a seeded `StdRng`, create a fresh one-instruction sequence initialized as `Instruction::Tst { width: RegisterWidth::X64, rm: Operand::Register(Register::X2), ... }` for each of 20,000 `mutate_operand` trials; shifted `rm` appears in a broad 12%-18% band, reflecting the 50% `rm` branch multiplied by the 30% shifted-register probability. Also assert the fresh `RegisterWidth::W32` TST path never emits `Operand::ShiftedRegister` in a smaller seeded loop.
   - Red: the current TST branch uses `0.15`, so the total shifted output rate is about 7.5% and should fail the 12% lower bound.
   - Green production code: replace the TST branch literal at line 247 with the shared constant or a tiny helper such as `should_emit_shifted_register(rng)`.

3. **Keep encodability and ROR policy intact**
   - Test/location: extend the new distribution tests or add a focused test in `src/search/stochastic/mutation.rs`.
   - Behavior under test: generated shifted operands installed into `Add`, `Sub`, `Cmp`, and `Cmn` remain encodable when `allow_ror=false`; generated shifted operands for logical/TST forms may include ROR only when `allow_ror=true`. This complements the existing `test_mutate_opcode_bridge_drops_ror_for_arith` at lines 1476-1517 and the proptest `mutator_output_is_classifiable` at lines 1912-1982.
   - Red: any accidental use of the logical ROR pool for arithmetic shifted-register forms would fail `is_encodable_aarch64()`.
   - Green production code: preserve the existing `allow_ror` threading in `random_operand_3op` and `random_shifted_register` at lines 1135-1162.

4. **Remove duplicated magic numbers and update comments**
   - Test/location: repository static check, not a Rust unit test: `rg -n "0\\.15|low probability" src/search/stochastic/mutation.rs`.
   - Behavior under test: the old 15% literal and stale "low probability" wording are gone; comments describe the heuristic as tuned and point to the shared constant.
   - Green production code: update comments around lines 1130-1134 and lines 244-247 without changing unrelated mutation behavior.

5. **Run the smallest useful regression set**
   - Test/location: existing unit tests in `src/search/stochastic/mutation.rs` and `src/search/stochastic/mcmc.rs`.
   - Behavior under test: stochastic mutation still produces classifiable/encodable candidates, preserves terminators, and the MCMC loop still runs.
   - Production code: no additional changes unless a regression exposes an issue in the probability helper.

## 4. Verification Surface

- ESBMC, Vow contracts, codegen, and the C model are not involved in this repository or this change. No properties need to be proved and no `tests/run/` or `examples/` fixtures need to grow.
- Parse -> print -> parse idempotency is unaffected because the parser, formatter, IR display, and instruction semantics are unchanged.
- Required local checks for the implementation stage:
  - `cargo test search::stochastic::mutation`
  - `cargo test search::stochastic::mcmc`
  - `cargo fmt -- --check`
  - `cargo clippy --all -- -D warnings`
  - Before commit/push, `./ci_check.sh` per `CLAUDE.md`.
- Performance evidence to record in the PR or issue comment: run or cite the deterministic distribution counts from the new unit tests, and optionally run a local stochastic probe against the existing `benches/algebraic_fusion/shift_fuse_lsl.s` target. Do not commit `benches/results/results.jsonl`; benchmark outputs are local artifacts.

## 5. Risk Areas

- Proposal mix regression: increasing shifted-register heat can reduce plain register/immediate proposals. Keep the first bump modest at 30% and do not change `MutationWeights` in the same PR.
- Probabilistic test flakiness: use `StdRng::seed_from_u64`, large trial counts, and broad bounds that fail 15% reliably but tolerate ordinary deterministic sample variance.
- Encodability churn: arithmetic shifted-register forms reject ROR, SP in some slots, and out-of-range shift amounts. Preserve `allow_ror=false` for `Add`, `Sub`, `Cmp`, and `Cmn`; keep relying on `Instruction::is_encodable_aarch64()`.
- W32 logical/TST behavior: the current W32 branches prefer logical-immediate forms and should not start emitting shifted-register operands accidentally.
- Clippy gate: adding a helper or constant only used in tests would trigger warnings. The shared probability constant must be used by production code.
- Binary fixed point, `BTreeMap` vs `HashMap` ordering, stack-slot layout, parser grammar, and codegen ordering are not touched.

## 6. Out Of Scope

- Adding a CLI flag or public `StochasticConfig` field for shifted-register probability.
- Retuning `MutationWeights`, acceptance temperature, iteration defaults, or random-sequence opcode selection.
- Redesigning the benchmark harness to emit stochastic rows by default. `src/bench_support.rs` already supports `Algorithm::Stochastic` when a caller constructs such a `BenchSpec`; changing fixture discovery from enumerative-only is a separate benchmark-policy PR.
- Changing candidate enumeration in `src/search/candidate.rs`, symbolic search, x86/RISC-V mutators, parser support, assembler encodability, or instruction semantics.
- Formatting churn, unrelated refactors, and edits under `build/` or any `symphony/` submodule if present.

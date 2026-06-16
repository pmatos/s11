# Plan - issue #112: Replace `bv_clz` ITE chain with binary-search decomposition

## 1. Problem Restated

The AArch64 SMT lowering currently computes CLZ with a width-deep nested ITE chain in `src/semantics/smt.rs::bv_clz`, so each symbolic `CLZ` contributes up to 64 dependent ITE levels, and each `CLS` reaches the same helper through the sign-fold expression `x ^ (x ASR 63)`. The goal is to keep the existing semantics exactly the same while changing the symbolic encoding to a binary-search decomposition over top halves (32, 16, 8, 4, 2, 1) so Z3 sees logarithmic ITE depth and lower solve time on CLZ/CLS-heavy equivalence queries.

## 2. Files To Touch

- `src/semantics/smt.rs` - replace the current `bv_clz` helper at lines 61-79, keep `Instruction::Clz` and `Instruction::Cls` call sites at lines 780-797 using the same helper, and add/extend unit tests in the existing `#[cfg(test)] mod tests` near the CLZ/CLS tests at lines 1578-1652 and concrete/SMT parity tests at lines 2777-2815.
- `benches/smt_clz.rs` [new] - add a narrow Criterion benchmark that times equivalent CLZ/CLS SMT queries directly through `check_equivalence_with_config_metrics`, separate from the search-oriented benchmark phases.
- `Cargo.toml` - add a `[[bench]]` entry for `smt_clz` next to the existing benchmark entries at lines 44-54.
- `benches/README.md` - document the new direct SMT benchmark command and make clear it is for before/after CLZ formula timing, not part of the phase 1/2/3 search fixture schema.
- `Justfile` [optional, only if keeping a project recipe useful] - add a `bench-smt-clz` recipe for `cargo bench --bench smt_clz`; do not silently fold this into long CI-like checks.

There are no `crates/`, `compiler/`, or `docs/spec/` directories in this s11 checkout. This is not a Vow compiler cross-cutting change, and no `docs/spec/*.md` update is required. The public AArch64 instruction set, parser grammar, CLI flags, and documented semantics do not change, so `docs/capability.md` and the ADRs should not change for this PR.

## 3. TDD Slices

1. Add a formula-shape regression test in `src/semantics/smt.rs`.
   - Test location: the existing SMT test module near `test_clz_of_one_is_63` at lines 1578-1598.
   - Behavior under test: a symbolic `bv_clz(&BV::new_const("x", 64), 64)` must not render as a width-deep ITE chain. Use a small test-only scanner over the SMT string to compute maximum nested `ite` depth, and assert a generous logarithmic bound such as `<= 16` rather than an exact count.
   - Red expectation: the current loop-based helper should fail because it nests one ITE per bit.
   - Production code to make it pass: replace `bv_clz` with a binary-search selected-half decomposition.

2. Implement the binary-search CLZ helper in `src/semantics/smt.rs`.
   - Production change: keep the public helper signature `fn bv_clz(value: &BV, width: u32) -> BV`.
   - Algorithm: maintain a selected chunk and a width-bit count. For each half size, test whether the upper half is zero; if yes, add the half size to the count and continue with the lower half, otherwise continue with the upper half. At the final one-bit chunk, add one only if that bit is zero.
   - Important shape: both branches of each `ite` must have the same bit width. The running count stays `width` bits; the selected chunk shrinks from 64 to 32 to 16 to 8 to 4 to 2 to 1 bits.
   - Guardrails: use `debug_assert!(width > 0)` and `debug_assert!(width.is_power_of_two())` because the current AArch64 path calls this with 64, and the halving logic assumes exact halves.

3. Extend CLZ semantic boundary coverage in `src/semantics/smt.rs`.
   - Test location: extend or split out from `test_clz_concrete_smt_parity` at lines 2777-2795.
   - Behavior under test: CLZ matches the concrete interpreter at split boundaries and edge cases: `0`, `1`, `2`, `3`, `0x10`, `1 << 31`, `1 << 32`, `1 << 63`, `u64::MAX`, and a mixed value such as `0x0000_0000_FFFF_FFFF`.
   - Production code that should make it pass: the new `bv_clz` helper used by `Instruction::Clz`.

4. Extend CLS transitive coverage in `src/semantics/smt.rs`.
   - Test location: extend `test_cls_concrete_smt_parity` at lines 2797-2815 and keep `test_cls_equivalent_to_clz_of_signfold` at lines 1413-1459 passing.
   - Behavior under test: CLS still matches concrete semantics for all-zero/all-one inputs, sign-bit-only inputs, opposite-sign-leading inputs, and boundary values whose sign-folded form crosses the same 32/16/8/4/2/1 CLZ splits.
   - Production code that should make it pass: the unchanged CLS lowering at lines 791-797 calling the new `bv_clz` helper.

5. Add direct before/after benchmark evidence.
   - Benchmark location: `benches/smt_clz.rs` [new].
   - Behavior under measurement: build equivalent sequence pairs such as one CLZ, four independent CLZs, one CLS, and four independent CLSs; compare each sequence with itself or with an equivalent temp-register form so `check_equivalence_with_config_metrics` reaches SMT and returns `Equivalent`.
   - Implementation detail: use `EquivalenceConfig::with_live_out(RegisterSet::from_registers(...)).random_tests(0).timeout(Duration::from_secs(30))` to reduce non-SMT noise, and let Criterion measure full wall time while recording `metrics.smt_elapsed`/`metrics.smt_formula_bytes` inside the benchmark if useful for `black_box`.
   - Baseline workflow: after adding only the benchmark file and Cargo entry, run `cargo bench --bench smt_clz -- --quick` on the old helper and save the output in the PR body or a local evidence note; rerun the same command after the `bv_clz` rewrite.

6. Refactor only after green.
   - Remove the stale TODO at lines 67-68 once the helper is rewritten.
   - Keep comments focused on the binary-search invariant and width choices.
   - Do not introduce a new public API unless the private helper becomes hard to read; all consumers should continue calling `bv_clz` through the existing CLZ/CLS instruction lowering.

## 4. Verification Surface

- ESBMC, Vow contracts, the C model, self-hosted compiler codegen, and `tests/run/` fixtures are not applicable in this repository. No contract should be weakened, and no function needs to be marked unverifiable.
- No `examples/`, `tests/asm/`, or `tests/integration/` fixtures need to grow because there is no parser, CLI, assembler, or machine-code behavior change.
- Focused tests:
  ```bash
  cargo test semantics::smt::tests::test_bv_clz_formula_has_logarithmic_ite_depth -- --exact
  cargo test semantics::smt::tests::test_clz_concrete_smt_parity -- --exact
  cargo test semantics::smt::tests::test_cls_concrete_smt_parity -- --exact
  cargo test semantics::smt::tests::test_clz_floor_log2_pattern -- --exact
  ```
- Broader local verification:
  ```bash
  cargo test semantics::smt
  cargo fmt -- --check
  cargo clippy --all-targets -- -D warnings
  ```
- Repository gate before commit/push:
  ```bash
  ./ci_check.sh
  ```
- Performance evidence:
  ```bash
  cargo bench --bench smt_clz -- --quick
  ```
  Capture before/after Criterion summaries plus `smt_elapsed`/formula-size observations if the benchmark prints them. Do not gate CI on timing thresholds; Z3 timings are noisy.

## 5. Risk Areas

- A naive recursive implementation can still build a large eager AST because both ITE branches are constructed before the parent ITE. Prefer the iterative selected-half decomposition so the selected chunk narrows each step and the term shape stays compact.
- Bit-vector width mismatches are the main correctness risk. The CLZ result must remain a `width`-bit BV because it is written into a 64-bit register and CLS subtracts a width-bit `1`; the selected chunk is the only term that shrinks.
- The zero input must return `width` (64 today), not `width - 1`. The final one-bit step must distinguish zero from one after all upper-zero decisions have been accumulated.
- `BV::extract(half - 1, 0)` and `BV::from_u64(half as u64, width)` need careful loop bounds to avoid underflow and branch sort mismatches.
- The formula-depth regression test will inspect Z3's printed term shape. Keep it deliberately coarse and do not assert exact formula bytes or exact ITE counts.
- Binary fixed-point risks are absent: there is no `compiler/` tree here, and this plan does not touch codegen ordering, `BTreeMap`/`HashMap` determinism, stack-slot layout, or any `vow-clif-shim`-style component.
- `parse -> print -> parse` idempotency is unaffected because no parser, formatter, or IR display code changes.
- The `cargo clippy --all-targets -- -D warnings` gate can fail on unused imports/helpers in the new benchmark or test-only scanner; keep helper functions local and used.
- Benchmark results can vary by host load and Z3 version. Treat them as supporting evidence, not a hard correctness criterion.

## 6. Out Of Scope

- Changing concrete CLZ/CLS semantics in `src/semantics/concrete.rs`.
- Changing the CLS sign-fold lowering beyond its use of the rewritten `bv_clz`.
- Adding or removing AArch64 mnemonics, parser rules, Capstone conversion behavior, assembler encodings, or `docs/capability.md` rows.
- Generalizing this work to x86 or RISC-V SMT helpers.
- Introducing an uninterpreted CLZ function, solver-specific tactics, or a new dependency to model CLZ.
- Refactoring `MachineState`, equivalence configuration, search algorithms, or the existing phase 1/2/3 benchmark JSON schema.
- Adding timing thresholds to unit tests or CI.

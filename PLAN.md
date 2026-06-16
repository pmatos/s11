# Plan - issue #115: Re-balance AArch64 MCMC bit-manipulation sampling

## 1. Problem Restated

The current AArch64 random candidate tables still route `CLZ`, `CLS`, `RBIT`, `REV`, `REV32`, and `REV16` through one shared random-generation slot in both `AArch64InstructionGenerator::generate_random` and `search::candidate::generate_random_instruction`. In the current 33-slot tree each bit-manipulation opcode is sampled at roughly `1 / (33 * 6)`, while singleton top-level opcodes are sampled at `1 / 33`; this preserves the original issue's 6x starvation even though later issues grew the table. The minimal fix is to give each of the six single-source bit-manipulation ops its own top-level slot in both samplers, without changing opcode IDs, semantics, parsing, assembler output, or `opcode_count()`.

## 2. Files To Touch

- `src/isa/aarch64.rs` - add a distribution regression test near `slot_23_sub_multiplexer_removed_for_issue_93`, promote the bit-manipulation arm in `AArch64InstructionGenerator::generate_random`, update the random-slot comments, and update the `opcode_count()` doc comment that currently says the bit ops are folded behind slot 26.
- `src/search/candidate.rs` - add the matching distribution regression test in the existing candidate-generator tests, promote the bit-manipulation arm in `generate_random_instruction`, and update the random-slot comments.
- `src/search/stochastic/mutation.rs` - update the stale comment that points at `candidate.rs::generate_random_instruction` "case 27" for `CCMP`/`CCMN` after candidate slots shift.

There are no `crates/`, `compiler/`, or `docs/spec/` directories in this repository, so this is not a cross-compiler or Vow-spec change. `docs/capability.md` does not need an update because the supported mnemonic set is unchanged; this PR changes only stochastic sampling weights.

## 3. TDD Slices

1. Add a red distribution test for the stochastic search candidate generator in `src/search/candidate.rs::tests`, near the existing random reachability tests around `random_opcode_ids`. Use `ChaCha8Rng`, `default_registers()`, `default_immediates()`, and `opcode_id` to count 30,000 calls to `generate_random_instruction`. Assert each representative `Instruction::{Clz, Cls, Rbit, Rev, Rev32, Rev16}` opcode ID appears at least 500 times. The current code should fail because each opcode is expected near 152 hits; the promoted 38-slot table should put each near 789 hits.

2. Make the candidate-generator test pass by changing `src/search/candidate.rs::generate_random_instruction`: grow `rng.random_range(0..33)` to `0..38`, replace the slot-26 six-way sub-multiplexer with slots `26` through `31` for `Clz`, `Cls`, `Rbit`, `Rev`, `Rev32`, and `Rev16`, then shift the existing later arms to `32` through `37` while preserving their internal sub-multiplexers.

3. Add the analogous red distribution test in `src/isa/aarch64.rs::tests`, near `slot_23_sub_multiplexer_removed_for_issue_93`. Use `AArch64InstructionGenerator::generate_random`, the same 30,000 fixed-seed draw count, and the same `>= 500` threshold for the six bit-manipulation opcode IDs. The current generator should fail for the same 6x-starvation reason.

4. Make the trait-generator test pass by changing `src/isa/aarch64.rs::AArch64InstructionGenerator::generate_random`: grow `rng.random_range(0..33)` to `0..38`, replace the slot-26 six-way sub-multiplexer with slots `26` through `31`, and shift `MADD` family, `CCMP`/`CCMN`, bit-field aliases, `CSET`, `CSETM`, and `ROR` to slots `32` through `37`. Keep `opcode_count()` at `55`; it counts stable opcode IDs, not random slots.

5. Refactor only the comments needed to keep contracts honest. In `src/isa/aarch64.rs`, update the top-of-table comment and the `opcode_count()` doc comment so they say the random table has 38 slots and no longer name the bit-manipulation ops as a folded family. In `src/search/stochastic/mutation.rs`, change the `candidate.rs` case-number comment to either the new slot number or a case-number-free phrase.

6. Run the focused green checks, then the normal repository gate:
   ```bash
   cargo test generate_random_instruction_promotes_single_source_bit_ops_to_top_level_slots
   cargo test aarch64_random_generation_promotes_single_source_bit_ops_to_top_level_slots
   cargo test slot_23_sub_multiplexer_removed_for_issue_93
   cargo fmt -- --check
   cargo test
   ./ci_check.sh
   ```

## 4. Verification Surface

- No ESBMC work is needed. This change does not touch contracts, codegen, the C model, SMT lowering, concrete semantics, parser grammar, assembler encoding, ELF patching, or binary output.
- No fixtures under `tests/run/` or `examples/` need to grow; neither directory exists in this checkout. No `tests/asm/`, `tests/integration/`, or benchmark fixture is required because the observable change is the random sampler distribution, not accepted syntax or end-to-end optimization behavior.
- The key proof-by-test is statistical but deterministic: fixed-seed 30,000-draw tests distinguish the current `~152` hits per bit opcode from the promoted `~789` hits per bit opcode with a wide threshold.

## 5. Risk Areas

- `opcode_count()` must not be bumped as part of this change. In the current tree it is explicitly the upper bound for `Instruction::opcode_id()`, not the random slot count; changing it would break the stable opcode-family contract and the existing `all_instruction_families_cover_trait_methods` test.
- The two random tables are parallel but not numerically identical today. Do not copy one table wholesale into the other; promote only the six bit-manipulation opcodes and shift each table's existing later arms in place.
- Distribution tests can become flaky if thresholds are too tight. Keep the fixed seed and a deliberately loose threshold that fails the current clustered table but sits far below the promoted table's expected count.
- Slot shifts can leave stale comments, especially the `CCMP`/`CCMN` case-number comment in `src/search/stochastic/mutation.rs`; use `rg "slot 26|slot 27|0\\.\\.33|6-way sub-multiplexer|case 27"` after the edit.
- The change slightly reduces every former top-level opcode's absolute probability from `1/33` to `1/38`; that is the intentional tradeoff for making the six bit ops first-class slots. Existing sub-multiplexed families such as multiply-accumulate and bit-field aliases remain out of scope.
- `parse -> print -> parse` idempotency and binary fixed-point concerns are absent because parsing, formatting, assembler/codegen ordering, map iteration, stack-slot layout, and `vow-clif-shim`-style components are not touched. The `cargo clippy --all -- -D warnings` gate should only be at risk from unused imports in the new tests.

## 6. Out Of Scope

- Adding or tuning a full Criterion stochastic-convergence benchmark for a CLZ-shaped target. The existing bench harness is not CI-gated and fixture sweeps are costly; this PR should close the sampler-policy issue with deterministic distribution regressions.
- Rebalancing other shared random slots such as multiply-accumulate, conditional compare, bit-field aliases, compare, multiply/divide, or conditional-select families.
- Refactoring the duplicated AArch64 random tables into a shared abstraction or introducing a global random-slot constant.
- Changing opcode IDs, `opcode_count()`, instruction semantics, encodability rules, parser support, docs/capability mnemonic inventories, CLI flags, or benchmark JSON schema.

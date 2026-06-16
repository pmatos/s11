# Plan - issue #121: Add 32-bit W-register forms across the AArch64 IR

## 1. Problem Restated

The AArch64 IR currently represents most data-processing instructions as operating on the canonical 64-bit X register view, with only a few already-width-aware islands for logical immediates and memory access widths. The goal is to add architecturally valid 32-bit W-register forms across the AArch64 IR stack without introducing a second register enum: parsing, display, encodability, concrete semantics, SMT semantics, assembler emission, search generation, mutation, costs, Capstone-to-IR coverage, and docs should agree that `wN` forms operate on the low 32 bits, wrap at 32 bits where applicable, compute flags from bit 31, and write back zero-extended results to the underlying architectural register.

## 2. Files To Touch

There are no `crates/`, `compiler/`, or `docs/spec/` directories in this repository, so the Vow self-hosted compiler/spec synchronization requirement is not applicable here. The accepted s11 sources of truth are `CLAUDE.md`, `docs/capability.md`, and the Rust modules below.

- `src/ir/types.rs` - keep `Register` as the physical register identity, reuse existing `RegisterWidth`, and add/reuse width-aware operand/register formatting helpers so W instructions print W operands consistently.
- `src/ir/instructions.rs` - add explicit W sibling variants for the first completed data-processing family, update `destination`, `destinations`, `source_registers`, `is_encodable_aarch64`, and `Display`. For a later broader sweep, either continue the sibling-variant pattern or migrate to `RegisterWidth` fields; for variants that already use `width` for another meaning, such as bitfield field width, use an unambiguous name like `reg_width`.
- `src/parser/mod.rs` - parse W and X data-processing forms with same-width checks, reject mixed W/X operands early, preserve existing W logical-immediate and memory parsing, and keep `convert_to_ir` delegation intact.
- `src/semantics/state.rs` - make AArch64 flag helpers width-parameterized or add wrappers that compute N/Z/C/V for 32-bit and 64-bit operations.
- `src/semantics/concrete.rs` - evaluate W forms with 32-bit masks, 32-bit shifts, 32-bit flag semantics, and zero-extended writes into the canonical register file.
- `src/semantics/smt.rs` - mirror concrete W behavior using 32-bit bitvectors internally and zero-extend results to the 64-bit machine-state width.
- `src/semantics/equivalence.rs` - add or route tests that prove W-specific equivalences and non-equivalences against the concrete/SMT bridge.
- `src/semantics/cost.rs` - ensure W and X forms have the same intended AArch64 cost unless a specific encoding size/cost difference is documented.
- `src/assembler/mod.rs` - emit dynasm W encodings for accepted W forms and reject any parser-accepted form that dynasm/ARM does not actually encode.
- `src/isa/aarch64.rs` - update ISA-level instruction construction, validation, and formatting hooks that pattern-match on changed variants.
- `src/search/candidate.rs` - add W candidates deliberately rather than blindly doubling the search space; start with the first completed vertical family, then expand.
- `src/search/stochastic/mutation.rs` - preserve instruction width during operand mutation and make opcode mutation choose compatible W/X families.
- `src/search/symbolic/sketch.rs` - audit the legacy sketch path. If it remains active for any widened instruction, add a width bit; otherwise document that direct sketches remain X64-only while concrete candidate synthesis covers W forms.
- `src/main.rs` - extend `convert_capstone_op_handles_all_supported_aarch64_mnemonics` with canonical W operand strings once the parser supports them.
- `src/docs_support.rs` - audit only; update if capability-table tests require width-specific documentation metadata.
- `docs/capability.md` - update the AArch64 support matrix to name W/X coverage precisely, including any deliberately X-only variants.
- `tests/integration/docs_capability.rs` - add docs guard coverage for the new W data-processing support.
- `tests/asm/w32_register_forms.s` - add only if an end-to-end `s11 equiv` or parser fixture gives useful coverage beyond unit tests.

## 3. TDD Slices

1. Establish the design guard for the first vertical slice.
   - Tests: add red tests in `src/parser/mod.rs` for `add w0, w1, w2`, `add w0, w1, #1`, `mov w0, w1`, and representative mixed-width rejections such as `add w0, x1, w2`.
   - Tests: add red display/idempotency tests in `src/ir/instructions.rs` so constructing the new W forms prints `add w0, w1, w2` and reparses to the same IR.
   - Production: add explicit `AddW`, `SubW`, and `MovRegW` variants; introduce width-aware parser helpers for ordinary data-processing registers; update all pattern matches mechanically until the crate compiles.

2. Complete ADD/SUB/MOV W semantics end to end.
   - Tests: in `src/semantics/concrete.rs`, assert `add w0, w1, #1` wraps from `0xffff_ffff` to `0`, zeroes the upper 32 bits, and leaves unrelated X registers unchanged.
   - Tests: in `src/semantics/smt.rs` or `src/semantics/equivalence.rs`, prove a W ADD rewrite such as `mov w0, w1; add w0, w0, #1` equals `add w0, w1, #1`, and add a non-equivalence showing X ADD differs when high bits are live.
   - Tests: in `src/assembler/mod.rs`, assemble W ADD/SUB/MOV register and immediate forms and assert successful encoding or exact bytes if the file already has byte-level expectations nearby.
   - Production: add width-aware concrete helpers, SMT helpers, assembler arms, and encodability rules for ADD/SUB/MOV W forms, including WSP where the ISA permits SP in immediate ADD/SUB forms. W extended-register arithmetic remains a documented follow-up.

3. Add flag-setting arithmetic and compare aliases.
   - Tests: in `src/parser/mod.rs`, parse and reject same/mixed-width forms for `adds`, `subs`, `cmp`, `cmn`, `neg`, and `negs`.
   - Tests: in `src/semantics/concrete.rs`, pin W flag behavior for bit 31 negative, zero, carry, and overflow cases.
   - Tests: in `src/semantics/smt.rs`, mirror the concrete flag cases with SMT parity tests.
   - Production: add `RegisterWidth` to `Adds`, `Subs`, `Cmp`, `Cmn`, `Neg`, and `Negs`; make AArch64 `ConditionFlags::from_add`, `from_sub`, and `from_logical` width-aware.

4. Expand existing logical W support from immediates to register and shifted-register forms.
   - Tests: in `src/parser/mod.rs`, cover `and w0, w1, w2`, `orr w0, w1, w2, lsl #3`, `eor w0, w1, w2`, `ands w0, w1, w2`, and `tst w1, w2`.
   - Tests: in `src/ir/instructions.rs`, update encodability so W register forms are accepted and W shifts reject `#32` while X still permits up to `#63`.
   - Tests: in `src/assembler/mod.rs`, add W register and shifted encodings for `and`, `orr`, `eor`, `ands`, and `tst`.
   - Production: reuse the existing `RegisterWidth` on `And`, `Orr`, `Eor`, `Ands`, and `Tst`, add width-aware operand display/evaluation, and remove the current `width == X64` restriction for W register operands.

5. Add logical aliases and unary logical forms.
   - Tests: in parser, concrete, SMT, and assembler modules, cover W forms for `bic`, `bics`, `orn`, `eon`, and `mvn`.
   - Tests: add W flag semantics for `bics` and ensure `mvn w0, w1` zero-extends.
   - Production: add `RegisterWidth` to these variants and wire the shared logical-register operand helper through parser, display, encodability, semantics, and dynasm emission.

6. Add shifts, rotates, and bitfield aliases.
   - Tests: cover `lsl w0, w1, #31`, `lsr w0, w1, #31`, `asr w0, w1, #31`, `ror w0, w1, #31`, and variable-shift forms where the IR supports them; reject W immediate shift `#32`.
   - Tests: cover W bitfield aliases such as `ubfx w0, w1, #0, #8`, `sbfx w0, w1, #8, #8`, `bfi w0, w1, #8, #8`, `bfxil w0, w1, #8, #8`, `ubfiz w0, w1, #8, #8`, and `sbfiz w0, w1, #8, #8`.
   - Production: add `RegisterWidth` to `Lsl`, `Lsr`, `Asr`, `Ror`, and add a separate `reg_width` to bitfield variants whose existing `width` field means bitfield length. Apply W-specific immediate bounds and zero-extension/sign-extension behavior.

7. Add single-source bit manipulation W forms.
   - Tests: cover `clz w0, w1` returning `32` for zero input, `cls w0, w1` using bit 31, `rbit w0, w1`, `rev w0, w1`, and `rev16 w0, w1`.
   - Tests: explicitly document whether `rev32 w0, w1` is rejected as architecturally invalid or encoded as a valid dynasm form; do not infer this from the X64 variant name alone.
   - Production: add `RegisterWidth` to `Clz`, `Cls`, `Rbit`, `Rev`, `Rev16`, and only to `Rev32` if the assembler confirms an architectural W form. Use 32-bit helpers and zero-extend W results.

8. Add multiply/divide and conditional-select W forms.
   - Tests: cover `mul`, `sdiv`, `udiv`, `madd`, `msub`, `mneg`, `csel`, `csinc`, `csinv`, `csneg`, `cset`, and `csetm` W forms, including signed 32-bit division edge cases.
   - Tests: assert `smulh` and `umulh` remain rejected for W unless an architectural W encoding is verified.
   - Production: add `RegisterWidth` to the valid variants, apply 32-bit wrap/sign behavior, and update assembler/search/cost pattern matches.

9. Add move-wide and explicit extension coverage.
   - Tests: cover `movn w0, #imm`, `movz w0, #imm`, and `movk w0, #imm, lsl #16`; reject W move-wide shifts above `#16` while X still permits `#32` and `#48`.
   - Tests: audit existing `uxtb`, `uxth`, `sxtb`, `sxth`, and `sxtw` parser/display/assembler behavior and add regression tests only where W/X spelling is currently misleading.
   - Production: add `RegisterWidth` to `MovN`, `MovZ`, and `MovK`; leave existing extension aliases alone unless tests show they need a register-width spelling fix.

10. Wire search, mutation, costs, and ISA integration after semantics are green.
    - Tests: in `src/search/candidate.rs`, assert the candidate pool includes representative W ADD/logical/CLZ forms and that every generated W candidate passes `is_encodable_aarch64`.
    - Tests: in `src/search/stochastic/mutation.rs`, mutate representative W instructions and assert the result stays W-compatible and encodable.
    - Tests: in `src/semantics/cost.rs` and/or existing cost tests, assert W and X forms have the intended equal cost.
    - Production: update candidate generation gradually by family, preserve width in mutators, avoid invalid W/X opcode swaps, and update `src/isa/aarch64.rs` constructors or trait hooks.

11. Update Capstone coverage, docs, and CLI-facing fixtures.
    - Tests: extend `src/main.rs::convert_capstone_op_handles_all_supported_aarch64_mnemonics` with W data-processing examples for every newly accepted family.
    - Tests: extend `tests/integration/docs_capability.rs` so `docs/capability.md` must mention W/X data-processing support, not just W logical immediates and W memory loads/stores.
    - Tests: add `tests/asm/w32_register_forms.s` only if it exercises a real end-to-end path not already covered by unit tests.
    - Production/docs: update `docs/capability.md`; no CLI flag or `--live-out` grammar change is planned because live-out registers can remain canonical X names observing the architectural register after W zero-extension.

12. Final verification before PR.
    - Run targeted tests after each slice, then run `cargo fmt -- --check`, `cargo test`, `cargo clippy --all -- -D warnings`, and the repository-required `./ci_check.sh`.
    - If a W form parses but cannot be emitted by dynasm, either implement the raw encoding with a focused test or remove that parser support and document the form as out of scope for this issue.

## 4. Verification Surface

ESBMC, C-model proofs, `tests/run/`, and self-hosted compiler fixed-point checks are not applicable in this s11 repository because those Vow paths are absent. The formal verification surface here is the existing Rust concrete interpreter plus Z3 SMT equivalence checking.

The implementation should prove or test these properties:

- W writes zero-extend into the 64-bit architectural register file.
- W arithmetic, logical, shift, rotate, bitfield, and multiply/divide operations use 32-bit masks and wrap where the ISA requires.
- W flag-setting operations compute N from bit 31, Z from the masked 32-bit result, and C/V from 32-bit arithmetic.
- Parser, `Display`, and parser round-trip agree on W spelling, and mixed W/X operands are rejected before reaching assembler or semantics.
- `is_encodable_aarch64` matches assembler reality for every newly accepted W form.
- Concrete and SMT behavior agree for representative W instructions and at least one W superoptimization equivalence.
- Capstone-style operand strings in `src/main.rs` still delegate through `parser::parse_line` without reintroducing a parallel mnemonic switch.

Fixtures under `tests/asm/` may grow with one compact W-register file if it gives CLI-equivalence coverage. `examples/` and `tests/data/llm_demo/` should not grow for this issue unless reviewers request user-facing examples.

## 5. Risk Areas

- The existing `Register` enum intentionally names physical registers, not X versus W views. Adding W enum variants would ripple through live-out, memory, and search unnecessarily; prefer `RegisterWidth` on instructions.
- Several variants already have a field named `width` for bitfield length or access width. Do not overload that name for register width in those variants; use `reg_width` or a similarly explicit field.
- `Operand::Display` currently prints register operands as X names. W register/shifted-register forms need width-aware operand formatting or parse-print-parse will silently produce invalid mixed-width text.
- W writes must zero upper 32 bits. Preserving upper bits would make concrete and SMT equivalence unsound.
- Flag helpers are currently mostly 64-bit for AArch64. Reusing them for W forms would get N/C/V wrong around bit 31.
- SP/WSP and ZR/WZR are context-sensitive. WSP is valid in some ADD/SUB immediate or extended positions, but plain W register operands should continue to reject SP where the ISA rejects it.
- Shift bounds differ by width. W immediate shifts and bitfield ranges must reject values that are legal for X forms.
- Candidate generation can explode if every W form is added blindly. Add W families after their parser/semantics/assembler slice is green, and keep tests around pool size or encodability if needed.
- Some current IR mnemonics may not have exact W encodings, especially `Rev32`, `Smulh`, and `Umulh`. Verify through assembler tests and document any X-only result in `docs/capability.md`.
- Updating enum fields will create broad pattern-match churn. Watch for `cargo clippy --all -- -D warnings` failures from unreachable arms, unused helpers, or partially-updated tests.
- Existing W logical-immediate and memory support must keep working; regression tests should cover those paths while broadening W data-processing.

## 6. Out Of Scope

- Introducing separate `W0..W30` register variants or changing live-out register-set syntax.
- Reworking the whole ISA trait abstraction or making x86/RISC-V changes.
- Changing memory access semantics, load/store W/X coverage, or ADR-0007 memory behavior except for incidental compile fixes.
- Adding SIMD, floating-point, atomics, or branch/terminator W-style features.
- Refactoring search architecture, cost modeling strategy, or symbolic sketch design beyond what is needed to support accepted W forms.
- Weakening any equivalence, parser, or encodability contract to fit a verifier.
- Modifying absent Vow paths such as `crates/`, `compiler/`, `docs/spec/`, `tests/run/`, or `vow-clif-shim`.
- Bundling unrelated formatting, docs cleanup, benchmark changes, mutation-test changes, or dependency updates into the implementation PR.

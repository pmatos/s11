# Plan — issue #74: x86 CMOVcc, Jcc, and symbolic EFLAGS

## 1. Problem Restated

The x86 backend can already optimize straight-line integer instructions, but CMP is only soundly useful when the backend also models the EFLAGS it writes and the instructions that read those flags. This issue closes that gap by treating CMOVcc as a rewritable flag-reading instruction, treating Jcc as a fixed trailing terminator whose branch outcome observes the prefix's final EFLAGS, and making concrete plus SMT equivalence reject register or EFLAGS divergence whenever flags are live or a pinned flag-reading terminator makes them observable. Current checkout already contains much of this shape; the implementation stage should complete the remaining gaps and normalize the stale surfaces rather than starting from a blank branch.

## 2. Files to Touch

No `crates/`, `compiler/`, or `docs/spec/` directories exist in this `s11` checkout, so there is no Rust/self-hosted compiler split and no `docs/spec/*.md` update for this issue. The authoritative docs are `CLAUDE.md`, `docs/capability.md`, and `docs/adr/*.md`.

Production and docs:

- `src/isa/x86.rs` — `X86Condition`, `X86Instruction::{Cmov,Jcc}`, destination/source/side-effect/terminator behavior, `FlagsAnalysis::{modifies_flags,reads_flags}`, stochastic `X86Mutator`, and `X86InstructionGenerator` opcode coverage. Clean up stale "14 variants" / "7 mnemonics" comments and tests.
- `src/parser/x86.rs` — CMOVcc and Jcc suffix parsing, GAS alias normalization, numeric target validation for Jcc, x86 assembly parser coverage.
- `src/assembler/x86.rs` — x86-64 and x86-32 dynasm encoding for CMOVcc plus placeholder short-form Jcc encoding used only by round-trip tests; production patching must continue pinning original Jcc bytes.
- `src/ir/instructions.rs` — `split_terminator_x86` tests and comments for trailing Jcc peeling.
- `src/semantics/state.rs` — `Eflags` helpers. Add accurate AF computation for add/sub (`((lhs ^ rhs ^ result) & 0x10) != 0`) while keeping logical-op AF as the chosen false/undefined model.
- `src/semantics/concrete_x86.rs` — concrete CMP, arithmetic/logical EFLAGS, CMOV true/false behavior, and live-out comparison including EFLAGS.
- `src/semantics/smt_x86.rs` — symbolic flag state. Prefer issue-faithful Z3 `Bool` fields for `cf/pf/af/zf/sf/of` instead of five 1-bit BVs; compute them in arithmetic/logical/CMP lowering; make CMOV select through `Bool::ite`.
- `src/semantics/equivalence.rs` — x86 equivalence must compare flag state when `X86LiveOutMask::flags_live()` is true, force flags live for matching trailing Jcc terminators, randomize initial EFLAGS in the fast path, and keep the SMT path as the authoritative flag proof.
- `src/search/candidate_x86.rs` — enumerate CMOVcc for search candidates, continue excluding Jcc terminators, and include CMOV in random x86 candidate generation if stochastic search is expected to synthesize it.
- `src/search/stochastic/backend.rs` — should need little production change if `candidate_x86`/`X86Mutator` are fixed, but keep x86-32 register filtering and terminator handling covered.
- `src/search/symbolic/backend.rs` — confirm both x86 backends enumerate CMOV candidates and append any target Jcc terminator to proposals before equivalence checking.
- `src/validation/live_out.rs` — derive x86 `flags_live` from the flag-writer predicate (`FlagsAnalysis::modifies_flags`) rather than relying on broad side-effect wording; keep CMOV/Jcc as flag readers, not flag writers.
- `src/main.rs` — Capstone-to-x86-IR bridge, x86 basic-block validation, fixed-terminator search/patching, and issue #74 end-to-end tests.
- `src/semantics/cost_x86.rs` — CMOV and Jcc cost estimates.
- `src/docs_support.rs` and `docs/capability.md` — list `cmov<cond>` / `j<cond>` support accurately, distinguishing rewritable CMOV from fixed Jcc terminators.
- `tests/integration/docs_capability.rs` — pin the x86 capability docs so CMOV/Jcc do not drift from the supported source surface.

## 3. TDD Slices

1. **Docs and capability red test.**
   - Test location: `tests/integration/docs_capability.rs::x86_support_is_visible_in_public_docs`.
   - Behavior: docs must mention the x86 core mnemonics plus CMOVcc support and Jcc as fixed trailing terminators; hybrid/LLM remain AArch64-only.
   - Production/docs: update `src/docs_support.rs::X86_SUPPORTED_MNEMONICS` and `docs/capability.md`.

2. **IR and parser suffix coverage.**
   - Test location: `src/isa/x86.rs::tests` and `src/parser/x86.rs::tests`.
   - Behavior: all 16 canonical conditions parse for `cmov*` and `j*`; common GAS aliases normalize; CMOV has destination plus `rd,rs` sources; Jcc has no destination/register sources, reads flags, and is a terminator.
   - Production: `src/isa/x86.rs` and `src/parser/x86.rs`.

3. **Assembler and Capstone round trips.**
   - Test location: `src/assembler/x86.rs::tests` plus `src/main.rs` issue #74 round-trip tests.
   - Behavior: x86-64 and x86-32 CMOV encodes/disassembles/parses back to the same IR; short-form placeholder Jcc encodes for tests; `convert_to_x86_ir` accepts Capstone CMOV/Jcc.
   - Production: `src/assembler/x86.rs`, `src/parser/x86.rs`, `src/main.rs`.

4. **Concrete EFLAGS and CMOV semantics.**
   - Test location: `src/semantics/concrete_x86.rs::tests` and `src/semantics/state.rs::tests`.
   - Behavior: ADD/SUB/CMP compute CF/PF/AF/ZF/SF/OF at width 32 and 64; logical ops clear CF/OF and use the selected false/undefined AF model; CMOV writes `rd` only when the incoming condition holds and never mutates EFLAGS.
   - Production: `src/semantics/state.rs` and `src/semantics/concrete_x86.rs`.

5. **Symbolic EFLAGS as Bool state.**
   - Test location: `src/semantics/smt_x86.rs::tests`.
   - Behavior: `MachineStateX86::new_symbolic` has symbolic Bool flags `cf/pf/af/zf/sf/of`; symbolic ADD/SUB/CMP/logical flag results match concrete samples; CMOV lowers to `cond.ite(rs, old_rd)` and preserves all flags.
   - Production: `src/semantics/smt_x86.rs`.

6. **Equivalence with live EFLAGS and fixed Jcc.**
   - Test location: `src/semantics/equivalence.rs::tests`.
   - Behavior: with `random_test_count = 0`, SMT rejects two CMPs that differ only in final EFLAGS under `flags_live=true`; without flags live, register-dead CMP-only differences remain equivalent; CMOV vs unconditional MOV is rejected for register live-out because initial flags are symbolic/randomized; matching trailing Jcc terminators force flag equality on prefixes; differing or one-sided Jcc terminators are rejected.
   - Production: `src/semantics/equivalence.rs` and `src/semantics/smt_x86.rs`.

7. **Search candidate surface.**
   - Test location: `src/search/candidate_x86.rs::tests`, `src/isa/x86.rs::tests`, and x86 stochastic tests under `src/search/stochastic/`.
   - Behavior: enumerative/symbolic candidate pools include every CMOV condition for each register pair, never include Jcc, and remain mode32-safe; random x86 candidate/mutator paths can synthesize or preserve CMOV without introducing Jcc.
   - Production: `src/search/candidate_x86.rs`, `src/isa/x86.rs`, and possibly `src/search/stochastic/backend.rs`.

8. **End-to-end x86 optimizer window behavior.**
   - Test location: `src/main.rs::tests`.
   - Behavior: mid-window Jcc is rejected; trailing Jcc is accepted as a pinned terminator; `find_shorter_equivalent_x86` can optimize a prefix while preserving the original Jcc bytes and refusing terminator changes; CMP+CMOV pipelines distinguish different CMOV sources under flags-live/register-live contracts.
   - Production: `src/main.rs`, `src/ir/instructions.rs`, `src/semantics/equivalence.rs`.

9. **Refactor cleanup and narrow verification.**
   - Test location: existing unit tests in touched modules.
   - Behavior: stale assertions that still expect "7 mnemonics", "14 variants", or "CMP symbolic no-op" are updated or deleted only when replaced by the stronger issue #74 assertions.
   - Production: comments and tests in touched files only.

## 4. Verification Surface

- No ESBMC, contract, C-model, `tests/run/`, or `examples/` work is required in this Rust-only repository slice.
- Codegen verification is the x86 assembler/Capstone round-trip tests in `src/assembler/x86.rs` and `src/main.rs`; Jcc patching verification must assert original terminator bytes are spliced back rather than re-encoded.
- Semantic verification is unit-level Z3 proof work in `src/semantics/smt_x86.rs` and `src/semantics/equivalence.rs`, especially tests that force the SMT path by setting `random_test_count = 0`.
- Search verification should include targeted unit tests plus the existing x86 stochastic/symbolic smoke tests. Do not rely on stochastic discovery as the only proof of correctness.
- Before PR: run `cargo fmt -- --check`, targeted `cargo test issue_74`, `cargo test x86`, `cargo test --test integration docs_capability`, then the repository-mandated `./ci_check.sh`.

## 5. Risk Areas

- **Bool vs 1-bit BV churn:** converting flags to Z3 `Bool` touches many helper/test expressions. Keep register values as BVs; only flags should become Bools.
- **AF semantics:** no current condition code reads AF, but `flags_live=true` compares EFLAGS. Model AF deterministically for ADD/SUB/CMP and document logical-op AF as the chosen false/undefined model.
- **Jcc target opacity:** the IR intentionally discards branch targets. Do not re-encode Jcc into patched binaries; only preserve original bytes for a trailing terminator.
- **Parse -> print -> parse:** `Display` for Jcc cannot recover a real target. Either keep tests away from Display-as-source for Jcc or choose a documented parseable dummy target; do not accidentally promise target round-tripping that the IR cannot provide.
- **Search pool blow-up:** CMOV multiplies register pairs by 16 conditions. Keep Jcc out of candidate pools and preserve mode32 register filtering.
- **Fast-path soundness:** random concrete inputs must vary initial EFLAGS whenever flag readers are involved; otherwise CMOV/Jcc rewrites can pass on the all-zero default flag state.
- **Trait surface drift:** `InstructionGenerator::opcode_count()` and `X86Instruction::opcode_id()` can become inconsistent if CMOV/Jcc are half-added. Define the invariant around rewritable non-terminators and test it.
- **Clippy gate:** Z3 Bool/BV refactors commonly create needless borrows, temporary lifetime issues in `Bool::or`, or clone noise; keep fixes local to touched modules.

## 6. Out of Scope

- AArch64 NZCV symbolic modelling improvements, even though this issue informs that future fix.
- SETcc, ADC/SBB, LAHF/SAHF, shifts, memory operands, calls/returns, unconditional jumps, and full control-flow graph modelling.
- Long-form Jcc displacement modelling or emitting new branch targets; trailing Jcc bytes stay pinned from the original binary.
- x86 LLM or text-input user workflows beyond the existing parser helper tests.
- The broader #77 ISA-trait collapse and deletion of parallel x86 modules.
- Refactoring unrelated comments, formatting unrelated files, changing merge policy, or touching any generated/build artifacts.

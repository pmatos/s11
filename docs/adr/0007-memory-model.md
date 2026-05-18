# ADR-0007 — AArch64 memory model for LDR/STR/LDP/STP equivalence

Status: Accepted
Date: 2026-05-18

## Context

Before this ADR, the AArch64 IR (`src/ir/instructions.rs:22-402`) and machine-state types (`src/semantics/state.rs:257-261`, `src/semantics/smt.rs:128-138`) carried no memory. The pipeline reasoned only about general-purpose registers and the four NZCV flag bits. Issue #68 closes that gap by adding the LDR / LDRB / LDRH / LDRSB / LDRSH / LDRSW / STR / STRB / STRH / LDP / STP / LDPSW family across all five addressing modes (immediate-offset, pre-index, post-index, register-offset, register-extend) and both W/X widths.

The user-facing scope decision for this work was the most ambitious option on every axis: the *full* instruction family, *full* search wiring (enumerative + stochastic + symbolic + LLM), *whole-memory* live-out, and *sound full aliasing*. This ADR records the resulting model choices so a future reviewer of `src/semantics/concrete.rs` or `src/semantics/smt.rs` can reconstruct *why* the layers look the way they do — and so a future widening (multi-region live-out, typed-array model, etc.) has a single document to revise.

The CLI grammar from ADR-0006 (`docs/adr/0006-live-out-cli-grammar.md`) reserves the per-flag tokens `n`/`z`/`c`/`v` after `;` for a future per-flag liveness rev. This ADR additionally reserves `mem` and `mem:<range>` in the same after-`;` namespace for an eventual multi-region memory-liveness grammar; the present implementation does not consume those tokens yet.

## Decision

1. **Memory is byte-addressed on both layers.** The concrete interpreter carries `memory: BTreeMap<u64, u8>` on `ConcreteMachineState`; the SMT layer carries `memory: z3::ast::Array<BV<64>, BV<8>>` on `MachineState`. Absent keys on the concrete side denote "zero", matching the SMT array's symbolic-default reading. No typed-by-width memory arrays — the byte granularity is the *only* representation that handles overlapping writes correctly (e.g. `STR x0, [x1]; STRH w2, [x1, #2]; LDR x3, [x1]` requires byte-level decomposition to give the right answer under Z3's array theory).

2. **Little-endian via a shared splitter.** A single `value_to_le_bytes(v: u64, width: AccessWidth) -> [u8; N]` (concrete) and `bv_split_le(bv: &BV, width: AccessWidth) -> Vec<BV>` (SMT) carry the byte-order decision. They MUST agree by construction; a divergence would silently flip fast-path vs. SMT verdicts. AArch64 SCTLR_EL1.E0E defaults to 0 (little-endian); we do not model the big-endian alternative.

3. **Sound full aliasing — no disjointness preconditions.** Z3's array theory reasons over every possible base-register overlap; we add no SMT-side preconditions about "distinct base registers refer to distinct regions". This is what the user requested with the "Full aliasing (sound)" answer to the planning grilling. Solver latency grows accordingly (see §Consequences).

4. **Whole-memory live-out is auto-derived.** A new helper `validation::live_out::touches_memory(&[Instruction]) -> bool` flags any sequence containing a memory op. `EquivalenceConfig.memory_live` defaults to false but is force-set to `true` inside `check_equivalence_with_config` whenever `touches_memory()` returns true on either sequence. There is no CLI knob this PR — the user does not have to remember `;mem`. Search algorithms (enumerative, stochastic, symbolic) pin `with_memory(true)` analogously to the existing `with_flags(true)`.

5. **`fast_only` is force-disabled on memory-bearing windows.** `EquivalenceConfig.fast_only` skips SMT entirely and trusts random concrete inputs. With memory in scope, sparse random inputs cannot enumerate all aliasing patterns, so a `fast_only` "Equivalent" verdict on a memory-bearing window is unsound. Inside `check_equivalence_with_config`, when `touches_memory()` returns true AND `fast_only == true`, force `fast_only = false` and log a one-line warning. This is a *code* change, not a documentation aside — the soundness floor matters more than the speed-up.

6. **Writeback semantics: observed through `destinations()`.** Pre-index `LDR Xt, [Xn, #imm]!` and post-index `LDR Xt, [Xn], #imm` write *two* registers — `Xt` from memory and `Xn` from the writeback. The IR exposes this via `Instruction::destinations() -> Vec<Register>` (retiring the singleton `destination() -> Option<Register>`). `compute_live_in_registers` and `compute_written_registers` migrate automatically; the live-out machinery sees the writeback as just another writer.

7. **Writeback `Xt == Xn` and pair `Xt == Xt2` are rejected at `is_encodable_aarch64`.** ARM ARM declares these CONSTRAINED UNPREDICTABLE / UNPREDICTABLE on real hardware. Rejection sits at the encodability gate (`src/ir/instructions.rs:564-810`) so it is enforced (a) at the parser exit, (b) during enumeration, and (c) inside the assembler — matching the precedent for SP-in-Xn slots and out-of-range immediates.

8. **Misaligned access is defined.** Real AArch64 traps misaligned access at EL0 (unless SCTLR_EL1.A is cleared), but for an equivalence proof we want a total semantics. The byte-addressed model gives this automatically: a 4-byte access reads/writes 4 individual byte addresses, none of which can "trap". This matches the existing precedent for division-by-zero (defined as 0 in `src/semantics/concrete.rs:108-123` and `src/semantics/smt.rs:423-443`).

9. **`LDR (literal)`, `LDUR`, `STUR` are out of scope.** Capstone emits `LDUR` for unscaled-signed-offset variants that LDR-immediate cannot encode, and `LDR (literal)` for PC-relative pool loads. Neither is part of this PR; the parser leaves them as `Unsupported`, and the Capstone-tripwire test (`src/main.rs:1768+`) pins three rows asserting that outcome so a future Capstone-syntax drift cannot silently start parsing them.

10. **`memory_live` lives on `EquivalenceConfig`, not on `LiveOutMask<R>` (yet).** ADR-0004 §5 commits to eventually replacing `LiveOut` with the generic `LiveOutMask<R>` (today scaffolded but not wired through `check_equivalence`). When that migration lands, `memory_live` migrates with `flags_live` onto the mask. The interim home on `EquivalenceConfig` mirrors `flags_live`'s current shape — keeping the two analogous bits in one place avoids a third-location-fork.

## Consequences

**Positive:**

- Real basic blocks (every "interesting" window in the issue's IP-checksum motivating example) become tractable for the first time. The store/load round-trip `STR x0, [x1]; LDR x2, [x1]` ≡ `MOV x2, x0` is provable by Z3 array extensionality.
- Soundness is unconditional. No `fast_only` carve-out, no aliasing precondition, no typed-array shortcut. A reviewer can ask "what does s11 promise about LDR/STR equivalence?" and the answer is "every byte agrees, every aliasing, every overlap".
- The CLI grammar of ADR-0006 (`<regs>[;nzcv]`) is unchanged. The `;mem` reservation is documented here for the future without breaking any in-flight scripts.
- The byte-addressed Z3 array idiom — single `Array<BV64,BV8>`, byte-by-byte select/store, array extensionality for equality — is a known-good super-optimisation technique. We are not inventing a memory model.

**Negative / scope:**

- Z3 solver latency grows. A multi-store-and-load chain produces nested `store(store(...select(...)))` expressions that the array theory must canonicalise. The default solver timeout in `src/semantics/smt.rs:84-90` (30 s) and the `Opt --solver-timeout` (5 s default at `src/main.rs:197-198`) may need to grow as users start exercising memory-bearing windows; we document the knob rather than pre-tuning.
- The `fast_only` carve-out for memory-bearing sequences eliminates a fast path. `equiv --fast-only` users will see a one-line warning and pay the SMT cost. This is the price of soundness.
- `LiveOutMask<R>` stays scaffolding. ADR-0004 §5's migration is not done by this PR; the `memory_live` bit will move when that migration lands.
- The `;mem` CLI grammar reservation is *not* parsed today. A user typing `--live-out "x0;mem"` gets an "unknown flag token" error. The reservation prevents a future per-region grammar from breaking, but does not yet provide the feature.

**Reversibility:** medium. The byte-addressed array idiom is the only sound shape under "full aliasing"; switching to a typed-array (BV64-keyed-by-address) model is observably wrong on overlapping stores, so we cannot easily go back. The decision to derive `memory_live` automatically (vs. requiring an explicit `;mem`) is high-reversibility — adding a future grammar opt-in is a strict superset.

## Notes on related ADRs

- **ADR-0001** (live-in derivation): unchanged. `compute_live_in_registers` already routes through `Instruction::source_registers()` / `destinations()`; memory-base and index registers flow through automatically once the IR exposes them.
- **ADR-0002** (flags live-out floor): the analogous floor for memory is "always live whenever a memory op appears". Implemented in §4 above.
- **ADR-0004 §5** (`LiveOutMask<R>` migration): deferred. See decision 10.
- **ADR-0006** (`--live-out` CLI grammar): this ADR extends the after-`;` reserved-token namespace to include `mem` / `mem:<range>` but does not yet consume them.

# ADR-0008 — NZCV live-out/live-in contract for carry-aware arithmetic

Status: Accepted
Date: 2026-06-18

## Context

Issue #205 adds the carry-threading opcodes `ADC` / `ADCS` / `SBC` / `SBCS`
(`src/ir/instructions.rs`, register-only, X-only). Unlike every prior
arithmetic opcode, `ADC`/`SBC` *read* the carry flag: NZCV becomes a genuine
**live-in** to a rewrite window, not only a live-out.

Two earlier ADRs frame the NZCV contract:

- **ADR-0002** restricted the LLM-assisted flow to refuse targets whose flags
  are live-out, on the grounds that the LLM is the only generator that might
  *legitimately* drop a final flag-setter. Its 2026-05-19 amendment recorded
  that the equivalence pipeline already models NZCV-as-live-out
  (`LiveOut.flags_live`, consumed by both the fast path and the SMT path in
  `src/semantics/equivalence.rs`), leaving only the LLM-specific static refusal
  in `src/search/llm/mod.rs` as the authoritative remnant of ADR-0002.
- **ADR-0006** added the `--live-out '<regs>;nzcv'` CLI grammar and reserved
  the per-flag tokens `n`/`z`/`c`/`v` after `;` for a future per-flag rev.

What neither ADR settled is (a) how NZCV-as-live-*in* is handled now that an
opcode reads carry, and (b) whether the LLM static refusal should remain once
carry-aware arithmetic exists. This ADR closes both.

## Decision

1. **Carry-in is a live-in, surfaced through `reads_flags()`.**
   `ADC`/`ADCS`/`SBC`/`SBCS` are listed in `Instruction::reads_flags()`
   (`src/ir/instructions.rs`). This is load-bearing, not cosmetic:
   `validation::live_out::reads_flags_before_writing()` keys off it, which in
   turn (a) drives the fast path to enumerate all 16 NZCV input combinations
   (`fast_path_initial_nzcv_variants` in `src/semantics/equivalence.rs`) and
   (b) makes live-in analysis treat NZCV as an input. There is **no new CLI
   knob** — carry-in liveness is derived from the opcode, mirroring how
   memory liveness is auto-derived in ADR-0007.

2. **The SMT layer treats the initial carry as a free symbolic input.**
   `MachineState::new_symbolic` already binds the NZCV bits to independent
   symbolic constants, so a candidate that depends on carry-in cannot be
   certified equivalent for the carry-in = 0 case alone. The regression tests
   `test_adc_not_equivalent_to_add_because_carry_in_is_live` and
   `test_sbc_not_equivalent_to_sub_because_borrow_in_is_live`
   (`src/semantics/equivalence.rs`) pin this soundness floor.

3. **The four search algorithms keep pinning `flags_live = true`.** Enumerative,
   stochastic, symbolic, and (now) LLM treat NZCV as a conservative live-out.
   This is unchanged for the first three and is the basis for decision 4.

4. **The LLM static refusal of flag-live-out targets is removed.** The ADR-0002
   refusal in `src/search/llm/mod.rs` is dropped; the LLM flow now relies on the
   same equivalence check as every other generator — the verifier pins
   `with_flags(true)` (`src/search/llm/outcome.rs`), so a candidate that drops a
   needed flag-setter is *rejected by equivalence* rather than pre-refused. This
   supersedes the part of ADR-0002 that its 2026-05-19 amendment had left
   standing.

5. **`flags_live` stays a single bit on `EquivalenceConfig` / `LiveOut`.** No
   per-flag (n/z/c/v) liveness split in this rev; the tokens ADR-0006 reserved
   remain unconsumed. Carry-aware arithmetic does not need finer granularity:
   treating all of NZCV as live is sound, and ADR-0004 §5 already commits to
   moving `flags_live` onto the generic mask later.

## Consequences

**Positive:**

- Carry chains (IP-checksum folds, multi-word adders) can be lifted from
  binaries and verified for the first time, with carry-in soundly modeled on
  both the fast path (16-way NZCV enumeration) and the SMT path (free symbolic
  carry).
- The LLM flow no longer refuses an entire class of targets; it now optimizes
  flag-live-out windows under the same sound equivalence contract as the other
  algorithms. ADR-0002's special-case is retired.

**Negative / deferred:**

- Pinning `with_flags(true)` makes the LLM (and the other algorithms) treat
  NZCV as live-out even when it is provably dead in the surrounding context, so
  some valid optimizations are still skipped. Plumbing the *actual* post-window
  live-out (via `flags_read_before_overwrite_after_window`) into the LLM flow is
  a future enhancement, not part of #205.
- `ADC`/`SBC` are intentionally absent from the random-generation pool
  (`opcode_id` 69–72 fall above `opcode_count`), so stochastic/enumerative
  search will not *synthesize* carry arithmetic yet — they lift, mutate, and
  verify it, but do not generate it from scratch. Generation is deferred until
  there is a concrete need, because a carry opcode is only meaningful when a
  prior instruction has established the carry.

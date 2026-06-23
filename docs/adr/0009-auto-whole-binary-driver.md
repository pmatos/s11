# ADR-0009 — `--auto` whole-binary superoptimization driver

Status: Proposed
Date: 2026-06-22

## Context

Today `s11 opt` rewrites exactly one operator-selected window. The CLI
(`src/main.rs`, the `Opt` subcommand near line 234) *requires* `--start-addr`
and `--end-addr`, runs the search over the single straight-line prefix between
them (`optimize_elf_binary` near line 807), and writes a sibling copy whose name
is auto-derived as `<stem>_optimized.<ext>` (`optimized_output_path` near line
784). There is no whole-program entry point: a human has to read a disassembly,
find a window that happens to lie entirely within the supported mnemonic subset
(see `docs/capability.md`), and feed its bounds in by hand.

This ADR records the decision to add a whole-binary driver behind a single
`--auto` flag, plus an explicit `-o/--output` path, so that

```
s11 opt --auto /bin/ls -o /home/pmatos/ls-opt
```

loads the binary, discovers its own candidate windows, superoptimizes them one
at a time, patches each result back in place, and repeats until a full pass
finds no further improvement. The per-window search, the SMT equivalence check,
and the patcher are unchanged; this ADR is about the *loop* that drives them and,
above all, about the **soundness invariants** that decide whether the emitted
binary is correct.

The loop is the easy part. Its entire risk budget is spent in window
*selection*: a window that is rewritten when it should not have been produces a
binary that crashes or misbehaves only on some inputs — the worst failure mode
this tool can have. This document exists so that a future reader of the driver
can reconstruct *why* the window-selection rules are as conservative as they are.

### Two enabling facts in the current tree

1. **In-place patching never moves a downstream address.** The patcher computes
   `length = window.end - window.start` and, when the optimized code is shorter,
   pads the remainder with architecture-canonical NOPs up to the original window
   length (`src/elf_patcher/…` near lines 207 and 251; `nop_sequence`). It never
   grows a window and never shifts the bytes after it. Therefore every branch
   target, call target, and relocation *outside* a rewritten window stays valid
   no matter how many windows the driver rewrites. This is what makes an
   iterated whole-binary loop sound without a relocation pass — and it is the
   load-bearing reason the driver is tractable at all.

2. **Boundary liveness is already half-derived from context.** The window path
   does not blindly assume all flags are live: `downstream_flags_live` is
   computed by scanning the instructions *after* the window
   (`x86_downstream_flags_live_from_section` near line 1762 and
   `aarch64_downstream_flags_live_from_section` near line 1691, both via
   `validation::live_out::flags_read_before_overwrite_after_window`). Register
   live-out, by contrast, is currently derived from the window itself
   (`x86_live_out_for_optimization` near line 1989, `x86_live_out_from_target`),
   i.e. "every register the window defines is assumed live". That is a safe
   over-approximation but a weak one; the driver will want the same downstream
   scan for registers that flags already get (see Decision 7).

## Decision

1. **`--auto` is a mode switch on the existing `Opt` subcommand, not a new
   subcommand.** When `--auto` is present the driver runs over the whole binary
   and `--start-addr`/`--end-addr` become illegal (clap-level mutual exclusion,
   with a clear error if all three are supplied). When `--auto` is absent the
   behaviour is exactly today's single-window path. All existing per-algorithm
   knobs (`--algorithm`, `--timeout`, `--cost-metric`, `--beta`, …) carry through
   to each window the driver selects.

2. **Add an explicit `-o/--output <path>`.** With `--auto`, writing the result
   next to a system binary as `ls_optimized` is the wrong default, so `-o`
   names the output file directly. When `-o` is omitted the driver falls back to
   the existing `optimized_output_path` derivation, preserving current behaviour
   for the single-window path. The input binary is never modified in place; the
   driver operates on an in-memory image and writes the patched image to `-o`.

3. **The driver is the five-step loop, ISA-agnostic.** load → find candidate
   windows → pick one → optimize and patch in place → repeat. It reuses the
   existing per-backend `optimize_elf_binary_with_backend` for the inner search
   and the existing patcher for replacement. "Supported instruction" is defined
   operationally by the existing Capstone→IR bridge: a window is admissible only
   if every instruction in it converts through `convert_capstone_op_for_optimization`
   (near line 1637) without rejection. The driver does not maintain a second
   mnemonic allow-list — drift between the driver and the search is thereby
   impossible, mirroring the parser-is-the-single-source-of-truth rule in
   `CLAUDE.md`.

4. **A window is admissible only if no instruction in its interior is a branch
   target.** The window *end* is pinned by NOP padding, but interior instruction
   addresses *do* move when the search reorders or shortens the prefix. Any
   control transfer that lands in the middle of a rewritten window would then
   jump into the wrong instruction. The driver therefore builds the set of all
   in-section branch targets and refuses any window whose interior (every
   address strictly after its start) contains one. A window may *begin* at a
   branch target — that address is fixed — but may not *contain* one past its
   first instruction.

5. **Indirect control flow is handled by conservative refusal, not by
   guessing.** Direct branch targets are recovered by linear scan. Indirect
   jumps (jump tables from `switch` lowering, PLT stubs, computed gotos,
   function pointers) have targets that are not visible to a linear sweep.
   Getting this wrong is the catastrophic case. The conservative rule:
   - treat any address named by a relocation as a potential entry point;
   - treat any value in `.rodata` / `.data.rel.ro` that falls inside an
     executable section's address range as a potential jump-table target;
   - refuse any window whose interior contains such an address.

   This over-approximates — it will reject some genuinely-safe windows near jump
   tables — and that is the intended trade. Soundness first; coverage of
   table-adjacent code is a later, separately-justified relaxation. The driver
   `log()`s how many windows it refused on this basis so suppressed coverage is
   never silent.

6. **RIP-relative operands inside a window are out of scope for v1.** An x86-64
   RIP-relative displacement is resolved against the address of the *following*
   instruction; reordering or resizing within a window invalidates it, and the
   x86 IR does not yet model the operand end to end. Windows containing a
   RIP-relative memory operand are refused for now. Lifting this requires either
   modelling the operand and fixing the displacement at patch time or pinning the
   instruction's position — both deferred.

7. **Window boundary liveness must be computed from the surrounding code, for
   registers as well as flags.** The driver feeds each window the
   downstream-derived `downstream_flags_live` it already computes, and adds the
   analogous downstream scan for *registers*: a register the window writes is
   live-out iff some later instruction reads it before overwriting it (or the
   window is followed by a `call`/`ret` whose ABI makes it observable, or control
   leaves the analyzable region — all conservative-to-live). Absent a precise
   answer, the safe default is "live". This is the one quality lever that decides
   whether the driver finds real wins or proves tautologies.

8. **The loop is a monotone worklist with a no-improvement cache.** Each accepted
   rewrite strictly lowers the chosen cost metric, so progress is monotone. To
   avoid re-proving the same window across passes and across overlaps, the driver
   caches "no improvement found" keyed by a hash of the window's instruction
   bytes; a window whose bytes are unchanged since a prior miss is skipped. A
   pass that accepts zero rewrites terminates the loop. Per-window search time is
   bounded by the existing `--timeout`, because superoptimizing every window of a
   binary the size of `/bin/ls` is otherwise unbounded.

9. **Window selection is prioritized, not exhaustive-by-default.** The driver
   prefers longer admissible runs and windows with apparent redundancy, and
   honours a global budget (time and/or window count). When the budget bounds
   coverage, the driver `log()`s what it skipped — a silent top-N would read as
   "the whole binary was optimized" when it was not.

10. **"Improvement" means lower cost under the selected `--cost-metric`, and the
    on-disk file never shrinks regardless of metric.** Because freed bytes become
    NOPs (Decision/fact 1), the output file is always the same size as the input;
    wins live in the *executed* instruction stream, not on disk. What counts as a
    win is exactly what the existing search already minimizes — `instruction-count`
    (default), `code-size`, or `latency` (`src/semantics/cost.rs`,
    `src/semantics/cost_x86.rs`). Crucially, the driver does **not** introduce any
    new notion of "faster": it inherits the current cost model verbatim, and that
    model's fidelity is a real limit (see Open questions). Calling `--auto` a
    "speed optimizer" is therefore only as true as the chosen metric — and on x86
    today the `latency` metric is a stub equal to instruction count, so `--auto`
    on `/bin/ls` optimizes *instruction count*, not measured speed.

11. **Initial ISA scope is whatever the per-window path already supports.** The
    driver is ISA-agnostic by construction, so it lights up for AArch64 and x86
    simultaneously. The motivating example is x86-64 `/bin/ls`; AArch64, with its
    far larger supported mnemonic set, will yield more admissible windows per
    binary.

## Consequences

**Positive:**

- A single command optimizes a whole binary with no human window-picking. The
  capability the engine already has becomes usable at binary scale.
- Soundness across arbitrarily many rewrites falls out of the existing in-place
  NOP-padding patcher; no relocation machinery is needed for v1.
- No second mnemonic allow-list: admissibility is defined by the existing
  Capstone→IR bridge, so the driver cannot drift from the search the way a
  parallel switch would.
- The conservative indirect-flow rule fails *closed*: an unrecognized target
  causes refusal (lost coverage), never an unsound rewrite.

**Negative / scope:**

- Coverage is bounded by the supported subset *and* by the conservative
  window-selection rules. On a stripped, optimized x86-64 binary the admissible
  windows will be sparse; many functions will yield nothing. This is expected and
  is reported, not hidden.
- The no-improvement cache and worklist add driver-side state and a hashing pass;
  these are bookkeeping, not algorithms, but they are new surface to test.
- Boundary register-liveness (Decision 7) is new analysis. Done wrong in the
  "too dead" direction it is *unsound*; the implementation must default to live
  whenever the downstream answer is uncertain.
- Whole-binary runs are long. Per-window `--timeout` and the global budget are
  the only things between the user and an unbounded run.

**Reversibility:** high. `--auto` is additive — every existing single-window
invocation is byte-for-byte unaffected, and `-o` defaults to today's derived
path. The conservative window-selection rules can each be relaxed later behind
their own justification (jump-table modelling, RIP-relative fixups, size-reducing
relocation) without revisiting this decision. If the driver proves not worth its
maintenance cost, deleting the `--auto` arm leaves the rest of the tool intact.

## Notes on related ADRs

- **ADR-0007** (memory model): memory-bearing windows already force SMT and
  whole-memory live-out and disable `fast_only`. The driver inherits this for
  free per window; no additional memory handling is introduced here.
- **ADR-0006 / ADR-0008** (`--live-out` grammar, NZCV live-out contract): the
  driver does not take a `--live-out` string in `--auto` mode — it *derives*
  the contract per window from surrounding code (Decision 7), which is the
  whole-binary analogue of the downstream-flags scan those ADRs describe.
- **ADR-0001** (live-in derivation): unchanged; per-window live-in continues to
  flow from `source_registers()` / `destinations()`.

## Open questions (resolved during implementation, not by this ADR)

- Exact priority function for window selection (Decision 9).
- Whether the no-improvement cache persists across process runs or is in-memory
  only (Decision 8) — in-memory is the v1 default.
- Whether `--auto` should accept a section filter (e.g. only `.text`) or always
  sweep every executable section.
- **Cost-model fidelity is the precondition for honestly calling this a speed
  optimizer.** The search accepts a window only when an equivalent candidate has
  strictly lower cost under the selected metric, so "we know it is better" reduces
  to "the metric says so". Today the `latency` metric is a static, additive
  per-opcode sum with no modelling of dependency chains, superscalar/out-of-order
  issue, micro-op fusion, port/throughput contention, or memory latency
  (`instruction_latency` in `src/semantics/cost.rs` is a hand-tuned Cortex-A72/A76
  table; the x86 `instruction_latency` in `src/semantics/cost_x86.rs` returns 1
  for every opcode, i.e. it is identical to instruction count). A real
  microarchitectural cost model is out of scope for this ADR but is tracked as a
  separate issue, and `--auto`'s "speed" claim is bounded by it.

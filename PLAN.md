# Plan: issue #834 — e2e: outcome cases - AArch64

## 1. Problem restated

`tests/e2e/` (landed by #832) has a declarative `Case`/`run()` harness but
`run()` still hard-panics on any case that sets `expected_instructions`
("Phase 2, see issues #834-#836"), and `tests/e2e/fixtures/` is empty. #834
must (a) implement that `expected_instructions` assertion in the shared
harness — parsing the real `Disassembled N instructions:` /
`Optimized to N instructions:` report lines into a structured
`(before, after)` comparison, not a prose `stdout.contains` — and (b) add at
least one fixed-address AArch64 fixture per known instruction-shortening
class, assembled by `build_tests.sh`, each ending in an explicit exit
syscall so a later behavioral tier (#837/#838) can execute it, none
depending on unseeded RNG (issue #409). `just e2e` must build and pass the
new cases in CI.

**Scope correction from empirical testing (see §6 and the issue comment):**
of the issue's example shortening classes, stp-writeback and ldp-post-index
folds do not converge through `s11 opt`'s enumerative search within a
CI-viable timeout — confirmed by direct experiment with the built binary,
not by inspection. The ldr-positive-offset class *is* achievable, via a
dead-load witness rather than an address-fold witness (§4 slice 4). Three
register-only classes fill in for the two dropped ones; details below.

## 2. Files to touch

New:
- `tests/aarch64_asm/dup_mov_imm.s` — redundant-mov elimination fixture.
- `tests/aarch64_asm/mov_add_fuse.s` — mov+add-imm fusion fixture.
- `tests/aarch64_asm/sub_via_add.s` — mov+sub-imm fusion fixture.
- `tests/aarch64_asm/ldr_dead_load.s` — ldr positive-offset (dead-load)
  fixture, the one issue-named memory-addressing class that is achievable.
- `tests/e2e/cases/outcome_aarch64.rs` — the four `#[test]` cases.

Modified:
- `tests/e2e/harness.rs` — implement `expected_instructions` in `run()`;
  update the now-stale doc comments on `Window`, `Case::fixture`, and the
  top-of-`run()` panic-guard comment (still true for `execution`, no longer
  true for `expected_instructions`).
- `tests/e2e/cases/mod.rs` — add `mod outcome_aarch64;`.
- `tests/e2e/fixtures/README.md` — record that AArch64 fixtures now live
  under `tests/e2e/fixtures/aarch64/` (built, gitignored); x86-64/x86-32
  remain pending in #835/#836.
- `build_tests.sh` — assemble `tests/aarch64_asm/*.s` into
  `tests/e2e/fixtures/aarch64/` (mirrors the existing `tests/x86_asm/*.s`
  loop, `-no-pie -nostdlib` for a fixed-address ELF).
- `.gitignore` — ignore built fixture binaries under `tests/e2e/fixtures/`
  while keeping `tests/e2e/fixtures/README.md` tracked.
- `Justfile` — `e2e` recipe gains a `build-tests` dependency (no longer
  true that "no fixture-based cases exist yet"); update its comment.

No `docs/spec/*.md` in this repo (that section of the template is for the
`vow` language project; s11 uses `docs/capability.md` + `CONTEXT.md` +
`docs/adr/`, none of which change — no new mnemonics, no CLI flags, no
semantics changes, only test infrastructure and fixtures).

## 3. Empirical validation already performed (informs slice ordering)

Before writing this plan, built `s11` locally (`cargo build -j8 --bin s11`,
system Z3 via `/usr/lib/libz3.so`, clean build in 15s) and:

- Assembled all candidate fixtures with `aarch64-linux-gnu-gcc -no-pie
  -nostdlib` and confirmed via `readelf -h` that a minimal `_start`-only
  `.s` file always links to entry point `0x4000d4` (no ASLR/PIE, no libc,
  identical trivial layout every time) — this is the `start_addr` used
  below, not a guess.
- Confirmed via `s11 equiv` (which shares the same SMT semantics module as
  `opt`) that all three chosen identities, AND the deferred memory-fold
  identities, are genuinely semantically equivalent — the deferral in §6 is
  a search-convergence limit, not a correctness problem.
- Ran the actual `s11 opt` CLI against each fixture end-to-end at
  `--cores 4` (approximating a CI runner) and recorded convergence time.

## 4. TDD slices

1. **Harness: implement `expected_instructions` parsing.**
   - Test: add a unit test in `tests/e2e/harness.rs`'s existing
     `#[cfg(test)] mod tests` that feeds a canned stdout string containing
     `"Disassembled 2 instructions:\n...\nOptimized to 1 instructions:\n"`
     into a new pure helper and asserts it returns `Some((2, 1))`; a second
     case with only `"Disassembled 2 instructions:"` (no `"Optimized to"`
     line — the `no_optimization_message()` branch) asserts the helper
     returns `None`, i.e. the harness must panic with a clear message
     rather than silently comparing garbage. Red: helper doesn't exist yet.
   - Production: add
     ```rust
     fn extract_reported_count(stdout: &str, prefix: &str) -> Option<usize> {
         let start = stdout.find(prefix)? + prefix.len();
         stdout[start..]
             .chars()
             .take_while(|c| c.is_ascii_digit())
             .collect::<String>()
             .parse()
             .ok()
     }
     ```
     Wire it into `run()`: delete the current unconditional
     `if case.expected_instructions.is_some() { panic!(...) }` guard at the
     top (keep the sibling `execution` guard — Phase 3 stays unimplemented).
     After the existing `expected_stdout_contains` block, add:
     ```rust
     if let Some((before, after)) = case.expected_instructions {
         let actual_before = extract_reported_count(&stdout, "Disassembled ")
             .unwrap_or_else(|| panic!(
                 "e2e case {:?}: could not find \"Disassembled N instructions:\" in stdout\n\
                  reproducer: {reproducer}\nstdout:\n{stdout}", case.name));
         let actual_after = extract_reported_count(&stdout, "Optimized to ")
             .unwrap_or_else(|| panic!(
                 "e2e case {:?}: could not find \"Optimized to N instructions:\" in stdout \
                  (the search may not have found the expected shortening)\n\
                  reproducer: {reproducer}\nstdout:\n{stdout}", case.name));
         assert_eq!(
             (actual_before, actual_after), (before, after),
             "e2e case {:?}: instruction count before->after mismatch\n\
              reproducer: {reproducer}\nstdout:\n{stdout}", case.name);
     }
     ```
     Green: `cargo test --test e2e_tests` (existing CLI-contract case still
     passes; new unit tests pass). This slice has no dependency on any
     fixture existing yet.
   - Refactor: none needed: the function is already minimal.

2. **First vertical fixture: `dup_mov_imm` (baseline, register-only,
   mirrors `tests/x86_asm/dup_mov_imm.s`).**
   - Add `tests/aarch64_asm/dup_mov_imm.s`:
     ```asm
     // Known one-instruction shortening fixture for the AArch64 opt path
     // (issue #834's baseline "redundant mov elimination" class).
     //
     // Two identical `mov x0, #5` instructions are semantically equivalent
     // to a single `mov x0, #5` (only X0 is live-out; MOVZ does not touch
     // NZCV), so the enumerative search deterministically rewrites the
     // 2-instruction window to 1 instruction. Mirrors
     // tests/x86_asm/dup_mov_imm.s for the x86-64 opt path.
     .text
     .global _start
     _start:
         mov x0, #5
         mov x0, #5
         mov x8, #93
         svc #0
     ```
   - `build_tests.sh`: inside the existing "AArch64 (cross-compiled)"
     section (after the `tests/*.c` loop, `aarch64-linux-gnu-gcc` is
     already confirmed present by the script's mandatory preflight check),
     add:
     ```bash
     # Hand-written register-only AArch64 assembly fixtures
     # (tests/aarch64_asm/*.s) for the e2e outcome-case suite (issue #834).
     # `-no-pie -nostdlib` gives a fixed-address ELF (entry point == the
     # fixture's first instruction) so e2e window addresses are stable
     # across rebuilds. Output goes to tests/e2e/fixtures/aarch64/, not
     # binaries/, per tests/e2e/fixtures/README.md.
     mkdir -p tests/e2e/fixtures/aarch64
     for asm_file in tests/aarch64_asm/*.s; do
         [ -e "$asm_file" ] || continue
         base_name=$(basename "$asm_file" .s)
         echo "Assembling AArch64 e2e fixture $base_name..."
         aarch64-linux-gnu-gcc -no-pie -nostdlib \
             -o "tests/e2e/fixtures/aarch64/${base_name}" "$asm_file"
     done
     ```
   - `.gitignore`: add
     ```
     # e2e outcome/behavioral fixtures built by build_tests.sh (issue #834+);
     # the directory's own README stays tracked.
     tests/e2e/fixtures/*
     !tests/e2e/fixtures/README.md
     ```
   - `Justfile`: change the `e2e` recipe to `e2e: build-tests` and drop the
     stale "No fixture-based cases exist yet" comment line.
   - Add `tests/e2e/cases/outcome_aarch64.rs`, register it in
     `tests/e2e/cases/mod.rs` (`mod outcome_aarch64;`), with:
     ```rust
     use crate::e2e::harness::{Case, Window, run};

     #[test]
     fn aarch64_dup_mov_imm_collapses_to_one_instruction() {
         run(&Case {
             name: "aarch64-outcome-dup-mov-imm",
             subcommand: Some("opt"),
             fixture: Some("aarch64/dup_mov_imm"),
             arch: Some("aarch64"),
             window: Some(Window { start_addr: "0x4000d4", end_addr: "0x4000dc" }),
             args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
             expected_exit_code: 0,
             expected_instructions: Some((2, 1)),
             ..Default::default()
         });
     }
     ```
   - Red: before running `build_tests.sh`, the harness's existing fixture
     assert (`fixture not found: ...`) fails the test — expected, and
     already covered by #832's harness, not new code.
   - Green: run `./build_tests.sh` (or `just build-tests`), then
     `cargo test --test e2e_tests -- --nocapture`. Verified locally in this
     planning session: `s11 opt` on this exact fixture/window/args reports
     `Disassembled 2 instructions:` / `Optimized to 1 instructions: mov x0,
     #5`, elapsed ~32ms at 4 cores.
   - `--force` is required, not optional: `s11 opt` refuses to run if the
     derived `<fixture>_optimized` output already exists (pinned by
     `test_opt_refuses_existing_derived_output_before_search` in
     `opt_test.rs`), and every fixture lives in a persistent tracked
     directory (not a per-test tempdir), so a second local run or a second
     CI run without `--force` would fail on the second invocation, not the
     first. `_optimized` siblings are covered by the same `tests/e2e/
     fixtures/*` gitignore pattern.

3. **Two more register-only classes: `mov_add_fuse`, `sub_via_add`.**
   - `tests/aarch64_asm/mov_add_fuse.s`:
     ```asm
     // Known one-instruction shortening fixture (issue #834's "mov+add-imm
     // fusion" class). `mov x0, x1; add x0, x0, #1` collapses to
     // `add x0, x1, #1` — the same identity as
     // benches/algebraic_fusion/mov_add_fuse.s, re-expressed as a runnable
     // fixed-address ELF for the e2e opt-outcome suite.
     .text
     .global _start
     _start:
         mov x0, x1
         add x0, x0, #1
         mov x8, #93
         svc #0
     ```
   - `tests/aarch64_asm/sub_via_add.s`:
     ```asm
     // Known one-instruction shortening fixture (issue #834's "mov+sub-imm
     // fusion" class). `mov x0, x1; sub x0, x0, #1` collapses to
     // `sub x0, x1, #1` — mirrors benches/algebraic_fusion/sub_via_add.s.
     .text
     .global _start
     _start:
         mov x0, x1
         sub x0, x0, #1
         mov x8, #93
         svc #0
     ```
   - Both link to the same entry point `0x4000d4` (identical trivial
     layout — verified). Add two more `#[test]` fns in
     `outcome_aarch64.rs`, same shape as slice 2's, `fixture:
     Some("aarch64/mov_add_fuse")` / `Some("aarch64/sub_via_add")`,
     `window: 0x4000d4..0x4000dc`, same `args`, `expected_instructions:
     Some((2, 1))`.
   - Verified locally: both converge in ~0.65s at 4 cores (`add x0, x1,
     #1` / `sub x0, x1, #1` respectively), comfortably inside the 15s
     per-case timeout.
   - Green: `cargo test --test e2e_tests -- --nocapture` (1 CLI-contract
     case + 3 outcome cases from this slice + the harness unit tests from
     slice 1, all passing).

4. **Fourth class: `ldr_dead_load` — the issue's "ldr positive-offset
   window" class, via a dead-load witness instead of an address fold.**
   - Insight from empirical testing: the search struggles when the
     *witness candidate itself* is a memory op (deep in generation order,
     weak fast-test filtering — see §6). But a window where the memory op
     is *in the target* and the witness is a plain register op sidesteps
     that entirely. `ldr x0, [x6, #16]; mov x0, #5` unconditionally
     overwrites X0 right after loading it, so `mov x0, #5` alone is
     equivalent (the load is dead) — and `mov x0, #5` is early in
     candidate-generation order, same profile as `dup_mov_imm`.
   - `tests/aarch64_asm/ldr_dead_load.s`:
     ```asm
     // Known one-instruction shortening fixture (issue #834's "ldr
     // positive-offset window" class — the RefOffset/Uscaled encoding
     // pinned by test_opt_accepts_ldr_positive_offset_window in
     // opt_test.rs). `ldr x0, [x6, #16]` loads into X0, which is then
     // unconditionally overwritten by `mov x0, #5` before any read — the
     // load is dead, so `mov x0, #5` alone is equivalent. Unlike an
     // address-fold identity (where the witness candidate is itself a
     // memory op, deep in the enumerative pool — see the issue #834
     // comment), the witness here is a plain MOV, so this converges as
     // fast as dup_mov_imm.
     .text
     .global _start
     _start:
         mov x6, sp
         ldr x0, [x6, #16]
         mov x0, #5
         mov x8, #93
         svc #0
     ```
     Window is `stp_writeback_fold`-shaped (setup instruction precedes the
     target pair), not `dup_mov_imm`-shaped: the `mov x6, sp` setup lives
     *before* `start_addr`, so the window covers only `ldr`+`mov x0,#5`.
   - Add a fourth `#[test]` fn in `outcome_aarch64.rs`:
     ```rust
     #[test]
     fn aarch64_ldr_dead_load_collapses_to_one_instruction() {
         run(&Case {
             name: "aarch64-outcome-ldr-dead-load",
             subcommand: Some("opt"),
             fixture: Some("aarch64/ldr_dead_load"),
             arch: Some("aarch64"),
             window: Some(Window { start_addr: "0x4000d8", end_addr: "0x4000e0" }),
             args: &["--algorithm", "enumerative", "--timeout", "15", "--force"],
             expected_exit_code: 0,
             expected_instructions: Some((2, 1)),
             ..Default::default()
         });
     }
     ```
   - Verified locally: `s11 equiv` on `ldr x0,[x6,#16]; mov x0,#5` vs
     `mov x0,#5` (default live-out x0..x7) reports EQUIVALENT; `s11 opt`
     on the built ELF at this exact window/args converges in ~99ms at 4
     cores, reporting `Optimized to 1 instructions: mov x0, #5`. The `//`
     comment leader in the `.s` file (gas AArch64 syntax) was confirmed to
     assemble cleanly in the same run.
   - Green: `cargo test --test e2e_tests -- --nocapture` (all four outcome
     cases plus the CLI-contract case and harness unit tests passing).

5. **Polish: stale doc comments + fixtures README.**
   - `tests/e2e/harness.rs`: `Window`'s doc comment currently says "only
     the outcome assertion that would consume it (`Case::expected_instructions`)
     is still unimplemented (Phase 2, #834-#836)" — now false, update it.
     `Case::fixture`'s doc comment says "no case uses one yet since
     `tests/e2e/fixtures/` is still empty (Phase 2, #834-#836)" — now
     false, update it. Leave every `execution`/Phase-3 reference alone
     (still accurate, still unimplemented).
   - `tests/e2e/fixtures/README.md`: replace the "reserved for... issues
     #834, #835, #836" line with a note that AArch64 fixtures now live
     under `aarch64/` (gitignored, built by `build_tests.sh` from
     `tests/aarch64_asm/*.s`), x86-64/x86-32 pending in #835/#836.
   - Run `cargo fmt`, then the full local gate (§ "Verification surface").

## 5. Verification surface

Not a `vow`/ESBMC project — no contracts, no C model, no `tests/run/`. The
equivalent local gate for this repo:

- `cargo fmt -- --check`
- `cargo build`
- `./build_tests.sh` (now also produces `tests/e2e/fixtures/aarch64/*`)
- `cargo test --test e2e_tests -- --nocapture` (`just e2e`)
- `cargo test --test integration_tests -- --nocapture` (unaffected, but run
  to confirm no collision with the new `tests/aarch64_asm/` directory or
  gitignore pattern)
- `cargo clippy --all-targets --no-deps` (also runs automatically via the
  `.claude/hooks/cargo-fmt-clippy.sh` PostToolUse hook on every `.rs` edit)
- `python3 -m unittest discover -s scripts -p 'test_*_policy.py'` — confirm
  the new `Justfile`/`build_tests.sh`/`.gitignore` edits don't trip
  `test_ci_policy.py`'s literal-match checks against `test.yml` (CI
  wiring for `E2E_TEST_COMMAND` was already added by #832 and needs no
  change here: `.github/workflows/test.yml` already runs `./build_tests.sh`
  before "Run e2e tests", and `ci_check.sh` already runs `build_tests.sh`
  before its test step — verified by reading both files in this session)
- Full `./ci_check.sh` before pushing, per this repo's `CLAUDE.md`

No ESBMC, no `parse -> print -> parse` idempotency (not applicable to this
codebase — that requirement is generic boilerplate from a different
project's plan template and does not apply here).

## 6. Risk areas

- **Fixed-address determinism.** All three fixtures link to entry point
  `0x4000d4` under `aarch64-linux-gnu-gcc -no-pie -nostdlib` with the
  toolchain installed in this workspace and in CI (`gcc-aarch64-linux-gnu`
  via apt on `ubuntu-24.04`, per `test.yml`). If a future binutils/gcc
  version shifts the default link layout, these literal addresses go
  stale and the harness's own `fixture not found`/exit-code assertions
  would not catch it — a shifted-but-still-valid window would just
  disassemble different bytes and most likely fail the
  `expected_instructions` assertion loudly (not silently), which is an
  acceptable failure mode (matches the `tests/x86_asm/dup_mov_imm.s`
  precedent's already-accepted address-stability risk, per its own
  comments) but is a real, not-yet-eliminated, source of flakiness on
  toolchain upgrade. No action needed now; note for a future ADR if it
  ever fires.
- **`s11 opt`'s AArch64 candidate register pool is fixed at X0..X7**
  (`aarch64_search_inputs::registers_from_target`, no CLI knob to shrink
  or grow it) **and memory-op candidates only enumerate `IndexMode::
  Offset`** (`src/search/candidate.rs`, `MEM_IMM_SAMPLES`/
  `MEM_PAIR_IMM_SAMPLES` are hardcoded consts, not derived from
  `--registers`-style input — there is no such flag). Combined with a
  ~268k-candidate enumerative pool per window, a shortening class whose
  only witness is itself a memory op is deep in generation order and
  costs thousands of SMT queries before the fast/random pre-filter even
  narrows the field, because concrete random testing does not appear to
  reject non-equivalent memory-touching candidates as cheaply as it
  rejects ALU ones (observed: STP address-fold — 12949/13237 candidates
  passed the fast filter and needed a real SMT query, 0 confirmed
  equivalent within budget; ADD-imm fusion — 2/268088 needed one,
  converged in <1s). This is why the STP-writeback and LDP-post-index
  *address-fold* classes are deferred (see the comment posted on issue
  #834 with the full reproducer and timing data: a plain duplicate-store
  fixture, structurally as simple as `dup_mov_imm` but for `str`, took
  90s at 4 cores without converging and ~11s at 21 cores). The
  LDR-positive-offset class is *not* deferred — §4 slice 4 sidesteps the
  problem with a dead-load witness (the memory op sits in the *target*,
  the witness candidate is a plain `mov`, so it converges as fast as
  `dup_mov_imm`); that trick doesn't generalize to STP (stores can't be
  "dead") or LDP (a compensating pair would need a longer window and a
  length-3 search, out of budget the same way). Any future attempt at the
  two remaining classes should budget for either a much longer per-case
  timeout (CI-cost tradeoff) or a reduction in the candidate pool (a
  `src/aarch64_search_inputs.rs`/`src/search/candidate.rs` change, out of
  scope here).
- **`--force` + persistent fixture directory.** Every case writes
  `<fixture>_optimized` next to the (tracked-source, gitignored-build)
  fixture on every run. Confirmed this is inert across repeated local
  runs (re-ran each fixture multiple times against stale `_optimized`
  siblings during verification, no failures once `--force` is present).
  If a future case ever needs strict isolation between concurrently
  running cases sharing one fixture, revisit with a tempdir-staging
  change to the harness — not needed for these three distinct fixtures.
- **`cargo test` intra-binary parallelism.** The three new cases use three
  distinct fixture files, so no cross-test collision; unaffected by
  default `cargo test` thread parallelism.
- **Determinism / issue #409.** All three identities use
  `--algorithm enumerative` (exhaustive, not the unseeded-RNG stochastic
  path), matching the existing `tests/integration/opt_test.rs`
  `x86_opt_command` precedent and the issue's explicit RNG constraint.

## 7. Out of scope

- Two of the three memory-op addressing-mode classes named as examples in
  the issue — stp writeback and ldp post-index — deferred per §6,
  documented on the issue with reproducer and timing evidence. (The third,
  ldr positive-offset, is delivered in §4 slice 4 via a dead-load witness.)
  Not silently dropped: a human reviewer can reopen with a wider timeout
  budget or a search-side fix if they disagree with the tradeoff.
- x86-64 (#835) and x86-32 (#836) outcome cases, and fixing
  `tests/x86_asm/dup_mov_imm.s`'s missing exit syscall (explicitly #835's
  job, not this ticket's).
- The Phase 3 behavioral tier (`Case::execution`, #837/#838) — the harness
  guard for it stays a panic; not touched.
- Porting any existing `tests/integration/opt_test.rs` case
  (`test_opt_accepts_stp_writeback_window` etc.) to the new harness — the
  parent PRD (#831) is explicit that this is opportunistic, not a
  big-bang move, and #834's scope is new outcome cases, not migration.
- Any change to `src/aarch64_search_inputs.rs` or
  `src/search/candidate.rs` to make the memory-fold classes CI-viable
  (e.g. a narrower candidate register pool, a CLI knob to select it, or
  pre/post-index candidate generation) — a real code change with its own
  design tradeoffs, not an e2e-test-authoring change.
- Any refactor of the existing CLI-contract case or `harness.rs` beyond
  what's needed to implement `expected_instructions` and fix the two
  stale doc comments.

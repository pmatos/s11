# Plan: issue #836 — e2e: outcome cases - x86-32

## 1. Problem restated

The e2e harness scaffolded by #832/#845 (`tests/e2e/harness.rs`) defines a
declarative `Case` shape with `expected_instructions: Option<(usize, usize)>`
and a `fixture` field, but both are currently stubs: `run()` unconditionally
panics if a case sets `expected_instructions`, and `tests/e2e/fixtures/` is
empty. Issue #836 asks for the x86-32 slice of Phase 2 (outcome cases): at
least one fixed-address x86-32 fixture per known shortening class, ending in
an explicit exit syscall (so a later Phase 3 ticket can execute it), asserted
through the harness's declarative shape rather than a prose `stdout.contains`,
gracefully skipped (not failed) when the `gcc -m32` multilib toolchain is
absent, and independent of unseeded RNG (issue #409). This repo has exactly
one demonstrated x86 shortening class today (duplicate-`mov reg, imm`
collapse, `tests/x86_asm/dup_mov_imm.s` for x86-64) — this issue reproduces it
for x86-32 and, as a prerequisite, implements the harness's
`expected_instructions` assertion (currently unimplemented) since no case can
satisfy the acceptance criteria without it.

Note on repo layout: the plan template's "crates/ and compiler/" framing is
Vow boilerplate and does not apply — s11 is a single Rust crate rooted at
`src/`, with test infrastructure under `tests/`. There is no `docs/spec/` in
this repo; nothing here changes CLI syntax/semantics, so no spec doc applies.

## 2. Files to touch

- `tests/e2e/harness.rs` — implement `expected_instructions`; add a
  `fixture_exists` pre-flight helper; refresh two stale doc comments that
  currently say "unimplemented (Phase 2, #834-#836)".
- `tests/e2e/cases/mod.rs` — register the new case module.
- `tests/e2e/cases/outcome_x86_32.rs` (new) — the x86-32 outcome case, with a
  toolchain/fixture-absence skip guard.
- `tests/e2e/fixtures/README.md` — record that `x86_32/` is now populated.
- `tests/x86_asm/dup_mov_imm_32.s` (new) — x86-32 fixture source: duplicate
  `mov eax, 5`, explicit `int 0x80` exit whose code echoes the live-out EAX
  value.
- `tests/x86_asm/README.md` — document the new fixture alongside the existing
  x86-64 ones.
- `build_tests.sh` — inside the existing `if gcc -m32 ...; then` guard, add a
  step that assembles `tests/x86_asm/*_32.s` into
  `tests/e2e/fixtures/x86_32/<name>` (mirrors the x86-64 block's `.s`
  assembly step already present, but targets the e2e fixtures directory
  instead of `binaries/`, matching what `tests/e2e/fixtures/README.md`
  already promises for this ticket).
- `.gitignore` — ignore `tests/e2e/fixtures/x86_32/` (built artifact, not
  source).
- `Justfile` — refresh the `e2e:` recipe's now-stale comment ("No
  fixture-based cases exist yet"); the recipe itself does **not** need a
  `build-tests` dependency (see Risk areas).

Nothing under `src/` changes — the x86-32 opt path is already implemented;
this is test-infrastructure only.

## 3. TDD slices

**Slice 0 — spike, not committed.** Build a throwaway probe with
`gcc -m32 -no-pie -nostdlib` from the exact fixture body planned below,
`objdump -d` it to confirm `_start`'s address and per-instruction byte
offsets, `cargo build -j<N>` (respect the memory budget), and run
`target/debug/s11 opt <probe> --arch x86-32 --algorithm enumerative --timeout
30 --start-addr <addr> --end-addr <addr>` by hand to confirm the exact
stdout text (`Disassembled 2 instructions:` / `Optimized to 1
instructions:`) and exit code 0. A planning-stage probe in `$TMPDIR` already
observed `_start` at `0x8049000` with `mov eax, 5` as two 5-byte `b8`
encodings (window `0x8049000`-`0x804900a`), but toolchain versions can drift
between sandboxes — reconfirm against the real, committed fixture before
pinning literals in slice 4, don't trust the spike blindly.

**Slice 1 — harness: implement `expected_instructions`.**
Test: `tests/e2e/harness.rs`, new `mod tests` unit tests, e.g.
`stdout_reports_instructions_matches_exact_counts` and
`stdout_reports_instructions_rejects_wrong_count`, against literal stdout
strings (no process spawn needed — keeps this slice fast and independent of
any fixture).
Production code: add a small pure helper (e.g.
`fn stdout_reports_instructions(stdout: &str, before: usize, after: usize) ->
bool`) that checks for the literal substrings `"Disassembled {before}
instructions:"` and `"Optimized to {after} instructions:"` (trailing colon
included, matching the exact `println!` format strings in
`src/elf_optimizer/mod.rs`). Wire it into `run()` in place of the current
`panic!("...not implemented by this harness yet...")` stub, panicking with
the reproducer command + actual stdout on mismatch (mirror the existing
`expected_stdout_contains` panic style). Update the `Case::expected_instructions`
doc comment to drop the "unimplemented" note.

**Slice 2 — harness: fixture pre-flight helper.**
Test: `tests/e2e/harness.rs` `mod tests`, e.g. `fixture_exists_finds_known_file`
asserting `fixture_exists("README.md")` is true (the fixtures-dir README
already exists) and `fixture_exists("does-not-exist")` is false — real,
concrete assertions, no fakes needed.
Production code: `pub(crate) fn fixture_exists(relative: &str) -> bool` next
to `fixture_dir()`. This lets a case check for its fixture and skip cleanly
*before* reaching `build_argv`'s hard `assert!(path.exists())`, which panics
(fails, doesn't skip) today. Update the stale `Case.fixture` doc comment
("no case uses one yet since tests/e2e/fixtures/ is still empty").

**Slice 3 — x86-32 fixture source + build wiring (not a Rust test; verified
by hand per slice 0's method, then transitively by slice 4).**
Add `tests/x86_asm/dup_mov_imm_32.s`:
```
.intel_syntax noprefix
.text
.globl _start
_start:
    mov eax, 5
    mov eax, 5
    mov ebx, eax
    mov eax, 1
    int 0x80
```
Two identical `mov eax, 5` (only EAX is live-out, neither touches EFLAGS) so
enumerative search collapses them to one — the x86-32 mirror of
`dup_mov_imm.s`. `mov ebx, eax` then `mov eax, 1` / `int 0x80` is the x86-32
Linux exit syscall (`sys_exit`, code in `ebx`), giving an explicit,
non-crashing exit whose code is a checksum of the live-out register (5),
matching the #831 PRD's "exit code is a checksum of live-out state"
constraint and setting up a future Phase 3 ticket to execute this fixture
directly. Update `build_tests.sh`'s x86-32 block to assemble
`tests/x86_asm/*_32.s` into `tests/e2e/fixtures/x86_32/<name minus _32>` with
`gcc -m32 -no-pie -nostdlib`, inside the existing toolchain-detection guard.
Update `tests/x86_asm/README.md`. Add `tests/e2e/fixtures/x86_32/` to
`.gitignore`. Run `./build_tests.sh` locally, confirm
`tests/e2e/fixtures/x86_32/dup_mov_imm` exists, and re-run slice 0's
`objdump`/manual-run check against this exact file.

**Slice 4 — the x86-32 e2e case.**
New `tests/e2e/cases/outcome_x86_32.rs`, registered via `mod outcome_x86_32;`
in `tests/e2e/cases/mod.rs`:
```rust
use crate::e2e::harness::{Case, Window, fixture_exists, run};

#[test]
fn dup_mov_collapses_to_one_x86_32() {
    if !fixture_exists("x86_32/dup_mov_imm") {
        eprintln!(
            "Skipping dup_mov_collapses_to_one_x86_32: x86_32/dup_mov_imm \
             fixture not present. Run ./build_tests.sh; it skips x86-32 \
             when gcc -m32 / gcc-multilib is unavailable."
        );
        return;
    }
    run(&Case {
        name: "outcome-x86-32-dup-mov-collapse",
        subcommand: Some("opt"),
        fixture: Some("x86_32/dup_mov_imm"),
        arch: Some("x86-32"),
        window: Some(Window {
            start_addr: "0x8049000", // reconfirm in slice 0/3 against the real build
            end_addr: "0x804900a",
        }),
        args: &["--algorithm", "enumerative", "--timeout", "30", "--force"],
        expected_exit_code: 0,
        expected_instructions: Some((2, 1)),
        ..Default::default()
    });
}
```
`--algorithm enumerative` keeps the result deterministic and RNG-free
(satisfies the issue's "no unseeded RNG" constraint by construction — the
enumerative search path performs no random sampling). `--force` makes
repeated local `cargo test`/`just e2e` invocations idempotent: `s11 opt`
without `-o` derives a sibling output path next to the input and refuses to
overwrite an existing one without `--force` (confirmed via `--help`'s output
policy text and `test_opt_force_overwrites_existing_custom_output` in
`tests/integration/opt_test.rs`); without `--force` a second local run would
fail on the leftover derived file from the first. `Case.expected_exit_code`
is `s11`'s own process exit code (0 = success), independent of the fixture
binary's *own* exit code (5, from `mov ebx, eax`) — the harness has no
execution-tier assertion yet (Phase 3, `ExecutionExpectation` stays
unimplemented), so the fixture's exit code isn't checked by this ticket; it
only needs to exist so the binary is runnable rather than crashing.
"Red" here is necessarily soft (no artificial failure to force, matching
every other fixture-gated test in this repo): before slice 3 lands the case
can't compile against a real fixture path meaningfully; after slices 1-3 land
it either passes (multilib present) or skips cleanly (absent) — both are
valid green outcomes. Verify both paths locally: once with
`tests/e2e/fixtures/x86_32/dup_mov_imm` present (`cargo test --test
e2e_tests -- --nocapture`, confirm the case actually runs and passes, not
just compiles) and once by temporarily moving that file aside to confirm the
skip message prints and the suite stays green.

**Slice 5 — docs.** Update `tests/e2e/fixtures/README.md` (x86_32/ now
populated by #836) and the `Justfile` `e2e:` recipe's stale comment. No test;
doc-only.

**Slice 6 — full verification.** Run `./ci_check.sh` per this repo's
CLAUDE.md. Separately confirm: `just e2e` with fixtures pre-built (case
passes) and `just e2e` on a clean `binaries`-and-fixtures-absent checkout
without running `build_tests.sh` first (case skips, suite still green, exit
0) — this is the literal behavior the issue's "skipped (not failed)"
criterion asks for. `cargo fmt -- --check` and `cargo clippy --all-targets
--no-deps` are already covered by `ci_check.sh` and the PostToolUse hook.

## 4. Verification surface

Not applicable in the ESBMC/contracts sense — this repo verifies semantic
equivalence with Z3 (`src/semantics/smt_x86.rs`), and this issue adds no new
instruction semantics, IR, or search code, so there is nothing new for Z3 to
prove. The only "fixture growth" is the new `tests/e2e/fixtures/x86_32/`
directory (one ELF) and the new `.s` source under `tests/x86_asm/`. The
regression surface is `tests/e2e/cases/outcome_x86_32.rs` plus the two new
`harness.rs` unit tests in slices 1-2.

## 5. Risk areas

- **Cross-ticket collision on `harness.rs`.** #834 (AArch64) and #835
  (x86-64) are sibling Phase-2 tickets on separate branches
  (`sym/s11/834-e2e-outcome-cases-aarch64`,
  `sym/s11/835-e2e-outcome-cases-x86-64`, both currently at `origin/main`
  with no commits yet, confirmed at planning time) that will very likely also
  need to implement `expected_instructions`. Since this repo squash-merges,
  whichever PR lands first "wins" that implementation; the others will hit a
  merge conflict or duplicate-logic diff on rebase. Before starting slice 1,
  `git fetch origin main` and re-read `tests/e2e/harness.rs` — if
  `expected_instructions` is already implemented upstream, skip slice 1
  (just consume it) rather than re-implementing; likewise for `fixture_exists`
  in slice 2 if some equivalent already landed.
- **`RUSTFLAGS: -D warnings`.** CI fails the build on any warning. Keep
  `fixture_exists` used (by slice 4's case) within the same PR so it's never
  briefly dead code at a commit that CI would evaluate independently — not a
  concern here since CI only runs on the final pushed state, but worth
  keeping in mind if slices are committed and CI'd independently.
- **Fixed-address fragility.** `0x8049000`/`0x804900a` depend on this
  environment's exact gcc/binutils default link layout for
  `-no-pie -nostdlib` 32-bit ELFs. Stable across rebuilds on one toolchain
  (per the existing x86-64 fixture's precedent comment), but must be
  reconfirmed against the actual committed fixture (slice 0/3), not assumed
  from the planning-stage scratch probe.
- **`--force` masking a real regression.** Because the case always passes
  `--force`, a second run's derived-output diff is never inspected; this is
  acceptable since the only assertions this ticket makes are exit code and
  the stdout instruction-count lines, not file contents.
- **Do not touch `tests/x86_asm/dup_mov_imm.s` or anything under
  `binaries/x86_64/`** — that fixture and its "must not fall off `_start`"
  fix belong to #835, not this ticket.

## 6. Out of scope

- Adding `gcc-multilib` to `.github/workflows/test.yml`'s "Install
  dependencies" step. The acceptance criteria are explicitly written for the
  graceful-skip path (CI today has no x86-32 multilib installed), matching
  the existing `build_tests.sh` precedent; installing it would be scope
  creep needing its own justification (extra Actions minutes, package
  review) and isn't required to satisfy #836.
- Any change to `src/` — the x86-32 opt path already works; this issue is
  test-infrastructure only.
- Migrating the existing x86-64 `binaries/x86_64/` fixtures/tests to
  `tests/e2e/fixtures/x86_64/` — that's #835's decision to make, not implied
  by this ticket.
- A second x86-32 shortening-class fixture or an `--auto` multi-window
  fixture (mirroring `auto_two_dup_mov.s`). Only one x86 shortening class
  (duplicate-MOV collapse) is demonstrated anywhere in this repo's test
  suite today; manufacturing a second one for x86-32 alone would be
  unjustified scope growth. A follow-up can add more once a second class
  exists for x86-64 too.
- Phase 3 (`ExecutionExpectation`, actually executing input vs. output and
  diffing exit codes) — stays an unimplemented, documented stub. This
  ticket's fixture is designed to be execution-ready (explicit exit syscall,
  checksum exit code) for whenever that later ticket lands, but does not
  implement or exercise it.
- `Justfile`'s `e2e:` recipe gaining a `build-tests` dependency. `build-tests`
  hard-fails without the AArch64 cross-compiler
  (`which aarch64-linux-gnu-gcc || exit 1` in `build_tests.sh`), so wiring it
  in would make `just e2e` newly require a toolchain unrelated to the case
  being added, regressing its current "no toolchain needed for the fast
  tier" property for CLI-contract-only cases. The new case's own
  `fixture_exists` skip guard already produces the required graceful
  behavior when fixtures haven't been built; CI's existing "Build test
  binaries" step (already before "Run e2e tests" in `test.yml`, and it
  invokes `build_tests.sh` unconditionally) covers the case where the
  fixture must actually exist.

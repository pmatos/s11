# Plan: issue #835 — e2e: outcome cases - x86-64

## 0. Template note

The planning prompt's boilerplate ("Files to touch" in `crates/`/`compiler/`,
`docs/spec/*.md`, ESBMC verification surface) describes a different project
(Vow). This repo is s11, a Rust superoptimizer with no `crates/`, `compiler/`,
or `docs/spec/` directories and no ESBMC/contract verification. The sections
below are the same six required headings, adapted to s11's actual structure
(`src/`, `tests/`, `docs/capability.md`, `docs/adr/`) per this repo's own
`CLAUDE.md`, which is the source of truth here.

## 1. Problem restated

The e2e harness scaffold (#832, merged as PR #845) defines a declarative
`Case` struct under `tests/e2e/` with an `expected_instructions: Option<(usize,
usize)>` field that is wired into the struct but deliberately unimplemented —
`harness::run()` panics naming issues #834-#836 if any case sets it. Issue
#835 asks for the first real consumer of that field on x86-64: at least one
fixed-address x86-64 fixture per known shortening class, assembled by
`build_tests.sh`, with the harness (not a hand-rolled prose-grep) asserting
the before→after instruction count. It also requires the two existing
hand-written `tests/x86_asm/*.s` fixtures to end with an explicit exit
syscall so they no longer crash if actually executed (needed by the later
Phase 3 behavioral tier), without introducing any dependency on unseeded RNG
(issue #409).

Scope call, stated explicitly per the operating contract (to be posted as a
`gh issue comment` on #835 during implementation): `tests/integration/opt_test.rs`
today has exactly **one** ad hoc x86-64 "known shortening" class —
`test_opt_x86_64_known_shortening`, duplicate-`mov rax,5` collapsing 2→1
instructions via `dup_mov_imm.s`. `auto_two_dup_mov.s` reuses that same class
twice to exercise `--auto`'s loop/fixpoint/budget mechanics, not a second
class. So "one fixture per known shortening class" for x86-64 means **one**
e2e outcome case is the correct, non-speculative scope; additional classes
(e.g. dead-store-via-overwrite, algebraic identities) are not proven
deterministic ad hoc precedents yet and are listed under Out of scope as
follow-ups, not invented here.

## 2. Files to touch

- `tests/x86_asm/dup_mov_imm.s` — replace the trailing NOP padding with an
  explicit exit syscall (`mov rdi, rax` / `mov rax, 60` / `syscall`), keeping
  the two-instruction `mov rax,5` window's address unchanged (it's first in
  `_start`).
- `tests/x86_asm/auto_two_dup_mov.s` — append an explicit exit syscall built
  from `push`/`pop` only (`push rcx` / `pop rdi` / `push 60` / `pop rax` /
  `syscall`), **not** `mov`-based, to avoid perturbing `--auto`'s
  maximal-supported-run candidate-window discovery (see Risk areas).
- `tests/x86_asm/README.md` — note both fixtures now exit explicitly and
  describe the live-out-derived exit code.
- `build_tests.sh` — in the existing x86-64 asm-fixture loop, also copy each
  assembled fixture into `tests/e2e/fixtures/x86_64/<name>` (`mkdir -p` that
  directory first). `binaries/x86_64/<name>` keeps being produced unchanged
  for the existing integration tests.
- `.gitignore` — add an arch-agnostic ignore pair for generated e2e fixture
  binaries:
  ```
  tests/e2e/fixtures/*
  !tests/e2e/fixtures/README.md
  ```
  (one shared change; #834/#836 will add their own `aarch64/`/`x86_32/`
  subdirectories under the same ignore rule without touching this file again).
- `tests/e2e/fixtures/README.md` — update: fixtures are now build artifacts
  under arch subdirectories (`x86_64/…`), produced by `build_tests.sh`, not
  checked in.
- `tests/e2e/harness.rs` — implement `expected_instructions`: remove the
  panic branch, add an output-only tempdir (`tempfile::TempDir`), append
  `-o <tempdir>/<case.name>-optimized` to argv (input fixture path is passed
  through unmodified — `s11 opt` never mutates its input, only writes `-o`
  or a derived sibling if `-o` is omitted, so no fixture copy is needed),
  run, then assert exit code plus `stdout.contains("Disassembled {before}
  instructions:")` and `stdout.contains("Optimized to {after}
  instructions:")` (colon-terminated so `1` can't match `10`). Keep the
  existing `execution` panic branch untouched (Phase 3, out of scope).
- `tests/e2e/cases/outcome_x86_64.rs` — new file, one `Case` for
  `dup_mov_imm`.
- `tests/e2e/cases/mod.rs` — add `mod outcome_x86_64;`.
- `Justfile` — change the `e2e` recipe to depend on `build-tests` (`e2e:
  build-tests`) and drop the now-stale "No fixture-based cases exist yet"
  comment. CI is unaffected (`.github/workflows/test.yml` and `ci_check.sh`
  already run `build_tests.sh` before the e2e test step); this only affects
  local `just e2e` invocations, which now require the AArch64 cross-compiler
  like `just test-all`/`just coverage` already do.

No `docs/capability.md` or ADR changes: no mnemonic support, IR semantics, or
CLI flag is being added or changed.

## 3. TDD slices

1. **Fixture runnability (no test framework involved, verified by hand +
   existing tests).** Edit `dup_mov_imm.s` per above. Rebuild
   (`./build_tests.sh`) and confirm: (a) `binaries/x86_64/dup_mov_imm` still
   runs and exits `5` (the live-out `RAX` value — a compile-time constant, so
   directly using it as the exit code is already a trivial "checksum" of
   live-out state per #831's constraint; no RNG involved); (b) the existing
   `test_opt_x86_64_known_shortening` and
   `test_opt_x86_64_*forced_output*`-family tests in
   `tests/integration/opt_test.rs` still pass unchanged — they locate the
   window by scanning for the `mov rax,5` byte pattern, which is unaffected
   by what comes after it.

2. **`auto_two_dup_mov.s` runnability, gated.** Apply the push/pop-based exit
   edit. Rebuild and run
   `cargo test --test integration_tests test_auto_x86_64_rewrites_two_windows_then_reaches_fixpoint
   -- --nocapture` **before** moving on. This test's assertions
   (`"2 rewrites accepted"`, the `"skipped 2 candidate window(s) due to
   budget"` count, and the byte-range-outside-rewrite-windows check) all
   depend on the candidate-window discovery still finding exactly the same
   two 2-instruction windows. Because `push`/`pop`/`syscall` stay outside the
   liftable x86 mnemonic subset (same precedent as the existing `push rbx`
   already in this fixture — see `src/elf_optimizer/mod.rs`'s
   maximal-supported-run window discovery), this should be a no-op for
   candidate-window shape, but it must be confirmed empirically, not assumed,
   before this slice is considered green. If it does perturb window shape,
   fall back to an even more inert sequence (e.g. `int3`-free `hlt`-avoidance
   via nested `push`/`pop` only, already chosen here) rather than any `mov`.

3. **Fixture placement (RED via missing file, GREEN via build_tests.sh).**
   Add the `tests/e2e/fixtures/x86_64/` copy step to `build_tests.sh` and the
   `.gitignore` pair. Verify by running `./build_tests.sh` and confirming
   `tests/e2e/fixtures/x86_64/dup_mov_imm` exists and `git status` shows it
   untracked-and-ignored (not appearing at all, given the ignore rule).

4. **Harness capability (RED: case panics "not implemented"; GREEN: assertion
   passes).** First add `tests/e2e/cases/outcome_x86_64.rs` (registered via
   `mod outcome_x86_64;` in `cases/mod.rs`) with:
   ```rust
   Case {
       name: "outcome-x86-64-dup-mov-imm",
       fixture: Some("x86_64/dup_mov_imm"),
       arch: Some("x86-64"),
       window: Some(Window { start_addr: "0x401000", end_addr: "0x40100e" }),
       args: &["--algorithm", "enumerative", "--timeout", "30"],
       expected_exit_code: 0,
       expected_instructions: Some((2, 1)),
       ..Default::default()
   }
   ```
   Run `cargo test --test e2e_tests` — this must fail with the harness's
   current "not implemented yet (Phase 2, see issues #834-#836)" panic
   message (proves the case is wired correctly and fails for the *expected*
   reason, not a missing-fixture or bad-args reason — slice 3 must have
   already made the fixture exist). Then implement the harness change
   described in Files to touch (tempdir + `-o` + assertions), removing the
   panic branch. Re-run — the case must now pass. The literal window
   addresses (`0x401000`/`0x40100e`) come from actually building the fixture
   locally and reading `readelf -h` / disassembling the two-instruction
   pair — confirmed during planning: `-no-pie -nostdlib` places `.text`
   (and `_start`, first in it) at the standard GNU ld default `0x401000`.

5. **CI/local wiring.** Update the `Justfile` `e2e` recipe as described.
   Run `./ci_check.sh` end-to-end once (`build_tests.sh` → `cargo test
   --verbose`, which includes both `integration_tests` and `e2e_tests`) to
   confirm nothing regressed.

6. **README updates** (`tests/x86_asm/README.md`,
   `tests/e2e/fixtures/README.md`) — documentation only, no test.

## 4. Verification surface

Not applicable in the Vow/ESBMC sense (no contracts, no C model, no
`docs/spec/`) — this repo has neither. The real verification surface is:

- `./ci_check.sh` (repo's actual quality gate): CI-policy tests, mutation-
  wrapper regressions, the cargo-fmt-clippy hook regression, `cargo fmt --
  --check`, build, `cargo test --verbose` (covers `integration_tests` and
  `e2e_tests`), then `./test_all.sh`. Per this repo's `CLAUDE.md`, run each
  gate step as a separate command, not `&&`-chained.
- `cargo clippy --all-targets --no-deps` (separate from `ci_check.sh`,
  required by the `rust-clippy.yml` workflow) — the new harness code and
  case file must be clippy-clean, and CI runs with `RUSTFLAGS=-D warnings`,
  so no dead code from removing the panic branch.
- The two pre-existing x86-64 integration tests
  (`test_opt_x86_64_known_shortening`,
  `test_auto_x86_64_rewrites_two_windows_then_reaches_fixpoint`) continuing
  to pass unchanged is itself part of the verification surface for this
  change, since both fixtures are being edited.
- `python3 -m unittest discover -s scripts -p 'test_*_policy.py'` — no new
  CI step or required-gate string is being added (the e2e step is already
  registered from #832/PR #845), so this should need no policy-test changes;
  running it confirms that.
- No new `tests/run/`- or `examples/`-style fixture growth is needed beyond
  what's listed above (this repo has no such directories; the closest
  analogue, `tests/asm/*.s` and `tests/*.c`, are untouched).

## 5. Risk areas

- **Concurrent sibling issues on the same shared file.** #833 (CLI contract
  coverage), #834 (AArch64 outcome cases), and #836 (x86-32 outcome cases)
  are all `sym:running` in parallel workspaces right now. #834 and #836 need
  the *exact same* `harness.rs` `expected_instructions` capability this issue
  implements — real conflict risk on `tests/e2e/harness.rs`, lower risk on
  `tests/e2e/cases/mod.rs` (one-line `mod` addition each) and `build_tests.sh`
  (different loop blocks per arch, unlikely to textually overlap). Before
  starting implementation: `git fetch origin` and check
  `git log origin/main -- tests/e2e/harness.rs` and `gh pr list --search e2e`
  for a sibling PR that already landed or is in flight with this capability.
  If one exists, read its diff and match its design (field handling, `-o`
  strategy, exact assertion strings) rather than implementing a second,
  differently-shaped version that will conflict on rebase.
- **`auto_two_dup_mov.s` exit-sequence perturbing `--auto` candidate-window
  discovery.** Addressed by using only non-liftable (`push`/`pop`/`syscall`)
  instructions for the exit sequence, matching the fixture's existing
  `push rbx` precedent, and gated by actually re-running
  `test_auto_x86_64_rewrites_two_windows_then_reaches_fixpoint` before
  considering slice 2 done (see TDD slice 2). Do not use `mov`-based
  instructions there even though they're simpler, since `mov` is in the
  liftable subset and would extend the maximal-supported run past the
  intended window.
- **Hardcoded literal window addresses.** `Window.start_addr`/`end_addr` are
  `&'static str`, so they must be literals, unlike the existing integration
  tests which scan for the window dynamically via
  `x86_find_byte_sequence`/`x86_first_executable_address`. `0x401000` is the
  standard GNU ld default for `-no-pie -nostdlib` (confirmed empirically
  during planning) and CI runs on `ubuntu-24.04` (stable toolchain), so this
  should be stable, but a future host-gcc/binutils default-address change
  would break the case loudly (harness prints a reproducer command) rather
  than silently — acceptable, not a silent-failure risk.
- **`s11 opt` default output behavior.** Omitting `-o` writes a derived
  `<name>_optimized` sibling next to the input by default (confirmed from
  existing integration-test comments). The harness change must always pass
  `-o <tempdir path>` for any case with `expected_instructions` set, or every
  `just e2e`/CI run would leave stray derived-output files next to the
  (gitignored but still real-working-tree) fixture.
- **x86-64 host gcc availability.** `build_tests.sh` gracefully skips the
  entire x86-64 block (including the new fixture-copy step) if no x86-64
  host gcc is present, but the e2e harness's `assert!(path.exists(), …)` is
  a hard failure, not a skip, unlike the integration tests' per-test skip
  guards. This is fine for CI (`ubuntu-24.04` runners are x86-64, so the
  fixture always builds there) but means local `just e2e` on a non-x86-64
  host would hard-fail rather than skip. Not fixing this here — it's a
  pre-existing property of the #832 harness scaffold's design (fixtures are
  assumed pre-built, not opportunistically skipped), not something specific
  to this issue.

## 6. Out of scope

- Additional x86-64 shortening classes beyond duplicate-MOV-immediate
  collapse (e.g. dead-store-via-overwrite, algebraic identities, zero-
  cancellation) — not yet an ad hoc precedent in `opt_test.rs`, so not
  "known" in the sense the acceptance criteria uses; candidates for a
  follow-up issue once a fixture author establishes each as deterministic.
- Phase 3 behavioral tier (actually executing input/output binaries and
  comparing exit codes) — `Case.execution`/`ExecutionExpectation` stays
  unimplemented; this issue only makes the fixtures *capable* of running
  (explicit exit syscalls) as a prerequisite, per #831's explicit phasing.
- x86-32 and AArch64 outcome cases — #836 and #834 respectively, separate
  issues, separate workspaces.
- Softening `build_tests.sh`'s hard requirement on
  `aarch64-linux-gnu-gcc` (needed once `just e2e: build-tests` is wired up
  locally) to a graceful skip like the `gcc -m32` x86-32 block already has —
  real usability improvement, but a separate, pre-existing concern not
  introduced by this issue; touches a shared script's control flow for an
  unrelated arch.
- `--format json` machine-readable output (PRD Phase 5) — the harness's new
  `expected_instructions` assertion still parses the existing prose
  ("Disassembled N instructions:", "Optimized to M instructions:") rather
  than a structured contract; that's an explicitly separate, larger PRD per
  #831.
- Any change to `docs/capability.md` or ADRs — no ISA/mnemonic/CLI surface
  changes.

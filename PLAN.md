# PLAN: #837 — e2e behavioral tier: execute-and-diff framework + x86

## 1. Problem restated

`tests/e2e/harness.rs::run()` already has a scaffolded `ExecutionExpectation`
field on `Case`, but it is a stub: any case that sets `execution` makes
`run()` panic immediately, naming issues #834-#836. The two blocking
tickets (#835 x86-64, #836 x86-32) are closed and left the fixtures
execution-ready on purpose: `tests/x86_asm/dup_mov_imm.s` and
`tests/x86_asm/x86_32/dup_mov_imm.s` both end with an explicit exit syscall
whose code is a compile-time checksum of live-out state (RAX=5 for x86-64,
EAX=5 for x86-32) instead of falling off `_start`. This issue turns that
stub into a real "execute-and-diff" mechanism: after `s11 opt -o out`
produces a patched binary, natively execute both the original input fixture
and the patched output and compare exit code + stdout, wire at least one
x86-64 and one x86-32 outcome case through it, and prove with a self-test
that the diff actually catches a divergence (not a mechanism that always
reports "equal"). AArch64 (which needs `qemu-user-static`, not native exec)
is explicitly out of scope — that's issue #838.

## 2. Files to touch

This is a test-only change; nothing under `src/` is touched, no CLI flags
change, and no `docs/spec/*.md`-equivalent exists for this repo (that section
of the template doesn't apply — see §6). Concretely:

- `tests/e2e/harness.rs` — the core change:
  - Replace the `execution.is_some()` → `panic!` stub in `run()` with a real
    execute-and-diff step.
  - Relax the `-o`/tempdir-creation predicate from
    `case.expected_instructions.is_some()` to
    `case.expected_instructions.is_some() || case.execution.is_some()`, and
    generalize the accompanying `subcommand == "opt"` assertion message to
    cover both fields.
  - Extract a small `resolve_input_path(case: &Case) -> PathBuf` helper
    (fixture-dir-join vs. `case.binary`) shared by `build_argv` and the new
    diff step, so the two don't silently diverge.
  - Add `run_to_completion(binary: &Path, timeout: Duration) -> ExecutionOutcome`
    (spawn, no args, no stdin; bounded wait; read captured stdout after exit)
    and `diff_execution(case_name, input_binary, output_binary, expectation,
    reproducer)` (three-way check, see §3.2).
  - Update the `ExecutionExpectation` and `Case::execution` doc comments —
    they currently say "Unimplemented ... panics".
  - Add unit tests to the existing `#[cfg(test)] mod tests` block proving the
    diff is load-bearing (§3.3, §3.4).
- `tests/e2e/cases/outcome_x86_64.rs` — add
  `execution: Some(ExecutionExpectation { expected_exit_code: 5 })` to the
  **existing** `dup_mov_imm_collapses_to_one_instruction` case. Do not add a
  second case that re-runs `s11 opt` on the same fixture; that doubles
  runtime for no new coverage.
- `tests/e2e/cases/outcome_x86_32.rs` — same one-line addition to the
  existing `dup_mov_collapses_to_one_x86_32` case (already behind its
  `fixture_exists` skip gate, so this is free to add unconditionally).
- `tests/e2e/fixtures/README.md` and `tests/x86_asm/README.md` — both
  currently say "future execution-tier e2e case" / "needed by the behavioral
  tier (later ticket)"; update to say it's implemented and name the cases.
- `Cargo.toml` — add `wait-timeout = "0.2"` under `[dev-dependencies]` (see
  §3.2 for why). Already resolved in `Cargo.lock` (0.2.1) as a transitive dep
  of an existing crate, so this adds no new download, just a direct-dep line
  and a `cargo build` re-resolve.

No changes to `Justfile`, `.github/workflows/test.yml`, `ci_check.sh`, or
`scripts/test_ci_policy.py` — `just e2e` / `cargo test --test e2e_tests` are
already wired into CI and the policy test from #832; this issue only adds
cases and harness capability within that existing entry point.

## 3. TDD slices

### 3.1 Red: harness rejects an `execution`-bearing case with a clear "not implemented" message (already true today)

No new test needed here — `deliberately_failing_case_prints_a_reproducer`-style
coverage already exists implicitly via the stub panic. This slice is the
starting "red" state; skip straight to making it real.

### 3.2 Green: `run_to_completion` + `diff_execution` primitives, unit-tested in isolation

Add to `tests/e2e/harness.rs`'s `#[cfg(test)] mod tests`, **before** touching
any real case:

- `stdout_diff_panics_on_divergent_output` — write two tiny `#!/bin/sh`
  scripts to a tempdir (`exit 0` vs. `echo foo && exit 0`), chmod 0o755,
  call `diff_execution` on them with `expected_exit_code: 0`, assert (via
  `catch_unwind`) it panics naming both paths and quoting the differing
  stdout. This exercises the stdout axis cheaply — no fixture or toolchain
  needed, since none of today's x86 fixtures emit stdout and this is the
  only way to cover that branch at all.
- `exit_code_diff_panics_when_input_and_output_diverge` — same two scripts,
  this time `exit 5` vs. `exit 6`, both silent; assert the panic names
  `5` and `6`.
- `run_to_completion_kills_a_hung_process_after_timeout` — a `#!/bin/sh`
  script that `sleep`s past a short (e.g. 200ms) test-supplied timeout;
  assert it returns/panics with a timeout-specific message inside a bounded
  wall-clock bound (so this test itself can't hang CI).

Production code to make these pass:

```rust
struct ExecutionOutcome { exit_code: i32, stdout: Vec<u8> }

fn run_to_completion(binary: &Path, timeout: Duration) -> ExecutionOutcome {
    // spawn with Stdio::piped() stdout, Stdio::null() stdin/stderr
    // wait_timeout::ChildExt::wait_timeout(&mut child, timeout)
    // on None (still running): child.kill(), panic naming binary + timeout
    // on Some(status): read_to_end the already-piped stdout, return outcome
}

fn diff_execution(
    case_name: &str,
    input_binary: &Path,
    output_binary: &Path,
    expectation: &ExecutionExpectation,
    reproducer: &str,
) {
    let input = run_to_completion(input_binary, EXECUTION_TIMEOUT);
    assert!(input.exit_code == expectation.expected_exit_code, /* names input_binary, both codes, reproducer */);
    let output = run_to_completion(output_binary, EXECUTION_TIMEOUT);
    assert!(output.exit_code == input.exit_code, /* "patched output diverged: exited N, input exited M — likely miscompile", both paths, reproducer */);
    assert!(output.stdout == input.stdout, /* names both stdout buffers, both paths, reproducer */);
}
```

Three distinct assertions/messages, per the debugging value each carries:
input-exit-code-wrong (fixture/expectation misconfigured, not the
optimizer's fault), output-exit-code-diverged (miscompile signal), stdout
diverged (miscompile signal, second axis). All three messages include the
reproducer command already built by `run()` so a human can copy-paste.

**Why `wait-timeout` over hand-rolling `codex.rs`'s poll loop:** a bounded
wait already exists in production (`src/search/llm/codex.rs::wait_for_child`
+ `child_poll_delay`), but it's a private fn in a binary-only crate —
`tests/e2e` is a black-box test crate that only execs the built `s11`
binary via `env!("CARGO_BIN_EXE_s11")` and cannot import it. Reimplementing
the same poll-and-kill logic in test code is more code to review for the
same behavior `wait-timeout` already provides, and it's already in the
lockfile transitively, so pulling it in as a direct dev-dependency costs one
`Cargo.toml` line and no new download. `Command::output()` (used elsewhere
in the harness) is not an option here because it has no timeout — a genuine
miscompiled infinite loop would hang the whole `cargo test` run forever.
Stdout is read only *after* `wait_timeout` reports the child has exited, not
concurrently — safe for these fixtures (empty or few-byte stdout, well
under the ~64KiB pipe buffer), not a fully general solution; call this out
as a documented constraint rather than adding a draining thread nothing
today exercises.

### 3.3 Green: wire the two closed-loop outcome cases

Add the one-line `execution: Some(...)` to the existing x86-64 and x86-32
cases (§2). Run `cargo test --test e2e_tests -- --nocapture` (after
`./build_tests.sh`) and confirm both pass: `s11 opt` collapses the two
`mov {rax,eax}, 5` into one, the patched output still exits 5 (same as the
unmodified input), stdout is empty on both sides. This is the "at least one
x86-64 and one x86-32 fixture exercised through the behavioral tier"
acceptance criterion — reusing the existing closed (#835/#836) fixtures
rather than adding new ones, since they were purpose-built for this.

### 3.4 Red→Green: prove the diff is load-bearing against a *real* `s11 opt` output

This is the "deliberately-broken patch... proving the diff is load-bearing"
acceptance criterion, and it should exercise a genuine `s11`-produced
artifact, not just the synthetic shell-script primitives from 3.2 (those
prove the comparator works; this proves it's wired to catch what actually
matters — the optimizer's own output).

New harness self-test, e.g. `execution_diff_catches_a_corrupted_patch`:

1. Run the real `s11` binary (`s11_binary_path()`) with the same argv as
   the `outcome-x86-64-dup-mov-imm` case (`opt`, `x86_64/dup_mov_imm`,
   `--arch x86-64`, the `0x401000`-`0x40100e` window, `-o` into a tempdir).
2. Read the patched output file's bytes. Verified locally with `gcc
   -no-pie -nostdlib` + `objdump`: pre-patch, `mov rax, 5` assembles to
   `48 C7 C0 05 00 00 00` at both 0x401000 and 0x401007 (7 bytes each,
   filling the whole 14-byte window); after the enumerative search
   collapses the pair, exactly one `48 C7 C0 05 00 00 00` occurrence should
   remain in the output file, followed by NOP padding. Search the output
   bytes for that 7-byte sequence and assert it occurs **exactly once**
   (this doubles as a byte-level confirmation that the collapse actually
   happened, independent of the `expected_instructions` stdout-marker
   check).
3. Flip that occurrence's immediate low byte (offset +3, `0x05` → `0x06`)
   in a copy of the file — this is "mov rax, 6" instead of 5, a minimal,
   realistic stand-in for a miscompile that corrupts live-out state.
4. Call `diff_execution` with `input_binary` = the original fixture,
   `output_binary` = the corrupted copy, `expected_exit_code: 5`, wrapped
   in `catch_unwind`. Assert it panics, and assert the message names both
   `5` and `6` (i.e. it's the output-diverged-from-input assertion firing,
   not some unrelated failure).

If the byte offset/count assumption above doesn't hold exactly when this
slice is implemented (e.g. a future search-algorithm change reorders
things), the test should fail loudly at the "exactly once" assertion rather
than silently mutating the wrong bytes — treat that as a signal to adjust
the byte search, not to weaken it to "at least once".

### 3.5 Refactor

Once 3.1-3.4 are green: re-read `run()` for duplicated fixture/binary
resolution between `build_argv` and the new execution block (should already
be avoided by `resolve_input_path`, but confirm), and check the two new
private functions' doc comments match the style of the existing ones in the
file (`stdout_reports_instructions`, `reproducer_command`).

## 4. Verification surface

N/A in the ESBMC/contracts/codegen sense — this template section describes
the Vow language's verification pipeline (`crates/`, `compiler/`, ESBMC
counterexamples, `parse → print → parse` idempotency), none of which exist
in this Rust superoptimizer repo. The closest equivalent "verification
surface" here is: does `just e2e` (→ `cargo test --test e2e_tests --
--nocapture`, already gated in `test.yml` and `scripts/test_ci_policy.py`)
pass, and do the new harness unit tests run as part of that same binary
(they do — `#[cfg(test)] mod tests` inside `tests/e2e/harness.rs` builds
into the `e2e_tests` test binary, no separate registration needed).

## 5. Risk areas

- **x86-32 case will skip in CI, not run — confirmed, not hypothetical.**
  `.github/workflows/test.yml`'s dependency-install step
  (`sudo apt-get install -y libcapstone-dev gcc-aarch64-linux-gnu z3
  libz3-dev`) does not install `gcc-multilib`, so `build_tests.sh`'s `gcc
  -m32 -E -x c -` probe fails, `tests/e2e/fixtures/x86_32/` is never
  populated, and the x86-32 case's `fixture_exists` guard skips it — same
  as the pre-existing #836 outcome case does today. The acceptance
  criterion ("at least one x86-32 fixture... exercised") is satisfiable
  locally (this repo's `build_tests.sh` supports it) and the code path is
  real and tested by CI's x86-64 case, but CI itself will not execute the
  x86-32 behavioral assertion until a separate change adds `gcc-multilib`
  to the workflow. **Decision: do not add `gcc-multilib` to `test.yml` in
  this PR** — it's a CI/dependency change orthogonal to this issue, and
  cross-arch multilib packages have known apt conflicts on some Ubuntu
  releases that deserve their own verification, not a drive-by addition
  here. Flag it as a follow-up in the PR description. Do **not** add any
  runtime "can the kernel exec 32-bit ELF" probe/skip — `fixture_exists`
  already gates on whether the toolchain produced the fixture at all, and a
  toolchain that successfully linked a 32-bit static ELF on this host
  implies the kernel can run it; guarding against a scenario that can't
  arise (per repo convention against speculative error handling) just adds
  dead code.
- **A genuinely miscompiled/looping patched binary must not hang `cargo
  test`.** Addressed by `run_to_completion`'s bounded wait + kill (§3.2);
  the timeout constant should be generous (existing `codex.rs` tests use
  5s as "generous") since a healthy fixture exits in milliseconds, but not
  so long it stalls CI noticeably on the (expected to be rare) real-timeout
  path.
- **Both `-o`-consuming code paths (`expected_instructions` and
  `execution`) must keep writing into the same tempdir/cleanup lifecycle.**
  The existing tempdir is deliberately *not* auto-cleaned via `TempDir`'s
  `Drop` so a failure leaves the reproducer's `-o` path inspectable; the
  execution-diff assertions must fire *before* the final `fs::remove_dir_all`
  cleanup at the end of `run()` (they will, since they're added inside the
  same function body before that cleanup line) — a misplaced insertion
  point would silently delete the evidence on the very failures a human
  most needs to inspect.
- **File-offset byte surgery in the 3.4 self-test is coupled to the current
  x86-64 dynasm/NOP-padding encoding.** Documented as a fast, loud failure
  (assert-exactly-once) rather than a silent wrong-byte flip if that
  encoding ever changes; acceptable because this is test-only code, not a
  contract other code depends on.
- **Executable-bit preservation on `-o` output is already handled by
  production code**, not something this harness needs to work around:
  `src/output_path.rs`'s `sanitize_output_permissions` copies the input's
  full `mode & 0o777` (including exec bits) onto the staged output before
  publishing it. Confirmed by reading `output_path.rs:55-81,444-449` and its
  existing test `resolved_output_preserves_access_permissions_without_privilege_bits`.
  No `chmod` needed in the new harness code before executing a `-o` output.

## 6. Out of scope

- AArch64 execution (issue #838 — needs `qemu-user-static`, a different
  execution primitive from native `Command::new`).
- Adding `gcc-multilib` to CI so the x86-32 case actually runs there (see
  §5) — separate, reviewable-on-its-own CI change.
- Any new CLI flag, `--format json`, or other `s11`-facing surface (Phase 5
  in the parent PRD #831, explicitly deferred there).
- Phase 4 (nightly deep tier, `--auto` over the full corpus with pinned
  seeds) — also explicitly deferred in #831.
- Refactoring `tests/integration/opt_test.rs`'s existing bespoke
  execution-free assertions to use the new e2e execution tier — #831 Phase
  1's stated policy is "port opportunistically, no big-bang move," and nothing
  in #837's acceptance criteria asks for it.
- Adding stdout-emitting fixtures beyond what's needed to prove the
  mechanism (the 3.2 shell-script self-tests cover the stdout axis cheaply;
  no new `.s` fixture is needed to satisfy the acceptance criteria as
  written).
- `crates/`, `compiler/`, `docs/spec/*.md`, ESBMC verification properties,
  `parse → print → parse` idempotency, `vow-clif-shim` stack-slot layout —
  none of these exist in this repository; this section of the plan template
  is written for the Vow language project and does not apply to s11.

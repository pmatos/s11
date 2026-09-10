# Plan: issue #838 — e2e: behavioral tier - AArch64 via qemu

## 1. Problem restated

The e2e execute-and-diff behavioral tier added in #837 (`ExecutionExpectation`/
`diff_execution` in `tests/e2e/harness.rs`) natively `Command::new`s the
unpatched input fixture and the `s11 opt`-patched output and diffs exit code +
stdout, but it only works for x86-64/x86-32 (host-native execution on the
`ubuntu-24.04` CI runner). The four AArch64 outcome fixtures from #834
(`tests/aarch64_asm/{dup_mov_imm,mov_add_fuse,sub_via_add,ldr_dead_load}.s`,
exercised by `tests/e2e/cases/outcome_aarch64.rs`) currently only assert
`expected_instructions`, never `execution` — AArch64 binaries can't run
directly on the x86-64 CI host. This issue wires AArch64 execution through
`qemu-aarch64-static`, resolving the sysroot dynamically via
`aarch64-linux-gnu-gcc -print-sysroot`, adds `qemu-user-static` to CI, and
adds one new dynamically-linked PIE AArch64 fixture (representative of a real
target binary, unlike the existing hand-written `-no-pie -nostdlib` fixtures)
that specifically exercises the qemu `-L <sysroot>` dynamic-linker-resolution
path, while keeping the four existing statically-linked fixtures as the
simpler baseline case. Everything here is test/CI/fixture wiring — no `src/`
production code changes are needed (confirmed below).

## 2. Files to touch

This is a pure test-infrastructure change; there is no `crates/`/`compiler/`
split in this repo (that boilerplate does not apply to s11) and no
`docs/spec/` update is required since no CLI flag, contract, or semantics
changes. Touched paths:

- `tests/e2e/harness.rs` — arch-aware execution: qemu wrapping for AArch64,
  sysroot resolution, toolchain-availability check.
- `tests/e2e/cases/outcome_aarch64.rs` — add `execution: Some(...)` to the
  four existing cases (with per-fixture correct expected exit codes, see
  slice 3) plus a new case for the PIE fixture, all gated on a new
  qemu-availability skip check alongside the existing `fixture_exists` skip.
- `tests/aarch64_asm/dup_mov_pie.s` (new) — hand-written AArch64 assembly
  fixture, same "two identical `mov x0, #5`" shortening identity as
  `dup_mov_imm.s`, but written as a libc `main` (not a raw `_start`) so gcc
  links it as a normal dynamically-linked PIE executable.
- `build_tests.sh` — new block assembling `dup_mov_pie.s` **without**
  `-no-pie -nostdlib` (default gcc PIE + dynamic linking against the
  cross-sysroot's libc), output to `tests/e2e/fixtures/aarch64/dup_mov_pie`.
- `tests/e2e/fixtures/README.md` — update the AArch64/qemu paragraph (it
  currently says qemu support "is tracked separately (#838)"); note the new
  PIE fixture and that this dir now has both a static and a dynamically-linked
  case.
- `.github/workflows/test.yml` — add `qemu-user-static` to the existing
  `apt-get install` line in the "Install dependencies" step (already installs
  `gcc-aarch64-linux-gnu`, which provides `aarch64-linux-gnu-gcc` for sysroot
  resolution).

No changes to `src/elf_patcher/`, `src/elf_optimizer/`, or any parser/ISA
code expected: `ElfPatcher` locates and patches bytes via section headers
(`sh_flags & SHF_EXECINSTR`, `sh_offset`/`sh_addr`), not program headers, and
only rejects `e_type == ET_REL` (`src/elf_optimizer/mod.rs:969`) — `ET_DYN`
(PIE) passes through unchanged. This is supported by existing precedent, not
just inference: `tests/integration/opt_test.rs:431` already runs `s11 opt`
against `binaries/arrays_debug`, a real `aarch64-linux-gnu-gcc`-compiled
dynamically-linked PIE binary with multiple `SHF_EXECINSTR` sections
(`.init`/`.plt`/`.text`/`.fini`), so the patcher already handles this ELF
shape today. What's genuinely new and unverified is this *specific* fixture
and window — slice 5 below is the first empirical check of that, and if it
turns up a real gap the plan's "out of scope" boundary should be revisited,
not silently worked around.

Confirmed empirically in this planning session: a hand-built
dynamically-linked PIE AArch64 fixture (`main:` calling libc `exit`)
assembles, and both it and the existing `-no-pie -nostdlib` fixtures execute
correctly and report the expected exit codes under `qemu-aarch64-static -L
<sysroot>` (the `-L` flag is a harmless no-op for the statically-linked
fixtures, confirmed locally, so the harness can pass it unconditionally
rather than branching on linkage type).

## 3. TDD slices

Each slice is red (test added/changed and fails or doesn't compile) then
green (minimal harness/fixture/CI change to pass). "Test" here means the
`cargo test --test e2e_tests` case, per repo convention (`just e2e`).

1. **Sysroot + qemu-availability helpers, unit-tested in `harness.rs`.**
   - Add `pub(crate) fn aarch64_sysroot() -> Option<PathBuf>` (shells out to
     `aarch64-linux-gnu-gcc -print-sysroot`, trims stdout, `None` if the
     command fails to spawn or exits non-zero) and
     `pub(crate) fn qemu_aarch64_available() -> bool` (checks
     `qemu-aarch64-static --version` spawns and exits successfully).
   - Red: add `#[cfg(test)]` unit tests in `harness.rs`'s existing `mod
     tests` that check *consistency*, not environment presence (asserting
     presence would hard-fail `just e2e` on any contributor machine without
     the toolchain installed, defeating acceptance criterion #4's graceful
     skip): `qemu_aarch64_available()` agrees with a direct `which
     qemu-aarch64-static` check, and `aarch64_sysroot()` returning `Some(p)`
     implies `p.exists()`. These fail to compile first (functions don't
     exist yet).
   - Green: implement the two functions.

2. **Arch-aware execution plumbing in `diff_execution`/`run_to_completion`.**
   - Thread an `arch: Option<&str>` parameter from `run()` (which already has
     `case.arch`) through `diff_execution` into `run_to_completion` and
     `spawn_retrying_etxtbsy`. Extract the `Command` construction into a new
     `fn build_execution_command(binary: &Path, arch: Option<&str>) ->
     Command`: for `arch == Some("aarch64")`, `Command::new("qemu-aarch64-static")`
     with `-L <sysroot>` (when `aarch64_sysroot()` returns `Some`) then the
     binary path as an argument; otherwise (x86-64/x86-32/`None`, unchanged
     today) `Command::new(binary)` directly. Keep the existing `ETXTBSY`
     retry loop wrapping whichever command is built — it stays a no-op for
     the qemu path (qemu opens the target for reading, not `execve`, so the
     race the retry was written for doesn't reproduce there) but costs
     nothing to leave unified.
   - Red: add a new unit test `run_to_completion_wraps_aarch64_binaries_in_qemu`
     mirroring `execution_diff_catches_a_corrupted_patch`'s existing pattern
     of using an already-built fixture rather than compiling one inline:
     gate on `fixture_exists("aarch64/dup_mov_imm")` and
     `qemu_aarch64_available()` (skip otherwise), then call
     `run_to_completion(&fixture_dir().join("aarch64/dup_mov_imm"),
     EXECUTION_TIMEOUT, Some("aarch64"))` and assert `exit_code == 5`. This
     fails to compile first (`run_to_completion`'s signature doesn't take
     `arch` yet).
   - Green: implement the signature change and `build_execution_command`.

3. **Wire `execution: Some(...)` into the four existing AArch64 outcome
   cases**, each gated by both the existing `fixture_exists` skip and a new
   `qemu_aarch64_available` skip (acceptance criterion: graceful skip with a
   clear message):
   - `aarch64-outcome-dup-mov-imm`: `expected_exit_code: 5`
   - `aarch64-outcome-mov-add-fuse`: `expected_exit_code: 1`
   - `aarch64-outcome-sub-via-add`: `expected_exit_code: 255`
   - `aarch64-outcome-ldr-dead-load`: `expected_exit_code: 5`
   These four values were verified empirically in this planning session by
   assembling each fixture and running it under `qemu-aarch64-static`
   directly (register `x1` is zeroed by the kernel at a bare `_start`'s
   entry, so `mov x0, x1; add x0, x0, #1` → 1, and `sub` → -1 → 255 as a `u8`
   exit code) — the implementation stage should re-verify rather than trust
   this document, per the source-of-truth rule for anything the PR will ship.
   - Red: add `execution: Some(ExecutionExpectation { expected_exit_code })`
     to each `Case` literal; cases fail today because `diff_execution` isn't
     wired to route AArch64 through qemu (sequence slice 2 before this one).
     Note: on a host with `qemu-user-static`'s `binfmt_misc` handlers
     registered (which the package installs as a side effect, and which CI
     will have once slice 6 lands), a bare `Command::new(aarch64_elf)` may
     already transparently execute via qemu — so this slice's "red" may only
     reproduce locally on a machine without binfmt registered, not in CI.
     That doesn't change the design: explicit `qemu-aarch64-static -L
     <sysroot>` wrapping is still required because binfmt invocation can't
     inject `-L`, which the new PIE fixture's dynamic linker
     (`/lib/ld-linux-aarch64.so.1`, absent from the x86-64 host root) needs.
   - Green: with slices 1-2 landed, these pass locally (toolchain present)
     and skip cleanly where it's absent.

4. **New dynamically-linked PIE fixture source + build.**
   - Add `tests/aarch64_asm/dup_mov_pie.s`:
     ```
     .text
     .global main
     main:
         mov x0, #5
         mov x0, #5
         bl exit
     ```
     (Same optimizable identity as `dup_mov_imm.s`; the only difference is
     `main`/`bl exit` instead of `_start`/raw `svc` syscall, which is what
     makes gcc emit a normal dynamically-linked PIE executable — the
     optimizer's window is `[main, main+8)`, entirely before the `bl`, so
     the patch never touches the call.)
   - Add a `build_tests.sh` block (near the existing "Hand-written
     register-only AArch64 assembly fixtures" block) that assembles it
     **without** `-no-pie -nostdlib`:
     `aarch64-linux-gnu-gcc -O0 -o tests/e2e/fixtures/aarch64/dup_mov_pie
     tests/aarch64_asm/dup_mov_pie.s`. This is unconditional (same hard
     preflight as the existing AArch64 block — the cross-toolchain is
     already a hard `build_tests.sh` requirement, not gracefully skipped).
   - Red: run `./build_tests.sh` and `file
     tests/e2e/fixtures/aarch64/dup_mov_pie`; must report `pie executable,
     ... dynamically linked, interpreter /lib/ld-linux-aarch64.so.1` (this
     step is a manual/CI verification, not a `cargo test` assertion — there
     is no existing "assert fixture linkage type" test pattern in this repo
     to extend, and inventing one is out of scope, see §6).
   - Green: land the fixture + build block.

5. **New AArch64 outcome case for the PIE fixture, exercising the sysroot
   path.**
   - Determine `main`'s exact address in the built fixture via
     `aarch64-linux-gnu-objdump -d` (or `nm`) — expect it to land shortly
     after the ELF/program headers, in the same range as this session's
     locally-observed `0x7a4`, but the implementation stage must re-verify
     against its own build rather than hardcode this document's number
     blind (see Risk areas).
   - Add `aarch64_dup_mov_pie_collapses_to_one_instruction` to
     `outcome_aarch64.rs`: `fixture: Some("aarch64/dup_mov_pie")`, `arch:
     Some("aarch64")`, `window: Some(Window { start_addr, end_addr })` (the
     two-instruction span found above), `expected_instructions: Some((2,
     1))`, `execution: Some(ExecutionExpectation { expected_exit_code: 5
     })`. Gate on both `fixture_exists` and `qemu_aarch64_available`. The
     other AArch64 cases pass `--force`, which per `src/main.rs:232-233` only
     changes the output-overwrite policy (refuse an existing `-o` path unless
     `--force`); since the harness always writes to a fresh tempdir, it's
     unclear any case actually needs it. Include it for consistency with the
     other AArch64 cases unless it turns out to be dead weight, but don't
     assume it's load-bearing for a different reason (e.g. symbol/relocation
     handling) without checking — confirm empirically rather than guessing.
   - Red: case fails/panics until the window address is correct and slices
     1-2 are in place.
   - Green: `just e2e` passes locally and (once CI installs
     `qemu-user-static`) in CI.

6. **CI wiring.**
   - Add `qemu-user-static` to `.github/workflows/test.yml`'s existing
     `sudo apt-get install -y libcapstone-dev gcc-aarch64-linux-gnu z3
     libz3-dev` line.
   - Red/Green here is CI-observational, not a local test: push and confirm
     the "Run e2e tests" step in Actions actually exercises (not skips) the
     five AArch64 execution cases — grep the job log for the absence of the
     "Skipping ... qemu" message this plan's skip path would otherwise emit.

7. **Docs.** Update `tests/e2e/fixtures/README.md`'s AArch64 paragraph: it
   currently says qemu support "is tracked separately (#838)" — replace with
   a short description of the qemu wrapping and the static-vs-PIE fixture
   split, mirroring the existing x86-64/x86-32 paragraph's level of detail.

## 4. Verification surface

Not applicable in the ESBMC/contracts sense (no ESBMC in this repo; that's
Vow-project boilerplate). The behavioral verification surface here is the
e2e suite itself:
- `just e2e` / `cargo test --test e2e_tests -- --nocapture` must pass with
  the toolchain present (locally confirmed available: `aarch64-linux-gnu-gcc`
  16.1.0, `qemu-aarch64-static`, sysroot `/usr/aarch64-linux-gnu`) and skip
  cleanly (not fail) when either is absent.
- No new fixtures under `tests/run/`/`examples/` (not applicable structures
  in this repo) — new fixture lives under `tests/aarch64_asm/` +
  `tests/e2e/fixtures/aarch64/`, per existing convention.
- `./ci_check.sh` (or its constituent steps run individually per this
  project's CLAUDE.md) must stay green, in particular `cargo fmt -- --check`
  on the harness changes and the repository CI-policy checks (workflow
  pinning policy does not apply — `qemu-user-static` is a plain `apt-get`
  package name, not a pinned `uses:` action).

## 5. Risk areas

- **PIE fixture window-address stability.** The four existing AArch64
  fixtures use `-no-pie -nostdlib`, giving a fully deterministic `_start`
  address (no crt/libc boilerplate at all) that's stable across binutils
  versions. The new `dup_mov_pie.s` fixture links against the cross
  sysroot's real glibc crt startup (`Scrt1.o`/`crti.o`), so `main`'s address
  depends on that startup code's size, which is toolchain/glibc-version
  dependent — verify locally with the exact toolchain, e.g. via
  `aarch64-linux-gnu-objdump -d`, and note the exact command in a fixture
  header comment so any future toolchain-driven drift is quickly
  diagnosable rather than a mysterious address mismatch. This is a real
  step up in fragility from the existing fixtures; accept it because it's
  the minimal fixture that can genuinely exercise "dynamically-linked PIE
  via qemu's `-L <sysroot>`" without also depending on unpredictable
  compiler-selected windows inside a full C program.
- **Qemu wrapping introduced only for execution, not for `s11 opt` itself.**
  `s11 opt`'s own analysis (disassembly, SMT check, patching) runs natively
  on the x86-64 host against ELF bytes — it never executes the AArch64
  binary. Only the new `diff_execution` runtime check needs qemu. Keep this
  boundary clean: don't accidentally make any non-execution code path depend
  on `qemu-aarch64-static`.
- **`-L <sysroot>` being a no-op for statically-linked fixtures** was
  confirmed locally (`qemu-aarch64-static -L /usr/aarch64-linux-gnu
  <static-binary>` still exits correctly) — if a future qemu version changes
  this behavior, the four existing fixtures would still need to keep
  passing; `build_execution_command` should pass `-L` unconditionally
  rather than branching per-fixture, so there's exactly one code path to
  keep correct.
- **CI-only failure mode**: if `qemu-user-static` is added to CI but the
  four existing skip-gated cases were previously silently no-op'ing (they
  currently assert nothing about execution), this PR is the first time CI
  actually executes AArch64 machine code — a genuine latent miscompile in
  the AArch64 backend could now surface as a new CI failure unrelated to
  this PR's own correctness. That would be a legitimate finding to report,
  not a flake to route around.
- **`EXECUTION_TIMEOUT` (5s, `harness.rs`)** now has to cover qemu process
  startup plus emulated dynamic-linker resolution against the sysroot, not
  just native process startup. Almost certainly still generous enough, but
  it's a new flake vector on a loaded CI runner — if a case ever times out,
  check for this before assuming a genuine hang/miscompile.
- Nothing here touches SMT/cost-model/parser code, so there's no risk to
  `parse → print → parse` idempotency or the enumerative/stochastic/symbolic
  search — this PR cannot change what `s11 opt` decides to emit, only
  whether the e2e suite additionally checks that the emitted binary still
  runs correctly.

## 6. Out of scope

- Migrating the four existing AArch64 fixtures to `-static`/PIE, or
  reconciling their `-no-pie -nostdlib` style with the new fixture's style —
  the issue explicitly asks to keep the dynamically-linked PIE case as an
  *addition*, not a replacement. The existing four don't need `-L <sysroot>`
  (no dynamic interpreter) and are left untouched beyond adding
  `execution: Some(...)`.
- Reusing `binaries/arrays_opt` (the real `tests/arrays.c`-compiled,
  `-O2`, dynamically-linked PIE binary mentioned in the issue as the
  "representative real target" example) directly as the new e2e fixture.
  Mining a stable, supported-mnemonic-only window out of real `-O2`
  compiler output is materially more fragile (compiler-version-dependent
  codegen, memory ops, stack layout) than a hand-written fixture with the
  same linkage characteristics, and the issue only asks for a fixture
  "representative of" that category, not literal reuse. Revisit only if a
  future issue specifically wants coverage of compiler-generated (not
  hand-written) AArch64 code in the e2e suite.
- Any RISC-V e2e work (out of scope for this issue and blocked upstream on
  RISC-V codegen per `build_tests.sh`'s own comment).
- Adding a harness-level "assert fixture ELF linkage type" test primitive —
  slice 4's `file`/`readelf` check is a one-time manual/CI-log verification
  during implementation, not a new standing regression test; inventing that
  abstraction for a single fixture would be scope creep.
- Any change to `src/elf_patcher/`, `src/elf_optimizer/`, or ISA/parser code
  — confirmed unnecessary in §2.
- Formatting/refactor cleanup elsewhere in `harness.rs` beyond the minimal
  signature threading needed for arch-awareness.

# Plan: issue #833 — e2e: CLI contract case coverage

## 1. Problem restated

The e2e harness (`tests/e2e/harness.rs`, `tests/e2e/cases/cli_contract.rs`) landed in
#845 with only a `--help` case. This issue adds the rest of `s11 opt`'s black-box
CLI contract to that harness: clap-level exit codes for missing/invalid
arguments, the `resolve_opt_target` policy errors (arch-mismatch, RISC-V
rejection), and the `resolve_output_path` output-policy errors
(existing/derived output, missing parent, trailing separator, unwritable
parent). All of it must stay fast and deterministic under `just e2e`, which
today builds only the `s11` binary itself (`CARGO_BIN_EXE_s11`) and does not
run `build_tests.sh` — none of the new cases may change that. `tests/integration/opt_test.rs`
already covers this ground with its own `Command`-based helpers; per the issue
body those are left untouched (ported opportunistically later), and the new
coverage here is written fresh against the declarative `Case`/`run()` harness,
using its existing `subcommand`/`arch`/`window` fields rather than hand-building
argv strings — that's the point of having the harness.

Investigation surfaced one load-bearing fact that shapes the whole plan:
`ElfPatcher::new()` only calls `ElfBytes::minimal_parse` to read `e_machine`
— it never touches a section table. Every check this issue needs to exercise
(`resolve_opt_target`'s arch/RISC-V rules, and every `resolve_output_path`
rule) runs *before* `optimize_elf_binary` ever asks for a text section. That
was confirmed empirically (`./target/debug/s11 opt <bare-64-byte-ELF-header>
--start-addr 0x0 --end-addr 0x4 ...` reaches the arch/output-policy errors,
not a parse error). So every case that needs an openable ELF at all can use a
single synthesized, header-only fixture (same trick as
`write_minimal_riscv_elf` in `opt_test.rs`, generalized to any `e_machine`)
instead of a real compiled fixture — no `build_tests.sh`, no cross-compiler,
no `tests/e2e/fixtures/` file, and no multi-megabyte file I/O per case.

## 2. Files to touch

This is a single-crate Rust project (no `crates/`/`compiler/` split, no
`docs/spec/`) — the generic run-template sections referring to those don't
apply. Everything lives under `tests/e2e/`:

- `tests/e2e/harness.rs` — extend `Case` with three small capabilities the
  existing declarative shape doesn't have yet (see §3, slice 1):
  - `binary: Option<PathBuf>` — a positional input path computed at test time
    (synthesized ELF), mutually exclusive with the existing `fixture` field.
  - `extra_args: Vec<String>` — owned, dynamically-computed argv pieces
    (e.g. `-o <tempdir path>`), appended after the existing `'static` `args`.
  - `expected_stderr_contains: &'static [&'static str]` — substring checks
    against stderr; `expected_stdout_contains` already exists but nothing
    today lets a case assert on stderr, which is where every error message
    in this issue is printed.
  `build_argv`'s existing field order (subcommand, then the positional
  input, then `arch`, then `window`, then `args`, then the new
  `extra_args`) already does the right thing for every case below — most
  cases need no change to that function beyond wiring in the three new
  fields.
- `tests/e2e/cases/cli_contract.rs` — new `#[test]` functions (§3, slices
  2-6) plus one private helper, `write_bare_elf`, that writes a header-only
  ELF with a chosen `e_machine`/class to a given path.
- `Justfile` — correct the `e2e` recipe's comment (lines 75-78): it currently
  says "No fixture-based cases exist yet, so this doesn't need build-tests";
  after this change that's misleading (cases do use synthesized ELF inputs)
  even though the conclusion is still correct (still no `build-tests`
  dependency, since nothing here is produced by `build_tests.sh`). Reword to
  say cases synthesize minimal ELF headers at test time rather than depending
  on `build_tests.sh`'s cross-compiled binaries.

No production code changes. No `docs/*.md` changes: this issue adds test
coverage for already-implemented, already-documented CLI behavior
(`resolve_opt_target`, `resolve_output_path`, both already have full doc
comments and unit tests) — there is no contract, flag, or behavior to
document that isn't already documented at its source.

## 3. TDD slices

Each slice is red (new test fails to compile or fails against current
harness capability) → green (harness/test code added) → refactor (none
expected; keep diffs minimal).

1. **Harness: `binary` field.**
   Add `binary: Option<PathBuf>` to `Case`. In `build_argv`, resolve the
   positional input as `fixture` XOR `binary` (panic if both are set — a
   case author error, not a runtime condition). Red: a scratch case setting
   both fields should panic with a clear message; write that as a
   `#[cfg(test)]` unit test in `harness.rs`'s existing `mod tests` block
   (alongside `reproducer_command_is_pasteable`). Green: implement the
   match arm.

2. **Harness: `extra_args` field.**
   Add `extra_args: Vec<String>` to `Case`, appended in `build_argv` after
   the existing `case.args.iter()...` line. Red/green via a unit test
   asserting `build_argv`-produced argv (through `reproducer_command`, which
   is already `pub(crate)` and tested) includes both the static `args` and
   the dynamic `extra_args` in order.

3. **Harness: `expected_stderr_contains` field.**
   Add `expected_stderr_contains: &'static [&'static str]` to `Case`
   (defaults to `&[]` via `Default`). In `run()`, after the existing
   `expected_stdout_contains` check, loop over the slice and assert
   `stderr.contains(needle)`, with the same panic-with-reproducer style as
   the existing checks. Red: add a unit test with a case whose
   `expected_stderr_contains` doesn't match, asserting the panic fires and
   names the missing needle. Green: implement the loop.

4. **Clap-level exit-code cases (need no ELF at all).**
   These fail before any file is opened, so no fixture helper is needed yet:
   - `opt_without_binary_exits_with_usage_error`: `subcommand: Some("opt")`,
     `window: Some(Window { start_addr: "0x1000", end_addr: "0x1004" })`, no
     `binary`/`fixture`, `expected_exit_code: 2`,
     `expected_stderr_contains: &["the following required arguments were not
     provided", "<BINARY>"]`.
   - `opt_without_start_addr_exits_with_usage_error`: a full `window` can't
     be used here (only one address is present), so build the partial
     argument list directly: `args: &["/nonexistent-input.elf", "--end-addr",
     "0x1004"]` (the path is never opened — clap rejects first),
     `expected_exit_code: 2`, `expected_stderr_contains: &["--start-addr"]`.
   - `opt_without_end_addr_exits_with_usage_error`: symmetric, `args:
     &["/nonexistent-input.elf", "--start-addr", "0x1000"]`,
     `expected_stderr_contains: &["--end-addr"]`.

5. **`write_bare_elf` helper + invalid address format (first real consumer).**
   Add `write_bare_elf(path: &Path, machine: u16, is_64_bit: bool)` to
   `cli_contract.rs`, mirroring `write_minimal_riscv_elf` in
   `tests/integration/opt_test.rs` (64/52-byte header, magic + class + data +
   version + `e_type=ET_EXEC` + `e_machine` + `e_ehsize`, no sections).
   Introducing it alongside its first two callers keeps the crate free of an
   unused-function warning, which `RUSTFLAGS="-D warnings"` in CI turns into
   a build failure. Every later slice reuses this same helper — no case in
   this plan needs a real compiled binary or `harness::s11_binary_path()` as
   input; the synthesized header is strictly smaller and faster, and using
   it uniformly means the "fast, deterministic, sub-millisecond ELF writes"
   property in §4 actually holds for every case.
   - `opt_rejects_invalid_start_address_format`: `binary: Some(write_bare_elf(
     &dir.join("program.elf"), elf::abi::EM_AARCH64, true))`, `window:
     Some(Window { start_addr: "zz", end_addr: "0x1004" })`,
     `expected_exit_code: 1`, `expected_stderr_contains: &["Error parsing
     start address", "Invalid hex address: zz"]`.
   - `opt_rejects_invalid_end_address_format`: same fixture, `window:
     Some(Window { start_addr: "0x1000", end_addr: "zz" })`,
     `expected_stderr_contains: &["Error parsing end address", "Invalid hex
     address: zz"]`.

6. **Arch-mismatch rejection.**
   Uses `write_bare_elf` with `elf::abi::EM_AARCH64`/`EM_X86_64`. Two cases
   (bidirectional, cheap and doubles confidence the check isn't
   accidentally one-directional):
   - `opt_rejects_declared_x86_64_against_aarch64_elf`: fixture machine
     `EM_AARCH64`, `arch: Some("x86-64")`, `window: Some(Window { start_addr:
     "0x0", end_addr: "0x4" })`, `expected_stderr_contains: &["Architecture
     mismatch: --arch x86-64 but ELF reports aarch64"]`.
   - `opt_rejects_declared_aarch64_against_x86_64_elf`: fixture machine
     `EM_X86_64`, `arch: Some("aarch64")`, same window,
     `expected_stderr_contains: &["Architecture mismatch: --arch aarch64 but
     ELF reports x86-64"]`.
   Both `expected_exit_code: 1`.

7. **RISC-V rejection — matching and mismatched.**
   Four cases exercising both RISC-V widths in both branches of
   `resolve_opt_target`'s ordering (arch-mismatch is checked before the
   RISC-V-unsupported rule, so a mismatched `--arch riscv64` against an
   AArch64 ELF reports the arch-mismatch message, not the RISC-V one — this
   was confirmed empirically and matches `OptTargetError`'s documented rule
   order):
   - `opt_rejects_riscv32_target_matching_elf_machine`: fixture machine
     `EM_RISCV`/32-bit class, `arch: Some("riscv32")`,
     `expected_stderr_contains: &["RISC-V optimization is not yet
     supported"]`.
   - `opt_rejects_riscv64_target_matching_elf_machine`: fixture machine
     `EM_RISCV`/64-bit class, `arch: Some("riscv64")`, same message.
   - `opt_rejects_riscv32_target_mismatched_with_elf_machine`: fixture
     machine `EM_AARCH64`, `arch: Some("riscv32")`, `expected_stderr_contains:
     &["Architecture mismatch: --arch riscv32 but ELF reports aarch64"]`.
   - `opt_rejects_riscv64_target_mismatched_with_elf_machine`: same with
     `riscv64`.
   All use `window: Some(Window { start_addr: "0x0", end_addr: "0x4" })` and
   `expected_exit_code: 1`.

8. **Output-policy cases (5).**
   Each case gets its own `tempfile::tempdir()` and writes a fresh
   `write_bare_elf(&dir.join("program.elf"), EM_AARCH64, true)` as input, so a
   derived-name write attempt can never collide with another test or with the
   real build output. `window: Some(Window { start_addr: "0x0", end_addr:
   "0x1" })` throughout (never parsed into real instructions; every one of
   these fails before that point). All `expected_exit_code: 1`.
   - `opt_refuses_existing_explicit_output`: pre-write `dir/out.bin` with
     sentinel bytes, `extra_args: vec!["-o".into(),
     out.to_string_lossy().into_owned()]`, `expected_stderr_contains:
     &["output path already exists", "--force"]`; assert after `run()` that
     the sentinel bytes are unchanged (the one behavioral assertion beyond
     exit code + stderr in this slice — it's what makes this a contract
     case and not just a message-string test).
   - `opt_refuses_existing_derived_output`: no `-o`; pre-write
     `dir/program_optimized.elf` with sentinel bytes; same
     `expected_stderr_contains`; same unchanged-sentinel assertion.
   - `opt_rejects_missing_output_parent`: `-o dir/missing/output.elf`,
     `expected_stderr_contains: &["output parent directory", "does not
     exist"]`; assert the path was never created.
   - `opt_rejects_trailing_separator_output`: `-o` built from
     `dir.join("result")` with a trailing `MAIN_SEPARATOR_STR` appended (same
     construction as `opt_test.rs`), `expected_stderr_contains: &["output
     path", "must name a file"]`.
   - `opt_rejects_unwritable_output_parent` (`#[cfg(unix)]`): create
     `dir/read-only`, chmod `0o555`, probe writability first and `return`
     early with an `eprintln!` skip notice if the probe unexpectedly
     succeeds (root) — same guard `opt_test.rs`'s
     `test_opt_rejects_unwritable_output_parent_before_search` already uses,
     needed for the same reason (containerized/root CI runners ignore the
     mode bit). `-o read-only/output.elf`, `expected_stderr_contains:
     &["output parent directory", "not writable"]`.

`--help` (acceptance criterion 6) is already covered by
`help_exits_zero_with_usage` from #845 — no new slice needed; noting it here
so the acceptance checklist reads as fully addressed by this PR.

## 4. Verification surface

Not applicable in the ESBMC/contracts sense the generic template describes
(this is a Rust superoptimizer, not the Vow verification pipeline) — there
is no C model, no `tests/run/` fixtures, and no ESBMC gate touched by this
change. The verification surface here is:

- `just e2e` (`cargo test --test e2e_tests -- --nocapture`) — must stay
  green and must stay fast (all new cases are sub-millisecond ELF writes plus
  one `s11 opt` subprocess each; no search algorithm ever runs because every
  case is rejected before `optimize_elf_binary` starts one).
- `cargo test --lib --bins` — untouched by this change, but part of
  `ci_check.sh`; the harness edits live in `tests/`, not `src/`, so no
  interaction expected.
- `./ci_check.sh` end to end before pushing, per this repo's CLAUDE.md.
- Confirm no case depends on `build_tests.sh`'s output: `grep -rn
  "binaries" tests/e2e/` must return nothing (the workspace's own
  `binaries/` directory, if present from an earlier manual `build_tests.sh`
  run, is gitignored scratch state, not a dependency of these tests — don't
  treat its presence as evidence `just e2e` needs it).

## 5. Risk areas

- **Message-string coupling.** Several `expected_stderr_contains` needles
  are close to full messages (e.g. the RISC-V-unsupported string). If
  `OptTargetError`'s `Display` or `resolve_output_path`'s error strings
  change wording, these cases fail loudly — intended (contract test), but
  worth flagging so a future wording tweak isn't surprised by e2e failures.
  These are plain string literals matching current wording, not imports of
  `main.rs`'s private constants (e.g. `ARCH_MISMATCH_PREFIX`) — `main.rs` is
  a binary crate, so the e2e test crate has no way to reference those
  privately-scoped items and must duplicate the literal text instead.
- **`ElfPatcher::new()`'s no-section-table behavior is load-bearing for this
  whole plan.** If a future change makes `ElfPatcher::new()` eagerly read
  section headers (e.g. to validate `e_shoff`/`e_shnum` up front), every
  synthetic-header fixture in this plan would start failing with a generic
  parse error instead of the intended contract error. That failure mode is
  self-diagnosing (the stderr needle simply won't match, and the diff
  against a passing baseline points straight at `ElfPatcher::new`), so this
  is flagged as a note for the implementer, not a blocker.
- **Root-run CI.** The one unwritable-parent case only exercises its
  intended path when the process's effective UID doesn't bypass the
  `0o555` mode. Guard with the same probe-and-skip pattern already
  established in `opt_test.rs`; don't assert the guard can never fire.
- **Test isolation.** `cargo test` runs same-binary tests concurrently by
  default. Every new case uses its own `tempfile::tempdir()`; none write
  into a shared path (in particular, none derive an output path next to
  `CARGO_BIN_EXE_s11` itself, and no case reads or copies the real `s11`
  binary as input — every fixture is a fresh, tiny synthesized ELF header).
- **Unused-helper warning.** `write_bare_elf` must land in the same slice as
  its first caller (slice 5), not earlier — `RUSTFLAGS="-D warnings"` turns
  an unused `fn` into a CI build failure, not just a lint note.
- **Harness field growth.** Adding `binary`, `extra_args`, and
  `expected_stderr_contains` to `Case` is the only harness change on the
  critical path; keep it to these three fields. Do not also generalize
  `expected_stdout_contains` to a slice or add unrelated convenience fields
  in the same PR — out of scope (see §6).

## 6. Out of scope

- Porting any existing `tests/integration/opt_test.rs` case to the e2e
  harness — the issue explicitly defers this ("port opportunistically
  later, this ticket does not do a big-bang move").
- Any behavioral/outcome fixture under `tests/e2e/fixtures/` (Phase 2/3,
  tracked separately in #834-#836); this issue's cases are all pre-search
  rejections and need none.
- Widening `Case.expected_stdout_contains` to a slice to match the new
  `expected_stderr_contains` shape, or any other harness refactor beyond the
  three additive fields in slices 1-3.
- `s11 disasm`'s own `--arch` handling (it has a separate, narrower
  RISC-V-rejection path via `SupportedArch::try_from(CliArch)` — already
  unit-tested in `main.rs`); this issue's RISC-V/arch-mismatch acceptance
  criteria map onto `s11 opt`'s `resolve_opt_target`, not `disasm`.
- Changing `build_tests.sh`, `binaries/`, or the CI workflow's existing
  `build_tests.sh` step — untouched; this plan deliberately avoids adding
  any new dependency on that toolchain.

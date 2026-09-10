# e2e fixtures

Outcome/behavioral fixtures (Phase 2/3 of the e2e harness PRD, see issues
#834, #835, #836, #837). CLI-contract cases (#833 and the initial case in
#832) need no fixture and pass `fixture: None`.

The behavioral tier (#837) natively executes both the unpatched input
fixture and the `s11 opt`-patched output and diffs exit code + stdout
(`ExecutionExpectation`/`diff_execution` in `tests/e2e/harness.rs`), for
x86-64 and x86-32 — AArch64 needs `qemu-user-static` instead of native
`Command::new` and is tracked separately (#838). See
`outcome-x86-64-dup-mov-imm` (`tests/e2e/cases/outcome_x86_64.rs`) and
`outcome-x86-32-dup-mov-collapse` (`tests/e2e/cases/outcome_x86_32.rs`).

AArch64 fixtures (#834) live under `aarch64/`, assembled unconditionally by
`build_tests.sh` from `tests/aarch64_asm/*.s` (the AArch64 cross-toolchain
is a hard build_tests.sh preflight requirement, not gracefully skipped).

`x86_32/` is populated by `build_tests.sh`'s `gcc -m32` block (issue #836)
from `tests/x86_asm/x86_32/*.s`; it's gracefully absent when the multilib
toolchain isn't installed, and consumed via `fixture_exists` preflight
checks so cases skip rather than fail.

`x86_64/` (issue #835) is populated by `build_tests.sh`'s host-gcc block,
which copies the assembled binaries from `tests/x86_asm/*.s` (see that
directory's README).

Every fixture directory here is gitignored (build artifact) apart from
this README. Run `./build_tests.sh` before `just e2e` / `cargo test --test
e2e_tests` if a directory is empty or missing an expected fixture.

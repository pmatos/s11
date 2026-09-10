# e2e fixtures

Outcome/behavioral fixtures (Phase 2/3 of the e2e harness PRD, see issues
#834, #835, #836). CLI-contract cases (#833 and the initial case in #832)
need no fixture and pass `fixture: None`.

AArch64 fixtures (#834) live under `aarch64/`, assembled by
`build_tests.sh` from `tests/aarch64_asm/*.s`; the directory is gitignored
(built, not tracked) apart from this README. x86-64/x86-32 fixtures are
pending in #835/#836.

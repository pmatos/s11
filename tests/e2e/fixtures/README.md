# e2e fixtures

Reserved for outcome/behavioral fixtures (Phase 2/3 of the e2e harness PRD,
see issues #834, #835, #836). CLI-contract cases (#833 and the initial case in
#832) need no fixture and pass `fixture: None`.

`x86_32/` is populated by `build_tests.sh`'s `gcc -m32` block (issue #836)
from `tests/x86_asm/x86_32/*.s`; it's gitignored (build artifact), gracefully
absent when the multilib toolchain isn't installed, and consumed via
`fixture_exists` preflight checks so cases skip rather than fail.

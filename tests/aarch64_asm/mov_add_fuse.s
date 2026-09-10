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

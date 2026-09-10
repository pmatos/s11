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

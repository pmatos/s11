// Known one-instruction shortening fixture for the AArch64 opt path
// (issue #834's baseline "redundant mov elimination" class).
//
// Two identical `mov x0, #5` instructions are semantically equivalent to a
// single `mov x0, #5` (only X0 is live-out; MOVZ does not touch NZCV), so
// the enumerative search deterministically rewrites the 2-instruction window
// to 1 instruction. Mirrors tests/x86_asm/dup_mov_imm.s for the x86-64 opt
// path.
.text
.global _start
_start:
    mov x0, #5
    mov x0, #5
    mov x8, #93
    svc #0

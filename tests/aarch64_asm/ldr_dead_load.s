// Known one-instruction shortening fixture (issue #834's "ldr positive
// offset window" class — the RefOffset/Uscaled encoding pinned by
// test_opt_accepts_ldr_positive_offset_window in opt_test.rs). `ldr x0,
// [x6, #16]` loads into X0, which is then unconditionally overwritten by
// `mov x0, #5` before any read — the load is dead, so `mov x0, #5` alone
// is equivalent. Unlike an address-fold identity (where the witness
// candidate is itself a memory op, deep in the enumerative pool), the
// witness here is a plain MOV, so this converges as fast as
// dup_mov_imm.
.text
.global _start
_start:
    mov x6, sp
    ldr x0, [x6, #16]
    mov x0, #5
    mov x8, #93
    svc #0

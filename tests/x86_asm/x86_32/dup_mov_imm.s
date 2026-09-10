// Known one-instruction shortening fixture for the x86-32 opt path.
//
// Two identical `mov eax, 5` instructions are semantically equivalent to a
// single `mov eax, 5` (only EAX is live-out, neither MOV touches EFLAGS), so
// the enumerative search deterministically rewrites the 2-instruction window
// to 1 instruction — the x86-32 mirror of `tests/x86_asm/dup_mov_imm.s`.
// Unlike that fixture, this one ends with an explicit x86-32 Linux exit
// syscall (`mov ebx, eax; mov eax, 1; int 0x80`) so a future execution-tier
// e2e case can run it directly; the exit code is 5, a checksum of the
// live-out EAX value. Register/immediate only — the x86 IR models no memory
// operands.
.intel_syntax noprefix
.text
.globl _start
_start:
    mov eax, 5
    mov eax, 5
    mov ebx, eax
    mov eax, 1
    int 0x80

// Known one-instruction shortening fixture for the x86-64 opt path.
//
// Two identical `mov rax, 5` instructions are semantically equivalent to a
// single `mov rax, 5` (only RAX is live-out; neither MOV touches EFLAGS), so
// the enumerative search deterministically rewrites the 2-instruction window
// to 1 instruction. Register/immediate only — the x86 IR models no memory
// operands. The tail is an explicit exit(RAX) syscall rather than padding
// NOPs, so this fixture can actually be executed (behavioral e2e tier) and
// not just disassembled: it exits with RAX's value (5), a compile-time
// constant used as a trivial checksum of live-out state.
.intel_syntax noprefix
.text
.globl _start
_start:
    mov rax, 5
    mov rax, 5
    mov rdi, rax
    mov rax, 60
    syscall

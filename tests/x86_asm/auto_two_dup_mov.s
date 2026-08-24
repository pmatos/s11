// Whole-binary --auto fixture with two independent optimizable windows.
//
// `push rbx` is deliberately outside s11's x86 IR subset, so candidate
// discovery splits the two duplicate-MOV pairs into distinct windows without
// introducing indirect control flow (which auto mode conservatively gates
// until issue #619 lands).
.intel_syntax noprefix
.text
.globl _start
_start:
    mov rax, 5
    mov rax, 5
    push rbx
    mov rcx, 7
    mov rcx, 7

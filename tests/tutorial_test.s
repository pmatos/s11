.global _start

_start:
    // Pattern 1: MOV X0, X1; ADD X0, X0, #1 -> ADD X0, X1, #1
    mov x0, x1
    add x0, x0, #1

    // Pattern 2: MOV X2, #0 equivalent to EOR X2, X2, X2
    mov x2, #0

    // Pattern 3: Redundant addition
    add x3, x3, #0

    // Pattern 4: Shift operations
    lsl x4, x5, #2

    // Pattern 5: Bitwise operations
    and x6, x7, x8
    orr x9, x10, x11
    eor x12, x13, x14

    // Exit
    mov x0, #0
    mov x8, #93        // exit syscall number
    svc #0

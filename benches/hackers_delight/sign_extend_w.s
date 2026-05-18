// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-6 (sign-extend low 32 bits)
// Pattern: shift left then arithmetic right by 32 to sign-extend.
// Single-instruction equivalents exist (sxtw / sbfx).
lsl x0, x0, #32
asr x0, x0, #32

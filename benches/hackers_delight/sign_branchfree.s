// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-7 (sign function via arithmetic shift)
// Pattern: arithmetic shift right by 63 yields -1 / 0 sign mask; OR
// with (-x >> 63) — but s11 has no NEG, so this slightly longer form
// uses (0 - x).
asr x1, x0, #63
mov x2, #0
sub x2, x2, x0
lsr x2, x2, #63
orr x0, x1, x2

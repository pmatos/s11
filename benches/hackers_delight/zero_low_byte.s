// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-1 (clear low 8 bits)
// Pattern: shift right by 8 then left by 8 to zero the low byte.
// A single AND with the right mask is the canonical short form.
lsr x0, x0, #8
lsl x0, x0, #8

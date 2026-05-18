// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-1 (mask the low 16 bits)
// Pattern: shift left then right to mask; canonical form is an AND with
// 0xFFFF (logical immediate) or a UBFX/UBFIZ.
lsl x0, x0, #48
lsr x0, x0, #48

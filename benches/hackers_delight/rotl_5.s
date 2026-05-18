// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-15 (rotate left by 5)
// Pattern: shift two halves and combine; the canonical short form is a
// single ROR/EXTR — neither is in s11's instruction pool yet, so the
// optimizer should at best preserve the 3-instruction form.
lsl x1, x0, #5
lsr x0, x0, #59
orr x0, x0, x1

// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-4 (absolute value)
// Pattern: arithmetic shift sign-extends x0; xor + sub turns it into |x0|.
asr x1, x0, #63
eor x0, x0, x1
sub x0, x0, x1

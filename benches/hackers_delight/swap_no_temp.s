// Live-in: x0, x1
// Live-out: x0, x1
// Reference: Hacker's Delight §2-19 (in-place swap via XOR)
eor x0, x0, x1
eor x1, x0, x1
eor x0, x0, x1

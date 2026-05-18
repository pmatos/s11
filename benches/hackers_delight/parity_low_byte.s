// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §5-2 (parity of low byte via shift-XOR fold)
// Each step folds high half onto low half; final result in bit 0.
eor x1, x0, x0, lsr #4
eor x1, x1, x1, lsr #2
eor x0, x1, x1, lsr #1
and x0, x0, #1

// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-15 (rotate right by 5)
lsr x1, x0, #5
lsl x0, x0, #59
orr x0, x0, x1

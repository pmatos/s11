// Live-in: x0, x1
// Live-out: x0
// Reference: Hacker's Delight §4 (max via conditional select)
cmp x0, x1
csel x0, x0, x1, gt

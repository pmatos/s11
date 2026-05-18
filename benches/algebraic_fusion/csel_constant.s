// Live-in: x1, x2
// Live-out: x0
// Identity: CSEL between equal sources is always the source.
cmp x1, x2
csel x0, x1, x1, eq

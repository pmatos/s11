// Live-in: x1
// Live-out: x0
// Identity: CSINC of (x, x, cond) equals x+1 when cond is false; the
// optimizer can rediscover the single-instruction CSINC form from
// CMP+ADD+CSEL patterns.
cmp x1, #0
add x2, x1, #1
csel x0, x1, x2, eq

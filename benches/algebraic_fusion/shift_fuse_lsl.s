// Live-in: x1, x2
// Live-out: x0
// Identity: LSL + ADD can fuse into ADD with a shifted-register
// operand (e.g. `add x0, x1, x2, lsl #2`).
lsl x3, x2, #2
add x0, x1, x3

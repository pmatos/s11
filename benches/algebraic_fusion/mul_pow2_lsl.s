// Live-in: x1
// Live-out: x0
// Identity: x * 8 ≡ x << 3 — strength reduction.
mov x0, #8
mul x0, x1, x0

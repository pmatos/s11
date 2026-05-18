// Live-in: x1
// Live-out: x0
// Identity: signed x / 4 ≡ x >> 2 for non-negative x (caveat: rounding
// differs for negatives — bench measures whether the optimizer notices
// the signed-division input contract via SMT).
mov x0, #4
sdiv x0, x1, x0

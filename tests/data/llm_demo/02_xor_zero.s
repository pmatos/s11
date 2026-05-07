// Live-in: (none)
// Live-out: x0
// Expected reduction: eor x0, x0, x0 (1) — already minimal; mov x0, #0 (1) is alt
mov x0, #0
mov x0, x0

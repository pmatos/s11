// Live-in: (none)
// Live-out: x0
// Expected reduction: 2 -> 1 (drop the redundant `mov x0, x0`).
//   `eor x0, x0, x0` and `mov x0, #0` are also valid 1-instruction equivalents.
mov x0, #0
mov x0, x0

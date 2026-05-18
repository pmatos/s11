// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §2-7 (extract sign bit to bit 0: x >> 63)
// One-instruction optimum (LSR by 63); a 2-instruction form via SBFX
// is an alternative target the optimizer can also choose.
lsr x0, x0, #63

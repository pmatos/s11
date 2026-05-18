// Live-in: x0
// Live-out: x0
// Reference: Hacker's Delight §10 (constant multiply by 16)
// Search should rediscover the single-shift form.
mov x1, #16
mul x0, x0, x1

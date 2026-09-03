# Architecture Decision Records

## Legacy numbering (0001-0011)

`0001-*.md` through `0011-*.md` use sequential numbers assigned by hand.
Two concurrent PRs once picked the same number for different decisions
(`0011-neon-register-state.md` and `0011-zero-solver-timeout-disables-smt.md`),
which is why the scheme changed. These files are frozen: don't renumber
or reuse a number from this range — they're referenced by number (e.g.
`ADR-0007`, `ADR-0004 decision 5`) throughout source comments, `CONTEXT.md`,
and `docs/capability.md`.

## Current naming

New ADRs use `docs/adr/YYYY-MM-DD-slug.md`, dated the day the ADR is
authored. Reference one in prose or comments as `ADR-YYYY-MM-DD` (add the
slug too if more than one ADR shares a date). Two authors can't
independently pick the same real-world date-and-slug pair the way they
could pick the same next integer, so there's no more numbering-collision
class to check for in CI.

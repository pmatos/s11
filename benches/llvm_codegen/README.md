# Phase 2 — LLVM AArch64 codegen fixtures

This directory hosts AArch64 basic blocks harvested from
`llvm-project/llvm/test/CodeGen/AArch64/`. The fixtures themselves are
not committed yet — run the harvester to populate:

```bash
scripts/harvest_llvm_codegen.sh [SEED] [SAMPLE_SIZE]
```

The script shallow-clones llvm-project, samples `.ll` files
deterministically, runs `llc -mtriple=aarch64-linux-gnu -O2`, filters
output to s11-supported mnemonics (see `CLAUDE.md:11`), and writes
each surviving block as `<basename>.s` with `// Source:` and inferred
`// Live-out:` headers.

Live-out inference is operand-based: destination registers from the
straight-line block are de-duplicated, sorted, and normalized to
parser-accepted names (`w9` becomes `x9`, `fp` becomes `x29`, and `sp`
stays `sp`). Compare/test-only instructions such as `cmp` and `tst`
do not contribute their first operand, and blocks with no destination
registers are skipped rather than defaulting to `x0`.

Review with `git status -- benches/llvm_codegen` and commit the
generated `.s` files. The Phase 2 criterion bench
(`benches/llvm_codegen.rs`) gracefully skips when this directory is
empty, so CI / `just bench` still passes on a fresh checkout.

## Refreshing the corpus

Re-run the harvester with the same seed to deterministically refresh,
or pick a new seed to draw a different sample. Diff the result, drop
fixtures that look uninteresting, verify the inferred live-out headers
against the block intent, and commit.

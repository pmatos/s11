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
each surviving block as `<sha>_<offset>.s` with `// Source:` and
`// Live-out:` headers.

Review with `git status -- benches/llvm_codegen` and commit the
generated `.s` files. The Phase 2 criterion bench
(`benches/llvm_codegen.rs`) gracefully skips when this directory is
empty, so CI / `just bench` still passes on a fresh checkout.

## Refreshing the corpus

Re-run the harvester with the same seed to deterministically refresh,
or pick a new seed to draw a different sample. Diff the result, drop
fixtures that look uninteresting, and commit.

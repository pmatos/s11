# s11 benchmark suite

Criterion-driven benchmark suite for issue #70. Three phases, one
shared JSON-Lines report.

## Running

```
just bench           # all three phases
just bench-phase1    # Hacker's Delight only
cargo bench --bench hackers_delight -- max --quick   # one fixture, fast smoke run
cargo bench --bench smt_clz -- --quick   # direct CLZ/CLS SMT formula timing
```

Output:

- `benches/results/results.jsonl` — exactly one record per fixture
  per `cargo bench` invocation, appended across all runs. Schema below.
- `target/criterion/<group>/<fixture>/report/index.html` — criterion's
  per-fixture HTML report.

The harness is **not wired into CI**. Full sweeps are tens of minutes,
which would burn through GitHub Actions budget.

`smt_clz` is a narrow direct-SMT benchmark for comparing CLZ/CLS formula
encodings. It calls the equivalence checker on equivalent CLZ/CLS-heavy
sequences and consumes the SMT metrics, but it is intentionally separate
from the phase 1/2/3 fixture harness and does not append JSON Lines.

## Layout

```
benches/
├── hackers_delight.rs     # Phase 1 driver
├── hackers_delight/*.s    # Phase 1 fixtures (~20, register-only HD idioms)
├── llvm_codegen.rs        # Phase 2 driver
├── llvm_codegen/          # Phase 2 fixtures — populated by the harvester
├── algebraic_fusion.rs    # Phase 3 driver
├── algebraic_fusion/*.s   # Phase 3 fixtures (~15, textbook identities)
├── smt_clz.rs             # Direct CLZ/CLS SMT formula timing
├── results/results.jsonl  # JSONL accumulator (gitignored)
└── README.md              # you are here
```

The shared harness (`load_sequence`, `run_bench`, `append_json`,
`discover_specs_in`, `run_provenance`, `BenchSpec`, `BenchRecord`)
lives in `src/bench_support.rs` because criterion's `harness = false`
mode prevents `#[test]` blocks under `benches/` from running — putting
the helpers in the library gives them a normal unit-test path.

## Adding a fixture

1. Drop a `.s` file under the phase directory of your choice.
2. Give it the required header:

   ```
   // Live-in: x0, x1
   // Live-out: x0
   // Reference / Identity: free-form note
   <body — straight-line AArch64 assembly>
   ```

   Header syntax matches `validation::live_out::parse_live_out_contract`
   (so `// Live-out: x0,x1;nzcv` declares X0, X1, and NZCV as observable).
3. Constrain the body to instructions s11 supports — see `CLAUDE.md`.
4. Re-run the bench; the discovery loop picks up new fixtures
   automatically.

A missing `// Live-out:` header panics with a pointer to this file.

## JSON record schema

One record per fixture per `cargo bench` run. Bench drivers emit the
JSON before driving criterion's `iter_custom`, so warm-up iterations
never appear in the file. Criterion's HTML report under
`target/criterion/<group>/<fixture>/` owns the per-sample variance; the
JSON record below is the canonical snapshot downstream tooling diffs
across commits.

```json
{
  "benchmark_id": "mov_add_fuse",
  "phase": 3,
  "algorithm": "enumerative",
  "seed": 42,
  "cost_metric": "instructioncount",
  "original_length": 2,
  "found_length": 1,
  "original_cost": 2,
  "best_cost": 1,
  "search_elapsed_ms": 22,
  "smt_elapsed_ms": 0,
  "smt_queries": 73000,
  "smt_equivalent": 1,
  "candidates_evaluated": 85000,
  "improved": true,
  "timeout": false,
  "git_sha": "9576937",
  "timestamp_utc": "1779000000s"
}
```

| Field | Meaning |
| --- | --- |
| `benchmark_id` | Fixture file stem (`abs`, `mov_add_fuse`, …). |
| `phase` | 1 = Hacker's Delight, 2 = LLVM CodeGen, 3 = algebraic identities. |
| `algorithm` | Search algorithm (currently always `enumerative`). |
| `seed` | RNG seed (passed verbatim from `spec.seed`; stochastic search uses it directly, deterministic algorithms ignore it). |
| `cost_metric` | Cost function: `instructioncount` / `latency` / `codesize`. |
| `original_length` / `found_length` | Target length and optimized length (or `null` if no optimization). |
| `original_cost` / `best_cost` | Cost under the chosen metric. |
| `search_elapsed_ms` | Wall time of the search itself, truncated to milliseconds for legibility. Sub-millisecond runs serialise as `0`; the bench driver uses the precise `Duration` internally so criterion's timing analysis sees real values. |
| `smt_elapsed_ms` | Cumulative Z3 `solver.check()` time. Often zero — the pre-SMT guard rejects most flag-divergent candidates before reaching the solver. |
| `smt_queries` / `smt_equivalent` | SMT call count (net of fast-path rollbacks) and how many proved equivalence. |
| `candidates_evaluated` | Total candidates considered. |
| `improved` / `timeout` | `improved`: whether the search returned a strictly cheaper sequence than the target — **not** "search completed without error" (a clean timeout that finds nothing also reports `improved: false`). Combine with `timeout` to distinguish "explored fully, no win" from "ran out of time." |
| `git_sha` / `timestamp_utc` | Run provenance, stamped once per `cargo bench` invocation. |

## Phase 2 refresh procedure

```
scripts/harvest_llvm_codegen.sh [SEED] [SAMPLE_SIZE]
```

The script shallow-clones `llvm-project`, samples `.ll` files
deterministically, drives them through `llc -mtriple=aarch64-linux-gnu
-O2`, filters output blocks to s11-supported mnemonics, and writes
each survivor as `benches/llvm_codegen/<basename>.s` with `// Source:`
provenance.

Maintainer-run only. Review `git status -- benches/llvm_codegen` and
commit fixtures you want to keep. Re-run with the same `SEED` for a
deterministic refresh.

## Caveats

- **Bench wall time is noisy** — Z3 is OS-scheduler-dependent, and
  rayon-parallel enumerative search uses every core. Pin `seed` for
  diffable runs across commits.
- **`smt_elapsed_ms = 0` is normal**. For most Phase 1 targets the
  pre-SMT guard catches flag-divergence early and the solver never
  fires. Use `smt_queries` to see how many candidates reached the
  solver (net of fast-path rollbacks).
- **Phase 2 emptiness is normal**. The harvester is opt-in; the bench
  driver skips the group when the fixture directory is empty.

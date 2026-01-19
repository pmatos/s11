# Phase 3: Parallelism Implementation Plan

## Overview

Phase 3 adds multi-threaded search execution to s11, enabling hybrid search where multiple stochastic workers run in parallel, optionally coordinated with a symbolic worker.

## Goals

1. **Multi-threaded execution** - Run search algorithms across multiple CPU cores
2. **Hybrid search mode** - Coordinate symbolic + stochastic search
3. **Solution sharing** - Workers share best solutions found
4. **CLI integration** - Add `-j/--cores` option

## Architecture

### Current State (Single-threaded)
```
User → CLI → Single Search Algorithm → Result
```

### Target State (Multi-threaded)
```
User → CLI → Coordinator
                ├── Worker 0: Symbolic (optional)
                ├── Worker 1: Stochastic (seed=S+1)
                ├── Worker 2: Stochastic (seed=S+2)
                └── Worker N: Stochastic (seed=S+N)
                        ↓
              Solution Aggregator → Best Result
```

## Implementation Tasks

### Task 1: Add rayon dependency and parallel infrastructure
**File**: `Cargo.toml`, `src/search/parallel/mod.rs`

- Add `rayon = "1.10"` dependency
- Create `src/search/parallel/` module
- Define `ParallelConfig` struct:
  ```rust
  pub struct ParallelConfig {
      pub num_workers: usize,
      pub include_symbolic: bool,
      pub solution_sharing: bool,
  }
  ```

### Task 2: Implement shared solution channel
**File**: `src/search/parallel/channel.rs`

- Use `crossbeam-channel` for lock-free communication
- Define `SolutionMessage`:
  ```rust
  pub enum SolutionMessage {
      Improvement { sequence: Vec<Instruction>, cost: u64, worker_id: usize },
      Finished { worker_id: usize },
  }
  ```
- Workers send improvements to coordinator
- Coordinator broadcasts best solution to all workers

### Task 3: Create parallel search coordinator
**File**: `src/search/parallel/coordinator.rs`

- Spawn worker threads using rayon's thread pool
- Each stochastic worker gets unique seed: `base_seed + worker_id`
- Collect results from all workers
- Return best solution found across all workers
- Implement timeout handling (stop all workers when timeout reached)

### Task 4: Implement hybrid search mode
**File**: `src/search/parallel/hybrid.rs`

- When `--algorithm hybrid`:
  - Worker 0: Run symbolic search (if enabled)
  - Workers 1..N: Run stochastic search with different seeds
- Symbolic worker provides initial solution for stochastic workers
- Stochastic workers can improve on symbolic solution

### Task 5: Add CLI options
**File**: `src/main.rs`

- Add `--cores` / `-j` option (default: number of CPUs)
- Add `--algorithm hybrid` variant
- Add `--no-symbolic` to disable symbolic worker in hybrid mode
- Wire up parallel coordinator when cores > 1

### Task 6: Add progress reporting
**File**: `src/search/parallel/progress.rs`

- Report improvements as they're found
- Show which worker found each improvement
- Display elapsed time and throughput

## File Structure

```
src/search/
├── mod.rs                    # Add parallel module
├── parallel/
│   ├── mod.rs               # Module exports
│   ├── config.rs            # ParallelConfig
│   ├── channel.rs           # Solution sharing channel
│   ├── coordinator.rs       # Worker coordination
│   ├── hybrid.rs            # Hybrid search implementation
│   └── progress.rs          # Progress reporting
├── stochastic/              # (existing)
└── symbolic/                # (existing)
```

## CLI Changes

```
s11 opt [OPTIONS] --start-addr <ADDR> --end-addr <ADDR> <BINARY>

Options:
    --algorithm <ALG>    enumerative|stochastic|symbolic|hybrid [default: enumerative]
    -j, --cores <N>      Number of worker threads [default: num_cpus]
    --no-symbolic        In hybrid mode, skip symbolic worker
    --timeout <SECS>     Overall search timeout
    ...
```

## Testing Strategy

1. **Unit tests**: Test channel, coordinator logic independently
2. **Integration tests**:
   - Verify parallel search finds same/better solutions than sequential
   - Test with 1, 2, 4 workers
   - Test hybrid mode
3. **Determinism**: With fixed seeds, parallel search should be reproducible

## Dependencies to Add

```toml
rayon = "1.10"
crossbeam-channel = "0.5"
num_cpus = "1.16"
```

## Success Criteria

1. `--cores 4` runs 4 stochastic workers in parallel
2. `--algorithm hybrid` runs symbolic + stochastic concurrently
3. Solutions found by any worker are reported
4. Search completes faster on multi-core machines
5. All existing tests still pass
6. CI checks pass

## Estimated Scope

- ~600-800 lines of new Rust code
- 6 new files in `src/search/parallel/`
- Updates to `main.rs` for CLI
- ~10 new unit tests

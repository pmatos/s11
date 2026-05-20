//! Parallel search coordinator that manages worker threads.

#![allow(dead_code)]

use crate::ir::Instruction;
use crate::search::SearchAlgorithm;
use crate::search::config::{Algorithm, SearchConfig};
use crate::search::parallel::channel::{
    CoordinatorChannels, CoordinatorMessage, WorkerChannels, WorkerMessage, create_channels,
};
use crate::search::parallel::config::ParallelConfig;
use crate::search::result::{SearchResult, SearchStatistics};
use crate::search::stochastic::StochasticSearch;
use crate::search::symbolic::SymbolicSearch;
use crate::semantics::live_out::LiveOut;
use crossbeam_channel::RecvTimeoutError;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Result from parallel search execution.
///
/// `best_result.statistics` is the *winning worker's* `SearchStatistics`
/// when an optimization was found, and the cross-worker aggregate when
/// none was. `total_statistics` is always the cross-worker aggregate:
/// `algorithm` is `Algorithm::Hybrid`, `elapsed_time` is the coordinator
/// wall-clock from start to teardown, counter fields are sums,
/// `original_cost` is the maximum across workers (workers see the same
/// target, so the max is robust to a worker that exited before recording
/// it), and `best_cost_found` is the minimum nonzero across workers
/// (falling back to `original_cost` when no worker recorded one).
/// `worker_statistics` carries the per-worker, per-algorithm breakdown
/// in arrival order. Each entry's `elapsed_time` is the coordinator
/// wall-clock at message arrival (`start_time.elapsed()`), not the
/// worker's own driver-reported duration; this gives every entry a
/// common time origin.
#[derive(Debug)]
pub struct ParallelResult {
    /// The best result found across all workers.
    pub best_result: SearchResult,
    /// Statistics aggregated from all workers.
    pub total_statistics: SearchStatistics,
    /// Per-worker statistics in arrival order. Each entry's
    /// `elapsed_time` is the coordinator wall-clock at message arrival
    /// (`start_time.elapsed()`), not the worker's own driver-reported
    /// duration — see the struct-level doc for the full aggregation
    /// contract.
    pub worker_statistics: Vec<(usize, Algorithm, SearchStatistics)>,
}

/// Run parallel search with the given configuration.
pub fn run_parallel_search(
    target: &[Instruction],
    live_out: &LiveOut,
    search_config: &SearchConfig,
    parallel_config: &ParallelConfig,
) -> ParallelResult {
    let start_time = Instant::now();
    let num_workers = parallel_config.num_workers;

    // Create communication channels
    let (coordinator_channels, worker_channels) = create_channels(num_workers);

    // Clone data for workers
    let target = Arc::new(target.to_vec());
    let live_out = Arc::new(live_out.clone());
    let search_config = Arc::new(search_config.clone());
    let parallel_config = Arc::new(parallel_config.clone());

    // Spawn workers using rayon's thread pool
    let worker_handles: Vec<_> = worker_channels
        .into_iter()
        .enumerate()
        .map(|(worker_id, channels)| {
            let target = Arc::clone(&target);
            let live_out = Arc::clone(&live_out);
            let search_config = Arc::clone(&search_config);
            let parallel_config = Arc::clone(&parallel_config);

            std::thread::spawn(move || {
                run_worker(
                    worker_id,
                    &target,
                    &live_out,
                    &search_config,
                    &parallel_config,
                    channels,
                )
            })
        })
        .collect();

    // Run coordinator loop
    let result = run_coordinator(
        &target,
        live_out.as_ref(),
        coordinator_channels,
        parallel_config.as_ref(),
        start_time,
    );

    // Wait for all workers to finish
    for handle in worker_handles {
        let _ = handle.join();
    }

    result
}

/// Coordinator loop that receives messages from workers and aggregates results.
fn run_coordinator(
    target: &[Instruction],
    _live_out: &LiveOut,
    channels: CoordinatorChannels,
    config: &ParallelConfig,
    start_time: Instant,
) -> ParallelResult {
    let mut best_result: Option<SearchResult> = None;
    let mut worker_stats: Vec<(usize, Algorithm, SearchStatistics)> = Vec::new();
    let mut finished_count = 0;
    let mut winning_worker_id: Option<usize> = None;
    let total_workers = config.num_workers;

    // Calculate timeout
    let deadline = config.timeout.map(|t| start_time + t);

    loop {
        // Check if we've exceeded timeout
        if deadline.is_some_and(|d| Instant::now() >= d) {
            channels.shared.signal_stop();
            // Broadcast stop to all workers
            for tx in &channels.to_workers {
                let _ = tx.send(CoordinatorMessage::Stop);
            }
        }

        // Receive with timeout to allow periodic checks
        let recv_timeout = Duration::from_millis(100);
        match channels.from_workers.recv_timeout(recv_timeout) {
            Ok(msg) => match msg {
                WorkerMessage::Improvement {
                    worker_id,
                    sequence,
                    cost,
                    algorithm,
                } => {
                    // Check if this is actually better than current best
                    if channels.shared.try_update(cost) {
                        if config.solution_sharing {
                            // Broadcast to other workers
                            for (i, tx) in channels.to_workers.iter().enumerate() {
                                if i != worker_id {
                                    let _ = tx.send(CoordinatorMessage::BetterSolution {
                                        sequence: sequence.clone(),
                                        cost,
                                    });
                                }
                            }
                        }

                        // Update best result. statistics is a placeholder
                        // here; it is finalised after every worker has
                        // reported, see post-loop block below.
                        // winning_worker_id is overwritten on each
                        // accepted Improvement: `try_update` only succeeds
                        // when `cost` is strictly less than the prior
                        // best, so the last accepted improvement is the
                        // overall winner.
                        let result = SearchResult {
                            found_optimization: true,
                            original_sequence: target.to_vec(),
                            optimized_sequence: Some(sequence),
                            statistics: SearchStatistics::new(algorithm),
                        };
                        best_result = Some(result);
                        winning_worker_id = Some(worker_id);
                    }
                }
                WorkerMessage::Finished {
                    worker_id,
                    statistics,
                } => {
                    finished_count += 1;
                    let mut stats = statistics;
                    // Use coordinator wall-clock for per-worker elapsed_time
                    // so all entries share a common time origin (start_time).
                    // statistics.algorithm is the single source of truth for
                    // which algorithm the worker ran (set by run_symbolic_worker
                    // / run_stochastic_worker, which themselves are routed by
                    // worker_algorithm() below) — read the label from there.
                    stats.elapsed_time = start_time.elapsed();
                    worker_stats.push((worker_id, stats.algorithm, stats));

                    if finished_count >= total_workers {
                        break;
                    }
                }
                WorkerMessage::Error { worker_id, message } => {
                    eprintln!("Worker {} error: {}", worker_id, message);
                    finished_count += 1;
                    if finished_count >= total_workers {
                        break;
                    }
                }
            },
            Err(RecvTimeoutError::Timeout) => {
                // Check if all workers finished or we should stop
                if channels.shared.should_stop() && finished_count >= total_workers {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                // All senders dropped, we're done
                break;
            }
        }
    }

    // Build cross-worker aggregate. Counters sum; original_cost takes the
    // max across workers (defensive against a worker that exited before
    // recording it); best_cost_found takes the min nonzero, falling back
    // to original_cost so the CLI never prints 0 when workers verified a
    // candidate.
    let elapsed = start_time.elapsed();
    let mut total_stats = SearchStatistics::new(Algorithm::Hybrid);
    total_stats.elapsed_time = elapsed;
    for (_, _, s) in &worker_stats {
        total_stats.candidates_evaluated += s.candidates_evaluated;
        total_stats.candidates_passed_fast += s.candidates_passed_fast;
        total_stats.smt_queries += s.smt_queries;
        total_stats.smt_elapsed += s.smt_elapsed;
        total_stats.smt_equivalent += s.smt_equivalent;
        total_stats.iterations += s.iterations;
        total_stats.accepted_proposals += s.accepted_proposals;
        total_stats.improvements_found += s.improvements_found;
    }
    total_stats.original_cost = worker_stats
        .iter()
        .map(|(_, _, s)| s.original_cost)
        .max()
        .unwrap_or(0);
    total_stats.best_cost_found = worker_stats
        .iter()
        .map(|(_, _, s)| s.best_cost_found)
        .filter(|&c| c > 0)
        .min()
        .unwrap_or(total_stats.original_cost);

    // Finalise best_result.statistics with the winning worker's own
    // statistics so the CLI surfaces real SMT/improvement numbers rather
    // than a fresh-zero placeholder.
    if let Some(ref mut br) = best_result {
        if let Some(winner) = winning_worker_id
            && let Some((_, _, winner_stats)) = worker_stats.iter().find(|(id, _, _)| *id == winner)
        {
            br.statistics = winner_stats.clone();
        } else {
            // A winner was recorded but its Finished message hadn't
            // arrived yet — reachable when the coordinator's outer
            // timeout fires and breaks the loop before every worker
            // drains. Fall back to the cross-worker aggregate so the
            // CLI surfaces the counters drained so far rather than a
            // fresh-zero placeholder.
            br.statistics = total_stats.clone();
        }
    }

    let final_result = best_result.unwrap_or_else(|| SearchResult {
        found_optimization: false,
        original_sequence: target.to_vec(),
        optimized_sequence: None,
        statistics: total_stats.clone(),
    });

    ParallelResult {
        best_result: final_result,
        total_statistics: total_stats,
        worker_statistics: worker_stats,
    }
}

/// Single source of truth for which algorithm a worker runs.
///
/// Mirrors the contract encoded by [`ParallelConfig::num_stochastic_workers`]:
/// a worker is symbolic only when `include_symbolic` is set, more than one
/// worker is configured, and this is worker 0. With a single worker the lone
/// worker is stochastic regardless of `include_symbolic`, so CLI knobs like
/// `--beta`, `--iterations`, and `--seed` are not silently ignored.
fn worker_algorithm(worker_id: usize, parallel_config: &ParallelConfig) -> Algorithm {
    if parallel_config.include_symbolic && parallel_config.num_workers > 1 && worker_id == 0 {
        Algorithm::Symbolic
    } else {
        Algorithm::Stochastic
    }
}

/// Worker function that runs a search algorithm.
fn run_worker(
    worker_id: usize,
    target: &[Instruction],
    live_out: &LiveOut,
    search_config: &SearchConfig,
    parallel_config: &ParallelConfig,
    channels: WorkerChannels,
) {
    let is_symbolic_worker = matches!(
        worker_algorithm(worker_id, parallel_config),
        Algorithm::Symbolic
    );

    // Build worker-specific config
    let mut config = search_config.clone();

    if is_symbolic_worker {
        // Run symbolic search
        run_symbolic_worker(worker_id, target, live_out, &config, channels);
    } else {
        // Run stochastic search with unique seed
        let seed = parallel_config
            .base_seed
            .map(|s| s.wrapping_add(worker_id as u64));

        if let Some(seed) = seed {
            let mut stochastic_config = config.stochastic.clone();
            stochastic_config.seed = Some(seed);
            config = config.with_stochastic(stochastic_config);
        }

        run_stochastic_worker(worker_id, target, live_out, &config, channels);
    }
}

/// Run a symbolic search worker.
fn run_symbolic_worker(
    worker_id: usize,
    target: &[Instruction],
    live_out: &LiveOut,
    config: &SearchConfig,
    channels: WorkerChannels,
) {
    let mut search: SymbolicSearch<crate::isa::AArch64> = SymbolicSearch::new();

    // Run search in chunks, checking for stop signal periodically.
    // The generic search returns `SearchResultFor<AArch64>`; convert to
    // the AArch64-typed `SearchResult` the coordinator consumes.
    let result: crate::search::result::SearchResult =
        search.search(target, live_out, config).into();

    if result.found_optimization
        && let Some(ref optimized) = result.optimized_sequence
    {
        let cost = crate::semantics::cost::sequence_cost(optimized, &config.cost_metric);
        let _ = channels.to_coordinator.send(WorkerMessage::Improvement {
            worker_id,
            sequence: optimized.clone(),
            cost,
            algorithm: Algorithm::Symbolic,
        });
    }

    let _ = channels.to_coordinator.send(WorkerMessage::Finished {
        worker_id,
        statistics: result.statistics,
    });
}

/// Run a stochastic search worker with periodic checks for better solutions.
fn run_stochastic_worker(
    worker_id: usize,
    target: &[Instruction],
    live_out: &LiveOut,
    config: &SearchConfig,
    channels: WorkerChannels,
) {
    let mut search: StochasticSearch<crate::isa::AArch64> = StochasticSearch::new();
    let best_cost = crate::semantics::cost::sequence_cost(target, &config.cost_metric);

    // Run stochastic search. The generic search returns
    // `SearchResultFor<AArch64>`; convert back to the AArch64-specific
    // `SearchResult` the parallel coordinator still consumes.
    let result: crate::search::result::SearchResult =
        search.search(target, live_out, config).into();

    if result.found_optimization
        && let Some(ref optimized) = result.optimized_sequence
    {
        let cost = crate::semantics::cost::sequence_cost(optimized, &config.cost_metric);
        if cost < best_cost {
            // Report improvement
            let _ = channels.to_coordinator.send(WorkerMessage::Improvement {
                worker_id,
                sequence: optimized.clone(),
                cost,
                algorithm: Algorithm::Stochastic,
            });
        }
    }

    let _ = channels.to_coordinator.send(WorkerMessage::Finished {
        worker_id,
        statistics: result.statistics,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::search::config::{SearchConfig, StochasticConfig, SymbolicConfig};

    fn mov_add_sequence() -> Vec<Instruction> {
        vec![
            Instruction::MovReg {
                rd: Register::X0,
                rn: Register::X1,
            },
            Instruction::Add {
                rd: Register::X0,
                rn: Register::X0,
                rm: Operand::Immediate(1),
            },
        ]
    }

    #[test]
    fn test_parallel_search_single_worker() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(1000));

        let parallel_config = ParallelConfig::default()
            .with_workers(1)
            .with_symbolic(false)
            .with_timeout(Duration::from_secs(5));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        // Should complete without errors
        assert!(result.total_statistics.elapsed_time.as_nanos() > 0);
    }

    // Issue #244 regression: hybrid dispatch must follow the contract pinned by
    // ParallelConfig::num_stochastic_workers. Worker 0 is symbolic only when
    // include_symbolic && num_workers > 1; otherwise the lone worker must run
    // stochastic so the user's --beta/--iterations/--seed knobs take effect.

    #[test]
    fn test_two_workers_with_symbolic_reports_one_symbolic_one_stochastic() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Keep the symbolic worker's solver budget tight so it terminates
        // quickly under Z3 on this trivial target.
        let symbolic_cfg = crate::search::config::SymbolicConfig::default()
            .with_timeout(Duration::from_millis(250));
        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(200))
            .with_symbolic(symbolic_cfg);

        let parallel_config = ParallelConfig::default()
            .with_workers(2)
            .with_symbolic(true)
            .with_seed(42)
            .with_timeout(Duration::from_secs(10));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        assert_eq!(result.worker_statistics.len(), 2);
        let mut pairs: Vec<(usize, Algorithm)> = result
            .worker_statistics
            .iter()
            .map(|(id, alg, _)| (*id, *alg))
            .collect();
        pairs.sort_by_key(|(id, _)| *id);
        assert_eq!(
            pairs,
            vec![(0, Algorithm::Symbolic), (1, Algorithm::Stochastic)],
            "expected worker 0 = Symbolic, worker 1 = Stochastic, got {:?}",
            pairs,
        );
    }

    #[test]
    fn test_single_worker_with_symbolic_is_stochastic() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(200));

        // include_symbolic = true but num_workers = 1: per the contract pinned
        // by ParallelConfig::num_stochastic_workers, the lone worker must be
        // stochastic. Before the fix, coordinator.rs dispatched worker 0 to
        // SymbolicSearch and reported Stochastic anyway via a hardcoded label.
        let parallel_config = ParallelConfig::default()
            .with_workers(1)
            .with_symbolic(true)
            .with_seed(42)
            .with_timeout(Duration::from_secs(5));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        assert_eq!(result.worker_statistics.len(), 1);
        assert_eq!(result.worker_statistics[0].0, 0);
        assert_eq!(
            result.worker_statistics[0].1,
            Algorithm::Stochastic,
            "single hybrid worker must run stochastic, got {:?}",
            result.worker_statistics[0].1,
        );
    }

    #[test]
    fn test_single_worker_without_symbolic_stays_stochastic() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(200));

        let parallel_config = ParallelConfig::default()
            .with_workers(1)
            .with_symbolic(false)
            .with_seed(42)
            .with_timeout(Duration::from_secs(5));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        assert_eq!(result.worker_statistics.len(), 1);
        assert_eq!(result.worker_statistics[0].1, Algorithm::Stochastic);
    }

    #[test]
    fn test_parallel_search_multiple_workers() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(500));

        let parallel_config = ParallelConfig::default()
            .with_workers(2)
            .with_symbolic(false)
            .with_seed(42)
            .with_timeout(Duration::from_secs(5));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        // Should aggregate candidates from both workers
        assert!(result.total_statistics.candidates_evaluated > 0);
    }

    // Issue #77 stage 1 step 2 safety net:
    // verify that every spawned worker reports Finished and that no per-worker
    // statistics are silently dropped. Stage 1 step 12 genericises the
    // coordinator + channel types over <I: ISA>; this test must keep passing
    // through that refactor. Iteration count is sized so all workers finish
    // naturally well inside the timeout (the current stochastic worker does
    // not check CoordinatorMessage::Stop mid-search; timeout-driven shutdown
    // is out of scope here).
    #[test]
    fn test_parallel_search_no_dropped_finished_messages() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 1, 2])
            .with_stochastic(StochasticConfig::default().with_iterations(200));

        let num_workers = 4;
        let parallel_config = ParallelConfig::default()
            .with_workers(num_workers)
            .with_symbolic(false)
            .with_seed(42)
            .with_timeout(Duration::from_secs(30));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        // Every worker reported its stats (no dropped Finished messages).
        assert_eq!(
            result.worker_statistics.len(),
            num_workers,
            "expected {} worker stat entries, got {}",
            num_workers,
            result.worker_statistics.len(),
        );

        // Each worker_id appears exactly once across [0, num_workers).
        let mut ids: Vec<usize> = result
            .worker_statistics
            .iter()
            .map(|(id, _, _)| *id)
            .collect();
        ids.sort();
        let expected: Vec<usize> = (0..num_workers).collect();
        assert_eq!(ids, expected, "worker IDs should cover 0..{}", num_workers);

        // At least one candidate was evaluated overall (sanity).
        assert!(
            result.total_statistics.candidates_evaluated > 0,
            "expected workers to evaluate at least one candidate",
        );
    }

    // Regression test for issue #242: a symbolic worker's `SearchStatistics`
    // must flow through the parallel coordinator without being relabelled as
    // stochastic or having every field except `candidates_evaluated` zeroed.
    // Hyperparameters mirror `test_symbolic_finds_mov_add_fusion` in
    // src/search/symbolic/synthesis.rs which is known to land the
    // mov-add -> add fusion within a few seconds.
    #[test]
    fn test_parallel_search_symbolic_worker_statistics_are_propagated() {
        let target = mov_add_sequence();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let search_config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1, 2])
            .with_symbolic(SymbolicConfig::default().with_timeout(Duration::from_secs(10)))
            .with_stochastic(StochasticConfig::default().with_iterations(200));

        let parallel_config = ParallelConfig::default()
            .with_workers(2)
            .with_symbolic(true)
            .with_seed(42)
            .with_timeout(Duration::from_secs(60));

        let result = run_parallel_search(&target, &live_out, &search_config, &parallel_config);

        // Per the coordinator's worker-spawn logic, worker_id 0 runs the
        // symbolic search and the remaining workers run stochastic.
        let symbolic_entries: Vec<_> = result
            .worker_statistics
            .iter()
            .filter(|(_, alg, _)| *alg == Algorithm::Symbolic)
            .collect();
        assert_eq!(
            symbolic_entries.len(),
            1,
            "expected exactly one Algorithm::Symbolic entry in worker_statistics, got {:?}",
            result
                .worker_statistics
                .iter()
                .map(|(id, alg, _)| (*id, *alg))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            symbolic_entries[0].0, 0,
            "symbolic worker should be worker_id 0",
        );
        for (id, alg, _) in &result.worker_statistics {
            if *id != 0 {
                assert_eq!(
                    *alg,
                    Algorithm::Stochastic,
                    "non-symbolic workers must be labeled Stochastic, got {:?} for id {}",
                    alg,
                    id,
                );
            }
        }

        // Symbolic worker reaches the solver to verify candidates, so
        // total_statistics.smt_queries must be nonzero — proving the
        // symbolic stats are aggregated rather than dropped.
        assert!(
            result.total_statistics.smt_queries > 0,
            "expected aggregated smt_queries > 0, got {}",
            result.total_statistics.smt_queries,
        );

        // The symbolic worker increments improvements_found when it finds
        // the mov-add -> add fusion.
        assert!(
            result.total_statistics.improvements_found > 0,
            "expected aggregated improvements_found > 0, got {}",
            result.total_statistics.improvements_found,
        );

        // Original-cost and best-cost fields must be populated from the
        // workers; today they are silently zero.
        assert!(
            result.total_statistics.original_cost > 0,
            "expected aggregated original_cost > 0, got {}",
            result.total_statistics.original_cost,
        );
        assert!(
            result.total_statistics.best_cost_found > 0,
            "expected aggregated best_cost_found > 0, got {}",
            result.total_statistics.best_cost_found,
        );

        // The winning result must carry the winning worker's statistics,
        // not a fresh placeholder. The symbolic worker is the only one
        // that can land the 2-instruction -> 1-instruction fusion on this
        // target, so its stats must be the ones we surface.
        assert!(
            result.best_result.found_optimization,
            "expected the hybrid run to find an optimization",
        );
        assert_eq!(
            result.best_result.statistics.algorithm,
            Algorithm::Symbolic,
            "best_result.statistics should reflect the winning (symbolic) worker, got {:?}",
            result.best_result.statistics.algorithm,
        );
    }
}

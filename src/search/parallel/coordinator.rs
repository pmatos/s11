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
#[derive(Debug)]
pub struct ParallelResult {
    /// The best result found across all workers.
    pub best_result: SearchResult,
    /// Statistics aggregated from all workers.
    pub total_statistics: SearchStatistics,
    /// Per-worker statistics.
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

                        // Update best result
                        let result = SearchResult {
                            found_optimization: true,
                            original_sequence: target.to_vec(),
                            optimized_sequence: Some(sequence),
                            statistics: SearchStatistics::new(algorithm),
                        };
                        best_result = Some(result);
                    }
                }
                WorkerMessage::Finished {
                    worker_id,
                    candidates_evaluated,
                } => {
                    finished_count += 1;
                    let algorithm = worker_algorithm(worker_id, config);
                    let mut stats = SearchStatistics::new(algorithm);
                    stats.candidates_evaluated = candidates_evaluated;
                    stats.elapsed_time = start_time.elapsed();
                    worker_stats.push((worker_id, algorithm, stats));

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

    // Build final result
    let elapsed = start_time.elapsed();
    let total_candidates: u64 = worker_stats
        .iter()
        .map(|(_, _, s)| s.candidates_evaluated)
        .sum();

    let mut total_stats = SearchStatistics::new(Algorithm::Hybrid);
    total_stats.elapsed_time = elapsed;
    total_stats.candidates_evaluated = total_candidates;

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
    let candidates_evaluated = result.statistics.candidates_evaluated;

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
        candidates_evaluated,
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
    let candidates_evaluated = result.statistics.candidates_evaluated;

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
        candidates_evaluated,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Operand, Register};
    use crate::search::config::{SearchConfig, StochasticConfig};

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
}

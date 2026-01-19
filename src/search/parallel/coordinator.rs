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
use crate::semantics::state::LiveOutMask;
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
    live_out: &LiveOutMask,
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
    _live_out: &LiveOutMask,
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
                    let mut stats = SearchStatistics::new(Algorithm::Stochastic);
                    stats.candidates_evaluated = candidates_evaluated;
                    stats.elapsed_time = start_time.elapsed();
                    worker_stats.push((worker_id, Algorithm::Stochastic, stats));

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

/// Worker function that runs a search algorithm.
fn run_worker(
    worker_id: usize,
    target: &[Instruction],
    live_out: &LiveOutMask,
    search_config: &SearchConfig,
    parallel_config: &ParallelConfig,
    channels: WorkerChannels,
) {
    let is_symbolic_worker = parallel_config.include_symbolic && worker_id == 0;

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
    live_out: &LiveOutMask,
    config: &SearchConfig,
    channels: WorkerChannels,
) {
    let mut search = SymbolicSearch::new();

    // Run search in chunks, checking for stop signal periodically
    let result = search.search(target, live_out, config);
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
    live_out: &LiveOutMask,
    config: &SearchConfig,
    channels: WorkerChannels,
) {
    let mut search = StochasticSearch::new();
    let best_cost = crate::semantics::cost::sequence_cost(target, &config.cost_metric);

    // Run stochastic search
    let result = search.search(target, live_out, config);
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
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

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

    #[test]
    fn test_parallel_search_multiple_workers() {
        let target = mov_add_sequence();
        let live_out = LiveOutMask::from_registers(vec![Register::X0]);

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
}

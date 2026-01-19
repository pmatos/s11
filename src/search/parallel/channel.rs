//! Solution sharing channel for parallel search workers.

#![allow(dead_code)]

use crate::ir::Instruction;
use crate::search::config::Algorithm;
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Message sent from workers to the coordinator.
#[derive(Debug, Clone)]
pub enum WorkerMessage {
    /// Worker found an improved solution.
    Improvement {
        worker_id: usize,
        sequence: Vec<Instruction>,
        cost: u64,
        algorithm: Algorithm,
    },
    /// Worker has finished searching.
    Finished {
        worker_id: usize,
        candidates_evaluated: u64,
    },
    /// Worker encountered an error.
    Error { worker_id: usize, message: String },
}

/// Message sent from coordinator to workers.
#[derive(Debug, Clone)]
pub enum CoordinatorMessage {
    /// A better solution was found by another worker.
    BetterSolution {
        sequence: Vec<Instruction>,
        cost: u64,
    },
    /// Signal workers to stop.
    Stop,
}

/// Shared state for tracking the best solution across all workers.
#[derive(Debug)]
pub struct SharedBest {
    /// Current best cost (AtomicU64::MAX means no solution yet).
    pub best_cost: AtomicU64,
    /// Flag to signal all workers to stop.
    pub should_stop: AtomicBool,
}

impl Default for SharedBest {
    fn default() -> Self {
        Self {
            best_cost: AtomicU64::new(u64::MAX),
            should_stop: AtomicBool::new(false),
        }
    }
}

impl SharedBest {
    /// Try to update the best cost. Returns true if this is a new best.
    pub fn try_update(&self, new_cost: u64) -> bool {
        let mut current = self.best_cost.load(Ordering::SeqCst);
        loop {
            if new_cost >= current {
                return false;
            }
            match self.best_cost.compare_exchange_weak(
                current,
                new_cost,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(c) => current = c,
            }
        }
    }

    /// Check if we should stop searching.
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::SeqCst)
    }

    /// Signal all workers to stop.
    pub fn signal_stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }

    /// Get the current best cost (u64::MAX if none found).
    pub fn current_best(&self) -> u64 {
        self.best_cost.load(Ordering::SeqCst)
    }
}

/// Channel endpoints for a worker.
pub struct WorkerChannels {
    /// Send messages to coordinator.
    pub to_coordinator: Sender<WorkerMessage>,
    /// Receive messages from coordinator.
    pub from_coordinator: Receiver<CoordinatorMessage>,
    /// Shared state for fast best-cost checking.
    pub shared: Arc<SharedBest>,
}

/// Channel endpoints for the coordinator.
pub struct CoordinatorChannels {
    /// Receive messages from workers.
    pub from_workers: Receiver<WorkerMessage>,
    /// Send messages to workers (one sender per worker, cloned).
    pub to_workers: Vec<Sender<CoordinatorMessage>>,
    /// Shared state.
    pub shared: Arc<SharedBest>,
}

/// Create channels for parallel search with the given number of workers.
pub fn create_channels(num_workers: usize) -> (CoordinatorChannels, Vec<WorkerChannels>) {
    let shared = Arc::new(SharedBest::default());

    // Unbounded channel from workers to coordinator (workers shouldn't block)
    let (worker_tx, coordinator_rx) = unbounded();

    // Create channels from coordinator to each worker
    let mut to_workers = Vec::with_capacity(num_workers);
    let mut worker_channels = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        // Bounded channel to workers (small buffer, workers check periodically)
        let (coord_tx, worker_rx) = bounded(8);
        to_workers.push(coord_tx);
        worker_channels.push(WorkerChannels {
            to_coordinator: worker_tx.clone(),
            from_coordinator: worker_rx,
            shared: Arc::clone(&shared),
        });
    }

    let coordinator = CoordinatorChannels {
        from_workers: coordinator_rx,
        to_workers,
        shared,
    };

    (coordinator, worker_channels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Register;

    #[test]
    fn test_shared_best_update() {
        let shared = SharedBest::default();

        // Initial update should succeed
        assert!(shared.try_update(100));
        assert_eq!(shared.current_best(), 100);

        // Better cost should succeed
        assert!(shared.try_update(50));
        assert_eq!(shared.current_best(), 50);

        // Worse cost should fail
        assert!(!shared.try_update(75));
        assert_eq!(shared.current_best(), 50);

        // Equal cost should fail
        assert!(!shared.try_update(50));
        assert_eq!(shared.current_best(), 50);
    }

    #[test]
    fn test_shared_stop_signal() {
        let shared = SharedBest::default();

        assert!(!shared.should_stop());
        shared.signal_stop();
        assert!(shared.should_stop());
    }

    #[test]
    fn test_create_channels() {
        let (coordinator, workers) = create_channels(4);

        assert_eq!(workers.len(), 4);
        assert_eq!(coordinator.to_workers.len(), 4);

        // Test sending from worker to coordinator
        let msg = WorkerMessage::Finished {
            worker_id: 0,
            candidates_evaluated: 100,
        };
        workers[0].to_coordinator.send(msg).unwrap();

        let received = coordinator.from_workers.recv().unwrap();
        match received {
            WorkerMessage::Finished {
                worker_id,
                candidates_evaluated,
            } => {
                assert_eq!(worker_id, 0);
                assert_eq!(candidates_evaluated, 100);
            }
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_coordinator_broadcast() {
        let (coordinator, workers) = create_channels(2);

        let seq = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 42,
        }];

        // Broadcast to all workers
        for tx in &coordinator.to_workers {
            tx.send(CoordinatorMessage::BetterSolution {
                sequence: seq.clone(),
                cost: 1,
            })
            .unwrap();
        }

        // All workers should receive it
        for (i, worker) in workers.iter().enumerate() {
            let msg = worker.from_coordinator.recv().unwrap();
            match msg {
                CoordinatorMessage::BetterSolution { cost, .. } => {
                    assert_eq!(cost, 1, "Worker {} received wrong cost", i);
                }
                _ => panic!("Worker {} received unexpected message", i),
            }
        }
    }
}

//! Configuration for parallel search execution.

#![allow(dead_code)]

use std::time::Duration;

/// Configuration for parallel search execution.
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of worker threads to spawn.
    pub num_workers: usize,
    /// Whether to include a symbolic search worker (in hybrid mode).
    pub include_symbolic: bool,
    /// Whether workers should share solutions with each other.
    pub solution_sharing: bool,
    /// Overall timeout for the parallel search.
    pub timeout: Option<Duration>,
    /// Base random seed (workers get seed + worker_id).
    pub base_seed: Option<u64>,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_workers: num_cpus::get(),
            include_symbolic: true,
            solution_sharing: true,
            timeout: None,
            base_seed: None,
        }
    }
}

impl ParallelConfig {
    /// Create a new parallel config with the specified number of workers.
    pub fn with_workers(mut self, num_workers: usize) -> Self {
        self.num_workers = num_workers.max(1);
        self
    }

    /// Enable or disable the symbolic worker in hybrid mode.
    pub fn with_symbolic(mut self, include_symbolic: bool) -> Self {
        self.include_symbolic = include_symbolic;
        self
    }

    /// Enable or disable solution sharing between workers.
    pub fn with_solution_sharing(mut self, enabled: bool) -> Self {
        self.solution_sharing = enabled;
        self
    }

    /// Set the overall timeout for parallel search.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the base random seed for reproducibility.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.base_seed = Some(seed);
        self
    }

    /// Set the base random seed from an Option.
    pub fn with_seed_option(mut self, seed: Option<u64>) -> Self {
        self.base_seed = seed;
        self
    }

    /// Set the overall timeout from an Option.
    pub fn with_timeout_option(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the number of stochastic workers.
    ///
    /// Stochastic workers occupy the trailing worker-id suffix. Any symbolic
    /// worker occupies the leading prefix.
    pub fn num_stochastic_workers(&self) -> usize {
        if self.include_symbolic && self.num_workers > 1 {
            self.num_workers - 1
        } else {
            self.num_workers
        }
    }

    /// Return whether the worker id belongs to the stochastic suffix.
    pub(crate) fn is_stochastic_worker(&self, worker_id: usize) -> bool {
        let first_stochastic_worker = self
            .num_workers
            .saturating_sub(self.num_stochastic_workers());
        worker_id >= first_stochastic_worker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ParallelConfig::default();
        assert!(config.num_workers >= 1);
        assert!(config.include_symbolic);
        assert!(config.solution_sharing);
        assert!(config.timeout.is_none());
        assert!(config.base_seed.is_none());
    }

    #[test]
    fn test_config_builder() {
        let config = ParallelConfig::default()
            .with_workers(4)
            .with_symbolic(false)
            .with_timeout(Duration::from_secs(60))
            .with_seed(42);

        assert_eq!(config.num_workers, 4);
        assert!(!config.include_symbolic);
        assert_eq!(config.timeout, Some(Duration::from_secs(60)));
        assert_eq!(config.base_seed, Some(42));
    }

    #[test]
    fn test_num_stochastic_workers() {
        // With symbolic, one worker is reserved
        let config = ParallelConfig::default()
            .with_workers(4)
            .with_symbolic(true);
        assert_eq!(config.num_stochastic_workers(), 3);

        // Without symbolic, all workers are stochastic
        let config = ParallelConfig::default()
            .with_workers(4)
            .with_symbolic(false);
        assert_eq!(config.num_stochastic_workers(), 4);

        // Single worker with symbolic still gets 1 stochastic
        let config = ParallelConfig::default()
            .with_workers(1)
            .with_symbolic(true);
        assert_eq!(config.num_stochastic_workers(), 1);
    }

    #[test]
    fn test_is_stochastic_worker() {
        let cases = [
            (
                ParallelConfig::default()
                    .with_workers(1)
                    .with_symbolic(true),
                vec![true],
            ),
            (
                ParallelConfig::default()
                    .with_workers(2)
                    .with_symbolic(true),
                vec![false, true],
            ),
            (
                ParallelConfig::default()
                    .with_workers(4)
                    .with_symbolic(true),
                vec![false, true, true, true],
            ),
            (
                ParallelConfig::default()
                    .with_workers(4)
                    .with_symbolic(false),
                vec![true, true, true, true],
            ),
        ];

        for (config, expected) in cases {
            let actual: Vec<bool> = (0..config.num_workers)
                .map(|worker_id| config.is_stochastic_worker(worker_id))
                .collect();

            assert_eq!(actual, expected);
            assert_eq!(
                actual
                    .iter()
                    .filter(|&&is_stochastic| is_stochastic)
                    .count(),
                config.num_stochastic_workers(),
            );
        }
    }

    #[test]
    fn test_minimum_workers() {
        let config = ParallelConfig::default().with_workers(0);
        assert_eq!(config.num_workers, 1);
    }
}

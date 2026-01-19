//! Parallel search execution for running multiple search workers concurrently.
//!
//! This module provides infrastructure for running multiple search algorithms
//! in parallel, with optional solution sharing between workers.
//!
//! # Architecture
//!
//! The parallel search system consists of:
//! - A **coordinator** that manages worker threads and aggregates results
//! - Multiple **workers** that run search algorithms (stochastic or symbolic)
//! - A **channel system** for communication between workers and coordinator
//! - **Shared state** for fast best-cost checking without channel overhead
//!
//! # Example
//!
//! ```ignore
//! use s11::search::parallel::{ParallelConfig, run_parallel_search};
//!
//! let config = ParallelConfig::default()
//!     .with_workers(4)
//!     .with_symbolic(true)  // Include one symbolic worker
//!     .with_timeout(Duration::from_secs(60));
//!
//! let result = run_parallel_search(&target, &live_out, &search_config, &config);
//! ```

pub mod channel;
pub mod config;
pub mod coordinator;

pub use config::ParallelConfig;
pub use coordinator::{ParallelResult, run_parallel_search};

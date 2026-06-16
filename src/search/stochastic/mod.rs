//! Stochastic (MCMC) search for superoptimization
//!
//! Implements MCMC-style search for finding shorter equivalent instruction
//! sequences. The algorithm randomly mutates candidate programs with heuristic
//! proposals and accepts/rejects mutations based on their cost using a
//! Metropolis temperature parameter. It does not compute a Hastings ratio for
//! proposal asymmetry.

pub mod acceptance;
pub mod backend;
pub mod mcmc;
pub mod mutation;

pub use mcmc::StochasticSearch;

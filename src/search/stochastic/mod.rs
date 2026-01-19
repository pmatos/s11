//! Stochastic (MCMC) search for superoptimization
//!
//! Implements Metropolis-Hastings MCMC search for finding shorter equivalent
//! instruction sequences. The algorithm randomly mutates candidate programs
//! and accepts/rejects mutations based on their cost using a temperature parameter.

pub mod acceptance;
pub mod mcmc;
pub mod mutation;

pub use mcmc::StochasticSearch;

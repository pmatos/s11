//! Metropolis-Hastings acceptance criterion for MCMC
//!
//! Implements the acceptance decision for stochastic search.
//! A proposal is accepted if:
//!   proposal_cost < current_cost - ln(random) / beta
//!
//! Where beta is the inverse temperature parameter.
//! Higher beta = more greedy (less likely to accept worse solutions)
//! Lower beta = more exploration (more likely to accept worse solutions)

#![allow(dead_code)]

use rand::Rng;

/// Acceptance criterion for Metropolis-Hastings MCMC
pub struct AcceptanceCriterion {
    /// Inverse temperature (higher = more greedy)
    beta: f64,
}

impl AcceptanceCriterion {
    /// Create a new acceptance criterion with the given beta parameter
    pub fn new(beta: f64) -> Self {
        assert!(beta > 0.0, "beta must be positive");
        Self { beta }
    }

    /// Get the beta parameter
    pub fn beta(&self) -> f64 {
        self.beta
    }

    /// Compute the acceptance threshold for the current cost
    ///
    /// Returns the maximum cost that would be accepted.
    /// threshold = current_cost - ln(random) / beta
    pub fn compute_threshold<R: Rng>(&self, rng: &mut R, current_cost: u64) -> f64 {
        let u: f64 = rng.random();
        // Avoid log(0) which is -infinity
        let u = u.max(1e-300);
        current_cost as f64 - u.ln() / self.beta
    }

    /// Decide whether to accept a proposal
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `current_cost` - Cost of current solution
    /// * `proposal_cost` - Cost of proposed solution
    ///
    /// # Returns
    /// true if the proposal should be accepted
    pub fn accept<R: Rng>(&self, rng: &mut R, current_cost: u64, proposal_cost: u64) -> bool {
        // Always accept if proposal is better
        if proposal_cost < current_cost {
            return true;
        }

        // For equal or worse proposals, use Metropolis criterion
        let threshold = self.compute_threshold(rng, current_cost);
        (proposal_cost as f64) < threshold
    }

    /// Decide whether to accept based on a cost difference
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `cost_delta` - proposal_cost - current_cost (positive = worse)
    ///
    /// # Returns
    /// true if the proposal should be accepted
    pub fn accept_delta<R: Rng>(&self, rng: &mut R, cost_delta: i64) -> bool {
        // Always accept improvements
        if cost_delta < 0 {
            return true;
        }

        // For equal or worse, use Boltzmann distribution
        let u: f64 = rng.random();
        let u = u.max(1e-300);

        // Accept if random threshold exceeds cost delta
        // threshold = -ln(u) / beta
        // Accept if cost_delta < threshold
        // Equivalent to: u < exp(-beta * cost_delta)
        let threshold = -u.ln() / self.beta;
        (cost_delta as f64) < threshold
    }

    /// Calculate acceptance probability for a cost difference
    ///
    /// P(accept) = min(1, exp(-beta * delta)) for delta >= 0
    pub fn acceptance_probability(&self, cost_delta: i64) -> f64 {
        if cost_delta < 0 {
            1.0
        } else {
            (-self.beta * cost_delta as f64).exp().min(1.0)
        }
    }
}

impl Default for AcceptanceCriterion {
    fn default() -> Self {
        Self::new(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_always_accept_improvement() {
        let criterion = AcceptanceCriterion::new(1.0);
        let mut rng = rand::rng();

        // Should always accept when proposal is better
        for _ in 0..100 {
            assert!(criterion.accept(&mut rng, 10, 5));
            assert!(criterion.accept(&mut rng, 100, 1));
            assert!(criterion.accept_delta(&mut rng, -5));
        }
    }

    #[test]
    fn test_sometimes_accept_equal() {
        let criterion = AcceptanceCriterion::new(1.0);
        let mut rng = rand::rng();

        let mut accepted = 0;
        for _ in 0..1000 {
            if criterion.accept(&mut rng, 10, 10) {
                accepted += 1;
            }
        }

        // With beta=1 and delta=0, P(accept) = 1, so all should be accepted
        // Actually with the threshold formula, equal cost will be < threshold most of the time
        assert!(accepted > 500);
    }

    #[test]
    fn test_rarely_accept_much_worse() {
        let criterion = AcceptanceCriterion::new(1.0);
        let mut rng = rand::rng();

        let mut accepted = 0;
        for _ in 0..1000 {
            if criterion.accept(&mut rng, 10, 100) {
                accepted += 1;
            }
        }

        // Should rarely accept proposals that are 10x worse
        assert!(accepted < 100);
    }

    #[test]
    fn test_high_beta_more_greedy() {
        let high_beta = AcceptanceCriterion::new(10.0);
        let low_beta = AcceptanceCriterion::new(0.1);
        let mut rng = rand::rng();

        let mut high_accepted = 0;
        let mut low_accepted = 0;

        for _ in 0..1000 {
            if high_beta.accept(&mut rng, 10, 15) {
                high_accepted += 1;
            }
            if low_beta.accept(&mut rng, 10, 15) {
                low_accepted += 1;
            }
        }

        // Low beta should accept worse proposals more often
        assert!(low_accepted > high_accepted);
    }

    #[test]
    fn test_acceptance_probability_improvement() {
        let criterion = AcceptanceCriterion::new(1.0);
        assert_eq!(criterion.acceptance_probability(-10), 1.0);
        assert_eq!(criterion.acceptance_probability(-1), 1.0);
    }

    #[test]
    fn test_acceptance_probability_same() {
        let criterion = AcceptanceCriterion::new(1.0);
        assert!((criterion.acceptance_probability(0) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_acceptance_probability_worse() {
        let criterion = AcceptanceCriterion::new(1.0);

        let p1 = criterion.acceptance_probability(1);
        let p5 = criterion.acceptance_probability(5);
        let p10 = criterion.acceptance_probability(10);

        // Probabilities should decrease as cost increases
        assert!(p1 > p5);
        assert!(p5 > p10);

        // All should be in [0, 1]
        assert!(p1 >= 0.0 && p1 <= 1.0);
        assert!(p5 >= 0.0 && p5 <= 1.0);
        assert!(p10 >= 0.0 && p10 <= 1.0);
    }

    #[test]
    fn test_acceptance_probability_high_beta() {
        let criterion = AcceptanceCriterion::new(10.0);

        let p1 = criterion.acceptance_probability(1);
        let p5 = criterion.acceptance_probability(5);

        // With high beta, even small cost increases have low acceptance
        assert!(p1 < 0.001);
        assert!(p5 < 1e-10);
    }

    #[test]
    fn test_acceptance_probability_low_beta() {
        let criterion = AcceptanceCriterion::new(0.01);

        let p1 = criterion.acceptance_probability(1);
        let p10 = criterion.acceptance_probability(10);

        // With low beta, even worse proposals have high acceptance
        assert!(p1 > 0.99);
        assert!(p10 > 0.9);
    }

    #[test]
    fn test_threshold_varies() {
        let criterion = AcceptanceCriterion::new(1.0);
        let mut rng = rand::rng();

        let mut thresholds = Vec::new();
        for _ in 0..100 {
            thresholds.push(criterion.compute_threshold(&mut rng, 10));
        }

        // Thresholds should vary (not all the same)
        let min = thresholds.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = thresholds.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        assert!(max > min + 0.1);
    }

    #[test]
    #[should_panic(expected = "beta must be positive")]
    fn test_invalid_beta_zero() {
        AcceptanceCriterion::new(0.0);
    }

    #[test]
    #[should_panic(expected = "beta must be positive")]
    fn test_invalid_beta_negative() {
        AcceptanceCriterion::new(-1.0);
    }

    #[test]
    fn test_accept_delta_equivalent_to_accept() {
        let criterion = AcceptanceCriterion::new(1.0);

        // Test that accept_delta with delta < 0 always accepts (like accept with better proposal)
        let mut rng = rand::rng();
        for _ in 0..100 {
            assert!(criterion.accept_delta(&mut rng, -5));
        }
    }
}

//! Configuration types for search algorithms

use crate::ir::Register;
use crate::semantics::cost::CostMetric;
use std::time::Duration;

/// Search algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// Exhaustive enumeration over all possible sequences
    #[default]
    Enumerative,
    /// Stochastic MCMC search using Metropolis-Hastings
    Stochastic,
    /// SMT-based symbolic synthesis
    Symbolic,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Enumerative => write!(f, "enumerative"),
            Algorithm::Stochastic => write!(f, "stochastic"),
            Algorithm::Symbolic => write!(f, "symbolic"),
        }
    }
}

impl std::str::FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "enumerative" | "enum" => Ok(Algorithm::Enumerative),
            "stochastic" | "stoch" | "mcmc" => Ok(Algorithm::Stochastic),
            "symbolic" | "sym" | "smt" => Ok(Algorithm::Symbolic),
            _ => Err(format!(
                "Unknown algorithm: '{}'. Valid options: enumerative, stochastic, symbolic",
                s
            )),
        }
    }
}

/// Cost metric wrapper for CLI parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CostMetricConfig(pub CostMetric);

impl std::fmt::Display for CostMetricConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            CostMetric::InstructionCount => write!(f, "instruction-count"),
            CostMetric::Latency => write!(f, "latency"),
            CostMetric::CodeSize => write!(f, "code-size"),
        }
    }
}

impl std::str::FromStr for CostMetricConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "instruction-count" | "count" | "instructions" => {
                Ok(CostMetricConfig(CostMetric::InstructionCount))
            }
            "latency" => Ok(CostMetricConfig(CostMetric::Latency)),
            "code-size" | "size" | "bytes" => Ok(CostMetricConfig(CostMetric::CodeSize)),
            _ => Err(format!(
                "Unknown cost metric: '{}'. Valid options: instruction-count, latency, code-size",
                s
            )),
        }
    }
}

/// Configuration for stochastic (MCMC) search
#[derive(Debug, Clone)]
pub struct StochasticConfig {
    /// Inverse temperature parameter for Metropolis-Hastings (higher = more greedy)
    pub beta: f64,
    /// Maximum number of MCMC iterations
    pub iterations: u64,
    /// Number of random test cases for fast validation
    pub test_count: usize,
    /// Mutation operator weights [operand, opcode, swap, instruction]
    pub mutation_weights: MutationWeights,
    /// Seed for random number generator (None = random seed)
    pub seed: Option<u64>,
}

impl Default for StochasticConfig {
    fn default() -> Self {
        Self {
            beta: 1.0,
            iterations: 1_000_000,
            test_count: 16,
            mutation_weights: MutationWeights::default(),
            seed: None,
        }
    }
}

impl StochasticConfig {
    pub fn with_beta(mut self, beta: f64) -> Self {
        self.beta = beta;
        self
    }

    pub fn with_iterations(mut self, iterations: u64) -> Self {
        self.iterations = iterations;
        self
    }

    pub fn with_test_count(mut self, count: usize) -> Self {
        self.test_count = count;
        self
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    pub fn with_seed_option(mut self, seed: Option<u64>) -> Self {
        self.seed = seed;
        self
    }
}

/// Weights for mutation operators in stochastic search
#[derive(Debug, Clone)]
pub struct MutationWeights {
    /// Weight for operand mutation (change register/immediate)
    pub operand: f64,
    /// Weight for opcode mutation (change instruction type)
    pub opcode: f64,
    /// Weight for swap mutation (swap two instructions)
    pub swap: f64,
    /// Weight for instruction mutation (replace entire instruction)
    pub instruction: f64,
}

impl Default for MutationWeights {
    fn default() -> Self {
        Self {
            operand: 0.50,
            opcode: 0.16,
            swap: 0.16,
            instruction: 0.18,
        }
    }
}

impl MutationWeights {
    /// Get cumulative thresholds for random selection
    pub fn cumulative_thresholds(&self) -> [f64; 4] {
        let total = self.operand + self.opcode + self.swap + self.instruction;
        [
            self.operand / total,
            (self.operand + self.opcode) / total,
            (self.operand + self.opcode + self.swap) / total,
            1.0,
        ]
    }
}

/// Search mode for symbolic synthesis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchMode {
    /// Linear search: try each length from 1 to target length
    #[default]
    Linear,
    /// Binary search: binary search on cost bound
    Binary,
}

impl std::fmt::Display for SearchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchMode::Linear => write!(f, "linear"),
            SearchMode::Binary => write!(f, "binary"),
        }
    }
}

impl std::str::FromStr for SearchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "linear" => Ok(SearchMode::Linear),
            "binary" => Ok(SearchMode::Binary),
            _ => Err(format!(
                "Unknown search mode: '{}'. Valid options: linear, binary",
                s
            )),
        }
    }
}

/// Configuration for symbolic (SMT) search
#[derive(Debug, Clone)]
pub struct SymbolicConfig {
    /// Maximum window size for synthesis
    pub window_size: usize,
    /// Initial cost bound (None = use target cost)
    pub cost_bound: Option<u64>,
    /// Search mode (linear or binary)
    pub search_mode: SearchMode,
    /// Timeout for each SMT query
    pub solver_timeout: Option<Duration>,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self {
            window_size: 3,
            cost_bound: None,
            search_mode: SearchMode::Linear,
            solver_timeout: Some(Duration::from_secs(30)),
        }
    }
}

impl SymbolicConfig {
    pub fn with_window_size(mut self, size: usize) -> Self {
        self.window_size = size;
        self
    }

    pub fn with_cost_bound(mut self, bound: u64) -> Self {
        self.cost_bound = Some(bound);
        self
    }

    pub fn with_search_mode(mut self, mode: SearchMode) -> Self {
        self.search_mode = mode;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.solver_timeout = Some(timeout);
        self
    }
}

/// Main search configuration
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Search algorithm to use
    pub algorithm: Algorithm,
    /// Cost metric for optimization
    pub cost_metric: CostMetric,
    /// Overall timeout for the search
    pub timeout: Option<Duration>,
    /// Registers available for use in synthesized code
    pub available_registers: Vec<Register>,
    /// Immediate values to consider in synthesis
    pub available_immediates: Vec<i64>,
    /// Stochastic-specific configuration
    pub stochastic: StochasticConfig,
    /// Symbolic-specific configuration
    pub symbolic: SymbolicConfig,
    /// Verbose output during search
    pub verbose: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            cost_metric: CostMetric::default(),
            timeout: Some(Duration::from_secs(60)),
            available_registers: vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
            ],
            available_immediates: vec![-1, 0, 1, 2, 4, 8, 16, 32, 64],
            stochastic: StochasticConfig::default(),
            symbolic: SymbolicConfig::default(),
            verbose: false,
        }
    }
}

impl SearchConfig {
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_cost_metric(mut self, metric: CostMetric) -> Self {
        self.cost_metric = metric;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_registers(mut self, registers: Vec<Register>) -> Self {
        self.available_registers = registers;
        self
    }

    pub fn with_immediates(mut self, immediates: Vec<i64>) -> Self {
        self.available_immediates = immediates;
        self
    }

    pub fn with_stochastic(mut self, stochastic: StochasticConfig) -> Self {
        self.stochastic = stochastic;
        self
    }

    pub fn with_symbolic(mut self, symbolic: SymbolicConfig) -> Self {
        self.symbolic = symbolic;
        self
    }

    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_timeout_option(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            "enumerative".parse::<Algorithm>().unwrap(),
            Algorithm::Enumerative
        );
        assert_eq!(
            "stochastic".parse::<Algorithm>().unwrap(),
            Algorithm::Stochastic
        );
        assert_eq!(
            "symbolic".parse::<Algorithm>().unwrap(),
            Algorithm::Symbolic
        );
        assert_eq!("mcmc".parse::<Algorithm>().unwrap(), Algorithm::Stochastic);
        assert_eq!("smt".parse::<Algorithm>().unwrap(), Algorithm::Symbolic);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", Algorithm::Enumerative), "enumerative");
        assert_eq!(format!("{}", Algorithm::Stochastic), "stochastic");
        assert_eq!(format!("{}", Algorithm::Symbolic), "symbolic");
    }

    #[test]
    fn test_cost_metric_from_str() {
        assert_eq!(
            "instruction-count".parse::<CostMetricConfig>().unwrap().0,
            CostMetric::InstructionCount
        );
        assert_eq!(
            "latency".parse::<CostMetricConfig>().unwrap().0,
            CostMetric::Latency
        );
        assert_eq!(
            "code-size".parse::<CostMetricConfig>().unwrap().0,
            CostMetric::CodeSize
        );
    }

    #[test]
    fn test_mutation_weights_cumulative() {
        let weights = MutationWeights::default();
        let thresholds = weights.cumulative_thresholds();

        assert!(thresholds[0] > 0.0);
        assert!(thresholds[0] < thresholds[1]);
        assert!(thresholds[1] < thresholds[2]);
        assert!((thresholds[3] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_search_config_builder() {
        let config = SearchConfig::default()
            .with_algorithm(Algorithm::Stochastic)
            .with_cost_metric(CostMetric::Latency)
            .verbose();

        assert_eq!(config.algorithm, Algorithm::Stochastic);
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert!(config.verbose);
    }

    #[test]
    fn test_stochastic_config_builder() {
        let config = StochasticConfig::default()
            .with_beta(2.0)
            .with_iterations(500_000)
            .with_seed(42);

        assert_eq!(config.beta, 2.0);
        assert_eq!(config.iterations, 500_000);
        assert_eq!(config.seed, Some(42));
    }

    #[test]
    fn test_symbolic_config_builder() {
        let config = SymbolicConfig::default()
            .with_window_size(5)
            .with_search_mode(SearchMode::Binary);

        assert_eq!(config.window_size, 5);
        assert_eq!(config.search_mode, SearchMode::Binary);
    }
}

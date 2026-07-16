//! Configuration types for search algorithms

#![allow(dead_code)]

use crate::ir::Register;
use crate::semantics::cost::CostMetric;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Search algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// Exhaustive enumeration over all possible sequences
    #[default]
    Enumerative,
    /// Stochastic MCMC-style search using heuristic proposals and Metropolis acceptance
    Stochastic,
    /// SMT-based symbolic synthesis
    Symbolic,
    /// Hybrid: parallel execution with symbolic + multiple stochastic workers
    Hybrid,
    /// LLM-assisted search via Codex CLI
    Llm,
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Enumerative => write!(f, "enumerative"),
            Algorithm::Stochastic => write!(f, "stochastic"),
            Algorithm::Symbolic => write!(f, "symbolic"),
            Algorithm::Hybrid => write!(f, "hybrid"),
            Algorithm::Llm => write!(f, "llm"),
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
            "hybrid" | "parallel" => Ok(Algorithm::Hybrid),
            "llm" | "codex" => Ok(Algorithm::Llm),
            _ => Err(format!(
                "Unknown algorithm: '{}'. Valid options: enumerative, stochastic, symbolic, hybrid, llm",
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
    /// Inverse temperature parameter for Metropolis acceptance (higher = more greedy)
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
    /// Bucket a uniform draw `r ∈ [0, 1)` into one of the four mutation
    /// categories, indexed in `MutationType` order: 0 = operand, 1 = opcode,
    /// 2 = swap, 3 = instruction. A category is chosen with probability
    /// proportional to its weight.
    ///
    /// Degenerate all-zero weights (total ≤ 0) collapse the whole interval
    /// onto the last bucket instead of dividing by zero into NaN thresholds.
    pub fn select_index(&self, r: f64) -> usize {
        let total = self.operand + self.opcode + self.swap + self.instruction;
        if total <= 0.0 {
            return 3;
        }
        let t0 = self.operand / total;
        let t1 = (self.operand + self.opcode) / total;
        let t2 = (self.operand + self.opcode + self.swap) / total;
        if r < t0 {
            0
        } else if r < t1 {
            1
        } else if r < t2 {
            2
        } else {
            3
        }
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

/// Default timeout for each SMT solver query used by verification/synthesis.
pub const DEFAULT_SYMBOLIC_SOLVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for symbolic (SMT) search
#[derive(Debug, Clone)]
pub struct SymbolicConfig {
    /// Maximum number of synthesized non-terminator instructions to consider.
    ///
    /// A value of 0 disables candidate search. If the target ends in a fixed
    /// terminator, that terminator is appended after synthesis and does not
    /// count against this window.
    pub window_size: usize,
    /// Exclusive initial cost bound.
    ///
    /// Candidate sequences must be strictly cheaper than this bound and the
    /// original target cost. `None` uses the original target cost.
    pub cost_bound: Option<u64>,
    /// Search mode (linear or binary)
    pub search_mode: SearchMode,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self {
            window_size: 3,
            cost_bound: None,
            search_mode: SearchMode::Linear,
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
}

/// Default Codex model identifier used by the LLM-assisted search flow.
///
/// Single source of truth for the model name; CLI defaults reference this
/// constant rather than embedding the literal in multiple places. Identifier
/// is the OpenAI Codex Spark model exposed via the `codex` CLI.
pub const DEFAULT_LLM_MODEL: &str = "gpt-5.3-codex-spark";

/// Configuration for the LLM-assisted (Codex) search algorithm.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Maximum number of `codex exec` invocations per search.
    pub max_codex_calls: u32,
    /// Codex model identifier (passed to `codex exec -m`).
    pub model: String,
    /// Path to the `codex` binary. Override for tests or unusual installs.
    ///
    /// **Security note:** treat this field as a Rust-only override. It is
    /// **not** wired up to any CLI flag, environment variable, or config file
    /// — only Rust callers within this crate can change it. If a future
    /// change exposes this to user input, it becomes an arbitrary-command-
    /// execution surface (we `Command::new(codex_bin)` the value), and that
    /// route should be locked down (e.g., resolve through `which` and reject
    /// non-canonical paths) before being shipped.
    pub codex_bin: String,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            max_codex_calls: 20,
            model: DEFAULT_LLM_MODEL.to_string(),
            codex_bin: "codex".to_string(),
        }
    }
}

impl LlmConfig {
    pub fn with_max_codex_calls(mut self, n: u32) -> Self {
        self.max_codex_calls = n;
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn with_codex_bin(mut self, bin: impl Into<String>) -> Self {
        self.codex_bin = bin.into();
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
    /// Timeout for each SMT solver query used by verification/synthesis.
    pub solver_timeout: Option<Duration>,
    /// Number of worker threads (rayon) for algorithms that parallelise.
    /// `None` lets rayon pick its default (typically logical-core count).
    /// `Some(0)` is coerced to 1 thread (rayon rejects zero-thread pools).
    /// Currently consumed by `EnumerativeSearch`; ignored by single-threaded
    /// algorithms.
    pub cores: Option<usize>,
    /// Registers available for use in synthesized code
    pub available_registers: Vec<Register>,
    /// Immediate values to consider in synthesis
    pub available_immediates: Vec<i64>,
    /// x86 register pool (issue #73). Consumed by
    /// `<X86_64 as StochasticBackend>::registers_from_config` and the
    /// x86 symbolic / LLM backends. Defaults to the same 8 GPRs the
    /// AArch64 pool ships at the same cardinality.
    pub x86_available_registers: Vec<crate::isa::x86::X86Register>,
    /// Whether x86 symbolic code-size search may consider same-instruction-count
    /// candidates. Defaults to true; callers may disable it as an additional
    /// conservative policy gate.
    pub x86_same_count_code_size_allowed: bool,
    /// Stochastic-specific configuration
    pub stochastic: StochasticConfig,
    /// Symbolic-specific configuration
    pub symbolic: SymbolicConfig,
    /// LLM-specific configuration
    pub llm: LlmConfig,
    /// Verbose output during search
    pub verbose: bool,
    /// Cooperative-cancel flag shared with an external coordinator.
    ///
    /// Single-threaded search callers leave this `None`; the parallel
    /// coordinator (`run_parallel_search`) clones `SharedBest::stop_flag()`
    /// into the per-worker config so the inner search loop can poll
    /// cancellation alongside its own `timeout` check.
    pub stop_flag: Option<Arc<AtomicBool>>,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            cost_metric: CostMetric::default(),
            timeout: Some(Duration::from_secs(60)),
            solver_timeout: Some(DEFAULT_SYMBOLIC_SOLVER_TIMEOUT),
            cores: None,
            available_registers: vec![
                Register::X0,
                Register::X1,
                Register::X2,
                Register::X3,
                Register::X4,
                Register::X5,
            ],
            available_immediates: vec![
                0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
            ],
            x86_available_registers: crate::isa::x86::default_x86_registers(),
            x86_same_count_code_size_allowed: true,
            stochastic: StochasticConfig::default(),
            symbolic: SymbolicConfig::default(),
            llm: LlmConfig::default(),
            verbose: false,
            stop_flag: None,
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

    pub fn with_solver_timeout(mut self, timeout: Duration) -> Self {
        self.solver_timeout = Some(timeout);
        self
    }

    /// Set the rayon worker thread count for parallel search algorithms.
    /// `None` uses the global rayon pool (typically logical-core count).
    /// `Some(0)` is silently coerced to 1 thread (rayon rejects zero-thread
    /// pools); callers expecting a no-parallelism behaviour should pass
    /// `Some(1)` explicitly.
    pub fn with_cores(mut self, cores: Option<usize>) -> Self {
        self.cores = cores;
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

    pub fn with_llm(mut self, llm: LlmConfig) -> Self {
        self.llm = llm;
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

    pub fn with_solver_timeout_option(mut self, timeout: Option<Duration>) -> Self {
        self.solver_timeout = timeout;
        self
    }

    /// Set the x86 register pool (issue #73).
    pub fn with_x86_registers(mut self, registers: Vec<crate::isa::x86::X86Register>) -> Self {
        self.x86_available_registers = registers;
        self
    }

    /// Attach a cooperative-cancel flag observable by the inner search loop.
    ///
    /// The flag is shared by `Arc`; cloning the resulting `SearchConfig`
    /// preserves the same underlying `AtomicBool`. Single-threaded callers
    /// can leave this unset and the search loops fall back to their usual
    /// `config.timeout` deadline.
    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = Some(flag);
        self
    }

    pub fn with_x86_same_count_code_size_allowed(mut self, allowed: bool) -> Self {
        self.x86_same_count_code_size_allowed = allowed;
        self
    }

    /// Per-query SMT solver timeout, resolving the fallback when unset.
    ///
    /// Single home for the fallback used when [`solver_timeout`] is `None`;
    /// the search backends resolve the timeout here rather than each repeating
    /// the literal. The fallback is `5s` — the value every backend used before
    /// this seam existed; note it differs from the `30s` the default config
    /// ships in the `Some` field, and only applies when a caller explicitly
    /// clears the timeout.
    ///
    /// [`solver_timeout`]: Self::solver_timeout
    pub fn solver_timeout(&self) -> Duration {
        self.solver_timeout.unwrap_or(Duration::from_secs(5))
    }

    /// Per-query SMT solver timeout clamped to the remaining search budget.
    ///
    /// `elapsed` is how long the overall search has been running. The result
    /// is [`solver_timeout`](Self::solver_timeout) capped at the time left
    /// before [`timeout`](Self::timeout) elapses (unbounded when `timeout` is
    /// `None`). Returns `None` when the budget is exhausted: Z3 timeouts are
    /// configured in whole milliseconds, so a sub-millisecond remainder cannot
    /// be represented usefully and is treated as exhausted.
    ///
    /// All SMT-driven backends resolve their per-query timeout here so the
    /// budget-clamping rule cannot drift between them.
    pub fn solver_timeout_within_budget(&self, elapsed: Duration) -> Option<Duration> {
        let solver_timeout = self.solver_timeout();
        let timeout = match self.timeout {
            Some(search_timeout) => solver_timeout.min(search_timeout.checked_sub(elapsed)?),
            None => solver_timeout,
        };
        (timeout.as_millis() > 0).then_some(timeout)
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
        assert_eq!(format!("{}", Algorithm::Hybrid), "hybrid");
        assert_eq!(format!("{}", Algorithm::Llm), "llm");
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
        assert_eq!(
            "instructions".parse::<CostMetricConfig>().unwrap().0,
            CostMetric::InstructionCount
        );
        assert_eq!(
            "bytes".parse::<CostMetricConfig>().unwrap().0,
            CostMetric::CodeSize
        );
        assert!("bogus".parse::<CostMetricConfig>().is_err());
        assert_eq!(
            format!("{}", CostMetricConfig(CostMetric::InstructionCount)),
            "instruction-count"
        );
        assert_eq!(
            format!("{}", CostMetricConfig(CostMetric::Latency)),
            "latency"
        );
        assert_eq!(
            format!("{}", CostMetricConfig(CostMetric::CodeSize)),
            "code-size"
        );
    }

    #[test]
    fn select_index_partitions_unit_interval_by_weight() {
        // Equal weights split [0, 1) into exact quarters (0.25/0.5/0.75 are
        // all representable in f64), so bucket boundaries are unambiguous.
        let weights = MutationWeights {
            operand: 1.0,
            opcode: 1.0,
            swap: 1.0,
            instruction: 1.0,
        };
        assert_eq!(weights.select_index(0.0), 0);
        assert_eq!(weights.select_index(0.24), 0);
        assert_eq!(weights.select_index(0.25), 1);
        assert_eq!(weights.select_index(0.49), 1);
        assert_eq!(weights.select_index(0.50), 2);
        assert_eq!(weights.select_index(0.74), 2);
        assert_eq!(weights.select_index(0.75), 3);
        assert_eq!(weights.select_index(0.999), 3);
    }

    #[test]
    fn select_index_default_weights_keep_operand_first() {
        // Defaults: operand 0.50, opcode 0.16, swap 0.16, instruction 0.18
        // (sum 1.0), so cutoffs sit at 0.50 / 0.66 / 0.82.
        let weights = MutationWeights::default();
        assert_eq!(weights.select_index(0.0), 0);
        assert_eq!(weights.select_index(0.49), 0);
        assert_eq!(weights.select_index(0.60), 1);
        assert_eq!(weights.select_index(0.70), 2);
        assert_eq!(weights.select_index(0.90), 3);
    }

    #[test]
    fn select_index_honours_skewed_weights() {
        // All mass on operand: every draw in [0, 1) buckets to operand (0).
        let weights = MutationWeights {
            operand: 1.0,
            opcode: 0.0,
            swap: 0.0,
            instruction: 0.0,
        };
        assert_eq!(weights.select_index(0.0), 0);
        assert_eq!(weights.select_index(0.5), 0);
        assert_eq!(weights.select_index(0.999), 0);

        // All mass on swap: every draw buckets to swap (2).
        let swap_only = MutationWeights {
            operand: 0.0,
            opcode: 0.0,
            swap: 1.0,
            instruction: 0.0,
        };
        assert_eq!(swap_only.select_index(0.0), 2);
        assert_eq!(swap_only.select_index(0.999), 2);
    }

    #[test]
    fn select_index_with_zero_total_is_defined() {
        // Degenerate all-zero weights must stay well-defined (no NaN from a
        // divide-by-zero); the whole interval collapses to the last bucket.
        let weights = MutationWeights {
            operand: 0.0,
            opcode: 0.0,
            swap: 0.0,
            instruction: 0.0,
        };
        assert_eq!(weights.select_index(0.0), 3);
        assert_eq!(weights.select_index(0.5), 3);
        assert_eq!(weights.select_index(0.999), 3);
    }

    #[test]
    fn test_search_config_builder() {
        let config = SearchConfig::default()
            .with_algorithm(Algorithm::Stochastic)
            .with_cost_metric(CostMetric::Latency)
            .with_timeout(Duration::from_secs(9))
            .with_registers(vec![Register::X0, Register::X1])
            .with_immediates(vec![0, 42])
            .with_verbose(false)
            .verbose();

        assert_eq!(config.algorithm, Algorithm::Stochastic);
        assert_eq!(config.cost_metric, CostMetric::Latency);
        assert_eq!(config.timeout, Some(Duration::from_secs(9)));
        assert_eq!(config.available_registers, vec![Register::X0, Register::X1]);
        assert_eq!(config.available_immediates, vec![0, 42]);
        assert!(config.verbose);
    }

    #[test]
    fn search_config_solver_timeout_builder_round_trips() {
        let default = SearchConfig::default();
        assert_eq!(default.solver_timeout, Some(Duration::from_secs(30)));

        let explicit = SearchConfig::default().with_solver_timeout(Duration::from_millis(250));
        assert_eq!(explicit.solver_timeout, Some(Duration::from_millis(250)));

        let unset = SearchConfig::default().with_solver_timeout_option(None);
        assert_eq!(unset.solver_timeout, None);
    }

    #[test]
    fn solver_timeout_resolves_default_fallback() {
        // Default config ships an explicit solver timeout.
        assert_eq!(
            SearchConfig::default().solver_timeout(),
            Duration::from_secs(30)
        );
        // An explicit value is returned verbatim.
        assert_eq!(
            SearchConfig::default()
                .with_solver_timeout(Duration::from_millis(250))
                .solver_timeout(),
            Duration::from_millis(250)
        );
        // When unset, the shared fallback is 5s (the value every backend used).
        assert_eq!(
            SearchConfig::default()
                .with_solver_timeout_option(None)
                .solver_timeout(),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn solver_timeout_within_budget_clamps_to_remaining_search_time() {
        // Solver timeout below the remaining budget is used unchanged.
        let solver_smaller = SearchConfig::default()
            .with_timeout(Duration::from_secs(10))
            .with_solver_timeout(Duration::from_millis(250));
        assert_eq!(
            solver_smaller.solver_timeout_within_budget(Duration::from_secs(1)),
            Some(Duration::from_millis(250))
        );

        // Solver timeout larger than the remaining budget is clamped down.
        let capped = SearchConfig::default()
            .with_timeout(Duration::from_millis(100))
            .with_solver_timeout(Duration::from_secs(1));
        assert_eq!(
            capped.solver_timeout_within_budget(Duration::from_millis(40)),
            Some(Duration::from_millis(60))
        );

        // Exactly-exhausted budget yields None.
        assert_eq!(
            capped.solver_timeout_within_budget(Duration::from_millis(100)),
            None
        );

        // A sub-millisecond remainder cannot be represented as a Z3 timeout,
        // so it is treated as exhausted.
        assert_eq!(
            capped.solver_timeout_within_budget(Duration::from_micros(99_500)),
            None
        );

        // Over-elapsed (elapsed beyond the deadline) is also exhausted.
        assert_eq!(
            capped.solver_timeout_within_budget(Duration::from_millis(250)),
            None
        );
    }

    #[test]
    fn solver_timeout_within_budget_is_unbounded_without_search_timeout() {
        // No overall timeout: the resolved solver timeout is returned as-is
        // regardless of elapsed time, falling back to 5s when unset.
        let unbounded = SearchConfig::default()
            .with_timeout_option(None)
            .with_solver_timeout_option(None);
        assert_eq!(
            unbounded.solver_timeout_within_budget(Duration::from_secs(999)),
            Some(Duration::from_secs(5))
        );

        let unbounded_explicit = SearchConfig::default()
            .with_timeout_option(None)
            .with_solver_timeout(Duration::from_secs(30));
        assert_eq!(
            unbounded_explicit.solver_timeout_within_budget(Duration::from_secs(999)),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn test_stochastic_config_builder() {
        let config = StochasticConfig::default()
            .with_beta(2.0)
            .with_iterations(500_000)
            .with_test_count(99)
            .with_seed(42)
            .with_seed_option(None);

        assert_eq!(config.beta, 2.0);
        assert_eq!(config.iterations, 500_000);
        assert_eq!(config.test_count, 99);
        assert_eq!(config.seed, None);
    }

    #[test]
    fn test_symbolic_config_builder() {
        let config = SymbolicConfig::default()
            .with_window_size(5)
            .with_cost_bound(2)
            .with_search_mode(SearchMode::Binary);

        assert_eq!(config.window_size, 5);
        assert_eq!(config.cost_bound, Some(2));
        assert_eq!(config.search_mode, SearchMode::Binary);
    }

    #[test]
    fn search_mode_and_algorithm_aliases_are_covered() {
        assert_eq!("enum".parse::<Algorithm>().unwrap(), Algorithm::Enumerative);
        assert_eq!("stoch".parse::<Algorithm>().unwrap(), Algorithm::Stochastic);
        assert_eq!("sym".parse::<Algorithm>().unwrap(), Algorithm::Symbolic);
        assert_eq!("parallel".parse::<Algorithm>().unwrap(), Algorithm::Hybrid);
        assert_eq!("codex".parse::<Algorithm>().unwrap(), Algorithm::Llm);
        assert!("wat".parse::<Algorithm>().is_err());

        assert_eq!(format!("{}", SearchMode::Linear), "linear");
        assert_eq!(format!("{}", SearchMode::Binary), "binary");
        assert_eq!("linear".parse::<SearchMode>().unwrap(), SearchMode::Linear);
        assert_eq!("binary".parse::<SearchMode>().unwrap(), SearchMode::Binary);
        assert!("diagonal".parse::<SearchMode>().is_err());
    }

    #[test]
    fn search_config_with_stop_flag_round_trips() {
        use std::sync::atomic::Ordering;

        // Default config has no stop flag.
        assert!(SearchConfig::default().stop_flag.is_none());

        let flag = Arc::new(AtomicBool::new(false));
        let config = SearchConfig::default().with_stop_flag(Arc::clone(&flag));
        let cloned = config.clone();

        // Both the config field and the clone observe the same `AtomicBool`.
        flag.store(true, Ordering::SeqCst);
        assert!(
            config
                .stop_flag
                .as_ref()
                .map(|f| f.load(Ordering::SeqCst))
                .unwrap_or(false),
            "original config should observe the signalled flag",
        );
        assert!(
            cloned
                .stop_flag
                .as_ref()
                .map(|f| f.load(Ordering::SeqCst))
                .unwrap_or(false),
            "cloned config should observe the same flag (Arc-shared, not deep-copied)",
        );
    }

    #[test]
    fn llm_and_nested_search_config_builders_are_covered() {
        let stochastic = StochasticConfig::default().with_iterations(3);
        let symbolic = SymbolicConfig::default().with_window_size(4);
        let llm = LlmConfig::default()
            .with_max_codex_calls(2)
            .with_model("test-model")
            .with_codex_bin("/bin/echo");

        let config = SearchConfig::default()
            .with_stochastic(stochastic.clone())
            .with_symbolic(symbolic.clone())
            .with_llm(llm.clone())
            .with_timeout_option(None);

        assert_eq!(config.stochastic.iterations, stochastic.iterations);
        assert_eq!(config.symbolic.window_size, symbolic.window_size);
        assert_eq!(config.llm.max_codex_calls, 2);
        assert_eq!(config.llm.model, "test-model");
        assert_eq!(config.llm.codex_bin, "/bin/echo");
        assert_eq!(config.timeout, None);
    }
}

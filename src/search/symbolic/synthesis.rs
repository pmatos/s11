//! SMT-based synthesis for superoptimization
//!
//! This module implements symbolic search using Z3 for equivalence verification.
//! The approach uses linear cost search: try sequences of length 1, 2, ... up to
//! the target length - 1, and for each length, enumerate candidates and verify
//! equivalence with SMT.
//!
//! Note: Full symbolic synthesis with symbolic opcodes/operands is very complex.
//! This implementation uses a hybrid approach: enumerate concrete candidates
//! and verify them with SMT, rather than synthesizing from purely symbolic sketches.

use crate::isa::ISA;
use crate::search::config::{SearchConfig, SearchMode};
use crate::search::result::{SearchResultFor, SearchStatistics};
use crate::search::symbolic::backend::SymbolicBackend;
use crate::search::{Algorithm, SearchAlgorithm};
use crate::semantics::EquivalenceResult;
use std::marker::PhantomData;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Whether the symbolic search loop should exit at the next checkpoint.
///
/// True if the configured `timeout` has elapsed *or* an external
/// coordinator (e.g. the parallel hybrid coordinator) has flipped the
/// cooperative-cancel flag carried in `config.stop_flag`. Centralised so
/// the checkpoint sites in `linear_search` / `search_at_length` stay
/// in sync.
fn should_stop(config: &SearchConfig, start_time: Instant) -> bool {
    if config.timeout.is_some_and(|t| start_time.elapsed() >= t) {
        return true;
    }
    config
        .stop_flag
        .as_ref()
        .is_some_and(|f| f.load(Ordering::Relaxed))
}

/// Symbolic search using SMT-based synthesis, generic over ISA.
///
/// Routes through `SymbolicBackend<I>` for every ISA-specific operation:
/// candidate enumeration, sequence-cost summation, equivalence check.
/// AArch64 routes to `check_equivalence_with_config`; x86 routes to
/// `check_equivalence_x86`.
pub struct SymbolicSearch<I = crate::isa::AArch64> {
    statistics: SearchStatistics,
    _marker: PhantomData<I>,
}

impl<I> SymbolicSearch<I> {
    pub fn new() -> Self {
        Self {
            statistics: SearchStatistics::new(Algorithm::Symbolic),
            _marker: PhantomData,
        }
    }
}

impl<I> SymbolicSearch<I>
where
    I: ISA + SymbolicBackend<I>,
{
    /// Linear cost search: try each length from 1 to target length - 1
    fn linear_search(
        &mut self,
        target: &[I::Instruction],
        live_out: &<I as SymbolicBackend<I>>::LiveOut,
        config: &SearchConfig,
        start_time: Instant,
    ) -> Option<Vec<I::Instruction>> {
        let regs = <I as SymbolicBackend<I>>::registers_from_config(config);
        let imms = <I as SymbolicBackend<I>>::immediates_from_config(config);
        let width = <I as SymbolicBackend<I>>::width(config);
        let all_instructions = <I as SymbolicBackend<I>>::enumerate_all(&regs, &imms);

        let original_cost =
            <I as SymbolicBackend<I>>::sequence_cost(target, &config.cost_metric, width);
        let mut best_solution: Option<Vec<I::Instruction>> = None;
        let mut best_cost = original_cost;

        // Try sequences of increasing length
        for length in 1..target.len() {
            if config.verbose {
                println!("Searching for equivalent sequences of length {}...", length);
            }

            // Check timeout / cooperative-cancel flag.
            if should_stop(config, start_time) {
                if config.verbose {
                    println!("Search timed out");
                }
                break;
            }

            // Generate and test all sequences of this length
            let found = self.search_at_length(
                target,
                live_out,
                config,
                &all_instructions,
                length,
                &mut best_cost,
                start_time,
            );

            if let Some(seq) = found {
                best_solution = Some(seq);
                // In linear search, we found a solution at this length
                // Continue to see if there's an even shorter one
            }
        }

        best_solution
    }

    /// Search for equivalent sequences at a specific length
    #[allow(clippy::too_many_arguments)]
    fn search_at_length(
        &mut self,
        target: &[I::Instruction],
        live_out: &<I as SymbolicBackend<I>>::LiveOut,
        config: &SearchConfig,
        all_instructions: &[I::Instruction],
        length: usize,
        best_cost: &mut u64,
        start_time: Instant,
    ) -> Option<Vec<I::Instruction>> {
        let width = <I as SymbolicBackend<I>>::width(config);
        let mut best_at_length: Option<Vec<I::Instruction>> = None;
        // If the target ends in a terminator (x86 Jcc, AArch64 branch),
        // candidate proposals must end in the same terminator for the
        // equivalence check's peel-and-compare precheck to admit them.
        // Compute once and append below.
        let target_terminator = <I as SymbolicBackend<I>>::target_terminator(target);
        let with_term = |mut seq: Vec<I::Instruction>| -> Vec<I::Instruction> {
            if let Some(t) = target_terminator {
                seq.push(t);
            }
            seq
        };

        if length == 1 {
            // Single instruction search
            for instr in all_instructions {
                // Check timeout / cooperative-cancel flag.
                if should_stop(config, start_time) {
                    return best_at_length;
                }

                let candidate = with_term(vec![*instr]);
                let candidate_cost = <I as SymbolicBackend<I>>::sequence_cost(
                    &candidate,
                    &config.cost_metric,
                    width,
                );

                if candidate_cost >= *best_cost {
                    continue;
                }

                self.statistics.candidates_evaluated += 1;

                if self.verify_equivalence(target, &candidate, live_out, config) {
                    *best_cost = candidate_cost;
                    best_at_length = Some(candidate);
                    self.statistics.improvements_found += 1;

                    if config.verbose {
                        println!("Found equivalent: {} (cost {})", instr, candidate_cost);
                    }
                }
            }
        } else if length == 2 {
            // Two instruction search
            for instr1 in all_instructions {
                // Check timeout / cooperative-cancel flag periodically.
                if should_stop(config, start_time) {
                    return best_at_length;
                }

                for instr2 in all_instructions {
                    if should_stop(config, start_time) {
                        return best_at_length;
                    }

                    let candidate = with_term(vec![*instr1, *instr2]);
                    let candidate_cost = <I as SymbolicBackend<I>>::sequence_cost(
                        &candidate,
                        &config.cost_metric,
                        width,
                    );

                    if candidate_cost >= *best_cost {
                        continue;
                    }

                    self.statistics.candidates_evaluated += 1;

                    if self.verify_equivalence(target, &candidate, live_out, config) {
                        *best_cost = candidate_cost;
                        best_at_length = Some(candidate);
                        self.statistics.improvements_found += 1;

                        if config.verbose {
                            println!(
                                "Found equivalent: {}; {} (cost {})",
                                instr1, instr2, candidate_cost
                            );
                        }
                    }
                }
            }
        } else {
            // For length >= 3, use iterative deepening with early termination
            // This is a simplified version - full enumeration is exponential
            let sample_size = 10000; // Limit candidates to sample
            let mut count = 0;

            for instr1 in all_instructions {
                if count >= sample_size {
                    break;
                }
                if should_stop(config, start_time) {
                    return best_at_length;
                }

                for instr2 in all_instructions {
                    if count >= sample_size {
                        break;
                    }
                    if should_stop(config, start_time) {
                        return best_at_length;
                    }

                    for instr3 in all_instructions {
                        if count >= sample_size {
                            break;
                        }
                        if should_stop(config, start_time) {
                            return best_at_length;
                        }

                        let candidate = if length == 3 {
                            with_term(vec![*instr1, *instr2, *instr3])
                        } else {
                            // For longer sequences, fill with first instruction
                            let mut seq = vec![*instr1, *instr2, *instr3];
                            while seq.len() < length {
                                seq.push(all_instructions[0]);
                            }
                            with_term(seq)
                        };

                        let candidate_cost = <I as SymbolicBackend<I>>::sequence_cost(
                            &candidate,
                            &config.cost_metric,
                            width,
                        );

                        if candidate_cost >= *best_cost {
                            count += 1;
                            continue;
                        }

                        self.statistics.candidates_evaluated += 1;

                        if self.verify_equivalence(target, &candidate, live_out, config) {
                            *best_cost = candidate_cost;
                            best_at_length = Some(candidate.clone());
                            self.statistics.improvements_found += 1;

                            if config.verbose {
                                println!(
                                    "Found equivalent sequence of length {} (cost {})",
                                    length, candidate_cost
                                );
                            }
                        }

                        count += 1;
                    }
                }
            }
        }

        best_at_length
    }

    /// Verify equivalence using SMT
    fn verify_equivalence(
        &mut self,
        target: &[I::Instruction],
        candidate: &[I::Instruction],
        live_out: &<I as SymbolicBackend<I>>::LiveOut,
        config: &SearchConfig,
    ) -> bool {
        let timeout = config
            .symbolic
            .solver_timeout
            .unwrap_or(Duration::from_secs(5));
        let width = <I as SymbolicBackend<I>>::width(config);

        self.statistics.smt_queries += 1;

        let (verdict, metrics) = <I as SymbolicBackend<I>>::check_equivalence(
            target, candidate, live_out, width, timeout,
        );
        self.statistics.smt_elapsed += metrics.smt_elapsed;
        match verdict {
            EquivalenceResult::Equivalent => {
                self.statistics.smt_equivalent += 1;
                self.statistics.candidates_passed_fast += 1;
                true
            }
            EquivalenceResult::NotEquivalentFast(_) => {
                // Failed fast test, no SMT query needed
                self.statistics.smt_queries -= 1; // Don't count as SMT query
                false
            }
            _ => false,
        }
    }

    /// Binary search on cost bound (not fully implemented yet)
    #[allow(dead_code)]
    fn binary_search(
        &mut self,
        _target: &[I::Instruction],
        _live_out: &<I as SymbolicBackend<I>>::LiveOut,
        _config: &SearchConfig,
        _start_time: Instant,
    ) -> Option<Vec<I::Instruction>> {
        // Binary search would use SMT with cost constraints
        // For now, fall back to linear search
        None
    }
}

impl<I> Default for SymbolicSearch<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I> SearchAlgorithm<I> for SymbolicSearch<I>
where
    I: ISA + SymbolicBackend<I>,
{
    type LiveOut = <I as SymbolicBackend<I>>::LiveOut;
    type Result = SearchResultFor<I>;

    fn search(
        &mut self,
        target: &[I::Instruction],
        live_out: &Self::LiveOut,
        config: &SearchConfig,
    ) -> Self::Result {
        self.reset();
        let start_time = Instant::now();
        let width = <I as SymbolicBackend<I>>::width(config);

        let original_cost =
            <I as SymbolicBackend<I>>::sequence_cost(target, &config.cost_metric, width);
        self.statistics.original_cost = original_cost;
        self.statistics.best_cost_found = original_cost;

        if target.is_empty() || target.len() == 1 {
            self.statistics.elapsed_time = start_time.elapsed();
            return SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone());
        }

        let result = match config.symbolic.search_mode {
            SearchMode::Linear => self.linear_search(target, live_out, config, start_time),
            SearchMode::Binary => {
                // Binary search not fully implemented, fall back to linear
                self.linear_search(target, live_out, config, start_time)
            }
        };

        self.statistics.elapsed_time = start_time.elapsed();

        if let Some(optimized) = result {
            self.statistics.best_cost_found =
                <I as SymbolicBackend<I>>::sequence_cost(&optimized, &config.cost_metric, width);
            SearchResultFor::with_optimization(target.to_vec(), optimized, self.statistics.clone())
        } else {
            SearchResultFor::no_optimization(target.to_vec(), self.statistics.clone())
        }
    }

    fn statistics(&self) -> SearchStatistics {
        self.statistics.clone()
    }

    fn reset(&mut self) {
        self.statistics = SearchStatistics::new(Algorithm::Symbolic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Instruction, Operand, Register};
    use crate::isa::{AArch64, ISA, ISAMutator, InstructionType, OperandType, RegisterType, U64};
    use crate::search::config::SymbolicConfig;
    use crate::semantics::EquivalenceMetrics;
    use crate::semantics::cost::CostMetric;
    use crate::semantics::live_out::LiveOut;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    static TEST_EQUIVALENCE_CHECKS: AtomicUsize = AtomicUsize::new(0);
    static SYMBOLIC_INNER_LOOP_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone)]
    struct TestIsa;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct TestRegister;

    impl std::fmt::Display for TestRegister {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "R0")
        }
    }

    impl RegisterType for TestRegister {
        fn index(&self) -> Option<u8> {
            Some(0)
        }

        fn from_index(idx: u8) -> Option<Self> {
            (idx == 0).then_some(Self)
        }

        fn is_zero_register(&self) -> bool {
            false
        }

        fn is_special(&self) -> bool {
            false
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum TestOperand {
        Reg(TestRegister),
        Imm(i64),
    }

    impl std::fmt::Display for TestOperand {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Reg(reg) => write!(f, "{reg}"),
                Self::Imm(imm) => write!(f, "#{imm}"),
            }
        }
    }

    impl OperandType for TestOperand {
        type Register = TestRegister;

        fn as_register(&self) -> Option<Self::Register> {
            match self {
                Self::Reg(reg) => Some(*reg),
                Self::Imm(_) => None,
            }
        }

        fn as_immediate(&self) -> Option<i64> {
            match self {
                Self::Reg(_) => None,
                Self::Imm(imm) => Some(*imm),
            }
        }

        fn from_register(reg: Self::Register) -> Self {
            Self::Reg(reg)
        }

        fn from_immediate(imm: i64) -> Self {
            Self::Imm(imm)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct TestInstruction(u8);

    impl std::fmt::Display for TestInstruction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "test{}", self.0)
        }
    }

    impl InstructionType for TestInstruction {
        type Register = TestRegister;
        type Operand = TestOperand;

        fn destination(&self) -> Option<Self::Register> {
            Some(TestRegister)
        }

        fn source_registers(&self) -> Vec<Self::Register> {
            Vec::new()
        }

        fn opcode_id(&self) -> u8 {
            self.0
        }

        fn mnemonic(&self) -> &'static str {
            "test"
        }
    }

    struct TestMutator;

    impl ISAMutator<TestInstruction> for TestMutator {
        fn mutate<R: rand::RngExt>(
            &self,
            _rng: &mut R,
            sequence: &[TestInstruction],
        ) -> Vec<TestInstruction> {
            sequence.to_vec()
        }
    }

    impl ISA for TestIsa {
        type Register = TestRegister;
        type Operand = TestOperand;
        type Instruction = TestInstruction;
        type Width = U64;
        type Flags = ();
        type Mutator = TestMutator;

        fn name(&self) -> &'static str {
            "Test"
        }

        fn register_count(&self) -> usize {
            1
        }

        fn instruction_size(&self) -> Option<usize> {
            Some(1)
        }

        fn general_registers(&self) -> Vec<Self::Register> {
            vec![TestRegister]
        }

        fn zero_register(&self) -> Option<Self::Register> {
            None
        }
    }

    impl SymbolicBackend<TestIsa> for TestIsa {
        type LiveOut = ();

        fn registers_from_config(_config: &SearchConfig) -> Vec<TestRegister> {
            vec![TestRegister]
        }

        fn immediates_from_config(_config: &SearchConfig) -> Vec<i64> {
            vec![0]
        }

        fn enumerate_all(_regs: &[TestRegister], _imms: &[i64]) -> Vec<TestInstruction> {
            vec![TestInstruction(0)]
        }

        fn sequence_cost(seq: &[TestInstruction], _metric: &CostMetric, _width: u32) -> u64 {
            seq.len() as u64
        }

        fn check_equivalence(
            _target: &[TestInstruction],
            _proposal: &[TestInstruction],
            _live_out: &Self::LiveOut,
            _width: u32,
            _timeout: Duration,
        ) -> (EquivalenceResult, EquivalenceMetrics) {
            TEST_EQUIVALENCE_CHECKS.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
            (
                EquivalenceResult::NotEquivalent,
                EquivalenceMetrics::default(),
            )
        }

        fn width(_config: &SearchConfig) -> u32 {
            64
        }
    }

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

    fn mov_zero_sequence() -> Vec<Instruction> {
        vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }]
    }

    #[test]
    fn test_symbolic_search_creation() {
        let search: SymbolicSearch<AArch64> = SymbolicSearch::new();
        let stats = search.statistics();
        assert_eq!(stats.algorithm, Algorithm::Symbolic);
    }

    #[test]
    fn test_symbolic_search_empty_sequence() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        let result = search.search(&[], &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[test]
    fn test_symbolic_search_single_instruction() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Single instruction can't be optimized to shorter
        let result = search.search(&mov_zero_sequence(), &live_out, &config);
        assert!(!result.found_optimization);
    }

    #[test]
    fn test_symbolic_finds_mov_add_fusion() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_symbolic(SymbolicConfig::default().with_timeout(Duration::from_secs(10)))
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![-1, 0, 1, 2]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Target: MOV X0, X1; ADD X0, X0, #1 (2 instructions)
        // Should find an equivalent 1-instruction sequence (e.g., ADD X0, X1, #1)
        let target = mov_add_sequence();
        let result = search.search(&target, &live_out, &config);

        assert!(result.found_optimization);
        assert_eq!(result.cost_savings(), 1);

        // Verify we found a 1-instruction equivalent sequence
        if let Some(ref optimized) = result.optimized_sequence {
            assert_eq!(optimized.len(), 1);
            // The instruction should write to X0
            assert_eq!(optimized[0].destination(), Some(Register::X0));
        }
    }

    #[test]
    fn test_symbolic_statistics() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_symbolic(SymbolicConfig::default())
            .with_registers(vec![Register::X0, Register::X1]);

        let live_out = LiveOut::from_registers(vec![Register::X0]);
        let target = mov_add_sequence();

        let result = search.search(&target, &live_out, &config);
        let stats = result.statistics;

        assert_eq!(stats.algorithm, Algorithm::Symbolic);
        assert!(stats.elapsed_time.as_nanos() > 0);
        assert!(stats.candidates_evaluated > 0);
    }

    #[test]
    fn test_symbolic_respects_live_out() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();

        let config = SearchConfig::default()
            .with_registers(vec![Register::X0, Register::X1, Register::X2])
            .with_immediates(vec![0, 1]);

        // Only X0 is live-out, X1 can differ
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // Target modifies both X0 and X1
        let target = vec![
            Instruction::MovImm {
                rd: Register::X0,
                imm: 0,
            },
            Instruction::MovImm {
                rd: Register::X1,
                imm: 1,
            },
        ];

        let result = search.search(&target, &live_out, &config);

        // Should find optimization since X1 doesn't need to match
        // MOV X0, #0 is sufficient (or EOR X0, X0, X0)
        assert!(result.found_optimization);
        assert_eq!(result.cost_savings(), 1);
    }

    /// Regression for issue #243: symbolic search must abort promptly when
    /// an external coordinator flips its cooperative-cancel flag, even if
    /// `config.timeout` is `None` and the candidate space is large.
    #[test]
    fn symbolic_search_respects_cooperative_stop_flag() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::thread;
        use std::time::Instant;

        let flag = Arc::new(AtomicBool::new(false));
        let flag_for_search = Arc::clone(&flag);

        let join = thread::spawn(move || {
            let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();
            let config = SearchConfig::default()
                .with_timeout_option(None)
                .with_stop_flag(flag_for_search)
                .with_symbolic(SymbolicConfig::default().with_timeout(Duration::from_secs(60)))
                .with_registers(vec![
                    Register::X0,
                    Register::X1,
                    Register::X2,
                    Register::X3,
                    Register::X4,
                    Register::X5,
                ])
                .with_immediates(vec![
                    0, 1, 2, 3, 4, 5, 7, 8, 10, 15, 16, 31, 32, 63, 64, 100, 255, 256, 1000, 4095,
                ]);
            let live_out = LiveOut::from_registers(vec![Register::X0]);
            let target = mov_add_sequence();
            search.search(&target, &live_out, &config)
        });

        // Give the worker a moment to enter `search_at_length`, then signal stop.
        thread::sleep(Duration::from_millis(20));
        flag.store(true, std::sync::atomic::Ordering::SeqCst);

        let started_join = Instant::now();
        let _result = join.join().expect("symbolic worker panicked");
        let join_elapsed = started_join.elapsed();

        assert!(
            join_elapsed < Duration::from_secs(2),
            "stop flag should abort the symbolic loop promptly; took {:?}",
            join_elapsed,
        );
    }

    #[test]
    fn symbolic_length_two_inner_loop_respects_cooperative_stop_flag() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::thread;
        use std::time::Instant;

        let _guard = SYMBOLIC_INNER_LOOP_TEST_LOCK
            .lock()
            .expect("symbolic inner-loop test lock poisoned");
        TEST_EQUIVALENCE_CHECKS.store(0, Ordering::SeqCst);

        let flag = Arc::new(AtomicBool::new(false));
        let flag_for_stop = Arc::clone(&flag);

        let stopper = thread::spawn(move || {
            while TEST_EQUIVALENCE_CHECKS.load(Ordering::SeqCst) == 0 {
                thread::yield_now();
            }
            flag_for_stop.store(true, Ordering::SeqCst);
        });

        let mut search: SymbolicSearch<TestIsa> = SymbolicSearch::new();
        let config = SearchConfig::default()
            .with_timeout_option(None)
            .with_stop_flag(flag);
        let all_instructions: Vec<_> = (0..64).map(TestInstruction).collect();
        let target = [
            TestInstruction(100),
            TestInstruction(101),
            TestInstruction(102),
        ];
        let mut best_cost = u64::MAX;

        let result = search.search_at_length(
            &target,
            &(),
            &config,
            &all_instructions,
            2,
            &mut best_cost,
            Instant::now(),
        );

        stopper.join().expect("stopper thread panicked");

        let checks = TEST_EQUIVALENCE_CHECKS.load(Ordering::SeqCst);
        assert_eq!(result, None);
        assert!(
            checks < 8,
            "length-2 search should poll cancellation inside the instr2 loop; ran {checks} checks",
        );
    }

    #[test]
    fn symbolic_length_three_inner_loops_respect_cooperative_stop_flag() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::thread;
        use std::time::Instant;

        let _guard = SYMBOLIC_INNER_LOOP_TEST_LOCK
            .lock()
            .expect("symbolic inner-loop test lock poisoned");
        TEST_EQUIVALENCE_CHECKS.store(0, Ordering::SeqCst);

        let flag = Arc::new(AtomicBool::new(false));
        let flag_for_stop = Arc::clone(&flag);

        let stopper = thread::spawn(move || {
            while TEST_EQUIVALENCE_CHECKS.load(Ordering::SeqCst) == 0 {
                thread::yield_now();
            }
            flag_for_stop.store(true, Ordering::SeqCst);
        });

        let mut search: SymbolicSearch<TestIsa> = SymbolicSearch::new();
        let config = SearchConfig::default()
            .with_timeout_option(None)
            .with_stop_flag(flag);
        let all_instructions: Vec<_> = (0..16).map(TestInstruction).collect();
        let target = [
            TestInstruction(100),
            TestInstruction(101),
            TestInstruction(102),
            TestInstruction(103),
        ];
        let mut best_cost = u64::MAX;

        let result = search.search_at_length(
            &target,
            &(),
            &config,
            &all_instructions,
            3,
            &mut best_cost,
            Instant::now(),
        );

        stopper.join().expect("stopper thread panicked");

        let checks = TEST_EQUIVALENCE_CHECKS.load(Ordering::SeqCst);
        assert_eq!(result, None);
        assert!(
            checks < 8,
            "length-3 search should poll cancellation inside the instr2/instr3 loops; ran {checks} checks",
        );
    }

    #[test]
    fn test_verify_equivalence() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // These should be equivalent
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let candidate = vec![Instruction::Eor {
            rd: Register::X0,
            rn: Register::X0,
            rm: Operand::Register(Register::X0),
        }];

        assert!(search.verify_equivalence(&target, &candidate, &live_out, &config));
    }

    #[test]
    fn test_verify_non_equivalence() {
        let mut search: SymbolicSearch<AArch64> = SymbolicSearch::new();
        let config = SearchConfig::default();
        let live_out = LiveOut::from_registers(vec![Register::X0]);

        // These should NOT be equivalent
        let target = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 0,
        }];
        let candidate = vec![Instruction::MovImm {
            rd: Register::X0,
            imm: 1,
        }];

        assert!(!search.verify_equivalence(&target, &candidate, &live_out, &config));
    }

    // ---- x86 symbolic search (issue #73 Phase D step 7) ----

    /// Tracer-bullet test that the generic `SymbolicSearch<X86_64>`
    /// instantiates and runs an end-to-end synthesis on a 2-instruction
    /// x86 target without panic.
    #[test]
    fn x86_symbolic_runs_end_to_end() {
        use crate::isa::X86_64;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::state::X86LiveOutMask;
        use std::time::Duration;

        let mut search: SymbolicSearch<X86_64> = SymbolicSearch::new();
        let config = SearchConfig::default()
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX])
            .with_immediates(vec![0])
            .with_x86_width(64)
            .with_timeout_option(Some(Duration::from_secs(30)));

        let live_out = X86LiveOutMask::from_registers(vec![X86Register::RAX]).with_flags(false);

        // Target: `mov rax, 0; add rax, rbx` — equivalent to a single
        // `mov rax, rbx` when flags aren't live (live_out.flags_live = false)
        // and RAX initial value is `imm = 0`.
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        ];

        let result = search.search(&target, &live_out, &config);
        assert_eq!(result.statistics.algorithm, Algorithm::Symbolic);
        // We don't assert a specific optimization was found — the test
        // just verifies the loop runs end-to-end through the generic
        // backend without panicking.
        assert!(result.statistics.elapsed_time.as_nanos() > 0);
    }

    /// Mirror of `x86_symbolic_runs_end_to_end` for x86-32. Covers the
    /// `SymbolicBackend<X86_32>` impl methods, including the width-32
    /// branch in `x86_check_equivalence` and the `width()` accessor
    /// reading `config.x86_width`.
    #[test]
    fn x86_symbolic_mode32_runs_end_to_end() {
        use crate::isa::X86_32;
        use crate::isa::x86::{X86Instruction, X86Register};
        use crate::semantics::state::X86LiveOutMask;
        use std::time::Duration;

        let mut search: SymbolicSearch<X86_32> = SymbolicSearch::new();
        let config = SearchConfig::default()
            .with_x86_registers(vec![X86Register::RAX, X86Register::RBX])
            .with_immediates(vec![0])
            .with_x86_width(32)
            .with_timeout_option(Some(Duration::from_secs(5)));

        let live_out = X86LiveOutMask::from_registers(vec![X86Register::RAX]).with_flags(false);
        let target = vec![
            X86Instruction::MovImm {
                rd: X86Register::RAX,
                imm: 0,
            },
            X86Instruction::AddReg {
                rd: X86Register::RAX,
                rs: X86Register::RBX,
            },
        ];

        let result = search.search(&target, &live_out, &config);
        assert_eq!(result.statistics.algorithm, Algorithm::Symbolic);
        assert!(result.statistics.elapsed_time.as_nanos() > 0);
    }
}

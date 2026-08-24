//! Monotone worklist for whole-binary `--auto` optimization.

use crate::elf_patcher::AddressWindow;
use std::collections::HashSet;

/// Default global count of per-window searches in one `--auto` run.
pub const DEFAULT_MAX_WINDOWS: usize = 100;

/// One candidate window plus the immutable facts used by the worklist.
#[derive(Clone, Debug)]
pub struct AutoWindow {
    pub window: AddressWindow,
    pub instruction_bytes: Vec<u8>,
    pub instruction_count: usize,
    pub redundancy_score: usize,
}

impl AutoWindow {
    pub fn new(
        window: AddressWindow,
        instruction_bytes: Vec<u8>,
        instruction_count: usize,
        redundancy_score: usize,
    ) -> Self {
        Self {
            window,
            instruction_bytes,
            instruction_count,
            redundancy_score,
        }
    }
}

/// Outcome of searching one candidate window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowSearchResult {
    NoImprovement,
    Improved {
        replacement: Vec<u8>,
        original_cost: u64,
        optimized_cost: u64,
    },
}

/// The adapter through which the ISA-agnostic loop discovers, searches, and
/// eventually patches one concrete image.
pub trait AutoOptimizationAdapter {
    fn discover_windows(&mut self) -> Result<Vec<AutoWindow>, String>;
    fn optimize_window(&mut self, candidate: &AutoWindow) -> Result<WindowSearchResult, String>;
    fn apply_optimization(
        &mut self,
        candidate: &AutoWindow,
        replacement: &[u8],
    ) -> Result<(), String>;
}

/// Observable accounting for one whole-binary run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoRunSummary {
    pub searches: usize,
    pub accepted_rewrites: usize,
    pub cache_hits: usize,
    pub budget_skipped: usize,
    pub fixpoint_reached: bool,
}

/// Drive prioritized passes, bounded by a global count of actual searches.
pub fn drive_auto_optimization<A: AutoOptimizationAdapter>(
    adapter: &mut A,
    max_windows: usize,
) -> Result<AutoRunSummary, String> {
    let mut summary = AutoRunSummary::default();
    let mut no_improvement_cache: HashSet<Vec<u8>> = HashSet::new();

    loop {
        let mut candidates = adapter.discover_windows()?;
        candidates.sort_by(|left, right| {
            right
                .instruction_count
                .cmp(&left.instruction_count)
                .then_with(|| right.redundancy_score.cmp(&left.redundancy_score))
                .then_with(|| left.window.start.cmp(&right.window.start))
        });

        let mut accepted_rewrite = false;
        for (index, candidate) in candidates.iter().enumerate() {
            if no_improvement_cache.contains(&candidate.instruction_bytes) {
                summary.cache_hits += 1;
                continue;
            }
            if summary.searches == max_windows {
                summary.budget_skipped = candidates[index..]
                    .iter()
                    .filter(|remaining| {
                        !no_improvement_cache.contains(&remaining.instruction_bytes)
                    })
                    .count();
                return Ok(summary);
            }

            summary.searches += 1;
            match adapter.optimize_window(candidate)? {
                WindowSearchResult::NoImprovement => {
                    no_improvement_cache.insert(candidate.instruction_bytes.clone());
                }
                WindowSearchResult::Improved {
                    replacement,
                    original_cost,
                    optimized_cost,
                } => {
                    if optimized_cost >= original_cost {
                        return Err(format!(
                            "auto driver refused non-monotone rewrite at 0x{:x}-0x{:x}: optimized cost {} is not strictly lower than original cost {}",
                            candidate.window.start,
                            candidate.window.end,
                            optimized_cost,
                            original_cost,
                        ));
                    }
                    adapter.apply_optimization(candidate, &replacement)?;
                    summary.accepted_rewrites += 1;
                    accepted_rewrite = true;
                    break;
                }
            }
        }

        if !accepted_rewrite {
            summary.fixpoint_reached = true;
            return Ok(summary);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf_patcher::AddressWindow;

    #[derive(Default)]
    struct MissAdapter {
        candidates: Vec<AutoWindow>,
        searched: Vec<u64>,
    }

    impl AutoOptimizationAdapter for MissAdapter {
        fn discover_windows(&mut self) -> Result<Vec<AutoWindow>, String> {
            Ok(self.candidates.clone())
        }

        fn optimize_window(
            &mut self,
            candidate: &AutoWindow,
        ) -> Result<WindowSearchResult, String> {
            self.searched.push(candidate.window.start);
            Ok(WindowSearchResult::NoImprovement)
        }

        fn apply_optimization(
            &mut self,
            _candidate: &AutoWindow,
            _replacement: &[u8],
        ) -> Result<(), String> {
            panic!("a miss-only adapter must never be patched")
        }
    }

    fn candidate(start: u64, instructions: usize, redundancy: usize) -> AutoWindow {
        AutoWindow::new(
            AddressWindow {
                start,
                end: start + instructions as u64,
            },
            vec![start as u8; instructions],
            instructions,
            redundancy,
        )
    }

    #[test]
    fn worklist_prioritizes_length_then_redundancy_and_reports_budget_skip() {
        let mut adapter = MissAdapter {
            candidates: vec![
                candidate(0x30, 2, 0),
                candidate(0x20, 3, 0),
                candidate(0x10, 3, 1),
            ],
            ..MissAdapter::default()
        };

        let summary = drive_auto_optimization(&mut adapter, 2).expect("driver should succeed");

        assert_eq!(adapter.searched, [0x10, 0x20]);
        assert_eq!(summary.searches, 2);
        assert_eq!(summary.budget_skipped, 1);
        assert!(!summary.fixpoint_reached);
    }

    #[derive(Default)]
    struct RewriteThenFixpointAdapter {
        patched: bool,
        discoveries: usize,
        searched: Vec<u64>,
        applied: Vec<u64>,
    }

    impl AutoOptimizationAdapter for RewriteThenFixpointAdapter {
        fn discover_windows(&mut self) -> Result<Vec<AutoWindow>, String> {
            self.discoveries += 1;
            let unchanged_miss = AutoWindow::new(
                AddressWindow {
                    start: 0x10,
                    end: 0x13,
                },
                vec![0xaa, 0xbb, 0xcc],
                3,
                0,
            );
            if self.patched {
                Ok(vec![unchanged_miss])
            } else {
                Ok(vec![unchanged_miss, candidate(0x20, 2, 0)])
            }
        }

        fn optimize_window(
            &mut self,
            candidate: &AutoWindow,
        ) -> Result<WindowSearchResult, String> {
            self.searched.push(candidate.window.start);
            if candidate.window.start == 0x20 {
                Ok(WindowSearchResult::Improved {
                    replacement: vec![0x20],
                    original_cost: 2,
                    optimized_cost: 1,
                })
            } else {
                Ok(WindowSearchResult::NoImprovement)
            }
        }

        fn apply_optimization(
            &mut self,
            candidate: &AutoWindow,
            _replacement: &[u8],
        ) -> Result<(), String> {
            self.patched = true;
            self.applied.push(candidate.window.start);
            Ok(())
        }
    }

    #[test]
    fn rewrite_restarts_discovery_and_unchanged_miss_is_cached_until_fixpoint() {
        let mut adapter = RewriteThenFixpointAdapter::default();

        let summary =
            drive_auto_optimization(&mut adapter, 10).expect("driver should reach a fixpoint");

        assert_eq!(adapter.searched, [0x10, 0x20]);
        assert_eq!(adapter.applied, [0x20]);
        assert_eq!(adapter.discoveries, 2);
        assert_eq!(summary.searches, 2);
        assert_eq!(summary.accepted_rewrites, 1);
        assert_eq!(summary.cache_hits, 1);
        assert_eq!(summary.budget_skipped, 0);
        assert!(summary.fixpoint_reached);
    }

    struct EqualCostAdapter {
        candidate: Option<AutoWindow>,
        apply_calls: usize,
    }

    impl AutoOptimizationAdapter for EqualCostAdapter {
        fn discover_windows(&mut self) -> Result<Vec<AutoWindow>, String> {
            Ok(self.candidate.take().into_iter().collect())
        }

        fn optimize_window(
            &mut self,
            _candidate: &AutoWindow,
        ) -> Result<WindowSearchResult, String> {
            Ok(WindowSearchResult::Improved {
                replacement: vec![0x90],
                original_cost: 2,
                optimized_cost: 2,
            })
        }

        fn apply_optimization(
            &mut self,
            _candidate: &AutoWindow,
            _replacement: &[u8],
        ) -> Result<(), String> {
            self.apply_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn non_decreasing_candidate_is_rejected_before_image_mutation() {
        let mut adapter = EqualCostAdapter {
            candidate: Some(candidate(0x10, 2, 0)),
            apply_calls: 0,
        };

        let error = drive_auto_optimization(&mut adapter, 1)
            .expect_err("equal-cost replacement violates the monotone invariant");

        assert!(
            error.contains("strictly lower"),
            "unexpected error: {error}"
        );
        assert_eq!(adapter.apply_calls, 0);
    }
}

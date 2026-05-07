//! Ledger of unsupported mnemonics emitted by the LLM during a search.
//!
//! Per ADR-0003, parse-rejection is a research signal, not lossage. This
//! accumulator records each rejected mnemonic and emits a frequency-ranked
//! report at the end of a run.

use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct UnsupportedMnemonicLedger {
    counts: HashMap<String, u32>,
}

impl UnsupportedMnemonicLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, mnemonic: &str) {
        *self.counts.entry(mnemonic.to_string()).or_insert(0) += 1;
    }

    /// Return the ledger as `(mnemonic, count)` pairs sorted by count
    /// descending, breaking ties alphabetically.
    pub fn into_sorted(self) -> Vec<(String, u32)> {
        let mut pairs: Vec<(String, u32)> = self.counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ledger() {
        let l = UnsupportedMnemonicLedger::new();
        assert!(l.into_sorted().is_empty());
    }

    #[test]
    fn single_record() {
        let mut l = UnsupportedMnemonicLedger::new();
        l.record("ldr");
        assert_eq!(l.into_sorted(), vec![("ldr".to_string(), 1)]);
    }

    #[test]
    fn repeated_mnemonic_aggregates() {
        let mut l = UnsupportedMnemonicLedger::new();
        l.record("ldr");
        l.record("ldr");
        l.record("ldr");
        assert_eq!(l.into_sorted(), vec![("ldr".to_string(), 3)]);
    }

    #[test]
    fn sorted_by_count_desc_then_alpha() {
        let mut l = UnsupportedMnemonicLedger::new();
        l.record("str"); // 1
        l.record("ldr"); // 1
        l.record("ldr"); // 2
        l.record("b"); // 1
        // Expected: ldr (2), b (1), str (1)  — alpha tie-break for the 1s.
        assert_eq!(
            l.into_sorted(),
            vec![
                ("ldr".to_string(), 2),
                ("b".to_string(), 1),
                ("str".to_string(), 1),
            ]
        );
    }
}

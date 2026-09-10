use super::{redact, Detector};
use crate::scanner::{Confidence, FindingCategory};

/// Generic catch-all: flags long tokens with high Shannon entropy, the way
/// gitleaks'/trufflehog's entropy rules work. This is the highest
/// false-positive detector in the set by design (hashes, lockfile
/// checksums, and minified identifiers all look "random" too) which is why
/// it reports Low confidence — it's meant to be triaged, not trusted raw.
pub struct EntropyDetector {
    threshold: f64,
    min_len: usize,
}

impl EntropyDetector {
    pub fn new(threshold: f64, min_len: usize) -> Self {
        Self { threshold, min_len }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    counts.values().fold(0.0_f64, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Split a line into candidate secret-alphabet tokens (base64/hex-ish),
/// dropping anything that isn't at least `min_len` chars long.
fn candidate_tokens(line: &str, min_len: usize) -> Vec<&str> {
    line.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-')
    })
    .filter(|t| t.len() >= min_len)
    .collect()
}

impl Detector for EntropyDetector {
    fn name(&self) -> &'static str {
        "high_entropy_token"
    }
    fn confidence(&self) -> Confidence {
        Confidence::Low
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Secret
    }
    fn scan_line(&self, line: &str) -> Vec<String> {
        candidate_tokens(line, self.min_len)
            .into_iter()
            .filter(|t| shannon_entropy(t) >= self.threshold)
            .map(redact)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_high_entropy_token() {
        let d = EntropyDetector::new(4.3, 20);
        // 32 random-looking base64 chars
        let hits = d.scan_line("token = \"aXpLQ9mTr7VwYb2Fh4Nq8DkS1oPuZeXc\"");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn ignores_low_entropy_repetition() {
        let d = EntropyDetector::new(4.3, 20);
        let hits = d.scan_line("padding = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"");
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_short_tokens_below_min_len() {
        let d = EntropyDetector::new(4.3, 20);
        let hits = d.scan_line("id = \"aXpLQ9mTr7\"");
        assert!(hits.is_empty());
    }

    #[test]
    fn shannon_entropy_of_single_char_is_zero() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }
}

mod entropy;
mod patterns;
mod sast;

use crate::scanner::{Confidence, FindingCategory};

/// A single detection rule. Implementations look at one line of text at a
/// time and return zero or more match strings (redacted for `Secret`
/// findings, shown in full for `Sast` findings — see `FindingCategory`).
/// They do not know about files, line numbers, or git — the scanner layer
/// attaches that context.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn confidence(&self) -> Confidence;
    fn category(&self) -> FindingCategory;
    fn scan_line(&self, line: &str) -> Vec<String>;
}

/// Redact a matched secret for safe display: keep the first/last 4 chars,
/// mask the rest. Short matches (<=8 chars) are fully masked.
pub fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if len <= 8 {
        return "*".repeat(len.max(1));
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[len - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(len - 8))
}

/// Build the default detector set. `entropy_threshold`/`entropy_min_len`
/// tune the generic high-entropy catch-all (see detectors/entropy.rs).
/// `include_sast` additionally enables the (opt-in) dangerous-code-pattern
/// detectors in detectors/sast.rs — off by default since scanning for
/// secrets and scanning for risky code patterns are different jobs, even
/// though they share this same engine.
pub fn all_detectors(
    entropy_threshold: f64,
    entropy_min_len: usize,
    include_sast: bool,
) -> Vec<Box<dyn Detector>> {
    let mut d: Vec<Box<dyn Detector>> = patterns::builtin_pattern_detectors();
    d.push(Box::new(entropy::EntropyDetector::new(
        entropy_threshold,
        entropy_min_len,
    )));
    if include_sast {
        d.extend(sast::builtin_sast_detectors());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_short_string_fully_masked() {
        assert_eq!(redact("abc"), "***");
    }

    #[test]
    fn redact_long_string_keeps_head_and_tail() {
        let r = redact("AKIAIOSFODNN7EXAMPLE"); // sieve:ignore
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("MPLE"));
        assert!(r.contains('*'));
        assert_eq!(r.chars().count(), "AKIAIOSFODNN7EXAMPLE".chars().count()); // sieve:ignore
    }
}

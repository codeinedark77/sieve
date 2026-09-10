use super::{redact, Detector};
use crate::scanner::{Confidence, FindingCategory};
use regex::Regex;

/// A detector backed by a single compiled regex. `Secret`-category matches
/// are redacted before display; `Sast`-category matches (code patterns,
/// not sensitive values) are shown in full.
pub struct RegexDetector {
    name: &'static str,
    confidence: Confidence,
    category: FindingCategory,
    re: Regex,
}

impl RegexDetector {
    pub(crate) fn new(
        name: &'static str,
        confidence: Confidence,
        category: FindingCategory,
        pattern: &str,
    ) -> Self {
        Self {
            name,
            confidence,
            category,
            re: Regex::new(pattern).unwrap_or_else(|e| panic!("bad regex for {name}: {e}")),
        }
    }

    fn secret(name: &'static str, confidence: Confidence, pattern: &str) -> Self {
        Self::new(name, confidence, FindingCategory::Secret, pattern)
    }
}

impl Detector for RegexDetector {
    fn name(&self) -> &'static str {
        self.name
    }
    fn confidence(&self) -> Confidence {
        self.confidence
    }
    fn category(&self) -> FindingCategory {
        self.category
    }
    fn scan_line(&self, line: &str) -> Vec<String> {
        match self.category {
            FindingCategory::Secret => self
                .re
                .find_iter(line)
                .map(|m| redact(m.as_str()))
                .collect(),
            FindingCategory::Sast => self
                .re
                .find_iter(line)
                .map(|m| m.as_str().to_string())
                .collect(),
        }
    }
}

/// `api_key = "..."` style assignments. Reports only the value, not the
/// full "keyname=value" text, so the keyword itself stays visible in the
/// finding for context.
pub struct ApiKeyAssignmentDetector {
    re: Regex,
}

impl ApiKeyAssignmentDetector {
    fn new() -> Self {
        Self {
            re: Regex::new(
                r#"(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)"?\s*[:=]\s*['"]([A-Za-z0-9_\-/+=]{16,})['"]"#,
            )
            .unwrap(),
        }
    }
}

impl Detector for ApiKeyAssignmentDetector {
    fn name(&self) -> &'static str {
        "generic_api_key_assignment"
    }
    fn confidence(&self) -> Confidence {
        Confidence::Medium
    }
    fn category(&self) -> FindingCategory {
        FindingCategory::Secret
    }
    fn scan_line(&self, line: &str) -> Vec<String> {
        self.re
            .captures_iter(line)
            .map(|c| {
                let keyword = &c[1];
                let value = redact(&c[2]);
                format!("{keyword}={value}")
            })
            .collect()
    }
}

pub fn builtin_pattern_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(RegexDetector::secret(
            "aws_access_key_id",
            Confidence::High,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        )),
        Box::new(RegexDetector::secret(
            "private_key_header",
            Confidence::High,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        )),
        Box::new(RegexDetector::secret(
            "github_token",
            Confidence::High,
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        )),
        Box::new(RegexDetector::secret(
            "slack_token",
            Confidence::High,
            r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b",
        )),
        Box::new(RegexDetector::secret(
            "slack_webhook_url",
            Confidence::High,
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
        )),
        Box::new(RegexDetector::secret(
            "jwt",
            Confidence::Medium,
            r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        )),
        // Only *_live_ — Stripe's own test-mode keys (sk_test_/rk_test_) are
        // explicitly non-sensitive by design, same reasoning as AWS's
        // EXAMPLE keys: flagging them would just be noise.
        Box::new(RegexDetector::secret(
            "stripe_api_key",
            Confidence::High,
            r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b",
        )),
        Box::new(RegexDetector::secret(
            "google_api_key",
            Confidence::High,
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
        )),
        Box::new(RegexDetector::secret(
            "sendgrid_api_key",
            Confidence::High,
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
        )),
        Box::new(RegexDetector::secret(
            "npm_token",
            Confidence::High,
            r"\bnpm_[A-Za-z0-9]{36}\b",
        )),
        Box::new(RegexDetector::secret(
            "twilio_api_key",
            Confidence::Medium,
            r"\bSK[0-9a-fA-F]{32}\b",
        )),
        Box::new(RegexDetector::secret(
            "db_connection_string_with_password",
            Confidence::Medium,
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[A-Za-z0-9_.\-]+:[^@\s'\x22]+@[A-Za-z0-9_.\-]+",
        )),
        Box::new(ApiKeyAssignmentDetector::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(name: &str, line: &str) -> Vec<String> {
        builtin_pattern_detectors()
            .into_iter()
            .find(|d| d.name() == name)
            .unwrap()
            .scan_line(line)
    }

    #[test]
    fn detects_aws_access_key() {
        let hits = find("aws_access_key_id", "aws_key = \"AKIAIOSFODNN7EXAMPLE\""); // sieve:ignore
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_private_key_header() {
        let hits = find("private_key_header", "-----BEGIN RSA PRIVATE KEY-----"); // sieve:ignore
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_github_token() {
        let hits = find(
            "github_token",
            "GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a", // sieve:ignore
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_slack_token() {
        let hits = find(
            "slack_token",
            &format!("SLACK_TOKEN={}-123456789012-abcdefghijklmnop", "xoxb"),
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_jwt() {
        let hits = find(
            "jwt",
            "auth = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", // sieve:ignore
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_stripe_live_key_but_not_test_key() {
        let hits = find(
            "stripe_api_key",
            &format!(
                "STRIPE_KEY = \"{}_live_51H8pQ2eZvKYlo2C0abcdefghijklmno\"",
                "sk"
            ),
        );
        assert_eq!(hits.len(), 1);

        // Stripe's own test-mode keys are explicitly non-sensitive.
        let test_hits = find(
            "stripe_api_key",
            "STRIPE_KEY = \"sk_test_51H8pQ2eZvKYlo2C0abcdefghijklmno\"",
        );
        assert!(test_hits.is_empty(), "sk_test_ keys must not be flagged");
    }

    #[test]
    fn detects_google_api_key() {
        let hits = find(
            "google_api_key",
            "maps_key = \"AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY\"", // sieve:ignore
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_sendgrid_api_key() {
        let hits = find(
            "sendgrid_api_key",
            &format!("SENDGRID_KEY={}.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "SG"),
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_npm_token() {
        let hits = find(
            "npm_token",
            "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789", // sieve:ignore
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_slack_webhook_url() {
        let hits = find(
            "slack_webhook_url",
            &format!(
                "curl -X POST {}/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "https://hooks.slack.com/services"
            ),
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_twilio_api_key() {
        let hits = find(
            "twilio_api_key",
            &format!("TWILIO_KEY = \"{}1234567890abcdef1234567890abcdef\"", "SK"),
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn detects_db_connection_string_with_password() {
        let hits = find(
            "db_connection_string_with_password",
            "DB_URL = \"postgresql://postgres:supersecretpassword@localhost:5432/mydb\"", // sieve:ignore
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn db_connection_string_without_password_is_not_flagged() {
        // No `:password@` segment — just a host, nothing to leak.
        let hits = find(
            "db_connection_string_with_password",
            "DATABASE_URL = \"postgres://db.internal.example.com:5432/prod\"",
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn generic_key_assignment_reports_keyword_and_redacted_value() {
        let hits = builtin_pattern_detectors()
            .into_iter()
            .find(|d| d.name() == "generic_api_key_assignment")
            .unwrap()
            .scan_line(&format!(
                "api_key = \"{}_live_abcdefghijklmnopqrstuvwxyz\"",
                "sk"
            ));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].starts_with("api_key="));
        assert!(hits[0].contains('*'));
    }

    #[test]
    fn generic_key_assignment_matches_json_style_quoted_key() {
        // "keyword": "value" — the closing quote before the colon is the
        // part a naive keyword-then-colon regex misses.
        let hits = builtin_pattern_detectors()
            .into_iter()
            .find(|d| d.name() == "generic_api_key_assignment")
            .unwrap()
            .scan_line(&format!(
                "  \"api_key\": \"{}_live_abcdefghijklmnopqrstuvwxyz\",",
                "sk"
            ));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn clean_line_has_no_hits() {
        assert!(find("aws_access_key_id", "let x = compute_total(items);").is_empty());
    }
}

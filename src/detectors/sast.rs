//! Optional SAST-lite rules: dangerous *code patterns*, not leaked
//! credentials. Off by default (`--sast` to enable) since "does this repo
//! leak secrets" and "does this repo have risky code patterns" are
//! different questions, even though they share the same line-scanning
//! engine. Every rule here is a heuristic worth a human look, not a
//! certain vulnerability — data flow (is the input actually
//! attacker-controlled?) is something a single-line regex fundamentally
//! cannot determine.
//!
//! Regex-engine note: Rust's `regex` crate has no lookahead/lookbehind
//! (it's the tradeoff for linear-time matching). `insecure_deserialization`
//! would ideally assert "yaml.load with no SafeLoader argument anywhere in
//! the call" — that needs a negative lookahead this engine can't express,
//! so it's flagged as a broader heuristic instead. Documented, not hidden.

use super::patterns::RegexDetector;
use super::Detector;
use crate::scanner::{Confidence, FindingCategory};

pub fn builtin_sast_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(RegexDetector::new(
            "shell_injection_risk",
            Confidence::Medium,
            FindingCategory::Sast,
            r"subprocess\.(?:run|call|Popen|check_call|check_output)\([^)]*shell\s*=\s*True|os\.(?:system|popen)\(",
        )),
        Box::new(RegexDetector::new(
            "dangerous_eval_exec",
            Confidence::Medium,
            FindingCategory::Sast,
            r"\b(?:eval|exec)\s*\(",
        )),
        Box::new(RegexDetector::new(
            "insecure_deserialization",
            Confidence::Medium,
            FindingCategory::Sast,
            r"\bpickle\.(?:loads?|Unpickler)\s*\(|\byaml\.load\s*\(",
        )),
        Box::new(RegexDetector::new(
            "disabled_tls_verification",
            Confidence::High,
            FindingCategory::Sast,
            r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\x22]?0\b",
        )),
        Box::new(RegexDetector::new(
            "sql_injection_risk",
            Confidence::Medium,
            FindingCategory::Sast,
            r#"(?i)f['\x22](?:select|insert|update|delete)\b[^'\x22]*\{"#,
        )),
        Box::new(RegexDetector::new(
            "hardcoded_debug_mode",
            Confidence::Medium,
            FindingCategory::Sast,
            r"\bDEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True",
        )),
        Box::new(RegexDetector::new(
            "react_dangerous_innerhtml",
            Confidence::Medium,
            FindingCategory::Sast,
            r"dangerouslySetInnerHTML",
        )),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(name: &str, line: &str) -> Vec<String> {
        builtin_sast_detectors()
            .into_iter()
            .find(|d| d.name() == name)
            .unwrap()
            .scan_line(line)
    }

    #[test]
    fn sast_findings_are_not_redacted() {
        // The whole point of the category split: the match itself isn't
        // sensitive, so it should show up verbatim, not masked.
        let hits = find("dangerous_eval_exec", "result = eval(user_expression)");
        assert_eq!(hits, vec!["eval(".to_string()]);
    }

    #[test]
    fn detects_shell_true() {
        assert_eq!(
            find("shell_injection_risk", "subprocess.run(cmd, shell=True)").len(),
            1
        );
        assert_eq!(find("shell_injection_risk", "os.system(cmd)").len(), 1);
    }

    #[test]
    fn shell_false_is_not_flagged() {
        assert!(find("shell_injection_risk", "subprocess.run(cmd, shell=False)").is_empty());
    }

    #[test]
    fn detects_eval_and_exec() {
        assert_eq!(find("dangerous_eval_exec", "eval(x)").len(), 1);
        assert_eq!(find("dangerous_eval_exec", "exec(code)").len(), 1);
    }

    #[test]
    fn does_not_flag_unrelated_identifiers_containing_eval() {
        // "evaluate(" must not match a bare `eval(` rule.
        assert!(find("dangerous_eval_exec", "evaluate(expression)").is_empty());
    }

    #[test]
    fn detects_pickle_and_yaml_load() {
        assert_eq!(
            find("insecure_deserialization", "obj = pickle.loads(data)").len(),
            1
        );
        assert_eq!(
            find("insecure_deserialization", "cfg = yaml.load(f)").len(),
            1
        );
    }

    #[test]
    fn detects_disabled_tls_verification() {
        assert_eq!(
            find(
                "disabled_tls_verification",
                "requests.get(url, verify=False)"
            )
            .len(),
            1
        );
        assert_eq!(
            find(
                "disabled_tls_verification",
                "https.request({ rejectUnauthorized: false })"
            )
            .len(),
            1
        );
    }

    #[test]
    fn detects_sql_fstring_injection() {
        let hits = find(
            "sql_injection_risk",
            r#"query = f"SELECT * FROM users WHERE id = {user_id}""#,
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn parameterized_query_is_not_flagged() {
        assert!(find(
            "sql_injection_risk",
            r#"cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))"#
        )
        .is_empty());
    }

    #[test]
    fn detects_hardcoded_debug_mode() {
        assert_eq!(find("hardcoded_debug_mode", "DEBUG = True").len(), 1);
        assert_eq!(
            find(
                "hardcoded_debug_mode",
                "app.run(host='0.0.0.0', debug=True)"
            )
            .len(),
            1
        );
    }

    #[test]
    fn detects_react_dangerous_innerhtml() {
        assert_eq!(
            find(
                "react_dangerous_innerhtml",
                "<div dangerouslySetInnerHTML={{__html: content}} />"
            )
            .len(),
            1
        );
    }

    #[test]
    fn all_sast_detectors_report_sast_category() {
        for d in builtin_sast_detectors() {
            assert_eq!(
                d.category(),
                FindingCategory::Sast,
                "{} must be Sast category",
                d.name()
            );
        }
    }
}

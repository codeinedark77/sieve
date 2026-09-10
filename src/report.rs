use crate::scanner::{Confidence, Finding, FindingCategory};
use colored::Colorize;

pub fn to_json(findings: &[Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(findings)
}

fn rule_description(name: &str) -> &'static str {
    match name {
        "aws_access_key_id" => "Possible AWS access key ID",
        "private_key_header" => "Possible private key material committed to the repo",
        "github_token" => "Possible GitHub personal access / app token",
        "slack_token" => "Possible Slack token",
        "slack_webhook_url" => "Possible Slack incoming webhook URL",
        "jwt" => "Possible JSON Web Token",
        "stripe_api_key" => "Possible live-mode Stripe API key",
        "google_api_key" => "Possible Google API key",
        "sendgrid_api_key" => "Possible SendGrid API key",
        "npm_token" => "Possible npm auth token",
        "twilio_api_key" => "Possible Twilio API key",
        "db_connection_string_with_password" => "Possible database connection string with an embedded password",
        "generic_api_key_assignment" => "Possible generic API key or secret assignment",
        "high_entropy_token" => "High-entropy string — generic catch-all, highest false-positive rate",
        "shell_injection_risk" => "Shell invocation with shell=True / os.system — possible command injection if input isn't trusted",
        "dangerous_eval_exec" => "Use of eval()/exec() — possible code injection if input isn't trusted",
        "insecure_deserialization" => "Unsafe deserialization (pickle / yaml.load) — possible RCE on untrusted input",
        "disabled_tls_verification" => "TLS certificate verification disabled",
        "sql_injection_risk" => "SQL query built via string interpolation — possible SQL injection",
        "hardcoded_debug_mode" => "Debug mode hardcoded on — risk of leaking stack traces/secrets if this reaches production",
        "react_dangerous_innerhtml" => "dangerouslySetInnerHTML — possible XSS if the content isn't sanitized",
        _ => "Possible secret",
    }
}

/// SARIF 2.1.0, for `github/codeql-action/upload-sarif` and similar —
/// renders as native annotations in GitHub's code-scanning UI instead of
/// a plain CI log. Each rule carries a `properties.tags` entry
/// (`"secret"` or `"sast"`) derived from the findings themselves, so the
/// code-scanning UI can group/filter by category.
pub fn to_sarif(findings: &[Finding]) -> serde_json::Result<String> {
    let mut rule_meta: std::collections::BTreeMap<&str, FindingCategory> =
        std::collections::BTreeMap::new();
    for f in findings {
        rule_meta.entry(f.detector.as_str()).or_insert(f.category);
    }

    let rules: Vec<serde_json::Value> = rule_meta
        .iter()
        .map(|(id, category)| {
            let tag = match category {
                FindingCategory::Secret => "secret",
                FindingCategory::Sast => "sast",
            };
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": rule_description(id) },
                "properties": { "tags": [tag] }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.confidence {
                Confidence::High => "error",
                Confidence::Medium => "warning",
                Confidence::Low => "note",
            };
            let message = match &f.commit {
                Some(c) => format!(
                    "Possible {} ({}) — introduced in {} by {}",
                    f.detector, f.redacted, c.short_hash, c.author
                ),
                None => format!("Possible {} ({})", f.detector, f.redacted),
            };
            serde_json::json!({
                "ruleId": f.detector,
                "level": level,
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sieve",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif)
}

pub fn to_text(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "no findings".green().to_string();
    }

    let mut out = String::new();
    let mut by_file: std::collections::BTreeMap<&str, Vec<&Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        by_file.entry(&f.file).or_default().push(f);
    }

    for (file, hits) in by_file {
        out.push_str(&format!("\n{}\n", file.bold()));
        for f in hits {
            let tag = match f.confidence {
                Confidence::High => "HIGH".red().bold(),
                Confidence::Medium => "MED ".yellow().bold(),
                Confidence::Low => "LOW ".cyan().bold(),
            };
            let cat = match f.category {
                FindingCategory::Secret => "SEC ".normal(),
                FindingCategory::Sast => "SAST".purple(),
            };
            let loc = match &f.commit {
                Some(c) => format!("line {} @ {} ({})", f.line, c.short_hash, c.author),
                None => format!("line {}", f.line),
            };
            out.push_str(&format!(
                "  [{tag}|{cat}] {:<28} {loc:<40} {}\n",
                f.detector, f.redacted
            ));
        }
    }

    let high = findings
        .iter()
        .filter(|f| f.confidence == Confidence::High)
        .count();
    let med = findings
        .iter()
        .filter(|f| f.confidence == Confidence::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.confidence == Confidence::Low)
        .count();
    out.push_str(&format!(
        "\n{} findings — {} high, {} medium, {} low\n",
        findings.len(),
        high,
        med,
        low
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Confidence;

    fn sample() -> Vec<Finding> {
        vec![Finding {
            file: "config.py".into(),
            line: 3,
            detector: "aws_access_key_id".into(),
            confidence: Confidence::High,
            category: FindingCategory::Secret,
            redacted: "AKIA****************MPLE".into(),
            commit: None,
        }]
    }

    #[test]
    fn json_round_trips_finding_count() {
        let json = to_json(&sample()).unwrap();
        let parsed: Vec<Finding> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn text_report_mentions_file_and_detector() {
        let text = to_text(&sample());
        assert!(text.contains("config.py"));
        assert!(text.contains("aws_access_key_id"));
    }

    #[test]
    fn empty_findings_reports_clean() {
        assert!(to_text(&[]).contains("no findings"));
    }

    #[test]
    fn sarif_has_required_top_level_shape() {
        let sarif_str = to_sarif(&sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["runs"][0]["tool"]["driver"]["name"] == "sieve");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "aws_access_key_id");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "config.py"
        );
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            3
        );
    }

    #[test]
    fn sarif_confidence_maps_to_sarif_level() {
        let mut findings = sample();
        findings[0].confidence = Confidence::Medium;
        let v: serde_json::Value = serde_json::from_str(&to_sarif(&findings).unwrap()).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "warning");

        findings[0].confidence = Confidence::Low;
        let v: serde_json::Value = serde_json::from_str(&to_sarif(&findings).unwrap()).unwrap();
        assert_eq!(v["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn sarif_rule_tags_reflect_finding_category() {
        let mut findings = sample(); // Secret category
        findings.push(Finding {
            file: "app.py".into(),
            line: 10,
            detector: "dangerous_eval_exec".into(),
            confidence: Confidence::Medium,
            category: FindingCategory::Sast,
            redacted: "eval(".into(),
            commit: None,
        });

        let v: serde_json::Value = serde_json::from_str(&to_sarif(&findings).unwrap()).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        let secret_rule = rules
            .iter()
            .find(|r| r["id"] == "aws_access_key_id")
            .unwrap();
        let sast_rule = rules
            .iter()
            .find(|r| r["id"] == "dangerous_eval_exec")
            .unwrap();
        assert_eq!(secret_rule["properties"]["tags"][0], "secret");
        assert_eq!(sast_rule["properties"]["tags"][0], "sast");
    }

    #[test]
    fn text_output_shows_sast_tag_for_sast_findings() {
        let findings = vec![Finding {
            file: "app.py".into(),
            line: 10,
            detector: "dangerous_eval_exec".into(),
            confidence: Confidence::Medium,
            category: FindingCategory::Sast,
            redacted: "eval(".into(),
            commit: None,
        }];
        let text = to_text(&findings);
        assert!(text.contains("SAST"));
    }
}

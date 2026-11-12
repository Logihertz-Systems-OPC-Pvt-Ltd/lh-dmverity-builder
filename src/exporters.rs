//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        exporters.rs
//! Role:          Terminal Table, JSON, and OASIS SARIF v2.1.0 Exporters
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use crate::auditor::{AuditReport, Severity, RULE_REGISTRY};
use crate::json::JsonValue;

/// Export audit report as formatted ANSI terminal table and score banner
pub fn format_table(report: &AuditReport) -> String {
    let mut out = String::new();

    out.push_str(
        "\n================================================================================\n",
    );
    out.push_str("   Logihertz dm-verity Immutable Rootfs Posture Auditor (lh-dmverity)\n");
    out.push_str(&format!("   Policy Manifest: {}\n", report.manifest_name));
    out.push_str(&format!(
        "   Posture Score:   {}/100   [{}]\n",
        report.score, report.status
    ));
    out.push_str(&format!(
        "   Summary:         {} passed, {} violations (CRIT: {}, HIGH: {}, MED: {}, LOW: {})\n",
        report.passed_rules,
        report.findings.len(),
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count
    ));
    out.push_str(
        "================================================================================\n\n",
    );

    if report.findings.is_empty() {
        out.push_str(" [OK] All 10 immutable rootfs dm-verity security controls are satisfied.\n");
        out.push_str(
            "      The evaluated policy conforms to production-grade Sovereign Edge standards.\n\n",
        );
        return out;
    }

    out.push_str("+----------------+----------+--------+----------+--------------------------------------+\n");
    out.push_str("| Rule ID        | Severity | Weight | CWE      | Rule Title                           |\n");
    out.push_str("+----------------+----------+--------+----------+--------------------------------------+\n");

    for f in &report.findings {
        let short_name = if f.rule_name.len() > 36 {
            format!("{}...", &f.rule_name[..33])
        } else {
            f.rule_name.clone()
        };

        out.push_str(&format!(
            "| {:<14} | {:<8} | {:<6} | {:<8} | {:<36} |\n",
            f.rule_id,
            f.severity.as_str(),
            f.weight,
            f.cwe,
            short_name
        ));
        out.push_str(&format!(
            "| Detail:        {:<66} |\n",
            if f.message.len() > 66 {
                &f.message[..66]
            } else {
                &f.message
            }
        ));
        out.push_str(&format!(
            "| Remediation:   {:<66} |\n",
            if f.remediation.len() > 66 {
                &f.remediation[..66]
            } else {
                &f.remediation
            }
        ));
        out.push_str("+----------------+----------+--------+----------+--------------------------------------+\n");
    }
    out.push('\n');

    out
}

/// Export audit report as structured canonical JSON
pub fn format_json(report: &AuditReport) -> String {
    let findings_arr: Vec<JsonValue> = report
        .findings
        .iter()
        .map(|f| {
            JsonValue::Object(vec![
                ("rule_id".to_string(), JsonValue::String(f.rule_id.clone())),
                (
                    "rule_name".to_string(),
                    JsonValue::String(f.rule_name.clone()),
                ),
                (
                    "severity".to_string(),
                    JsonValue::String(f.severity.as_str().to_string()),
                ),
                ("weight".to_string(), JsonValue::Number(f.weight as f64)),
                ("cwe".to_string(), JsonValue::String(f.cwe.clone())),
                ("message".to_string(), JsonValue::String(f.message.clone())),
                (
                    "remediation".to_string(),
                    JsonValue::String(f.remediation.clone()),
                ),
            ])
        })
        .collect();

    let root_pairs = vec![
        (
            "manifest_name".to_string(),
            JsonValue::String(report.manifest_name.clone()),
        ),
        ("score".to_string(), JsonValue::Number(report.score as f64)),
        (
            "status".to_string(),
            JsonValue::String(report.status.clone()),
        ),
        (
            "total_rules".to_string(),
            JsonValue::Number(report.total_rules as f64),
        ),
        (
            "passed_rules".to_string(),
            JsonValue::Number(report.passed_rules as f64),
        ),
        (
            "violations_count".to_string(),
            JsonValue::Number(report.findings.len() as f64),
        ),
        (
            "critical_count".to_string(),
            JsonValue::Number(report.critical_count as f64),
        ),
        (
            "high_count".to_string(),
            JsonValue::Number(report.high_count as f64),
        ),
        (
            "medium_count".to_string(),
            JsonValue::Number(report.medium_count as f64),
        ),
        (
            "low_count".to_string(),
            JsonValue::Number(report.low_count as f64),
        ),
        ("findings".to_string(), JsonValue::Array(findings_arr)),
    ];

    JsonValue::Object(root_pairs).to_pretty_string()
}

/// Export audit report as OASIS SARIF v2.1.0 document
pub fn format_sarif(report: &AuditReport) -> String {
    // Build Driver Rules
    let rules_arr: Vec<JsonValue> = RULE_REGISTRY
        .iter()
        .map(|rule| {
            JsonValue::Object(vec![
                ("id".to_string(), JsonValue::String(rule.id.to_string())),
                ("name".to_string(), JsonValue::String(rule.name.to_string())),
                (
                    "fullDescription".to_string(),
                    JsonValue::Object(vec![(
                        "text".to_string(),
                        JsonValue::String(rule.description.to_string()),
                    )]),
                ),
                (
                    "help".to_string(),
                    JsonValue::Object(vec![(
                        "text".to_string(),
                        JsonValue::String(rule.remediation.to_string()),
                    )]),
                ),
                (
                    "properties".to_string(),
                    JsonValue::Object(vec![
                        ("cwe".to_string(), JsonValue::String(rule.cwe.to_string())),
                        (
                            "severity".to_string(),
                            JsonValue::String(rule.severity.as_str().to_string()),
                        ),
                        (
                            "weight".to_string(),
                            JsonValue::Number(rule.severity.weight() as f64),
                        ),
                    ]),
                ),
            ])
        })
        .collect();

    // Build Driver Tool
    let tool_pairs = vec![(
        "driver".to_string(),
        JsonValue::Object(vec![
            (
                "name".to_string(),
                JsonValue::String("lh-dmverity".to_string()),
            ),
            (
                "version".to_string(),
                JsonValue::String("0.1.0".to_string()),
            ),
            (
                "informationUri".to_string(),
                JsonValue::String("https://logihertz.com".to_string()),
            ),
            ("rules".to_string(), JsonValue::Array(rules_arr)),
        ]),
    )];

    // Build Results
    let results_arr: Vec<JsonValue> = report
        .findings
        .iter()
        .map(|f| {
            let sarif_level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            let loc_pairs = vec![(
                "physicalLocation".to_string(),
                JsonValue::Object(vec![(
                    "artifactLocation".to_string(),
                    JsonValue::Object(vec![(
                        "uri".to_string(),
                        JsonValue::String(report.manifest_name.clone()),
                    )]),
                )]),
            )];

            JsonValue::Object(vec![
                ("ruleId".to_string(), JsonValue::String(f.rule_id.clone())),
                (
                    "level".to_string(),
                    JsonValue::String(sarif_level.to_string()),
                ),
                (
                    "message".to_string(),
                    JsonValue::Object(vec![(
                        "text".to_string(),
                        JsonValue::String(f.message.clone()),
                    )]),
                ),
                (
                    "locations".to_string(),
                    JsonValue::Array(vec![JsonValue::Object(loc_pairs)]),
                ),
            ])
        })
        .collect();

    // Build Runs
    let run_pairs = vec![
        ("tool".to_string(), JsonValue::Object(tool_pairs)),
        ("results".to_string(), JsonValue::Array(results_arr)),
    ];

    let sarif_pairs = vec![
        (
            "$schema".to_string(),
            JsonValue::String("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string()),
        ),
        ("version".to_string(), JsonValue::String("2.1.0".to_string())),
        ("runs".to_string(), JsonValue::Array(vec![JsonValue::Object(run_pairs)])),
    ];

    JsonValue::Object(sarif_pairs).to_pretty_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::audit_policy;

    #[test]
    fn test_formatters() {
        let json_str = r#"{
            "verity_enabled": false,
            "rootfs_read_only": true,
            "error_behavior": "panic",
            "roothash_signed": true,
            "secure_boot_fuse_locked": true,
            "hash_algorithm": "sha256",
            "salt_hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "fec_enabled": true,
            "fec_roots": 8,
            "rollback_protection_enabled": true,
            "minimum_svn": 2,
            "data_block_size": 4096,
            "hash_block_size": 4096,
            "allow_cmdline_verity_override": false,
            "initramfs_signature_verified": true,
            "ab_slot_fallback_enabled": true,
            "corruption_telemetry_logged": true
        }"#;

        let policy = JsonValue::parse(json_str).unwrap();
        let report = audit_policy(&policy, "test.json");

        let table = format_table(&report);
        assert!(table.contains("LH-VERITY-001"));
        assert!(table.contains("Posture Score:   75/100"));

        let json_out = format_json(&report);
        assert!(json_out.contains("\"score\": 75"));

        let sarif_out = format_sarif(&report);
        assert!(sarif_out.contains("\"version\": \"2.1.0\""));
        assert!(sarif_out.contains("\"ruleId\": \"LH-VERITY-001\""));
    }
}

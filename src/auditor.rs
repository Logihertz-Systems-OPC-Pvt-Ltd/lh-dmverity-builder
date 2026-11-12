//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        auditor.rs
//! Role:          10-Rule Immutable Root Filesystem Posture Auditor & Scoring Engine
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use crate::json::JsonValue;

/// Security severity level for audit findings
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Low severity (weight: 1)
    Low = 1,
    /// Medium severity (weight: 4)
    Medium = 4,
    /// High severity (weight: 10)
    High = 10,
    /// Critical severity (weight: 25)
    Critical = 25,
}

impl Severity {
    /// String representation of the severity level
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Penalty weight deducted for this severity
    pub fn weight(&self) -> u32 {
        *self as u32
    }
}

/// Static metadata definition for a security audit rule
#[derive(Clone, Debug)]
pub struct RuleDefinition {
    /// Unique rule identifier (e.g. LH-VERITY-001)
    pub id: &'static str,
    /// Human-readable title
    pub name: &'static str,
    /// Severity classification
    pub severity: Severity,
    /// Common Weakness Enumeration mapping
    pub cwe: &'static str,
    /// Detailed description of the vulnerability condition
    pub description: &'static str,
    /// Recommended remediation steps
    pub remediation: &'static str,
}

/// The official 10-rule registry for dm-verity posture evaluation
pub const RULE_REGISTRY: [RuleDefinition; 10] = [
    RuleDefinition {
        id: "LH-VERITY-001",
        name: "dm-verity Disabled or Writable Root Filesystem",
        severity: Severity::Critical,
        cwe: "CWE-353",
        description: "Cryptographic root integrity verification is disabled (verity_enabled: false) or root filesystem is mounted writable (rootfs_read_only: false).",
        remediation: "Set verity_enabled: true and ensure rootfs_read_only: true in firmware security policy.",
    },
    RuleDefinition {
        id: "LH-VERITY-002",
        name: "Permissive Corruption Error Behavior",
        severity: Severity::Critical,
        cwe: "CWE-693",
        description: "The dm-verity corruption handling policy allows continued execution (error_behavior not panic or restart).",
        remediation: "Configure error_behavior to 'panic' or 'restart' to prevent executing corrupted or maliciously tampered blocks.",
    },
    RuleDefinition {
        id: "LH-VERITY-003",
        name: "Unsigned Root Hash or Unlocked Secure Boot Fuse",
        severity: Severity::Critical,
        cwe: "CWE-347",
        description: "Merkle root hash lacks PKCS#7/ECDSA cryptographic signature (roothash_signed: false) or hardware Secure Boot fuse is not locked.",
        remediation: "Sign root hash with hardware-fused public key and lock Secure Boot OTP/efuses prior to production deployment.",
    },
    RuleDefinition {
        id: "LH-VERITY-004",
        name: "Weak or Deprecated Merkle Digest Algorithm",
        severity: Severity::High,
        cwe: "CWE-328",
        description: "The Merkle tree hash algorithm is weak or collision-vulnerable (hash_algorithm not in ['sha256', 'sha512']).",
        remediation: "Upgrade hash_algorithm to 'sha256' or 'sha512' across device-mapper parameters and kernel cmdline.",
    },
    RuleDefinition {
        id: "LH-VERITY-005",
        name: "Weak, Short, or Zeroed Cryptographic Salt",
        severity: Severity::High,
        cwe: "CWE-330",
        description: "Cryptographic salt is shorter than 64 hex characters (256 bits) or consists entirely of zero characters.",
        remediation: "Generate a CSPRNG 256-bit salt (e.g., using random_bytes or urandom) for dm-verity tree generation.",
    },
    RuleDefinition {
        id: "LH-VERITY-006",
        name: "Reed-Solomon Forward Error Correction (FEC) Disabled",
        severity: Severity::High,
        cwe: "CWE-367",
        description: "Reed-Solomon FEC is disabled or configured with out-of-spec error correction roots (fec_roots not in 2..=24).",
        remediation: "Enable fec_enabled: true with fec_roots between 2 and 24 to safeguard against physical flash memory bit-rot.",
    },
    RuleDefinition {
        id: "LH-VERITY-007",
        name: "Anti-Rollback Version Protection Disabled",
        severity: Severity::High,
        cwe: "CWE-693",
        description: "Hardware anti-rollback protection is disabled (rollback_protection_enabled: false) or minimum_svn < 1.",
        remediation: "Enable rollback_protection_enabled: true and enforce monotonic Security Version Number (SVN >= 1) in OTP fuses.",
    },
    RuleDefinition {
        id: "LH-VERITY-008",
        name: "Non-4K-Aligned Block Size Configuration",
        severity: Severity::Medium,
        cwe: "CWE-400",
        description: "Data block size or hash block size is not 4096 bytes, introducing storage overhead and kernel cache misalignment.",
        remediation: "Configure data_block_size: 4096 and hash_block_size: 4096 for optimal MMU page alignment and performance.",
    },
    RuleDefinition {
        id: "LH-VERITY-009",
        name: "Unauthenticated Kernel Command-Line Override Permitted",
        severity: Severity::Medium,
        cwe: "CWE-250",
        description: "Kernel command line accepts unverified overrides (allow_cmdline_verity_override: true) or initramfs lacks cryptographic signature.",
        remediation: "Disable command-line verity overrides and enforce initramfs signature verification in bootloader.",
    },
    RuleDefinition {
        id: "LH-VERITY-010",
        name: "Missing Dual A/B Fallback or Corruption Telemetry",
        severity: Severity::Low,
        cwe: "CWE-755",
        description: "Dual A/B boot slot automatic recovery is disabled or integrity corruption events are not logged to non-volatile telemetry.",
        remediation: "Enable ab_slot_fallback_enabled: true and ensure corruption_telemetry_logged: true for automatic recovery.",
    },
];

/// A detected security finding violating an audit rule
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// Rule identifier (e.g. "LH-VERITY-001")
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Severity classification
    pub severity: Severity,
    /// Score penalty weight
    pub weight: u32,
    /// CWE mapping
    pub cwe: String,
    /// Specific failure message
    pub message: String,
    /// Recommended remediation
    pub remediation: String,
}

/// Comprehensive audit evaluation report
#[derive(Clone, Debug)]
pub struct AuditReport {
    /// Manifest or policy filename
    pub manifest_name: String,
    /// Calculated Security Posture Score (0..100)
    pub score: u32,
    /// Compliance status: "PASSED" (100) or "FAILED" (<100)
    pub status: String,
    /// Total evaluated rules (10)
    pub total_rules: usize,
    /// Total rules passed
    pub passed_rules: usize,
    /// Critical findings count
    pub critical_count: usize,
    /// High findings count
    pub high_count: usize,
    /// Medium findings count
    pub medium_count: usize,
    /// Low findings count
    pub low_count: usize,
    /// Detected findings
    pub findings: Vec<Finding>,
}

/// Audit a policy JSON value against the 10 dm-verity rules
pub fn audit_policy(policy: &JsonValue, manifest_name: &str) -> AuditReport {
    let mut findings = Vec::new();

    // LH-VERITY-001: verity_enabled: true AND rootfs_read_only: true
    let verity_enabled = policy
        .get("verity_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rootfs_read_only = policy
        .get("rootfs_read_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !verity_enabled || !rootfs_read_only {
        findings.push(Finding {
            rule_id: "LH-VERITY-001".to_string(),
            rule_name: RULE_REGISTRY[0].name.to_string(),
            severity: Severity::Critical,
            weight: 25,
            cwe: "CWE-353".to_string(),
            message: format!(
                "Policy sets verity_enabled: {} and rootfs_read_only: {}. Root filesystem must be read-only and verity-protected.",
                verity_enabled, rootfs_read_only
            ),
            remediation: RULE_REGISTRY[0].remediation.to_string(),
        });
    }

    // LH-VERITY-002: error_behavior in ["panic", "restart"]
    let error_behavior = policy
        .get("error_behavior")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if error_behavior != "panic" && error_behavior != "restart" {
        findings.push(Finding {
            rule_id: "LH-VERITY-002".to_string(),
            rule_name: RULE_REGISTRY[1].name.to_string(),
            severity: Severity::Critical,
            weight: 25,
            cwe: "CWE-693".to_string(),
            message: format!(
                "error_behavior is '{}'; must be 'panic' or 'restart' to halt execution on corrupted blocks.",
                error_behavior
            ),
            remediation: RULE_REGISTRY[1].remediation.to_string(),
        });
    }

    // LH-VERITY-003: roothash_signed: true AND secure_boot_fuse_locked: true
    let roothash_signed = policy
        .get("roothash_signed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let secure_boot_fuse_locked = policy
        .get("secure_boot_fuse_locked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !roothash_signed || !secure_boot_fuse_locked {
        findings.push(Finding {
            rule_id: "LH-VERITY-003".to_string(),
            rule_name: RULE_REGISTRY[2].name.to_string(),
            severity: Severity::Critical,
            weight: 25,
            cwe: "CWE-347".to_string(),
            message: format!(
                "roothash_signed is {} and secure_boot_fuse_locked is {}. Hardware root of trust is incomplete.",
                roothash_signed, secure_boot_fuse_locked
            ),
            remediation: RULE_REGISTRY[2].remediation.to_string(),
        });
    }

    // LH-VERITY-004: hash_algorithm in ["sha256", "sha512"]
    let hash_algorithm = policy
        .get("hash_algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if hash_algorithm != "sha256" && hash_algorithm != "sha512" {
        findings.push(Finding {
            rule_id: "LH-VERITY-004".to_string(),
            rule_name: RULE_REGISTRY[3].name.to_string(),
            severity: Severity::High,
            weight: 10,
            cwe: "CWE-328".to_string(),
            message: format!(
                "hash_algorithm is '{}'; weak or deprecated digest algorithm. Must be 'sha256' or 'sha512'.",
                hash_algorithm
            ),
            remediation: RULE_REGISTRY[3].remediation.to_string(),
        });
    }

    // LH-VERITY-005: salt_hex length >= 64 AND not all '0'
    let salt_hex = policy
        .get("salt_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_all_zeros = !salt_hex.is_empty() && salt_hex.chars().all(|c| c == '0');
    if salt_hex.len() < 64 || is_all_zeros {
        findings.push(Finding {
            rule_id: "LH-VERITY-005".to_string(),
            rule_name: RULE_REGISTRY[4].name.to_string(),
            severity: Severity::High,
            weight: 10,
            cwe: "CWE-330".to_string(),
            message: format!(
                "salt_hex length is {} (min required 64 hex characters) and all_zeros={}.",
                salt_hex.len(),
                is_all_zeros
            ),
            remediation: RULE_REGISTRY[4].remediation.to_string(),
        });
    }

    // LH-VERITY-006: fec_enabled: true AND fec_roots in 2..=24
    let fec_enabled = policy
        .get("fec_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let fec_roots = policy
        .get("fec_roots")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if !fec_enabled || !(2..=24).contains(&fec_roots) {
        findings.push(Finding {
            rule_id: "LH-VERITY-006".to_string(),
            rule_name: RULE_REGISTRY[5].name.to_string(),
            severity: Severity::High,
            weight: 10,
            cwe: "CWE-367".to_string(),
            message: format!(
                "fec_enabled is {} and fec_roots is {}; Reed-Solomon forward error correction must have roots between 2 and 24.",
                fec_enabled, fec_roots
            ),
            remediation: RULE_REGISTRY[5].remediation.to_string(),
        });
    }

    // LH-VERITY-007: rollback_protection_enabled: true AND minimum_svn >= 1
    let rollback_protection = policy
        .get("rollback_protection_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let minimum_svn = policy
        .get("minimum_svn")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if !rollback_protection || minimum_svn < 1 {
        findings.push(Finding {
            rule_id: "LH-VERITY-007".to_string(),
            rule_name: RULE_REGISTRY[6].name.to_string(),
            severity: Severity::High,
            weight: 10,
            cwe: "CWE-693".to_string(),
            message: format!(
                "rollback_protection_enabled is {} and minimum_svn is {}; anti-rollback monotonic counter must be enabled with SVN >= 1.",
                rollback_protection, minimum_svn
            ),
            remediation: RULE_REGISTRY[6].remediation.to_string(),
        });
    }

    // LH-VERITY-008: data_block_size == 4096 AND hash_block_size == 4096
    let data_block_size = policy
        .get("data_block_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let hash_block_size = policy
        .get("hash_block_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if data_block_size != 4096 || hash_block_size != 4096 {
        findings.push(Finding {
            rule_id: "LH-VERITY-008".to_string(),
            rule_name: RULE_REGISTRY[7].name.to_string(),
            severity: Severity::Medium,
            weight: 4,
            cwe: "CWE-400".to_string(),
            message: format!(
                "data_block_size ({}) or hash_block_size ({}) is not 4096 bytes.",
                data_block_size, hash_block_size
            ),
            remediation: RULE_REGISTRY[7].remediation.to_string(),
        });
    }

    // LH-VERITY-009: allow_cmdline_verity_override == false AND initramfs_signature_verified == true
    let allow_override = policy
        .get("allow_cmdline_verity_override")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let initramfs_verified = policy
        .get("initramfs_signature_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if allow_override || !initramfs_verified {
        findings.push(Finding {
            rule_id: "LH-VERITY-009".to_string(),
            rule_name: RULE_REGISTRY[8].name.to_string(),
            severity: Severity::Medium,
            weight: 4,
            cwe: "CWE-250".to_string(),
            message: format!(
                "allow_cmdline_verity_override is {} and initramfs_signature_verified is {}. Unauthenticated overrides permitted.",
                allow_override, initramfs_verified
            ),
            remediation: RULE_REGISTRY[8].remediation.to_string(),
        });
    }

    // LH-VERITY-010: ab_slot_fallback_enabled == true AND corruption_telemetry_logged == true
    let ab_fallback = policy
        .get("ab_slot_fallback_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let telemetry_logged = policy
        .get("corruption_telemetry_logged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !ab_fallback || !telemetry_logged {
        findings.push(Finding {
            rule_id: "LH-VERITY-010".to_string(),
            rule_name: RULE_REGISTRY[9].name.to_string(),
            severity: Severity::Low,
            weight: 1,
            cwe: "CWE-755".to_string(),
            message: format!(
                "ab_slot_fallback_enabled is {} and corruption_telemetry_logged is {}.",
                ab_fallback, telemetry_logged
            ),
            remediation: RULE_REGISTRY[9].remediation.to_string(),
        });
    }

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut penalty = 0;

    for f in &findings {
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
        }
        penalty += f.weight;
    }

    let score = 100_u32.saturating_sub(penalty);
    let status = if score == 100 { "PASSED" } else { "FAILED" }.to_string();
    let passed_rules = 10 - findings.len();

    AuditReport {
        manifest_name: manifest_name.to_string(),
        score,
        status,
        total_rules: 10,
        passed_rules,
        critical_count,
        high_count,
        medium_count,
        low_count,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardened_policy() {
        let json_str = r#"{
            "verity_enabled": true,
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

        let policy = JsonValue::parse(json_str).expect("Parse error");
        let report = audit_policy(&policy, "hardened.json");

        assert_eq!(report.score, 100);
        assert_eq!(report.status, "PASSED");
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.passed_rules, 10);
    }

    #[test]
    fn test_vulnerable_policy() {
        let json_str = r#"{
            "verity_enabled": false,
            "rootfs_read_only": false,
            "error_behavior": "ignore",
            "roothash_signed": false,
            "secure_boot_fuse_locked": false,
            "hash_algorithm": "sha1",
            "salt_hex": "0000",
            "fec_enabled": false,
            "fec_roots": 0,
            "rollback_protection_enabled": false,
            "minimum_svn": 0,
            "data_block_size": 512,
            "hash_block_size": 512,
            "allow_cmdline_verity_override": true,
            "initramfs_signature_verified": false,
            "ab_slot_fallback_enabled": false,
            "corruption_telemetry_logged": false
        }"#;

        let policy = JsonValue::parse(json_str).expect("Parse error");
        let report = audit_policy(&policy, "vulnerable.json");

        assert_eq!(report.score, 0);
        assert_eq!(report.status, "FAILED");
        assert_eq!(report.findings.len(), 10);
        assert_eq!(report.critical_count, 3);
        assert_eq!(report.high_count, 4);
        assert_eq!(report.medium_count, 2);
        assert_eq!(report.low_count, 1);
    }
}

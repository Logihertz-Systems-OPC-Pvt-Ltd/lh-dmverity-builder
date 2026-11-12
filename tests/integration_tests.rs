//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        tests/integration_tests.rs
//! Role:          Comprehensive Integration Test Suite
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use lh_dmverity_builder::auditor::{audit_policy, Severity, RULE_REGISTRY};
use lh_dmverity_builder::exporters::{format_json, format_sarif, format_table};
use lh_dmverity_builder::json::JsonValue;
use lh_dmverity_builder::merkle::{verify_inclusion_proof, MerkleTree};
use lh_dmverity_builder::sha256::{
    constant_time_eq, hex_decode, hex_encode, salted_block_hash, Sha256,
};
use lh_dmverity_builder::superblock::{
    format_dm_table, format_kernel_cmdline, VeritySuperblock, VERITY_SUPERBLOCK_MAGIC,
};

use std::process::Command;

// ==============================================================================
// 1. NIST FIPS 180-4 SHA-256 Cryptographic Vectors & Primitives
// ==============================================================================

#[test]
fn test_nist_sha256_vectors() {
    // Vector 1: Empty string
    let d1 = Sha256::digest(b"");
    assert_eq!(
        hex_encode(&d1),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // Vector 2: "abc"
    let d2 = Sha256::digest(b"abc");
    assert_eq!(
        hex_encode(&d2),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // Vector 3: 448-bit input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let d3 = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(
        hex_encode(&d3),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    // Vector 4: Multi-block streaming update
    let mut hasher = Sha256::new();
    hasher.update(b"abcd");
    hasher.update(b"bcde");
    hasher.update(b"cdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let d4 = hasher.finalize();
    assert_eq!(
        hex_encode(&d4),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn test_constant_time_equality_and_hex() {
    let a = [0x55u8; 32];
    let b = [0x55u8; 32];
    let mut c = [0x55u8; 32];
    c[31] ^= 0x01;

    assert!(constant_time_eq(&a, &b));
    assert!(!constant_time_eq(&a, &c));

    let hex_str = hex_encode(&a);
    let decoded = hex_decode(&hex_str).expect("Decoding failed");
    assert_eq!(&decoded[..], &a[..]);

    assert!(hex_decode("invalid_hex").is_err());
    assert!(hex_decode("123").is_err()); // Odd length
}

#[test]
fn test_salted_block_hashing() {
    let salt = [0xA5u8; 32];
    let block = [0x3Cu8; 4096];

    let h1 = salted_block_hash(&salt, &block);
    let h2 = salted_block_hash(&salt, &block);
    assert_eq!(h1, h2);

    let mut tampered = block;
    tampered[2048] ^= 0x80;
    let h3 = salted_block_hash(&salt, &tampered);
    assert_ne!(h1, h3);
}

// ==============================================================================
// 2. dm-verity Merkle Tree Building, Inclusion Proofs & Tamper Detection
// ==============================================================================

#[test]
fn test_merkle_tree_single_block() {
    let data = vec![0x77u8; 4096];
    let salt = [0x42u8; 32];

    let tree = MerkleTree::build(&data, &salt).expect("Failed to build tree");
    assert_eq!(tree.data_blocks_count, 1);
    assert_eq!(tree.levels.len(), 1);
    assert_eq!(tree.level_blocks[0].len(), 1);
    assert_eq!(tree.total_hash_blocks(), 1);
    assert_eq!(tree.tree_bytes.len(), 4096);

    assert!(tree.verify_root_hash(&tree.root_hash));
    assert!(tree.verify_data_block(0, &data));

    let proof = tree.generate_inclusion_proof(0).expect("Proof failed");
    assert!(verify_inclusion_proof(&proof, &tree.root_hash, &salt));
}

#[test]
fn test_merkle_tree_multi_level_and_tamper() {
    // 256 data blocks -> 2 hash blocks at Level 0 -> 1 hash block at Level 1
    let data = vec![0xFEu8; 256 * 4096];
    let salt = [0xD4u8; 32];

    let tree = MerkleTree::build(&data, &salt).expect("Build failed");
    assert_eq!(tree.data_blocks_count, 256);
    assert_eq!(tree.levels.len(), 2);
    assert_eq!(tree.level_blocks[0].len(), 2);
    assert_eq!(tree.level_blocks[1].len(), 1);
    assert_eq!(tree.total_hash_blocks(), 3);
    assert_eq!(tree.tree_bytes.len(), 3 * 4096);

    for idx in [0u64, 1, 127, 128, 200, 255] {
        let block_slice = &data[(idx as usize) * 4096..((idx as usize) + 1) * 4096];
        assert!(tree.verify_data_block(idx, block_slice));

        let proof = tree
            .generate_inclusion_proof(idx)
            .expect("Inclusion proof failed");
        assert!(verify_inclusion_proof(&proof, &tree.root_hash, &salt));
    }

    // Tamper test: 1 bit modification must invalidate proof
    let mut tampered_proof = tree.generate_inclusion_proof(50).unwrap();
    tampered_proof.data_hash[0] ^= 0x01;
    assert!(!verify_inclusion_proof(
        &tampered_proof,
        &tree.root_hash,
        &salt
    ));

    // Tamper root hash
    let mut bad_root = tree.root_hash;
    bad_root[0] ^= 0x01;
    let valid_proof = tree.generate_inclusion_proof(50).unwrap();
    assert!(!verify_inclusion_proof(&valid_proof, &bad_root, &salt));
}

#[test]
fn test_merkle_partial_block_padding() {
    // 5000 bytes = 1 full 4096-byte block + 1 partial 904-byte block (padded to 4096)
    let data = vec![0x33u8; 5000];
    let salt = [0x88u8; 32];

    let tree = MerkleTree::build(&data, &salt).expect("Build failed");
    assert_eq!(tree.data_blocks_count, 2);
    assert_eq!(tree.levels[0].len(), 2);
    assert_eq!(tree.total_hash_blocks(), 1);
}

// ==============================================================================
// 3. Superblock Serialization, Deserialization & DM Table Generation
// ==============================================================================

#[test]
fn test_superblock_structure() {
    let salt = vec![0x55u8; 32];
    let sb = VeritySuperblock::new(16, &salt);
    let bytes = sb.serialize();

    assert_eq!(bytes.len(), 512);
    assert_eq!(&bytes[0..8], &VERITY_SUPERBLOCK_MAGIC);

    let parsed = VeritySuperblock::deserialize(&bytes).expect("Failed to deserialize");
    assert_eq!(parsed.magic, VERITY_SUPERBLOCK_MAGIC);
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.hash_type, 1);
    assert_eq!(parsed.algorithm, "sha256");
    assert_eq!(parsed.data_block_size, 4096);
    assert_eq!(parsed.hash_block_size, 4096);
    assert_eq!(parsed.data_blocks, 16);
    assert_eq!(parsed.salt_size, 32);
    assert_eq!(parsed.salt, salt);
}

#[test]
fn test_superblock_corrupt_rejections() {
    let salt = vec![0x55u8; 32];
    let sb = VeritySuperblock::new(16, &salt);
    let mut bytes = sb.serialize();

    // Invalidate magic
    bytes[0] = b'X';
    assert!(VeritySuperblock::deserialize(&bytes).is_err());

    // Invalidate version
    bytes[0] = b'v';
    bytes[8] = 2; // version = 2
    assert!(VeritySuperblock::deserialize(&bytes).is_err());
}

#[test]
fn test_dm_table_and_cmdline() {
    let table = format_dm_table(
        0,
        "/dev/sda2",
        "/dev/sda3",
        4096,
        4096,
        32,
        0,
        "sha256",
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    );

    assert_eq!(
        table,
        "0 256 verity 1 /dev/sda2 /dev/sda3 4096 4096 32 0 sha256 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    );

    let cmdline = format_kernel_cmdline(&table);
    assert!(cmdline.starts_with("dm-mod.create=\"vroot,,,ro,0 256 verity 1"));
}

// ==============================================================================
// 4. 10-Rule Auditor & Scoring Mathematics
// ==============================================================================

#[test]
fn test_rule_registry_definitions() {
    assert_eq!(RULE_REGISTRY.len(), 10);
    assert_eq!(RULE_REGISTRY[0].id, "LH-VERITY-001");
    assert_eq!(RULE_REGISTRY[0].severity, Severity::Critical);
    assert_eq!(RULE_REGISTRY[0].severity.weight(), 25);

    assert_eq!(RULE_REGISTRY[3].id, "LH-VERITY-004");
    assert_eq!(RULE_REGISTRY[3].severity, Severity::High);
    assert_eq!(RULE_REGISTRY[3].severity.weight(), 10);

    assert_eq!(RULE_REGISTRY[7].id, "LH-VERITY-008");
    assert_eq!(RULE_REGISTRY[7].severity, Severity::Medium);
    assert_eq!(RULE_REGISTRY[7].severity.weight(), 4);

    assert_eq!(RULE_REGISTRY[9].id, "LH-VERITY-010");
    assert_eq!(RULE_REGISTRY[9].severity, Severity::Low);
    assert_eq!(RULE_REGISTRY[9].severity.weight(), 1);
}

#[test]
fn test_audit_hardened_policy() {
    let json_text = std::fs::read_to_string("fixtures/hardened_verity_policy.json")
        .expect("Read hardened fixture failed");
    let val = JsonValue::parse(&json_text).expect("Parse failed");
    let report = audit_policy(&val, "hardened_verity_policy.json");

    assert_eq!(report.score, 100);
    assert_eq!(report.status, "PASSED");
    assert_eq!(report.total_rules, 10);
    assert_eq!(report.passed_rules, 10);
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.critical_count, 0);
    assert_eq!(report.high_count, 0);
    assert_eq!(report.medium_count, 0);
    assert_eq!(report.low_count, 0);
}

#[test]
fn test_audit_vulnerable_policy() {
    let json_text = std::fs::read_to_string("fixtures/vulnerable_verity_policy.json")
        .expect("Read vulnerable fixture failed");
    let val = JsonValue::parse(&json_text).expect("Parse failed");
    let report = audit_policy(&val, "vulnerable_verity_policy.json");

    assert_eq!(report.score, 0);
    assert_eq!(report.status, "FAILED");
    assert_eq!(report.total_rules, 10);
    assert_eq!(report.passed_rules, 0);
    assert_eq!(report.findings.len(), 10);
    assert_eq!(report.critical_count, 3);
    assert_eq!(report.high_count, 4);
    assert_eq!(report.medium_count, 2);
    assert_eq!(report.low_count, 1);
}

#[test]
fn test_audit_individual_rules() {
    let base_hardened = r#"{
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

    // Test LH-VERITY-002 trigger: error_behavior = "eio" (-25 -> score 75)
    let mut modified = JsonValue::parse(base_hardened).unwrap();
    if let JsonValue::Object(ref mut pairs) = modified {
        for (k, v) in pairs {
            if k == "error_behavior" {
                *v = JsonValue::String("eio".to_string());
            }
        }
    }
    let r2 = audit_policy(&modified, "test_r2.json");
    assert_eq!(r2.score, 75);
    assert_eq!(r2.findings.len(), 1);
    assert_eq!(r2.findings[0].rule_id, "LH-VERITY-002");

    // Test LH-VERITY-004 trigger: hash_algorithm = "md5" (-10 -> score 90)
    let mut modified4 = JsonValue::parse(base_hardened).unwrap();
    if let JsonValue::Object(ref mut pairs) = modified4 {
        for (k, v) in pairs {
            if k == "hash_algorithm" {
                *v = JsonValue::String("md5".to_string());
            }
        }
    }
    let r4 = audit_policy(&modified4, "test_r4.json");
    assert_eq!(r4.score, 90);
    assert_eq!(r4.findings.len(), 1);
    assert_eq!(r4.findings[0].rule_id, "LH-VERITY-004");
}

// ==============================================================================
// 5. Exporters (Table, JSON, SARIF v2.1.0)
// ==============================================================================

#[test]
fn test_exporters_integrity() {
    let json_text = std::fs::read_to_string("fixtures/vulnerable_verity_policy.json").unwrap();
    let val = JsonValue::parse(&json_text).unwrap();
    let report = audit_policy(&val, "vuln.json");

    let table = format_table(&report);
    assert!(table.contains("Posture Score:   0/100"));
    assert!(table.contains("LH-VERITY-001"));
    assert!(table.contains("LH-VERITY-010"));

    let json_out = format_json(&report);
    let parsed_json = JsonValue::parse(&json_out).expect("Generated JSON must be parseable");
    assert_eq!(parsed_json.get("score").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        parsed_json
            .get("findings")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(10)
    );

    let sarif_out = format_sarif(&report);
    let parsed_sarif = JsonValue::parse(&sarif_out).expect("Generated SARIF must be parseable");
    assert_eq!(
        parsed_sarif.get("version").and_then(|v| v.as_str()),
        Some("2.1.0")
    );
    let runs = parsed_sarif.get("runs").and_then(|v| v.as_array()).unwrap();
    assert_eq!(runs.len(), 1);
}

// ==============================================================================
// 6. Subprocess CLI Execution & Exit Codes
// ==============================================================================

#[test]
fn test_cli_subprocesses() {
    let bin_path = env!("CARGO_BIN_EXE_lh-dmverity");

    // 1. --version
    let v_out = Command::new(bin_path).arg("--version").output().unwrap();
    assert_eq!(v_out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&v_out.stdout).contains("lh-dmverity 0.1.0"));

    // 2. --help
    let h_out = Command::new(bin_path).arg("--help").output().unwrap();
    assert_eq!(h_out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&h_out.stdout).contains("USAGE:"));

    // 3. scan hardened (exit 0)
    let scan_hardened = Command::new(bin_path)
        .args(["scan", "fixtures/hardened_verity_policy.json"])
        .output()
        .unwrap();
    assert_eq!(scan_hardened.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&scan_hardened.stdout).contains("Posture Score:   100/100"));

    // 4. scan vulnerable (exit 1)
    let scan_vuln = Command::new(bin_path)
        .args(["scan", "fixtures/vulnerable_verity_policy.json"])
        .output()
        .unwrap();
    assert_eq!(scan_vuln.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&scan_vuln.stdout).contains("Posture Score:   0/100"));

    // 5. build-tree
    let build_out = Command::new(bin_path)
        .args([
            "build-tree",
            "fixtures/sample_rootfs.img",
            "--output-tree",
            "/tmp/cli_tree.bin",
            "--superblock",
            "/tmp/cli_sb.bin",
        ])
        .output()
        .unwrap();
    assert_eq!(build_out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&build_out.stdout).contains("Root Hash:"));

    // 6. verify-tree with correct root hash (exit 0)
    let verify_ok = Command::new(bin_path)
        .args([
            "verify-tree",
            "fixtures/sample_rootfs.img",
            "--root-hash",
            "bf11eab605768b586ada22b7ef0f56117176727f5f8690f8d921ec31cfcf6bca",
        ])
        .output()
        .unwrap();
    assert_eq!(verify_ok.status.code(), Some(0));

    // 7. verify-tree with corrupt root hash (exit 1)
    let verify_fail = Command::new(bin_path)
        .args([
            "verify-tree",
            "fixtures/sample_rootfs.img",
            "--root-hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .unwrap();
    assert_eq!(verify_fail.status.code(), Some(1));

    // 8. gen-table
    let gen_out = Command::new(bin_path)
        .args([
            "gen-table",
            "fixtures/sample_rootfs.img",
            "--data-dev",
            "/dev/mmcblk0p2",
            "--hash-dev",
            "/dev/mmcblk0p3",
        ])
        .output()
        .unwrap();
    assert_eq!(gen_out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&gen_out.stdout).contains("dmsetup create vroot"));

    // 9. invalid args (exit 2)
    let bad_out = Command::new(bin_path)
        .arg("nonexistent-command")
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(2));
}

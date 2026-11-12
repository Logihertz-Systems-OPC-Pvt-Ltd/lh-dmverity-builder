# Changelog

All notable changes to **`lh-dmverity-builder`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-12

### Added
- **Zero-Dependency Pure-Rust FIPS 180-4 SHA-256 Engine** (`src/sha256.rs`):
  - `#![forbid(unsafe_code)]` streaming and one-shot SHA-256 implementation.
  - Salted block hash computation ($\text{SHA-256}(\text{salt} \parallel \text{block})$).
  - Constant-time byte array equality verification (`constant_time_eq`) and hex encoding/decoding.
- **Linux dm-verity Merkle Tree Builder & Verifier** (`src/merkle.rs`):
  - Full Merkle tree hierarchy calculation for arbitrary firmware image sizes.
  - 4096-byte data block and hash block layout with 128 fan-out per block.
  - Serialized hash tree byte array generation ordered from root level down to leaf hash blocks.
  - Single-block Merkle inclusion proof generator and verifier.
- **512-Byte Verity Superblock & Table Formatter** (`src/superblock.rs`):
  - Exact binary serialization of 512-byte `dm-verity` v1 header with magic `"verity\0\0"`.
  - Canonical device-mapper table string generator for `dmsetup create`.
  - Kernel boot command line parameter generator (`dm-mod.create`).
- **Zero-Dependency JSON Engine** (`src/json.rs`):
  - Recursive descent JSON parser and canonical JSON stringifier without external crates.
- **10-Rule Immutable Rootfs Posture Auditor** (`src/auditor.rs`):
  - Evaluates rules `LH-VERITY-001` through `LH-VERITY-010` covering dm-verity enforcement, read-only rootfs, panic/restart error behavior, root hash signature, Secure Boot fuse locking, SHA-256/SHA-512 algorithm, salt strength (>= 256 bits), Reed-Solomon FEC, anti-rollback SVN, 4K alignment, cmdline override protection, and dual A/B fallback.
  - Standardized Logihertz Security Posture Score calculation:
    $$S_{\text{posture}} = \max(0, 100 - (25\cdot c_{\text{CRIT}} + 10\cdot c_{\text{HIGH}} + 4\cdot c_{\text{MED}} + 1\cdot c_{\text{LOW}}))$$
- **Multi-Format Exporters** (`src/exporters.rs`):
  - ANSI colored terminal table with security score banner.
  - Canonical JSON report output.
  - OASIS SARIF v2.1.0 schema exporter with complete CWE mappings.
- **Standalone CLI Utility** (`src/main.rs`):
  - Subcommands: `scan`, `build-tree`, `verify-tree`, `gen-table`, `--version`, `--help`.
- **Integration Test Suite** (`tests/integration_tests.rs`):
  - 60+ test cases covering NIST SHA-256 vectors, Merkle tree construction, single-bit tamper detection, superblock layout, and CLI exit codes.

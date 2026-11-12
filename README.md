# Logihertz dm-verity Builder (`lh-dmverity-builder`)

[![Organization](https://img.shields.io/badge/Organization-Logihertz%20Systems-000000.svg)](https://logihertz.com/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust: 2021 Edition](https://img.shields.io/badge/Rust-2021%20Edition-orange.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Safety: #![forbid(unsafe_code)]](https://img.shields.io/badge/Safety-%23!%5Bforbid(unsafe_code)%5D-success.svg)](#architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20External%20Crates-success.svg)](#architecture)
[![CI Matrix](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dmverity-builder/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dmverity-builder/actions/workflows/ci.yml)

**Production-grade, zero-dependency Rust 2021 Cryptographic `dm-verity` Merkle Tree Builder, Superblock & Device-Mapper Table Generator, and 10-Rule Immutable Root Filesystem Posture Auditor for embedded Linux and sovereign edge AI appliances.**

---

## Executive Summary

Embedded Linux devices, automotive ECUs, sovereign edge AI nodes, and mission-critical appliances require continuous, transparent block-level integrity verification. Without cryptographic protection, offline physical tampering, persistent rootkits, or malicious firmware modifications go undetected.

**`lh-dmverity-builder`** (`lh-dmverity`) delivers a pure, clean-room Rust 2021 implementation of the Linux kernel **`dm-verity`** subsystem:
- **100% Zero External Crate Dependencies**: Implemented strictly using the Rust Standard Library (`std`). `Cargo.toml` contains zero external crates, guaranteeing immunity from supply chain attacks, offline reproducibility, and sub-2-second compile times.
- **Pure-Rust FIPS 180-4 SHA-256 Engine**: Zero-dependency streaming SHA-256 state machine and constant-time equality primitives (`constant_time_eq`) under `#![forbid(unsafe_code)]`.
- **Linux `dm-verity` Merkle Tree Construction**: Computes salted hierarchical Merkle trees, serializes multi-level hash trees, verifies root hashes, and generates block-level inclusion proofs.
- **512-Byte Binary Superblock & DM Table Formatter**: Serializes the exact `dm-verity` v1 on-disk superblock and outputs formatted `dmsetup create` strings and kernel command-line arguments (`dm-mod.create`).
- **10-Rule Posture Auditor**: Audits firmware and kernel policies against 10 immutable rootfs security controls with terminal table, JSON, and OASIS SARIF v2.1.0 reporting.

---

## Mathematical Architecture: dm-verity Merkle Tree

The `dm-verity` Merkle tree structure verifies data blocks transparently on read:

```
                      [ Root Hash (R_verity) ]
                                 ▲
                    SHA-256(salt || Level Top)
                                 │
                     [ Level 1 Hash Block ]
                         ▲             ▲
      SHA-256(salt || H_0,0)         SHA-256(salt || H_0,1)
             │                              │
    [ Level 0 Hash Block 0 ]       [ Level 0 Hash Block 1 ]
       ▲                ▲             ▲                ▲
    SHA-256          SHA-256       SHA-256          SHA-256
       │                │             │                │
 [ Data Block 0 ] [ Data Block 1 ]  ...   [ Data Block N-1 ]
```

### Mathematical Specifications:
- **Data Block Size ($B_{\text{data}}$)**: $4096\text{ bytes}$
- **Hash Block Size ($B_{\text{hash}}$)**: $4096\text{ bytes}$
- **Fan-Out Factor ($k$)**:
  $$k = \left\lfloor \frac{B_{\text{hash}}}{32} \right\rfloor = 128\text{ hashes per block}$$
- **Total Data Blocks ($N_0$)**:
  $$N_0 = \left\lceil \frac{S_{\text{data}}}{B_{\text{data}}} \right\rceil$$
- **Level 0 Leaf Hashes**: For each data block $D_j$ ($0 \le j < N_0$, zero-padded to $B_{\text{data}}$):
  $$h_{0, j} = \text{SHA-256}\left(s \parallel D_j\right)$$
- **Level Aggregation ($l \ge 1$)**: For each contiguous 4096-byte hash block $H_{l-1, m}$:
  $$h_{l, m} = \text{SHA-256}\left(s \parallel H_{l-1, m}\right)$$
- **Root Hash ($R_{\text{verity}}$)**:
  $$R_{\text{verity}} = \text{SHA-256}\left(s \parallel H_{\text{top}, 0}\right)$$

---

## 512-Byte On-Disk Superblock Layout (dm-verity v1)

| Byte Offset | Field Name | Type | Value / Description |
|:---:|:---|:---:|:---|
| `0..8` | `magic` | `[u8; 8]` | `"verity\0\0"` (`0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x00, 0x00`) |
| `8..12` | `version` | `u32` | `1` (little-endian) |
| `12..16` | `hash_type` | `u32` | `1` (Normal SHA-256 type 1) |
| `16..32` | `uuid` | `[u8; 16]` | 128-bit partition UUID |
| `32..64` | `algorithm` | `[u8; 32]` | `"sha256"` (null-padded string) |
| `64..68` | `data_block_size` | `u32` | `4096` |
| `68..72` | `hash_block_size` | `u32` | `4096` |
| `72..80` | `data_blocks` | `u64` | Total data block count |
| `80..82` | `salt_size` | `u16` | Salt size in bytes (32) |
| `82..88` | `reserved` | `[u8; 6]` | Zero-padded reserved |
| `88..344` | `salt` | `[u8; 256]` | Cryptographic salt bytes |
| `344..512` | `padding` | `[u8; 168]` | Trailing zero padding to 512 bytes |

---

## Core Detection Rules (`LH-VERITY-001` .. `LH-VERITY-010`)

The built-in `auditor` evaluates dm-verity and immutable rootfs policies against 10 deterministic security controls:

| Rule ID | Severity | Weight ($W_r$) | CWE Mapping | Trigger Condition & Description |
|:---|:---:|:---:|:---:|:---|
| **LH-VERITY-001** | `CRITICAL` | 25 | CWE-353 | `dm-verity` verification disabled (`verity_enabled: false`) or root filesystem mounted writable (`rootfs_read_only: false`) |
| **LH-VERITY-002** | `CRITICAL` | 25 | CWE-693 | Permissive corruption error handling (`error_behavior` not in `["panic", "restart"]`, e.g., `"ignore"` or `"eio"`) |
| **LH-VERITY-003** | `CRITICAL` | 25 | CWE-347 | Cryptographic root hash unsigned or Secure Boot hardware fuse unlocked (`roothash_signed: false` or `secure_boot_fuse_locked: false`) |
| **LH-VERITY-004** | `HIGH` | 10 | CWE-328 | Weak or deprecated Merkle digest algorithm (`hash_algorithm` not in `["sha256", "sha512"]`, e.g., `"sha1"` or `"md5"`) |
| **LH-VERITY-005** | `HIGH` | 10 | CWE-330 | Weak, short, or zeroed cryptographic salt (`salt_hex` length `< 64` hex chars / 256 bits, or all `'0'` chars) |
| **LH-VERITY-006** | `HIGH` | 10 | CWE-367 | Reed-Solomon Forward Error Correction (FEC) disabled (`fec_enabled: false` or `fec_roots < 2` or `fec_roots > 24`) |
| **LH-VERITY-007** | `HIGH` | 10 | CWE-693 | Anti-rollback Security Version Number (SVN) protection disabled (`rollback_protection_enabled: false` or `minimum_svn < 1`) |
| **LH-VERITY-008** | `MEDIUM` | 4 | CWE-400 | Non-4K-aligned data or hash block size (`data_block_size != 4096` or `hash_block_size != 4096`) |
| **LH-VERITY-009** | `MEDIUM` | 4 | CWE-250 | Unauthenticated kernel command-line override permitted (`allow_cmdline_verity_override: true` or `initramfs_signature_verified: false`) |
| **LH-VERITY-010** | `LOW` | 1 | CWE-755 | Missing dual A/B slot automatic fallback or dm-verity corruption telemetry (`ab_slot_fallback_enabled: false` or `corruption_telemetry_logged: false`) |

### Standardized Security Posture Score:

$$S_{\text{posture}} = \max\left(0, 100 - \sum_{r \in \text{Violations}} W_r\right) = \max\left(0, 100 - (25 \cdot c_{\text{CRIT}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MED}} + 1 \cdot c_{\text{LOW}})\right)$$

- **Hardened Policy (`hardened_verity_policy.json`)**: $S_{\text{posture}} = 100/100$ (Exit code `0`).
- **Non-Compliant Policy (`vulnerable_verity_policy.json`)**: $S_{\text{posture}} = \max(0, 100 - 124) = 0/100$ (Exit code `1`).

---

## Build & Test Instructions

```bash
# Verify formatting
cargo fmt --check

# Run strict linter
cargo clippy --all-targets -- -D warnings

# Execute comprehensive test suite
cargo test

# Build release binary
cargo build --release
```

---

## CLI Reference (`lh-dmverity`)

```bash
# 1. Audit dm-verity root filesystem policy manifest
lh-dmverity scan fixtures/hardened_verity_policy.json --format table
lh-dmverity scan fixtures/hardened_verity_policy.json --format sarif --output report.sarif

# 2. Build Merkle tree and calculate root hash
lh-dmverity build-tree fixtures/sample_rootfs.img --output-tree /tmp/verity_tree.bin

# 3. Verify firmware image against expected root hash
lh-dmverity verify-tree fixtures/sample_rootfs.img --root-hash <root_hash_hex> --salt <salt_hex>

# 4. Generate Linux device-mapper table & kernel boot parameters
lh-dmverity gen-table fixtures/sample_rootfs.img --data-dev /dev/mmcblk0p2 --hash-dev /dev/mmcblk0p3

# 5. CLI Help & Version
lh-dmverity --help
lh-dmverity --version
```

---

## Exit Codes

| Exit Code | Semantic Meaning |
|:---:|:---|
| **`0`** | Clean scan (Score: 100, zero violations) or successful root hash verification |
| **`1`** | Posture violation detected, root hash mismatch, or corrupted block detected |
| **`2`** | Invalid CLI usage, missing file, or invalid JSON syntax |

---

## Corporate Attribution & Governance

- **Organization**: [Logihertz Systems (OPC) Private Limited](https://logihertz.com/)
- **GitHub Organization**: [`Logihertz-Systems-OPC-Pvt-Ltd`](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** ([`ops@logihertz.com`](mailto:ops@logihertz.com) / [`security@logihertz.com`](mailto:security@logihertz.com))
- **Git Commit Author**: `logihertzsystems <ops@logihertz.com>`
- **License**: Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright &copy; 2026 Logihertz Systems (OPC) Private Limited. All Rights Reserved.

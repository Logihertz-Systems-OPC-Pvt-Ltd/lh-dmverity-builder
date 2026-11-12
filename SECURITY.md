# Security Policy

## Scope & Commitment

Logihertz Systems (OPC) Private Limited maintains high assurance and cryptographic
standards across our sovereign edge AI, secure hardware, and embedded Linux tooling.

**`lh-dmverity-builder`** provides cryptographic root-of-trust verification and
immutable root filesystem auditing for edge appliances and IoT hardware.

We welcome responsible security disclosures regarding:
- Cryptographic flaws or collisions in the SHA-256 state machine or Merkle tree aggregation.
- Inconsistencies or overflows in 512-byte superblock binary serialization.
- Bypasses or timing side-channels in root hash or block inclusion proof verification.
- Inconsistencies in the 10-rule `dm-verity` posture auditor.
- Memory safety or logic errors in pure-Rust zero-dependency parsing routines.

---

## Supported Versions

| Version | Status | Security Support |
|:---|:---:|:---|
| `0.1.x` | Active | Full security updates and patches |
| `< 0.1.0` | End of Life | Not supported |

---

## Reporting a Vulnerability

Please report potential security vulnerabilities privately. **Do not create public GitHub issues for undisclosed security flaws.**

### Reporting Channels:
1. **Email (Primary)**: [`security@logihertz.com`](mailto:security@logihertz.com)
2. **Operations (Escalation)**: [`ops@logihertz.com`](mailto:ops@logihertz.com)

### When submitting a report, please include:
- A technical description of the vulnerability and its potential cryptographic or integrity impact.
- Exact reproduction steps, including sample firmware images, salts, or policy manifests.
- Affected Rust version (`rustc --version`).
- Suggested remediation or patch if available.

---

## Service Level Agreements (SLA)

| Milestone | Target Response Time |
|:---|:---:|
| **Initial Acknowledgment** | Within 48 hours |
| **Triage & Severity Classification** | Within 3 business days |
| **Fix Development & Private Verification** | Within 5 business days |
| **Public Advisory & Coordinated Release** | Within 14 calendar days |

---

## Disclosure Guidelines

- Please allow sufficient time for patch validation across target architectures before public disclosure.
- Ensure test artifacts do not contain proprietary firmware keys or production certificates.
- Logihertz Systems acknowledges security researchers in our release notes and `CHANGELOG.md`.

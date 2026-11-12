# Contributing to Logihertz dm-verity Builder (`lh-dmverity-builder`)

Thank you for contributing to **`lh-dmverity-builder`**! We adhere to
strict zero-dependency minimalism, memory safety under `#![forbid(unsafe_code)]`,
and cryptographic rigor.

---

## 1. Zero External Dependencies Mandate

- **Strict Standard Library Only**: `[dependencies]` in `Cargo.toml` must remain **completely empty**.
- **Forbidden**: External cryptographic crates (e.g. `sha2`, `ring`, `hex`, `serde`, `serde_json`) are strictly prohibited.
- All cryptographic primitives (SHA-256), binary serialization, JSON parsing, and SARIF output must be authored within the crate using standard `std` constructs.

---

## 2. Memory Safety & Coding Guidelines

- **Forbid Unsafe Code**: All source modules must compile under `#![forbid(unsafe_code)]`. No `unsafe` blocks are permitted.
- **Compiler Cleanliness**: Code must pass `cargo clippy --all-targets -- -D warnings` with zero warnings.
- **Formatting**: Adhere to `rustfmt` formatting standard (`cargo fmt --check`).
- **Constant-Time Verification**: All cryptographic hash comparisons must use constant-time comparison primitives (`constant_time_eq`) to eliminate timing side-channels.

---

## 3. dm-verity Merkle Tree Construction Standards

When proposing enhancements to the tree builder:
- Maintain strict alignment with Linux kernel `Documentation/admin-guide/device-mapper/verity.rst`.
- Ensure standard block size support ($4096\text{ bytes}$) and salt prepending ($s \parallel D$).
- Ensure tree level serialization correctly packs from top level down to leaf hash blocks.
- Maintain exact 512-byte little-endian format for the `VeritySuperblock`.

---

## 4. Local Build & Test Workflow

```bash
# Verify formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets -- -D warnings

# Execute test suite
cargo test

# Build release binary
cargo build --release

# Smoke test CLI
./target/release/lh-dmverity --help
./target/release/lh-dmverity scan fixtures/hardened_verity_policy.json --format table
```

---

## 5. Commit & Attribution Standards

- Maintainer attribution: `Sameer Tawade <ops@logihertz.com>`
- Organization identity: `logihertzsystems <ops@logihertz.com>`
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).

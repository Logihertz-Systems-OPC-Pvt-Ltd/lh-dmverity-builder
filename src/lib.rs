//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        lib.rs
//! Role:          Library Root & Public API Exports
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # Logihertz dm-verity Builder (`lh-dmverity`)
//!
//! Production-grade, zero-dependency Rust 2021 Cryptographic dm-verity Merkle Tree Builder,
//! Superblock & Device-Mapper Table Generator, and 10-Rule Immutable Root Filesystem Posture Auditor
//! for embedded Linux and sovereign edge AI appliances.
//!
//! Developed by Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Logihertz Systems (OPC) Private Limited <ops@logihertz.com>

pub mod auditor;
pub mod exporters;
pub mod json;
pub mod merkle;
pub mod sha256;
pub mod superblock;

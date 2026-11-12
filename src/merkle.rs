//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        merkle.rs
//! Role:          Cryptographic Merkle Tree Builder & Proof Verifier
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use crate::sha256::{constant_time_eq, salted_block_hash};
use std::io::{self, Read};

/// Standard Linux dm-verity data block size (4096 bytes)
pub const DEFAULT_DATA_BLOCK_SIZE: usize = 4096;

/// Standard Linux dm-verity hash block size (4096 bytes)
pub const DEFAULT_HASH_BLOCK_SIZE: usize = 4096;

/// Standard SHA-256 digest output size (32 bytes)
pub const DIGEST_SIZE: usize = 32;

/// Number of SHA-256 digests packed into a single 4096-byte hash block (128)
pub const HASHES_PER_BLOCK: usize = DEFAULT_HASH_BLOCK_SIZE / DIGEST_SIZE;

/// Single step in a dm-verity Merkle inclusion verification path
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// Zero-based level index (0 = leaf hash level)
    pub level: usize,
    /// Block index within this level
    pub block_index: usize,
    /// Offset of the target hash within this block (0..128)
    pub hash_index: usize,
    /// Expected hash stored at this position
    pub expected_hash: [u8; 32],
    /// Complete 4096-byte hash block containing this hash
    pub block_bytes: Vec<u8>,
}

/// Cryptographic inclusion proof for a single data block
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    /// Data block index being proven
    pub data_block_index: u64,
    /// SHA-256 hash of the data block (salted)
    pub data_hash: [u8; 32],
    /// Verification path from leaf level up to the root block
    pub path: Vec<ProofStep>,
    /// Expected root hash of the Merkle tree
    pub root_hash: [u8; 32],
}

/// In-memory representation of a dm-verity Merkle hash tree
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Data block size in bytes (typically 4096)
    pub data_block_size: usize,
    /// Hash block size in bytes (typically 4096)
    pub hash_block_size: usize,
    /// Cryptographic salt bytes prepended to each block prior to hashing
    pub salt: Vec<u8>,
    /// Total number of data blocks verified by this tree
    pub data_blocks_count: u64,
    /// Computed 32-byte root hash of the top-level block
    pub root_hash: [u8; 32],
    /// Tree levels from Level 0 (hashes of data blocks) up to Level Top
    pub levels: Vec<Vec<[u8; 32]>>,
    /// Multi-level 4096-byte hash blocks per level (level 0 up to level top)
    pub level_blocks: Vec<Vec<Vec<u8>>>,
    /// Complete serialized hash tree byte array (top level down to Level 0)
    pub tree_bytes: Vec<u8>,
}

impl MerkleTree {
    /// Build a dm-verity Merkle tree from an in-memory byte slice
    pub fn build(data: &[u8], salt: &[u8]) -> Result<Self, String> {
        let mut cursor = io::Cursor::new(data);
        Self::build_from_reader(&mut cursor, data.len() as u64, salt)
    }

    /// Build a dm-verity Merkle tree by streaming through a `Read` source
    pub fn build_from_reader<R: Read>(
        reader: &mut R,
        total_data_bytes: u64,
        salt: &[u8],
    ) -> Result<Self, String> {
        let data_block_size = DEFAULT_DATA_BLOCK_SIZE;
        let hash_block_size = DEFAULT_HASH_BLOCK_SIZE;

        if total_data_bytes == 0 {
            return Err("Cannot build dm-verity tree for empty data (0 bytes)".to_string());
        }

        let data_blocks_count = total_data_bytes.div_ceil(data_block_size as u64);

        // Step 1: Compute Level 0 hashes by streaming and hashing each data block
        let mut level0_hashes = Vec::with_capacity(data_blocks_count as usize);
        let mut block_buf = vec![0u8; data_block_size];
        let mut bytes_remaining = total_data_bytes;

        for _ in 0..data_blocks_count {
            let to_read = std::cmp::min(bytes_remaining, data_block_size as u64) as usize;
            block_buf.fill(0);
            reader
                .read_exact(&mut block_buf[..to_read])
                .map_err(|e| format!("Failed to read data block: {}", e))?;
            bytes_remaining -= to_read as u64;

            let h = salted_block_hash(salt, &block_buf);
            level0_hashes.push(h);
        }

        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut level_blocks: Vec<Vec<Vec<u8>>> = Vec::new();

        // Step 2: Build hierarchical levels until a single top block is reached
        let mut current_hashes = level0_hashes.clone();
        levels.push(level0_hashes);

        loop {
            // Pack current level hashes into 4096-byte blocks
            let num_blocks = current_hashes.len().div_ceil(HASHES_PER_BLOCK);
            let mut blocks_for_level = Vec::with_capacity(num_blocks);

            for b in 0..num_blocks {
                let mut block = vec![0u8; hash_block_size];
                let start_idx = b * HASHES_PER_BLOCK;
                let end_idx = std::cmp::min(start_idx + HASHES_PER_BLOCK, current_hashes.len());

                for (idx_in_block, hash) in current_hashes[start_idx..end_idx].iter().enumerate() {
                    let byte_offset = idx_in_block * DIGEST_SIZE;
                    block[byte_offset..byte_offset + DIGEST_SIZE].copy_from_slice(hash);
                }
                blocks_for_level.push(block);
            }

            level_blocks.push(blocks_for_level.clone());

            // If this level has only 1 block, it is the top-level block
            if blocks_for_level.len() <= 1 {
                break;
            }

            // Next level consists of hashes of the blocks of this level
            let mut next_hashes = Vec::with_capacity(blocks_for_level.len());
            for blk in &blocks_for_level {
                let h = salted_block_hash(salt, blk);
                next_hashes.push(h);
            }

            levels.push(next_hashes.clone());
            current_hashes = next_hashes;
        }

        // Top level has exactly 1 block
        let top_level_index = level_blocks.len() - 1;
        let top_block = &level_blocks[top_level_index][0];
        let root_hash = salted_block_hash(salt, top_block);

        // Step 3: Serialize tree blocks in standard dm-verity order:
        // Top level down to Level 0
        let mut tree_bytes = Vec::new();
        for lvl_idx in (0..level_blocks.len()).rev() {
            for blk in &level_blocks[lvl_idx] {
                tree_bytes.extend_from_slice(blk);
            }
        }

        Ok(Self {
            data_block_size,
            hash_block_size,
            salt: salt.to_vec(),
            data_blocks_count,
            root_hash,
            levels,
            level_blocks,
            tree_bytes,
        })
    }

    /// Verify whether a given 32-byte hash matches the tree's root hash
    pub fn verify_root_hash(&self, expected: &[u8; 32]) -> bool {
        constant_time_eq(&self.root_hash, expected)
    }

    /// Verify an individual data block against the in-memory Merkle tree
    pub fn verify_data_block(&self, block_index: u64, data: &[u8]) -> bool {
        if block_index >= self.data_blocks_count {
            return false;
        }

        let mut padded = [0u8; DEFAULT_DATA_BLOCK_SIZE];
        let copy_len = std::cmp::min(data.len(), DEFAULT_DATA_BLOCK_SIZE);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);

        let computed_hash = salted_block_hash(&self.salt, &padded);
        let expected_hash = self.levels[0][block_index as usize];

        constant_time_eq(&computed_hash, &expected_hash)
    }

    /// Generate a cryptographic inclusion proof for a given data block index
    pub fn generate_inclusion_proof(&self, block_index: u64) -> Result<InclusionProof, String> {
        if block_index >= self.data_blocks_count {
            return Err(format!(
                "Block index {} out of range (total blocks: {})",
                block_index, self.data_blocks_count
            ));
        }

        let data_hash = self.levels[0][block_index as usize];
        let mut path = Vec::new();
        let mut current_idx = block_index as usize;

        for level_idx in 0..self.level_blocks.len() {
            let block_idx = current_idx / HASHES_PER_BLOCK;
            let hash_idx = current_idx % HASHES_PER_BLOCK;
            let block_bytes = self.level_blocks[level_idx][block_idx].clone();
            let expected_hash = self.levels[level_idx][current_idx];

            path.push(ProofStep {
                level: level_idx,
                block_index: block_idx,
                hash_index: hash_idx,
                expected_hash,
                block_bytes,
            });

            current_idx = block_idx;
        }

        Ok(InclusionProof {
            data_block_index: block_index,
            data_hash,
            path,
            root_hash: self.root_hash,
        })
    }

    /// Total number of 4096-byte hash blocks across all levels in the tree
    pub fn total_hash_blocks(&self) -> u64 {
        self.level_blocks.iter().map(|lvl| lvl.len() as u64).sum()
    }
}

/// Verify an inclusion proof against a known root hash and salt
pub fn verify_inclusion_proof(proof: &InclusionProof, root_hash: &[u8; 32], salt: &[u8]) -> bool {
    if !constant_time_eq(&proof.root_hash, root_hash) {
        return false;
    }

    if proof.path.is_empty() {
        return false;
    }

    let mut current_expected_hash = proof.data_hash;

    for (step_i, step) in proof.path.iter().enumerate() {
        if step.block_bytes.len() != DEFAULT_HASH_BLOCK_SIZE {
            return false;
        }

        // Verify the expected hash is at the correct byte offset inside block_bytes
        let offset = step.hash_index * DIGEST_SIZE;
        if offset + DIGEST_SIZE > step.block_bytes.len() {
            return false;
        }

        if !constant_time_eq(
            &step.block_bytes[offset..offset + DIGEST_SIZE],
            &current_expected_hash,
        ) {
            return false;
        }

        // Hash of this block becomes the expected hash for the next level
        let block_hash = salted_block_hash(salt, &step.block_bytes);

        if step_i + 1 == proof.path.len() {
            // Last step must match the root hash
            if !constant_time_eq(&block_hash, root_hash) {
                return false;
            }
        } else {
            current_expected_hash = block_hash;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_single_block() {
        let data = vec![0x42u8; 4096];
        let salt = [0x5au8; 32];
        let tree = MerkleTree::build(&data, &salt).expect("Build tree failed");

        assert_eq!(tree.data_blocks_count, 1);
        assert_eq!(tree.levels.len(), 1);
        assert_eq!(tree.level_blocks.len(), 1);
        assert_eq!(tree.level_blocks[0].len(), 1);
        assert_eq!(tree.tree_bytes.len(), 4096);

        assert!(tree.verify_root_hash(&tree.root_hash));
        assert!(tree.verify_data_block(0, &data));

        let proof = tree.generate_inclusion_proof(0).expect("Proof failed");
        assert!(verify_inclusion_proof(&proof, &tree.root_hash, &salt));
    }

    #[test]
    fn test_merkle_multi_level() {
        // 200 data blocks requires 2 hash blocks at Level 0, and 1 block at Level 1
        let data = vec![0xAAu8; 200 * 4096];
        let salt = [0x11u8; 32];
        let tree = MerkleTree::build(&data, &salt).expect("Build tree failed");

        assert_eq!(tree.data_blocks_count, 200);
        assert_eq!(tree.levels.len(), 2);
        assert_eq!(tree.level_blocks[0].len(), 2);
        assert_eq!(tree.level_blocks[1].len(), 1);
        assert_eq!(tree.total_hash_blocks(), 3);
        assert_eq!(tree.tree_bytes.len(), 3 * 4096);

        // Verify arbitrary block inclusion proofs
        for idx in [0, 50, 127, 128, 199] {
            let block_slice = &data[idx * 4096..(idx + 1) * 4096];
            assert!(tree.verify_data_block(idx as u64, block_slice));
            let proof = tree
                .generate_inclusion_proof(idx as u64)
                .expect("Proof failed");
            assert!(verify_inclusion_proof(&proof, &tree.root_hash, &salt));
        }
    }

    #[test]
    fn test_tamper_detection() {
        let mut data = vec![0x55u8; 16 * 4096];
        let salt = [0x99u8; 32];
        let tree = MerkleTree::build(&data, &salt).expect("Build failed");

        // Tamper with 1 bit in data block 5
        data[5 * 4096 + 10] ^= 0x01;

        assert!(!tree.verify_data_block(5, &data[5 * 4096..6 * 4096]));
    }
}

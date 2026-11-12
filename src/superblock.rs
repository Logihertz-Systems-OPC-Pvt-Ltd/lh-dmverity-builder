//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        superblock.rs
//! Role:          512-Byte Binary Superblock & Device-Mapper Table Generator
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

/// Magic signature for Linux dm-verity superblock ("verity\0\0")
pub const VERITY_SUPERBLOCK_MAGIC: [u8; 8] = [b'v', b'e', b'r', b'i', b't', b'y', 0, 0];

/// Standard superblock binary size in bytes (512 bytes)
pub const VERITY_SUPERBLOCK_SIZE: usize = 512;

/// Linux dm-verity on-disk v1 superblock structure (512 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VeritySuperblock {
    /// 8-byte magic header ("verity\0\0")
    pub magic: [u8; 8],
    /// Superblock version (1)
    pub version: u32,
    /// Hash type (1 = standard salted SHA-256)
    pub hash_type: u32,
    /// 128-bit filesystem UUID
    pub uuid: [u8; 16],
    /// Cryptographic digest algorithm name (e.g. "sha256")
    pub algorithm: String,
    /// Size of each data block in bytes (4096)
    pub data_block_size: u32,
    /// Size of each hash block in bytes (4096)
    pub hash_block_size: u32,
    /// Total number of verified data blocks
    pub data_blocks: u64,
    /// Size of the cryptographic salt in bytes
    pub salt_size: u16,
    /// Cryptographic salt bytes
    pub salt: Vec<u8>,
}

impl Default for VeritySuperblock {
    fn default() -> Self {
        Self {
            magic: VERITY_SUPERBLOCK_MAGIC,
            version: 1,
            hash_type: 1,
            uuid: [0u8; 16],
            algorithm: "sha256".to_string(),
            data_block_size: 4096,
            hash_block_size: 4096,
            data_blocks: 0,
            salt_size: 32,
            salt: vec![0u8; 32],
        }
    }
}

impl VeritySuperblock {
    /// Create a new superblock for a given data block count and salt
    pub fn new(data_blocks: u64, salt: &[u8]) -> Self {
        let mut uuid = [0u8; 16];
        // Deterministic dummy UUID if not specified
        uuid[0] = 0x56;
        uuid[1] = 0x45;
        uuid[2] = 0x52;
        uuid[3] = 0x54;

        Self {
            magic: VERITY_SUPERBLOCK_MAGIC,
            version: 1,
            hash_type: 1,
            uuid,
            algorithm: "sha256".to_string(),
            data_block_size: 4096,
            hash_block_size: 4096,
            data_blocks,
            salt_size: salt.len() as u16,
            salt: salt.to_vec(),
        }
    }

    /// Serialize the superblock into standard 512-byte binary format
    pub fn serialize(&self) -> [u8; VERITY_SUPERBLOCK_SIZE] {
        let mut buf = [0u8; VERITY_SUPERBLOCK_SIZE];

        // 0..8: Magic
        buf[0..8].copy_from_slice(&self.magic);

        // 8..12: Version (u32 LE)
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());

        // 12..16: Hash type (u32 LE)
        buf[12..16].copy_from_slice(&self.hash_type.to_le_bytes());

        // 16..32: UUID
        buf[16..32].copy_from_slice(&self.uuid);

        // 32..64: Algorithm (null-padded 32-byte string)
        let alg_bytes = self.algorithm.as_bytes();
        let alg_len = std::cmp::min(alg_bytes.len(), 32);
        buf[32..32 + alg_len].copy_from_slice(&alg_bytes[..alg_len]);

        // 64..68: data_block_size (u32 LE)
        buf[64..68].copy_from_slice(&self.data_block_size.to_le_bytes());

        // 68..72: hash_block_size (u32 LE)
        buf[68..72].copy_from_slice(&self.hash_block_size.to_le_bytes());

        // 72..80: data_blocks (u64 LE)
        buf[72..80].copy_from_slice(&self.data_blocks.to_le_bytes());

        // 80..82: salt_size (u16 LE)
        buf[80..82].copy_from_slice(&self.salt_size.to_le_bytes());

        // 82..88: reserved [u8; 6] (remains 0)

        // 88..344: salt [u8; 256]
        let copy_salt_len = std::cmp::min(self.salt.len(), 256);
        buf[88..88 + copy_salt_len].copy_from_slice(&self.salt[..copy_salt_len]);

        // 344..512: padding (remains 0)
        buf
    }

    /// Deserialize a 512-byte buffer into a `VeritySuperblock`
    pub fn deserialize(buf: &[u8; VERITY_SUPERBLOCK_SIZE]) -> Result<Self, String> {
        if buf[0..8] != VERITY_SUPERBLOCK_MAGIC {
            return Err("Invalid dm-verity magic signature".to_string());
        }

        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != 1 {
            return Err(format!("Unsupported dm-verity version: {}", version));
        }

        let hash_type = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[16..32]);

        // Algorithm is null-terminated or up to 32 bytes
        let alg_slice = &buf[32..64];
        let alg_len = alg_slice.iter().position(|&b| b == 0).unwrap_or(32);
        let algorithm = String::from_utf8_lossy(&alg_slice[..alg_len]).to_string();

        let data_block_size = u32::from_le_bytes(buf[64..68].try_into().unwrap());
        let hash_block_size = u32::from_le_bytes(buf[68..72].try_into().unwrap());
        let data_blocks = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        let salt_size = u16::from_le_bytes(buf[80..82].try_into().unwrap());

        let salt_len = std::cmp::min(salt_size as usize, 256);
        let salt = buf[88..88 + salt_len].to_vec();

        Ok(Self {
            magic: VERITY_SUPERBLOCK_MAGIC,
            version,
            hash_type,
            uuid,
            algorithm,
            data_block_size,
            hash_block_size,
            data_blocks,
            salt_size,
            salt,
        })
    }
}

/// Format a standard Linux device-mapper table mapping line for dm-verity
#[allow(clippy::too_many_arguments)]
pub fn format_dm_table(
    start_sector: u64,
    data_dev: &str,
    hash_dev: &str,
    data_block_size: u32,
    hash_block_size: u32,
    data_blocks: u64,
    hash_start_block: u64,
    algorithm: &str,
    root_hash_hex: &str,
    salt_hex: &str,
) -> String {
    // 1 block = (data_block_size / 512) sectors
    let sectors_per_block = (data_block_size / 512) as u64;
    let data_sectors = data_blocks * sectors_per_block;

    format!(
        "{} {} verity 1 {} {} {} {} {} {} {} {} {}",
        start_sector,
        data_sectors,
        data_dev,
        hash_dev,
        data_block_size,
        hash_block_size,
        data_blocks,
        hash_start_block,
        algorithm,
        root_hash_hex,
        salt_hex
    )
}

/// Format the kernel command-line parameter (`dm-mod.create`) for early boot mounting
pub fn format_kernel_cmdline(table: &str) -> String {
    format!("dm-mod.create=\"vroot,,,ro,{}\"", table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_superblock_roundtrip() {
        let salt = vec![0x12u8; 32];
        let sb = VeritySuperblock::new(1024, &salt);
        let bytes = sb.serialize();
        assert_eq!(bytes.len(), 512);
        assert_eq!(&bytes[0..8], &VERITY_SUPERBLOCK_MAGIC);

        let parsed = VeritySuperblock::deserialize(&bytes).expect("Deserialize failed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.data_blocks, 1024);
        assert_eq!(parsed.data_block_size, 4096);
        assert_eq!(parsed.hash_block_size, 4096);
        assert_eq!(parsed.algorithm, "sha256");
        assert_eq!(parsed.salt_size, 32);
        assert_eq!(parsed.salt, salt);
    }

    #[test]
    fn test_dm_table_format() {
        let line = format_dm_table(
            0,
            "/dev/mmcblk0p2",
            "/dev/mmcblk0p3",
            4096,
            4096,
            16,
            0,
            "sha256",
            "abcdef1234567890",
            "1234567890abcdef",
        );
        assert_eq!(
            line,
            "0 128 verity 1 /dev/mmcblk0p2 /dev/mmcblk0p3 4096 4096 16 0 sha256 abcdef1234567890 1234567890abcdef"
        );

        let cmdline = format_kernel_cmdline(&line);
        assert!(cmdline.starts_with("dm-mod.create=\"vroot,,,ro,0 128 verity 1"));
    }
}

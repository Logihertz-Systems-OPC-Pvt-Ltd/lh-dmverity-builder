//! Pure-Rust FIPS 180-4 SHA-256 Cryptographic Primitives
//!
//! Implements a clean-room, `#![forbid(unsafe_code)]` SHA-256 state machine,
//! salted block hashing, constant-time equality comparisons, and hex conversion
//! without external crate dependencies.

/// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pure-Rust streaming SHA-256 state machine
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Initialize a new SHA-256 instance with standard IV
    pub fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Process a slice of input bytes
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // If buffer already has partial data, try to fill it
        if self.buf_len > 0 {
            let to_fill = 64 - self.buf_len;
            if data.len() >= to_fill {
                self.buffer[self.buf_len..64].copy_from_slice(&data[..to_fill]);
                self.process_block(self.buffer);
                self.buf_len = 0;
                offset = to_fill;
            } else {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
        }

        // Process full 64-byte blocks directly
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.process_block(block);
            offset += 64;
        }

        // Retain remaining partial block
        let rem = data.len() - offset;
        if rem > 0 {
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
    }

    /// Finalize the hash computation and return the 32-byte digest
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        // Append 0x80 byte
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough room for 8-byte length, pad and process block
        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..64] {
                *b = 0;
            }
            self.process_block(self.buffer);
            self.buf_len = 0;
        }

        // Pad with zeros up to byte 56
        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }

        // Append big-endian 64-bit length
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.process_block(self.buffer);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Compute one-shot SHA-256 digest
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn process_block(&mut self, block: [u8; 64]) {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Compute SHA-256 of salt concatenated with block data: SHA-256(salt || block)
pub fn salted_block_hash(salt: &[u8], block: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(block);
    hasher.finalize()
}

/// Encode byte slice into lower-case hexadecimal string
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hexadecimal string into byte vector
pub fn hex_decode(hex_str: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_str.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(format!(
            "Hex string length must be even, got {}",
            trimmed.len()
        ));
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let chars = trimmed.as_bytes();

    for i in (0..chars.len()).step_by(2) {
        let hi = hex_char_to_val(chars[i])
            .ok_or_else(|| format!("Invalid hex character '{}'", chars[i] as char))?;
        let lo = hex_char_to_val(chars[i + 1])
            .ok_or_else(|| format!("Invalid hex character '{}'", chars[i + 1] as char))?;
        bytes.push((hi << 4) | lo);
    }

    Ok(bytes)
}

fn hex_char_to_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Constant-time slice equality comparison mitigating microarchitectural timing side-channels
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (&x, &y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nist_empty_string() {
        let digest = Sha256::digest(b"");
        assert_eq!(
            hex_encode(&digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_nist_abc() {
        let digest = Sha256::digest(b"abc");
        assert_eq!(
            hex_encode(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_nist_multi_block() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = Sha256::digest(msg);
        assert_eq!(
            hex_encode(&digest),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let raw = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67];
        let encoded = hex_encode(&raw);
        assert_eq!(encoded, "deadbeef01234567");
        let decoded = hex_decode(&encoded).expect("valid hex");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }
}

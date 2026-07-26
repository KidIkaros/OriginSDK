// SPDX-License-Identifier: Apache-2.0

//! Native SHA3-256 and SHA3-512 implementation — replacement for `sha3` crate.
//!
//! Implements Keccak-f\[1600\] with the SHA3 padding (10*1 pattern).
//! Reference: FIPS 202

/// Keccak-f[1600] round constants
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotate left for u64
#[inline(always)]
fn rotl64(x: u64, n: u32) -> u64 {
    (x << n) | (x >> (64 - n))
}

/// Keccak-f[1600] permutation - FIPS 202 compliant
/// Based on well-tested implementation from tiny-keccak
#[inline(always)]
fn keccakf1600(state: &mut [u64; 25]) {
    for i in 0..24 {
        // Theta
        let c0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        let c1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        let c2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        let c3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        let c4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        let t0 = c4 ^ rotl64(c1, 1);
        let t1 = c0 ^ rotl64(c2, 1);
        let t2 = c1 ^ rotl64(c3, 1);
        let t3 = c2 ^ rotl64(c4, 1);
        let t4 = c3 ^ rotl64(c0, 1);

        state[0] ^= t0;
        state[5] ^= t0;
        state[10] ^= t0;
        state[15] ^= t0;
        state[20] ^= t0;
        state[1] ^= t1;
        state[6] ^= t1;
        state[11] ^= t1;
        state[16] ^= t1;
        state[21] ^= t1;
        state[2] ^= t2;
        state[7] ^= t2;
        state[12] ^= t2;
        state[17] ^= t2;
        state[22] ^= t2;
        state[3] ^= t3;
        state[8] ^= t3;
        state[13] ^= t3;
        state[18] ^= t3;
        state[23] ^= t3;
        state[4] ^= t4;
        state[9] ^= t4;
        state[14] ^= t4;
        state[19] ^= t4;
        state[24] ^= t4;

        // Rho Pi
        let mut b = [0u64; 25];
        b[0] = state[0];
        b[1] = rotl64(state[6], 44);
        b[2] = rotl64(state[12], 43);
        b[3] = rotl64(state[18], 21);
        b[4] = rotl64(state[24], 14);
        b[5] = rotl64(state[3], 28);
        b[6] = rotl64(state[9], 20);
        b[7] = rotl64(state[10], 3);
        b[8] = rotl64(state[16], 45);
        b[9] = rotl64(state[22], 61);
        b[10] = rotl64(state[1], 1);
        b[11] = rotl64(state[7], 6);
        b[12] = rotl64(state[13], 25);
        b[13] = rotl64(state[19], 8);
        b[14] = rotl64(state[20], 18);
        b[15] = rotl64(state[4], 27);
        b[16] = rotl64(state[5], 36);
        b[17] = rotl64(state[11], 10);
        b[18] = rotl64(state[17], 15);
        b[19] = rotl64(state[23], 56);
        b[20] = rotl64(state[2], 62);
        b[21] = rotl64(state[8], 55);
        b[22] = rotl64(state[14], 39);
        b[23] = rotl64(state[15], 41);
        b[24] = rotl64(state[21], 2);

        // Chi
        state[0] = b[0] ^ (!b[1] & b[2]);
        state[1] = b[1] ^ (!b[2] & b[3]);
        state[2] = b[2] ^ (!b[3] & b[4]);
        state[3] = b[3] ^ (!b[4] & b[0]);
        state[4] = b[4] ^ (!b[0] & b[1]);
        state[5] = b[5] ^ (!b[6] & b[7]);
        state[6] = b[6] ^ (!b[7] & b[8]);
        state[7] = b[7] ^ (!b[8] & b[9]);
        state[8] = b[8] ^ (!b[9] & b[5]);
        state[9] = b[9] ^ (!b[5] & b[6]);
        state[10] = b[10] ^ (!b[11] & b[12]);
        state[11] = b[11] ^ (!b[12] & b[13]);
        state[12] = b[12] ^ (!b[13] & b[14]);
        state[13] = b[13] ^ (!b[14] & b[10]);
        state[14] = b[14] ^ (!b[10] & b[11]);
        state[15] = b[15] ^ (!b[16] & b[17]);
        state[16] = b[16] ^ (!b[17] & b[18]);
        state[17] = b[17] ^ (!b[18] & b[19]);
        state[18] = b[18] ^ (!b[19] & b[15]);
        state[19] = b[19] ^ (!b[15] & b[16]);
        state[20] = b[20] ^ (!b[21] & b[22]);
        state[21] = b[21] ^ (!b[22] & b[23]);
        state[22] = b[22] ^ (!b[23] & b[24]);
        state[23] = b[23] ^ (!b[24] & b[20]);
        state[24] = b[24] ^ (!b[20] & b[21]);

        // Iota
        state[0] ^= RC[i];
    }
}

/// XOR bytes into state at offset
#[inline(always)]
fn xor_bytes(state: &mut [u64; 25], offset: usize, data: &[u8]) {
    for (i, &byte) in data.iter().enumerate() {
        let word_idx = (offset + i) / 8;
        let byte_idx = (offset + i) % 8;
        state[word_idx] ^= (byte as u64) << (byte_idx * 8);
    }
}

/// Extract bytes from state
#[inline(always)]
fn extract_bytes(state: &[u64; 25], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let word = state[i].to_le_bytes();
        for (j, byte) in chunk.iter_mut().enumerate() {
            *byte = word[j];
        }
    }
}

/// SHA3-256 implementation (rate=136 bytes, capacity=64 bytes, output=32 bytes)
pub struct Sha3_256 {
    state: [u64; 25],
    buffer: [u8; 136],
    buf_len: usize,
}

impl Sha3_256 {
    /// Create a new SHA3-256 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; 136],
            buf_len: 0,
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // If we have buffered data, try to fill the buffer
        if self.buf_len > 0 {
            let to_copy = std::cmp::min(136 - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == 136 {
                xor_bytes(&mut self.state, 0, &self.buffer);
                keccakf1600(&mut self.state);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + 136 <= data.len() {
            xor_bytes(&mut self.state, 0, &data[offset..offset + 136]);
            keccakf1600(&mut self.state);
            offset += 136;
        }

        // Buffer remaining data
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 32] {
        // SHA3 padding: 0b01100001 pattern (0x06 followed by zeros and 0x80 at end)
        self.buffer[self.buf_len] = 0x06;
        self.buffer[135] = 0x80;

        xor_bytes(&mut self.state, 0, &self.buffer);
        keccakf1600(&mut self.state);

        let mut output = [0u8; 32];
        extract_bytes(&self.state, &mut output);
        output
    }

    /// One-shot hash computation
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Sha3_256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `state` holds the SHA3 permutation state plus XORed input bytes during
        // absorption. `buffer` holds the most-recently-absorbed partial block.
        // Both redact by default; if SHA3 hashes secret data, leaks would
        // otherwise surface via `:?` formatting.
        f.debug_struct("Sha3_256")
            .field("state", &"<redacted>")
            .field("buffer", &"<redacted>")
            .field("buf_len", &self.buf_len)
            .finish()
    }
}

/// SHA3-512 implementation (rate=72 bytes, capacity=128 bytes, output=64 bytes)
pub struct Sha3_512 {
    state: [u64; 25],
    buffer: [u8; 72],
    buf_len: usize,
}

impl Sha3_512 {
    /// Create a new SHA3-512 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; 72],
            buf_len: 0,
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // If we have buffered data, try to fill the buffer
        if self.buf_len > 0 {
            let to_copy = std::cmp::min(72 - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset = to_copy;

            if self.buf_len == 72 {
                xor_bytes(&mut self.state, 0, &self.buffer);
                keccakf1600(&mut self.state);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + 72 <= data.len() {
            xor_bytes(&mut self.state, 0, &data[offset..offset + 72]);
            keccakf1600(&mut self.state);
            offset += 72;
        }

        // Buffer remaining data
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 64] {
        // SHA3 padding
        self.buffer[self.buf_len] = 0x06;
        self.buffer[71] = 0x80;

        xor_bytes(&mut self.state, 0, &self.buffer);
        keccakf1600(&mut self.state);

        let mut output = [0u8; 64];
        extract_bytes(&self.state, &mut output);
        output
    }

    /// One-shot hash computation
    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Sha3_512 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Same rationale as Sha3_256: state and buffer redact; buf_len surfaces
        // for flow-control debugging.
        f.debug_struct("Sha3_512")
            .field("state", &"<redacted>")
            .field("buffer", &"<redacted>")
            .field("buf_len", &self.buf_len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST test vector: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    #[test]
    fn sha3_256_empty() {
        let result = Sha3_256::digest(b"");
        let expected =
            hex_to_bytes32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(result, expected);
    }

    // NIST test vector: SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    #[test]
    fn sha3_256_abc() {
        let result = Sha3_256::digest(b"abc");
        let expected =
            hex_to_bytes32("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(result, expected);
    }

    // NIST test vector: SHA3-512("") = a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
    #[test]
    fn sha3_512_empty() {
        let result = Sha3_512::digest(b"");
        let expected = hex_to_bytes64("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_256_incremental() {
        let mut hasher = Sha3_256::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        let result = hasher.finalize();
        let expected =
            hex_to_bytes32("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        assert_eq!(result, expected);
    }

    #[test]
    fn sha3_256_large_message() {
        let data = vec![0u8; 10000];
        let result = Sha3_256::digest(&data);
        // Just verify it doesn't panic and produces consistent results
        let result2 = Sha3_256::digest(&data);
        assert_eq!(result, result2);
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn hex_to_bytes64(hex: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for i in 0..64 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}

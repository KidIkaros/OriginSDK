// SPDX-License-Identifier: Apache-2.0

//! Poly1305 message authentication code (native implementation)
//!
//! Implementation follows RFC 8439 §2.5 (Poly1305 for IETF Protocols).
//!
//! Poly1305 is a fast one-time authenticator based on arithmetic in the
//! prime field GF(2^130 − 5). Given a 256-bit one-time key, it computes
//! a 128-bit authentication tag.
//!
//! # Security
//!
//! - **One-time key**: The key MUST be unique for each message. Reusing a
//!   key allows forgery. In AEAD constructions, this is handled automatically.
//! - **Constant-time**: Field arithmetic avoids secret-dependent branches.
//!
//! # References
//!
//! - RFC 8439 §2.5: Poly1305 specification
//! - DJB's Poly1305-AES specification

/// Poly1305 tag size in bytes (128 bits)
pub const POLY1305_TAG_SIZE: usize = 16;

/// Poly1305 key size in bytes (256 bits = 128-bit r + 128-bit s)
pub const POLY1305_KEY_SIZE: usize = 32;

/// Poly1305 block size in bytes (128 bits)
const POLY1305_BLOCK_SIZE: usize = 16;

/// Poly1305 authenticator state
///
/// Uses 5 limbs of 26 bits each to represent elements in GF(2^130 − 5).
pub struct Poly1305 {
    /// Clamped r value (5 × 26-bit limbs)
    r: [u32; 5],
    /// Precomputed 5*r values for reduction
    s_: [u32; 4],
    /// Accumulator (5 × 26-bit limbs)
    h: [u32; 5],
    /// Pad value (s portion of key)
    pad: [u32; 4],
    /// Buffer for partial blocks
    buf: [u8; POLY1305_BLOCK_SIZE],
    /// Current buffer position
    buf_pos: usize,
    /// Whether finalize has been called
    finalized: bool,
}

impl Poly1305 {
    /// Create a new Poly1305 instance from a 32-byte one-time key.
    pub fn new(key: &[u8; POLY1305_KEY_SIZE]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);

        // Clamping (RFC 8439 §2.5)
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        // Convert r to 5 × 26-bit limbs
        let r = [
            (u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]])) & 0x3ffffff,
            (u32::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6]]) >> 2) & 0x3ffffff,
            (u32::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9]]) >> 4) & 0x3ffffff,
            (u32::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12]]) >> 6)
                & 0x3ffffff,
            (u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]) >> 8)
                & 0x3ffffff,
        ];

        let s_ = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        let pad = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];

        Self {
            r,
            s_,
            h: [0; 5],
            pad,
            buf: [0; POLY1305_BLOCK_SIZE],
            buf_pos: 0,
            finalized: false,
        }
    }

    /// Process a single 16-byte block
    fn process_block(&mut self, block: &[u8], is_final_partial: bool) {
        let hibit = if is_final_partial { 0u32 } else { 1u32 << 24 };

        let mut n = [0u8; 16];
        let len = block.len().min(16);
        n[..len].copy_from_slice(&block[..len]);

        let h0 = self.h[0] + (u32::from_le_bytes([n[0], n[1], n[2], n[3]]) & 0x3ffffff);
        let h1 = self.h[1] + ((u32::from_le_bytes([n[3], n[4], n[5], n[6]]) >> 2) & 0x3ffffff);
        let h2 = self.h[2] + ((u32::from_le_bytes([n[6], n[7], n[8], n[9]]) >> 4) & 0x3ffffff);
        let h3 = self.h[3] + ((u32::from_le_bytes([n[9], n[10], n[11], n[12]]) >> 6) & 0x3ffffff);
        let h4 = self.h[4] + ((u32::from_le_bytes([n[12], n[13], n[14], n[15]]) >> 8) | hibit);

        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;
        let s1 = self.s_[0] as u64;
        let s2 = self.s_[1] as u64;
        let s3 = self.s_[2] as u64;
        let s4 = self.s_[3] as u64;

        let h0 = h0 as u64;
        let h1 = h1 as u64;
        let h2 = h2 as u64;
        let h3 = h3 as u64;
        let h4 = h4 as u64;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c: u64;
        let mut h0 = d0 as u32 & 0x3ffffff;
        c = d0 >> 26;
        let d1 = d1 + c;
        let mut h1 = d1 as u32 & 0x3ffffff;
        c = d1 >> 26;
        let d2 = d2 + c;
        let h2 = d2 as u32 & 0x3ffffff;
        c = d2 >> 26;
        let d3 = d3 + c;
        let h3 = d3 as u32 & 0x3ffffff;
        c = d3 >> 26;
        let d4 = d4 + c;
        let h4 = d4 as u32 & 0x3ffffff;
        c = d4 >> 26;
        h0 += c as u32 * 5;
        c = (h0 >> 26) as u64;
        h0 &= 0x3ffffff;
        h1 += c as u32;

        self.h = [h0, h1, h2, h3, h4];
    }

    /// Update the authenticator with more data
    pub fn update(&mut self, data: &[u8]) {
        if self.finalized {
            return;
        }

        let mut offset = 0;

        if self.buf_pos > 0 {
            let needed = POLY1305_BLOCK_SIZE - self.buf_pos;
            let to_copy = needed.min(data.len());
            self.buf[self.buf_pos..self.buf_pos + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_pos += to_copy;
            offset += to_copy;

            if self.buf_pos == POLY1305_BLOCK_SIZE {
                let block = self.buf;
                self.process_block(&block, false);
                self.buf_pos = 0;
            }
        }

        while offset + POLY1305_BLOCK_SIZE <= data.len() {
            self.process_block(&data[offset..offset + POLY1305_BLOCK_SIZE], false);
            offset += POLY1305_BLOCK_SIZE;
        }

        let remaining = &data[offset..];
        if !remaining.is_empty() {
            self.buf[..remaining.len()].copy_from_slice(remaining);
            self.buf_pos = remaining.len();
        }
    }

    /// Finalize and compute the 16-byte authentication tag
    pub fn finalize(mut self) -> [u8; POLY1305_TAG_SIZE] {
        if !self.finalized {
            if self.buf_pos > 0 {
                let pos = self.buf_pos;
                self.buf[pos] = 1;
                for i in (pos + 1)..POLY1305_BLOCK_SIZE {
                    self.buf[i] = 0;
                }
                let block = self.buf;
                self.process_block(&block, true);
            }

            self.finalized = true;
        }

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        h0 = (h0 & !mask) | (g0 & mask);
        h1 = (h1 & !mask) | (g1 & mask);
        h2 = (h2 & !mask) | (g2 & mask);
        h3 = (h3 & !mask) | (g3 & mask);
        h4 = (h4 & !mask) | (g4 & mask);

        let f0 = (h0 | (h1 << 26)) as u64 + self.pad[0] as u64;
        let f1 = ((h1 >> 6) | (h2 << 20)) as u64 + self.pad[1] as u64 + (f0 >> 32);
        let f2 = ((h2 >> 12) | (h3 << 14)) as u64 + self.pad[2] as u64 + (f1 >> 32);
        let f3 = ((h3 >> 18) | (h4 << 8)) as u64 + self.pad[3] as u64 + (f2 >> 32);

        let mut tag = [0u8; POLY1305_TAG_SIZE];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

        tag
    }
}

/// Compute Poly1305 MAC in one shot
pub fn poly1305_mac(msg: &[u8], key: &[u8; POLY1305_KEY_SIZE]) -> [u8; POLY1305_TAG_SIZE] {
    let mut poly = Poly1305::new(key);
    poly.update(msg);
    poly.finalize()
}

impl std::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact `r` (clamped key material), `s_` (5*r), `h` (accumulator),
        // `pad` (key s portion), and `buf` (partial-block plaintext).
        // Surface `buf_pos` and `finalized` for flow control debugging.
        f.debug_struct("Poly1305")
            .field("buf_pos", &self.buf_pos)
            .field("finalized", &self.finalized)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.5.2 — Poly1305 test vector
    #[test]
    fn test_poly1305_rfc8439() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(msg, &key);

        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        assert_eq!(&tag[..], &expected[..]);
    }

    /// Test incremental vs one-shot
    #[test]
    fn test_poly1305_incremental() {
        let key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let msg = b"This is a longer test message for incremental processing of Poly1305 authentication code";

        let one_shot = poly1305_mac(msg, &key);

        let mut poly = Poly1305::new(&key);
        poly.update(&msg[..10]);
        poly.update(&msg[10..50]);
        poly.update(&msg[50..]);
        let incremental = poly.finalize();

        assert_eq!(one_shot, incremental);
    }
}

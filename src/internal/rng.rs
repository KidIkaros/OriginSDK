// SPDX-License-Identifier: Apache-2.0

//! Native ChaCha20 CSPRNG — replacement for `rand_chacha::ChaCha20Rng`.
//!
//! Implements `rand::RngCore` and `rand::SeedableRng` so existing callers
//! in the crate can continue to use the standard RNG trait while the
//! underlying implementation is fully native.

use rand::{CryptoRng, RngCore, SeedableRng};

use crate::primitives::chacha20::{chacha20_block, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};

/// A ChaCha20-based CSPRNG backed by our native implementation.
pub struct ChaCha20Rng {
    key: [u8; CHACHA20_KEY_SIZE],
    nonce: [u8; CHACHA20_NONCE_SIZE],
    counter: u64,
    block: [u8; 64],
    block_pos: usize,
}

impl ChaCha20Rng {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: [u8; CHACHA20_KEY_SIZE]) -> Self {
        Self {
            key: seed,
            nonce: [0u8; CHACHA20_NONCE_SIZE],
            counter: 0,
            block: [0u8; 64],
            block_pos: 64, // force generation of first block on next use
        }
    }

    /// Create from OS entropy.
    pub fn from_entropy() -> Self {
        let mut seed = [0u8; CHACHA20_KEY_SIZE];
        crate::internal::getrandom::fill(&mut seed).expect("OS RNG failed");
        Self::from_seed(seed)
    }

    fn refill_block(&mut self) {
        // chacha20_block takes a u32 counter; use lower 32 bits of our u64 counter
        let counter = self.counter as u32;
        self.block = chacha20_block(&self.key, counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);
        self.block_pos = 0;
    }

    /// Fill `dest` with random bytes (convenience method).
    pub fn fill(&mut self, dest: &mut [u8]) {
        self.fill_bytes(dest);
    }
}

impl RngCore for ChaCha20Rng {
    fn next_u32(&mut self) -> u32 {
        // Read up to 4 bytes from the block
        if self.block_pos + 4 > 64 {
            self.refill_block();
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.block[self.block_pos..self.block_pos + 4]);
        self.block_pos += 4;
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        // Read up to 8 bytes from the block
        if self.block_pos + 8 > 64 {
            self.refill_block();
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.block[self.block_pos..self.block_pos + 8]);
        self.block_pos += 8;
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.block_pos >= 64 {
                self.refill_block();
            }
            let n = std::cmp::min(64 - self.block_pos, dest.len() - written);
            dest[written..written + n]
                .copy_from_slice(&self.block[self.block_pos..self.block_pos + n]);
            self.block_pos += n;
            written += n;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ChaCha20Rng {}

impl SeedableRng for ChaCha20Rng {
    type Seed = [u8; CHACHA20_KEY_SIZE];

    fn from_seed(seed: Self::Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl std::fmt::Debug for ChaCha20Rng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact `key`, `nonce` (derived from seed), and `block` (current keystream).
        // Surface `counter` and `block_pos` for flow control debugging — both are
        // bookkeeping and do not leak secret material.
        f.debug_struct("ChaCha20Rng")
            .field("counter", &self.counter)
            .field("block_pos", &self.block_pos)
            .finish_non_exhaustive()
    }
}

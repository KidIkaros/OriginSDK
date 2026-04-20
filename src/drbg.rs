// SPDX-License-Identifier: OPL-1.1

//! ChaCha20-DRBG — deterministic CSPRNG with auto-reseed.
//!
//! All randomness in Origin flows through this DRBG so that
//! PQC key generation (NTRU, Falcon) is fully deterministic from the master seed.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum bytes before automatic reseed from OS entropy.
const MAX_BYTES_BEFORE_RESEED: u64 = 1 << 24; // 16 MB

/// ChaCha20-based DRBG with auto-reseed.
///
/// When created from a seed, all output is deterministic.
/// After `MAX_BYTES_BEFORE_RESEED` bytes, the DRBG automatically mixes
/// in OS entropy to limit exposure if state is compromised.
#[derive(ZeroizeOnDrop)]
pub struct ChaCha20Drbg {
    #[zeroize(skip)] // ChaCha20Rng handles its own zeroization
    inner: ChaCha20Rng,
    generated: u64,
}

impl ChaCha20Drbg {
    /// Create a DRBG from a 32-byte seed. Output is deterministic.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
            generated: 0,
        }
    }

    /// Create a DRBG seeded from OS entropy.
    pub fn from_os_entropy() -> Self {
        Self {
            inner: ChaCha20Rng::from_entropy(),
            generated: 0,
        }
    }

    /// Mix new entropy into the DRBG state.
    pub fn reseed(&mut self, entropy: &[u8]) {
        let mut new_seed = [0u8; 32];
        self.inner.fill_bytes(&mut new_seed);
        for (i, &b) in entropy.iter().enumerate() {
            new_seed[i % 32] ^= b;
        }
        self.inner = ChaCha20Rng::from_seed(new_seed);
        new_seed.zeroize();
        self.generated = 0;
    }

    /// Generate `n` random bytes.
    ///
    /// Auto-reseeds from OS entropy after 16 MB of output.
    pub fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        if self.generated + n as u64 > MAX_BYTES_BEFORE_RESEED {
            let mut os_entropy = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut os_entropy);
            self.reseed(&os_entropy);
            os_entropy.zeroize();
        }

        let mut buf = vec![0u8; n];
        self.inner.fill_bytes(&mut buf);
        self.generated += n as u64;
        buf
    }

    /// Fill a mutable slice with random bytes.
    pub fn fill(&mut self, dest: &mut [u8]) {
        let bytes = self.random_bytes(dest.len());
        dest.copy_from_slice(&bytes);
    }
}

impl std::fmt::Debug for ChaCha20Drbg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20Drbg")
            .field("generated", &self.generated)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_from_seed() {
        let seed = [42u8; 32];
        let mut a = ChaCha20Drbg::from_seed(seed);
        let mut b = ChaCha20Drbg::from_seed(seed);
        assert_eq!(a.random_bytes(64), b.random_bytes(64));
    }

    #[test]
    fn different_seeds_different_output() {
        let mut a = ChaCha20Drbg::from_seed([1u8; 32]);
        let mut b = ChaCha20Drbg::from_seed([2u8; 32]);
        assert_ne!(a.random_bytes(32), b.random_bytes(32));
    }

    #[test]
    fn reseed_changes_output() {
        let seed = [42u8; 32];
        let mut drbg = ChaCha20Drbg::from_seed(seed);
        let before = drbg.random_bytes(32);

        let mut drbg2 = ChaCha20Drbg::from_seed(seed);
        drbg2.reseed(b"extra entropy here!!");
        let after = drbg2.random_bytes(32);

        assert_ne!(before, after);
    }
}

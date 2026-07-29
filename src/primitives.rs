// SPDX-License-Identifier: Apache-2.0

//! Low-level cryptographic primitives
//!
//! Native implementations of core algorithms with no external crypto dependencies.

pub mod chacha20;
pub mod chacha20poly1305;
pub mod chacha40;
pub mod poly1305;
pub mod sha3;
pub mod tier;

pub use sha3::{sha3_256, sha3_512, Sha3_256, Sha3_512, Shake128, Shake256};
pub use tier::MemoryTier;

/// BLAKE3 hash function — fast, parallelizable, suitable for hybrid constructions.
pub mod blake3 {
    pub use blake3::{Hash, Hasher, KEY_LEN, OUT_LEN};

    /// Compute BLAKE3 hash of input.
    pub fn hash(input: &[u8]) -> Hash {
        blake3::hash(input)
    }

    /// Compute keyed BLAKE3 hash (BLAKE3 keyed hash mode).
    pub fn keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> Hash {
        blake3::keyed_hash(key, input)
    }

    /// Compute BLAKE3-derived key (derive_key mode).
    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; OUT_LEN] {
        blake3::derive_key(context, key_material)
    }
}

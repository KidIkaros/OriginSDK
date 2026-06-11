// SPDX-License-Identifier: OPL-1.1

//! Test utilities for downstream users.
//!
//! This module provides deterministic seeds, mock key generation, and
//! proptest strategies so users can write tests against the SDK without
//! touching real cryptographic randomness.
//!
//! **Feature-gated** — only available with `features = ["test-utils"]`.
//!
//! # Example
//!
//! ```ignore
//! use origin_crypto_sdk::test_utils::deterministic_seed;
//!
//! let seed = deterministic_seed(42);
//! // Use seed for key derivation, signing, etc.
//! ```

use crate::types::Seed;

/// A deterministic 32-byte seed for testing.
///
/// Generated from a simple PRNG seeded with the given index.
/// NOT cryptographically secure — for tests only.
pub fn deterministic_seed(index: u64) -> Seed {
    let mut state = index.wrapping_add(0x9E3779B97F4A7C15);
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes[i] = state as u8;
    }
    Seed::from(bytes)
}

/// Generate a deterministic Ed25519 signing key for testing.
///
/// The key is derived from a deterministic seed indexed by `index`.
/// NOT for production use.
pub fn deterministic_ed25519_key(index: u64) -> ed25519_dalek::SigningKey {
    let seed = deterministic_seed(index);
    ed25519_dalek::SigningKey::from_bytes(seed.as_bytes())
}

/// Generate a deterministic 32-byte key for testing AEAD operations.
pub fn deterministic_key(index: u64) -> [u8; 32] {
    *deterministic_seed(index).as_bytes()
}

/// Generate a deterministic 24-byte nonce for testing.
pub fn deterministic_nonce_24(index: u64) -> [u8; 24] {
    let seed = deterministic_seed(index);
    let mut nonce = [0u8; 24];
    nonce[..24].copy_from_slice(&seed.as_bytes()[..24]);
    nonce
}

/// Generate a deterministic 12-byte nonce for testing.
pub fn deterministic_nonce_12(index: u64) -> [u8; 12] {
    let seed = deterministic_seed(index);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&seed.as_bytes()[..12]);
    nonce
}

/// Generate a deterministic random-ish byte vector of the given length.
pub fn deterministic_bytes(index: u64, len: usize) -> Vec<u8> {
    let mut state = index.wrapping_add(0xCAFEBABE_DEADC0DE);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(state as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_seed_reproducible() {
        let s1 = deterministic_seed(42);
        let s2 = deterministic_seed(42);
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_different_indices_different_seeds() {
        let s1 = deterministic_seed(1);
        let s2 = deterministic_seed(2);
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn test_deterministic_key_32_bytes() {
        let key = deterministic_key(99);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_deterministic_nonce_24() {
        let nonce = deterministic_nonce_24(7);
        assert_eq!(nonce.len(), 24);
    }

    #[test]
    fn test_deterministic_nonce_12() {
        let nonce = deterministic_nonce_12(7);
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_deterministic_bytes_length() {
        let bytes = deterministic_bytes(0, 100);
        assert_eq!(bytes.len(), 100);
        assert_ne!(bytes, vec![0u8; 100]);
    }
}

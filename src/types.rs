// SPDX-License-Identifier: Apache-2.0

//! Typed wrappers for cryptographic primitives.
//!
//! Raw `&[u8]` parameters are error-prone — passing a nonce where a seed is
//! expected compiles fine but is silently wrong. These newtypes add type-level
//! distinction while remaining zero-cost via `Deref` and `From` impls.
//!
//! # When to use
//!
//! Use these types in new code. Existing `&[u8]` APIs remain available for
//! backward compatibility; the newtypes implement `AsRef<[u8]>` and `From<[u8; N]>`
//! so they interoperate freely.
//!
//! # Example
//!
//! ```rust
//! use origin_crypto_sdk::types::Seed;
//!
//! let raw = [0x42u8; 32];
//! let seed = Seed::from(raw);
//! assert_eq!(seed.as_bytes().len(), 32);
//! ```

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;

// ─── Seed (32 bytes) ─────────────────────────────────────────────────

/// A 32-byte cryptographic seed.
///
/// Master seeds are the root of all key derivation in this crate. This type
/// ensures seeds are always 32 bytes and zeroized on drop.
#[derive(Clone)]
pub struct Seed([u8; Self::LEN]);

impl Seed {
    /// Seed length in bytes.
    pub const LEN: usize = 32;

    /// Create from a 32-byte array.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Create from a byte slice. Returns error if not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "Seed",
                expected: Self::LEN,
                got: slice.len(),
            });
        }
        let mut arr = [0u8; Self::LEN];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Convert to the inner array (consumes self).
    pub fn into_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}

impl From<[u8; 32]> for Seed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seed")
            .field("len", &Self::LEN)
            .finish_non_exhaustive()
    }
}

// ─── XNonce (24 bytes — XChaCha20-Poly1305) ──────────────────────────

/// A 24-byte nonce for XChaCha20-Poly1305.
///
/// XChaCha20 extends the ChaCha20 nonce from 12 to 24 bytes using
/// HChaCha20, eliminating the need for random nonces to be collision-free.
#[derive(Clone, Debug)]
pub struct XNonce([u8; Self::LEN]);

impl XNonce {
    /// Nonce length in bytes.
    pub const LEN: usize = 24;

    /// Create from a 24-byte array.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    ///
    /// # Panics
    /// Panics if the operating-system entropy source is unavailable or fails.
    /// Use [`XNonce::try_random`] for a fallible variant.
    pub fn random() -> Self {
        Self::try_random().expect("failed to generate random nonce")
    }

    /// Generate a random nonce, returning an error on RNG failure.
    pub fn try_random() -> Result<Self> {
        let mut bytes = [0u8; Self::LEN];
        crate::internal::getrandom::fill(&mut bytes)
            .map_err(|error| CryptoError::Io(std::io::Error::other(error)))?;
        Ok(Self(bytes))
    }

    /// Create from a byte slice. Returns error if not exactly 24 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(CryptoError::InvalidNonceLength {
                algorithm: "XChaCha20-Poly1305",
                expected: Self::LEN,
                got: slice.len(),
            });
        }
        let mut arr = [0u8; Self::LEN];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl From<[u8; 24]> for XNonce {
    fn from(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for XNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ─── CNonce (12 bytes — ChaCha20-Poly1305 / ChaCha20-BLAKE3) ─────────

/// A 12-byte nonce for ChaCha20-Poly1305 or ChaCha20-BLAKE3.
///
/// With a 12-byte nonce you must ensure uniqueness per key — either
/// use a counter or, for the simplest safe default, prefer [`XNonce`]
/// (24 bytes) which doesn't have this constraint.
#[derive(Clone, Debug)]
pub struct CNonce([u8; Self::LEN]);

impl CNonce {
    /// Nonce length in bytes.
    pub const LEN: usize = 12;

    /// Create from a 12-byte array.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    ///
    /// # Panics
    /// Panics if the operating-system entropy source is unavailable or fails.
    /// Use [`CNonce::try_random`] for a fallible variant.
    pub fn random() -> Self {
        Self::try_random().expect("failed to generate random nonce")
    }

    /// Generate a random nonce, returning an error on RNG failure.
    pub fn try_random() -> Result<Self> {
        let mut bytes = [0u8; Self::LEN];
        crate::internal::getrandom::fill(&mut bytes)
            .map_err(|error| CryptoError::Io(std::io::Error::other(error)))?;
        Ok(Self(bytes))
    }

    /// Create from a byte slice. Returns error if not exactly 12 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LEN {
            return Err(CryptoError::InvalidNonceLength {
                algorithm: "ChaCha20",
                expected: Self::LEN,
                got: slice.len(),
            });
        }
        let mut arr = [0u8; Self::LEN];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl From<[u8; 12]> for CNonce {
    fn from(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for CNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_roundtrip() {
        let raw = [0xABu8; 32];
        let seed = Seed::new(raw);
        assert_eq!(seed.as_bytes(), &raw);
        let back = seed.into_bytes();
        assert_eq!(back, raw);
    }

    #[test]
    fn test_seed_from_slice_wrong_len() {
        let short = [0u8; 16];
        let err = Seed::from_slice(&short).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                got: 16,
                ..
            }
        ));
    }

    #[test]
    fn test_seed_debug_no_leak() {
        let seed = Seed::new([0x42u8; 32]);
        let dbg = format!("{:?}", seed);
        assert!(!dbg.contains("42"));
    }

    #[test]
    fn test_xnonce_random_unique() {
        let a = XNonce::random();
        let b = XNonce::random();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_cnonce_from_slice_wrong_len() {
        let short = [0u8; 8];
        let err = CNonce::from_slice(&short).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidNonceLength {
                expected: 12,
                got: 8,
                ..
            }
        ));
    }

    #[test]
    fn test_xnonce_from_slice_correct() {
        let raw = [0x99u8; 24];
        let nonce = XNonce::from_slice(&raw).unwrap();
        assert_eq!(nonce.as_bytes(), &raw);
    }

    #[test]
    fn test_cnonce_random_unique() {
        let a = CNonce::random();
        let b = CNonce::random();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}

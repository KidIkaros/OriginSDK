// SPDX-License-Identifier: OPL-1.1

//! Classical (non-post-quantum) signing primitives.
//!
//! This module exposes Ed25519 signing with a clean seed-based API.
//! For new applications that need quantum resistance, use
//! [`super::hybrid::HybridSigningKeyBundle`] instead — it pairs Ed25519
//! with Falcon-1024 so the signature remains unforgeable even if Ed25519
//! is broken.
//!
//! # Example
//!
//! ```rust
//! use origin_crypto_sdk::signing::classical::Ed25519Signer;
//!
//! let signer = Ed25519Signer::from_seed(&[0x42u8; 32]);
//! let sig = signer.sign(b"hello world");
//! assert!(signer.verify(b"hello world", &sig));
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Ed25519 signer with a clean seed-based API.
///
/// Pure Ed25519 — no post-quantum insurance. For new applications that
/// need quantum resistance, prefer [`super::hybrid::HybridSigningKeyBundle`].
#[derive(Clone)]
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Create a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Create a signer from an existing Ed25519 secret key.
    pub fn from_secret_key(key: SigningKey) -> Self {
        Self { key }
    }

    /// Sign a message. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// Verify a 64-byte Ed25519 signature against this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.key.verify(message, &sig).is_ok()
    }

    /// Verify a signature against an arbitrary public key.
    pub fn verify_with_pubkey(
        pubkey: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig).is_ok()
    }

    /// Get the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Get the 32-byte Ed25519 secret key seed.
    pub fn secret_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let s = Ed25519Signer::from_seed(&[1u8; 32]);
        let msg = b"hello";
        let sig = s.sign(msg);
        assert!(s.verify(msg, &sig));
    }

    #[test]
    fn verify_rejects_tampered_msg() {
        let s = Ed25519Signer::from_seed(&[1u8; 32]);
        let sig = s.sign(b"original");
        assert!(!s.verify(b"tampered", &sig));
    }

    #[test]
    fn verify_with_pubkey() {
        let s = Ed25519Signer::from_seed(&[2u8; 32]);
        let pubkey = s.public_key();
        let sig = s.sign(b"x");
        assert!(Ed25519Signer::verify_with_pubkey(&pubkey, b"x", &sig));
    }
}

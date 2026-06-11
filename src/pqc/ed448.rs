// SPDX-License-Identifier: Apache-2.0

//! Ed448 signature scheme per RFC 8032.
//!
//! Ed448 is the Edwards-curve digital signature algorithm operating on
//! the "Edwards448" curve (Goldilocks). Standardized for use in TLS 1.3
//! (RFC 8446) and DNSSEC (RFC 8080).
//!
//! # Curve parameters (RFC 8032 §5.1.2)
//!
//! - Prime field: p = 2^448 - 2^224 - 1
//! - Curve: -x^2 + y^2 = 1 + d*x^2*y^2, with d = -39081
//! - Base point: (x, y) where y = 5/7, x is the larger root
//! - Order: n = 2^446 - 13818066809895115352007386748515426880336692474882178609894523903805
//! - Cofactor: 4
//!
//! # Implementation
//!
//! This module is a thin wrapper around [`ed448_goldilocks`], the
//! RustCrypto Ed448 implementation. We expose:
//!
//! - [`SigningKey`] — 57-byte private key (any bytes, high bit ignored)
//! - [`VerifyingKey`] — 57-byte public key
//! - [`Signature`] — 114-byte signature (R || S, each 57 bytes)
//!
//! # Security
//!
//! - Conjectured security: ~223 bits (above the 2^128 target)
//! - Deterministic signatures: same (key, message) → same sig
//! - Constant-time: no branches on secret data
//! - Domain separation: "SigEd448" prefix prevents cross-curve attacks
//!
//! # Difference from Ed41417
//!
//! Ed448 and Ed41417 are NOT the same curve. They are two different
//! high-security Edwards curves:
//!
//! - **Ed448** (Mike Hamburg, 2015) — operates over a 448-bit Goldilocks
//!   prime, standardized in RFC 8032 / RFC 8446 / RFC 8080. Conjectured
//!   ~223 bits of security. Standard for TLS 1.3 and DNSSEC.
//! - **Ed41417** (Daniel J. Bernstein, 2014) — operates over a 414-bit
//!   prime, used in specific protocols like X41417.

use ed448_goldilocks::SigningKey as InnerSigningKey;
use ed448_goldilocks::VerifyingKey as InnerVerifyingKey;
use ed448_goldilocks::Signature as InnerSignature;

use crate::error::{CryptoError, Result};

/// Size of a private key in bytes (any 57 bytes; high bit ignored per RFC 8032).
pub const SECRET_KEY_SIZE: usize = 57;

/// Size of a public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 57;

/// Size of a signature in bytes.
pub const SIGNATURE_SIZE: usize = 114;

/// Ed448 signing key (RFC 8032).
///
/// Wraps a 57-byte private key. The high bit of the last byte is
/// ignored per RFC 8032 (the "clamping" step is part of signing, not
/// the key storage).
pub struct SigningKey(InnerSigningKey);

impl SigningKey {
    /// Construct a signing key from raw 57-byte secret bytes.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Result<Self> {
        InnerSigningKey::try_from(bytes.as_slice())
            .map(SigningKey)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed448 secret key: {e}")))
    }

    /// Sign a message. Returns a 114-byte Ed448 signature.
    ///
    /// Uses "pure" Ed448 (not Ed448ph) — the message is hashed directly
    /// without a prehash separator.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign_raw(message))
    }

    /// Get the corresponding 57-byte public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Get the 57-byte secret key bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        let mut out = [0u8; SECRET_KEY_SIZE];
        out.copy_from_slice(&self.0.to_bytes()[..]);
        out
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        // Inner SigningKey drops its secret via ZeroizeOnDrop
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public_key", &hex::encode(self.verifying_key().to_bytes()))
            .finish_non_exhaustive()
    }
}

/// Ed448 verifying key (RFC 8032).
pub struct VerifyingKey(InnerVerifyingKey);

impl Clone for VerifyingKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("bytes", &hex::encode(self.0.to_bytes()))
            .finish()
    }
}

impl VerifyingKey {
    /// Parse a verifying key from 57 bytes.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<Self> {
        InnerVerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid Ed448 public key: {e}")))
    }

    /// Get the 57-byte public key bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Verify a 114-byte signature over a message.
    ///
    /// Returns `Ok(())` if the signature is valid, or an error otherwise.
    /// The argument order is `verify(message, signature)` to match the
    /// convention used by the hybrid constructions in this SDK.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.0
            .verify_raw(&signature.0, message)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Ed448 signature (RFC 8032).
///
/// A signature is the concatenation of two 57-byte components: R (the
/// encoded Edwards point) and S (the encoded scalar). Total 114 bytes.
pub struct Signature(InnerSignature);

impl Signature {
    /// Serialize the signature to 114 bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0.to_bytes()
    }

    /// Parse a signature from 114 bytes.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self> {
        InnerSignature::try_from(bytes.as_slice())
            .map(Signature)
            .map_err(|e| CryptoError::InvalidParameter(format!("invalid Ed448 signature: {e}")))
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("bytes", &hex::encode(self.to_bytes()))
            .finish()
    }
}

// Compile-time size sanity check
const _: () = {
    assert!(SECRET_KEY_SIZE == 57);
    assert!(PUBLIC_KEY_SIZE == 57);
    assert!(SIGNATURE_SIZE == 114);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_sizes() {
        assert_eq!(SECRET_KEY_SIZE, 57);
        assert_eq!(PUBLIC_KEY_SIZE, 57);
        assert_eq!(SIGNATURE_SIZE, 114);
    }

    fn sk(seed_byte: u8) -> SigningKey {
        let seed = [seed_byte; SECRET_KEY_SIZE];
        SigningKey::from_bytes(&seed).expect("test seed must be valid")
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = sk(0x42);
        let pk = sk.verifying_key();
        let msg = b"hello Ed448";
        let sig = sk.sign(msg);
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = sk(0x42);
        let pk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(pk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = sk(0x42);
        let pk = sk.verifying_key();
        let mut sig = sk.sign(b"x");
        let mut bytes = sig.to_bytes();
        bytes[10] ^= 0x01;
        let bad_sig = Signature::from_bytes(&bytes).unwrap();
        assert!(pk.verify(b"x", &bad_sig).is_err());
    }

    #[test]
    fn deterministic_signatures() {
        // Ed448 (and EdDSA in general) is deterministic: same key + message
        // → same signature, no random nonce.
        let sk1 = sk(0x42);
        let sk2 = sk(0x42);
        let msg = b"deterministic test";
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn public_key_derivation() {
        let sk = sk(0x42);
        let pk = sk.verifying_key();
        let bytes = pk.to_bytes();
        let restored = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), pk.to_bytes());
    }
}

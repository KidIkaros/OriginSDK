// SPDX-License-Identifier: Apache-2.0

//! Post-quantum signing primitives — Falcon, SLH-DSA, ML-DSA.
//!
//! These are NIST-standardized (or NIST-selected) post-quantum signature
//! schemes, exposed individually. For most applications, prefer
//! [`super::hybrid::HybridSigningKeyBundle`] which pairs a classical
//! primitive with a post-quantum one — that gives defense in depth
//! against either primitive being broken.
//!
//! # Algorithms
//!
//! - **Falcon-1024** — lattice-based, ~NIST level 5 (~256-bit security).
//!   Compact signatures (~1280 bytes), fast verification. The post-quantum
//!   half of the canonical hybrid signing scheme.
//! - **Falcon-512** — lattice-based, ~NIST level 1 (~128-bit security).
//!   Smaller signatures (~666 bytes) but weaker — for compatibility only.
//! - **SLH-DSA** (FIPS 205) — hash-based. Requires no number-theoretic
//!   assumptions; security reduces to SHAKE128 collision resistance.
//!   Very large signatures (~7-50 KB depending on parameter set).
//! - **ML-DSA** (FIPS 204) — lattice-based. Standardized as the "primary"
//!   post-quantum signature algorithm.
//!
//! # Example
//!
//! ```rust
//! use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;
//!
//! let signer = Falcon1024Signer::from_seed(&[0x42u8; 32])
//!     .expect("valid seed");
//! let sig = signer.sign(b"hello").expect("Falcon sign");
//! assert!(signer.verify(b"hello", &sig));
//! ```

// ──────────────────────────────────────────────────────────────────────
// Falcon-1024
// ──────────────────────────────────────────────────────────────────────

impl std::fmt::Debug for Falcon1024Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact `key` (FalconPrivateKey). Surface `public_key` for identity
        // debugging — public keys are not secret.
        f.debug_struct("Falcon1024Signer")
            .field("public_key", &"<present, 1793 bytes>")
            .finish_non_exhaustive()
    }
}

/// Falcon-1024 signer (lattice-based, ~NIST level 5).
pub struct Falcon1024Signer {
    key: crate::pqc::falcon1024::FalconPrivateKey,
    public_key: crate::pqc::falcon1024::FalconPublicKey,
}

impl Falcon1024Signer {
    /// Create a signer from a 32-byte seed.
    ///
    /// Note: Falcon-1024 keygen is expensive (~100ms on first call;
    /// ~10ms on cached re-derivation).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, crate::error::CryptoError> {
        let (pk, sk) = crate::pqc::falcon1024::generate_keypair_from_seed(seed).map_err(|e| {
            crate::error::CryptoError::InvalidKey(format!("Falcon-1024 keygen: {e}"))
        })?;
        Ok(Self {
            key: sk,
            public_key: pk,
        })
    }

    /// Create from an existing private/public key pair.
    pub fn from_keys(
        sk: crate::pqc::falcon1024::FalconPrivateKey,
        pk: crate::pqc::falcon1024::FalconPublicKey,
    ) -> Self {
        Self {
            key: sk,
            public_key: pk,
        }
    }

    /// Sign a message. Returns a ~1280-byte Falcon-1024 signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::error::CryptoError> {
        crate::pqc::falcon1024::sign(message, &self.key)
            .map(|s| s.as_bytes().to_vec())
            .map_err(|e| crate::error::CryptoError::InvalidKey(format!("Falcon-1024 sign: {e}")))
    }

    /// Verify a signature against this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(sig) = crate::pqc::falcon1024::FalconSignature::from_bytes(signature) else {
            return false;
        };
        crate::pqc::falcon1024::verify(message, &sig, &self.public_key).is_ok()
    }

    /// Verify a signature against an arbitrary Falcon-1024 public key.
    pub fn verify_with_pubkey(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = crate::pqc::falcon1024::FalconPublicKey::from_bytes(pubkey) else {
            return false;
        };
        let Ok(sig) = crate::pqc::falcon1024::FalconSignature::from_bytes(signature) else {
            return false;
        };
        crate::pqc::falcon1024::verify(message, &sig, &pk).is_ok()
    }

    /// Get the 1793-byte Falcon-1024 public key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

// ──────────────────────────────────────────────────────────────────────
// Falcon-512 (smaller, weaker — for compatibility only)
// ──────────────────────────────────────────────────────────────────────

/// Falcon-512 signer (lattice-based, ~NIST level 1).
///
/// Smaller signatures (~666 bytes) but ~128-bit security. For new
/// applications, prefer [`Falcon1024Signer`] which has ~256-bit security.
impl std::fmt::Debug for Falcon512Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact `sk` (Falcon512PrivateKey). Surface `pk` for identity
        // debugging — public keys are not secret.
        f.debug_struct("Falcon512Signer")
            .field("pk", &"<present, public bytes>")
            .finish_non_exhaustive()
    }
}

pub struct Falcon512Signer {
    sk: crate::pqc::falcon512::Falcon512PrivateKey,
    pk: crate::pqc::falcon512::Falcon512PublicKey,
}

impl Falcon512Signer {
    /// Create a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (sk, pk) = crate::pqc::falcon512::generate_keypair(*seed);
        Self { sk, pk }
    }

    /// Sign a message. Returns a ~809-byte Falcon-512 signature (CT format).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::error::CryptoError> {
        crate::pqc::falcon512::sign(message, &self.sk)
            .map(|s| s.0)
            .map_err(|e| crate::error::CryptoError::InvalidKey(format!("Falcon-512 sign: {e}")))
    }

    /// Verify a signature against this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig = crate::pqc::falcon512::Falcon512Signature(signature.to_vec());
        crate::pqc::falcon512::verify(message, &sig, &self.pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon1024_roundtrip() {
        let s = Falcon1024Signer::from_seed(&[1u8; 32]).unwrap();
        let msg = b"hello";
        let sig = s.sign(msg).unwrap();
        assert!(s.verify(msg, &sig));
    }

    #[test]
    fn falcon1024_rejects_tampered() {
        let s = Falcon1024Signer::from_seed(&[2u8; 32]).unwrap();
        let sig = s.sign(b"original").unwrap();
        assert!(!s.verify(b"tampered", &sig));
    }

    #[test]
    fn falcon512_roundtrip() {
        let s = Falcon512Signer::from_seed(&[3u8; 32]);
        let msg = b"hello";
        let sig = s.sign(msg).unwrap();
        assert!(s.verify(msg, &sig));
    }
}

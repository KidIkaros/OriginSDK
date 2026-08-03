// SPDX-License-Identifier: Apache-2.0

//! Algorithm identifiers for downgrade resistance.
//!
//! Every cryptographic operation in the SDK should be bound to an explicit
//! algorithm identifier. This prevents downgrade attacks where an attacker
//! substitutes a weaker algorithm for a stronger one.
//!
//! # Design
//!
//! Algorithm IDs are 16-bit unsigned integers. The high byte identifies the
//! algorithm family; the low byte identifies the variant or version.
//! IDs are stable and will not be reused or reassigned.
//!
//! # Usage
//!
//! Algorithm IDs are included in AAD for AEAD operations and in the signed
//! context for signature operations. This binds the ciphertext or signature
//! to the algorithm that produced it, preventing algorithm substitution.
//!
//! # Experimental
//!
//! This module is part of the 0.7 stabilization effort. The ID assignments
//! are frozen, but the binding mechanism (how IDs are incorporated into
//! AAD or signature context) may evolve before 1.0.0.

#![allow(dead_code)]

/// 16-bit algorithm identifier.
///
/// High byte = algorithm family, low byte = variant/version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    // ── AEAD (0x01xx) ──────────────────────────────────────────────────
    /// XChaCha20-Poly1305 via external `chacha20poly1305` crate
    XChaCha20Poly1305 = 0x0101,
    /// Native XChaCha20-Poly1305 (custom implementation)
    XChaCha20Poly1305Native = 0x0102,
    /// ChaCha20-BLAKE3 (committing AEAD)
    ChaCha20Blake3 = 0x0103,

    // ── KDF (0x02xx) ───────────────────────────────────────────────────
    /// Argon2id password-based KDF
    Argon2id = 0x0201,
    /// HKDF-SHA3-256
    HkdfSha3_256 = 0x0202,
    /// HKDF-SHA3-512
    HkdfSha3_512 = 0x0203,

    // ── Hash (0x03xx) ──────────────────────────────────────────────────
    /// SHA3-256
    Sha3_256 = 0x0301,
    /// SHA3-512
    Sha3_512 = 0x0302,
    /// BLAKE3
    Blake3 = 0x0303,
    /// Skein-512
    Skein512 = 0x0304,
    /// Skein-1024
    Skein1024 = 0x0305,
    /// SHAKE256 (XOF)
    Shake256 = 0x0306,

    // ── Signatures (0x04xx) ────────────────────────────────────────────
    /// Ed25519 (via ed25519-dalek)
    Ed25519 = 0x0401,
    /// Ed448 (via ed448-goldilocks)
    Ed448 = 0x0402,
    /// Falcon-512 (via falcon-rs (FIPS 206))
    Falcon512 = 0x0403,
    /// Falcon-1024 (via falcon-rs (FIPS 206))
    Falcon1024 = 0x0404,
    /// SLH-DSA (SPHINCS+, FIPS 205)
    SlhDsa = 0x0405,
    /// ML-DSA (Dilithium, FIPS 204)
    MlDsa = 0x0406,

    // ── Hybrid signatures (0x05xx) ────────────────────────────────────
    /// Ed25519 + Falcon-1024
    Ed25519Falcon1024 = 0x0501,
    /// Ed25519 + Falcon-512
    Ed25519Falcon512 = 0x0502,
    /// Ed448 + Falcon-1024
    Ed448Falcon1024 = 0x0503,
    /// Ed25519 + BLAKE3 hash
    Ed25519Blake3 = 0x0504,
    /// Ed25519 + SHAKE256 XOF
    Ed25519Shake256 = 0x0505,
    /// Ed25519 + Skein-512
    Ed25519Skein512 = 0x0506,

    // ── KEM (0x06xx) ───────────────────────────────────────────────────
    /// Streamlined NTRU Prime (sntrup761)
    NtruPrime = 0x0601,
    /// X25519 (via external crate)
    X25519 = 0x0602,

    // ── Custom curves (0x07xx) ─────────────────────────────────────────
    /// Curve41417 (Ed41417)
    Ed41417 = 0x0701,
    /// secp256k1 (custom arithmetic)
    Secp256k1 = 0x0702,

    // ── DRBG (0x08xx) ──────────────────────────────────────────────────
    /// ChaCha20-DRBG (custom)
    ChaCha20Drbg = 0x0801,

    // ── MAC (0x09xx) ───────────────────────────────────────────────────
    /// Poly1305 (native implementation)
    Poly1305 = 0x0901,
    /// SipHash-c-d (compute hardener, not a security boundary)
    SipHash = 0x0902,
    /// HMAC-SHA3-256
    HmacSha3_256 = 0x0903,

    // ── Persistence (0x0Axx) ───────────────────────────────────────────
    /// Seed Blob v2 (ORGB magic)
    SeedBlobV2 = 0x0A01,
    /// Seed Blob v1 (legacy)
    SeedBlobV1 = 0x0A02,
}

impl AlgorithmId {
    /// Convert to a 2-byte big-endian representation for inclusion in
    /// AAD, signature context, or format headers.
    pub fn to_bytes(self) -> [u8; 2] {
        let v = self as u16;
        [v.to_be_bytes()[0], v.to_be_bytes()[1]]
    }

    /// Convert to a 2-byte little-endian representation.
    pub fn to_bytes_le(self) -> [u8; 2] {
        let v = self as u16;
        [v.to_le_bytes()[0], v.to_le_bytes()[1]]
    }

    /// The algorithm family (high byte).
    pub fn family(self) -> u8 {
        (self as u16 >> 8) as u8
    }

    /// The algorithm variant within the family (low byte).
    pub fn variant(self) -> u8 {
        (self as u16 & 0xFF) as u8
    }

    /// Human-readable name for the algorithm.
    pub fn name(self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Self::XChaCha20Poly1305Native => "XChaCha20-Poly1305 (native)",
            Self::ChaCha20Blake3 => "ChaCha20-BLAKE3",
            Self::Argon2id => "Argon2id",
            Self::HkdfSha3_256 => "HKDF-SHA3-256",
            Self::HkdfSha3_512 => "HKDF-SHA3-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake3 => "BLAKE3",
            Self::Skein512 => "Skein-512",
            Self::Skein1024 => "Skein-1024",
            Self::Shake256 => "SHAKE256",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::Falcon512 => "Falcon-512",
            Self::Falcon1024 => "Falcon-1024",
            Self::SlhDsa => "SLH-DSA (SPHINCS+)",
            Self::MlDsa => "ML-DSA (Dilithium)",
            Self::Ed25519Falcon1024 => "Ed25519+Falcon-1024",
            Self::Ed25519Falcon512 => "Ed25519+Falcon-512",
            Self::Ed448Falcon1024 => "Ed448+Falcon-1024",
            Self::Ed25519Blake3 => "Ed25519+BLAKE3",
            Self::Ed25519Shake256 => "Ed25519+SHAKE256",
            Self::Ed25519Skein512 => "Ed25519+Skein-512",
            Self::NtruPrime => "NTRU Prime (sntrup761)",
            Self::X25519 => "X25519",
            Self::Ed41417 => "Ed41417 (Curve41417)",
            Self::Secp256k1 => "secp256k1",
            Self::ChaCha20Drbg => "ChaCha20-DRBG",
            Self::Poly1305 => "Poly1305",
            Self::SipHash => "SipHash-c-d",
            Self::HmacSha3_256 => "HMAC-SHA3-256",
            Self::SeedBlobV2 => "Seed Blob v2",
            Self::SeedBlobV1 => "Seed Blob v1 (legacy)",
        }
    }

    /// Whether this algorithm is a custom (non-external) implementation.
    pub fn is_custom(self) -> bool {
        matches!(
            self,
            Self::XChaCha20Poly1305Native
                | Self::NtruPrime
                | Self::Ed41417
                | Self::Secp256k1
                | Self::ChaCha20Drbg
                | Self::Poly1305
                | Self::SipHash
                | Self::SeedBlobV2
                | Self::SeedBlobV1
        )
    }

    /// Whether this algorithm is a hybrid composition.
    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            Self::Ed25519Falcon1024
                | Self::Ed25519Falcon512
                | Self::Ed448Falcon1024
                | Self::Ed25519Blake3
                | Self::Ed25519Shake256
                | Self::Ed25519Skein512
        )
    }
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:04X})", self.name(), *self as u16)
    }
}

/// Downgrade policy: the minimum acceptable algorithm for each family.
///
/// When verifying a signature or decrypting a ciphertext, the caller can
/// check that the algorithm used meets the minimum required strength.
/// This prevents an attacker from substituting a weaker algorithm.
#[derive(Debug, Clone, Copy)]
pub enum DowngradePolicy {
    /// Accept any algorithm in the family (no downgrade protection)
    AllowAny,
    /// Reject algorithms weaker than the specified minimum
    Minimum(AlgorithmId),
    /// Accept only the exact specified algorithm
    Exact(AlgorithmId),
}

impl DowngradePolicy {
    /// Check whether an algorithm is acceptable under this policy.
    pub fn accepts(&self, alg: AlgorithmId) -> bool {
        match self {
            Self::AllowAny => true,
            Self::Minimum(min) => alg as u16 >= *min as u16,
            Self::Exact(required) => alg == *required,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_id_to_bytes_roundtrip() {
        for alg in [
            AlgorithmId::XChaCha20Poly1305,
            AlgorithmId::Ed25519Falcon1024,
            AlgorithmId::Argon2id,
            AlgorithmId::SeedBlobV2,
        ] {
            let bytes = alg.to_bytes();
            let reconstructed = u16::from_be_bytes(bytes);
            assert_eq!(reconstructed, alg as u16, "roundtrip failed for {alg}");
        }
    }

    #[test]
    fn algorithm_id_family_and_variant() {
        assert_eq!(AlgorithmId::XChaCha20Poly1305.family(), 0x01);
        assert_eq!(AlgorithmId::XChaCha20Poly1305.variant(), 0x01);
        assert_eq!(AlgorithmId::Ed25519Falcon1024.family(), 0x05);
        assert_eq!(AlgorithmId::Ed25519Falcon1024.variant(), 0x01);
    }

    #[test]
    fn algorithm_id_is_custom() {
        assert!(AlgorithmId::NtruPrime.is_custom());
        assert!(AlgorithmId::Poly1305.is_custom());
        assert!(!AlgorithmId::XChaCha20Poly1305.is_custom());
        assert!(!AlgorithmId::Ed25519.is_custom());
    }

    #[test]
    fn algorithm_id_is_hybrid() {
        assert!(AlgorithmId::Ed25519Falcon1024.is_hybrid());
        assert!(AlgorithmId::Ed25519Blake3.is_hybrid());
        assert!(!AlgorithmId::Ed25519.is_hybrid());
        assert!(!AlgorithmId::XChaCha20Poly1305.is_hybrid());
    }

    #[test]
    fn downgrade_policy_exact() {
        let policy = DowngradePolicy::Exact(AlgorithmId::Ed25519Falcon1024);
        assert!(policy.accepts(AlgorithmId::Ed25519Falcon1024));
        assert!(!policy.accepts(AlgorithmId::Ed25519Falcon512));
    }

    #[test]
    fn downgrade_policy_minimum() {
        // Minimum = Ed25519Falcon1024 (0x0501)
        let policy = DowngradePolicy::Minimum(AlgorithmId::Ed25519Falcon1024);
        assert!(policy.accepts(AlgorithmId::Ed25519Falcon1024));
        // Ed25519Falcon512 (0x0502) has a higher ID
        assert!(policy.accepts(AlgorithmId::Ed25519Falcon512));
        // Ed448Falcon1024 (0x0503) has a higher ID
        assert!(policy.accepts(AlgorithmId::Ed448Falcon1024));
        // Ed25519Blake3 (0x0504) has a higher ID
        assert!(policy.accepts(AlgorithmId::Ed25519Blake3));
        // Ed25519 (0x0401) is in a different family and has a lower ID
        assert!(!policy.accepts(AlgorithmId::Ed25519));
    }

    #[test]
    fn downgrade_policy_allow_any() {
        let policy = DowngradePolicy::AllowAny;
        assert!(policy.accepts(AlgorithmId::Ed25519));
        assert!(policy.accepts(AlgorithmId::XChaCha20Poly1305));
    }

    #[test]
    fn algorithm_id_display() {
        let s = format!("{}", AlgorithmId::Ed25519Falcon1024);
        assert!(s.contains("Ed25519+Falcon-1024"));
        assert!(s.contains("0x0501"));
    }
}

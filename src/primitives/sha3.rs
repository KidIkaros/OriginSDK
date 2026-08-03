// SPDX-License-Identifier: Apache-2.0

//! SHA3 hash functions and SHAKE XOFs
//!
//! Re-exports from `crate::internal::sha3` for backward compatibility.
//! SHAKE XOFs are re-exported from the external `sha3` crate.
//!
//! # NTRU Prime KEM helpers
//!
//! This module also provides hash helpers for the NTRU Prime KEM flow:
//! - `hash_prefix`: NIST reference `Hash_prefix()` — SHA-512 with 1-byte domain separator
//! - `hash_confirm`: NIST reference `HashConfirm()` — confirmation hash
//! - `hash_session`: NIST reference `HashSession()` — session key hash
//! - `hash4`: NIST reference `Hash4()` — cache hash of public key
//!
//! SHAKE-based variants are provided behind feature flags for performance
//! comparison:
//! - `ntru-shake128`: SHAKE128-based KEM hashing (single absorb)
//! - `ntru-shake256`: SHAKE256-based KEM hashing (two-call and single-absorb)

pub use crate::internal::sha3::{Sha3_256, Sha3_512};
pub use sha3::{Shake128, Shake256};

use sha2::Digest;
use sha2::Sha512;

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data)
}

/// Compute SHA3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data)
}

// ============================================================================
// NIST Reference Hash Functions (SHA-2-512 with domain separation)
// ============================================================================

/// Hash bytes constant (32 bytes — first half of SHA-512 output)
pub const HASH_BYTES: usize = 32;

/// NIST reference `Hash_prefix()`: SHA-512 with 1-byte prefix.
///
/// Computes `SHA-512(prefix || data)[..32]`.
///
/// This is the core hash primitive used by the NIST NTRU Prime KEM:
/// - prefix=1: session key (success)
/// - prefix=0: session key (CCA failure)
/// - prefix=2: confirmation hash
/// - prefix=3: inner hash of r_enc
/// - prefix=4: cache hash of pk
pub fn hash_prefix(prefix: u8, data: &[u8]) -> [u8; HASH_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(&[prefix]);
    hasher.update(data);
    let full = hasher.finalize();
    let mut out = [0u8; HASH_BYTES];
    out.copy_from_slice(&full[..HASH_BYTES]);
    out
}

/// NIST reference `Hash4()`: cache hash of public key.
///
/// Computes `Hash_prefix(4, pk)` = `SHA-512(0x04 || pk)[..32]`.
///
/// This is precomputed during keygen and stored in the secret key to avoid
/// recomputing it on every decapsulation.
pub fn hash4(pk: &[u8]) -> [u8; HASH_BYTES] {
    hash_prefix(4, pk)
}

/// NIST reference `HashConfirm()`: confirmation hash.
///
/// Computes `Hash_prefix(2, Hash_prefix(3, r_enc) || cache)[..32]`.
///
/// This binds the ciphertext to the public key via the cache, providing
/// CCA security against adaptive chosen-ciphertext attacks.
///
/// # Arguments
/// - `r_enc`: Small-encoded r (191 bytes)
/// - `cache`: Precomputed `Hash4(pk)` (32 bytes)
pub fn hash_confirm(r_enc: &[u8], cache: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let inner = hash_prefix(3, r_enc);
    let mut x = [0u8; HASH_BYTES * 2];
    x[..HASH_BYTES].copy_from_slice(&inner);
    x[HASH_BYTES..].copy_from_slice(cache);
    hash_prefix(2, &x)
}

/// NIST reference `HashSession()`: session key hash.
///
/// Computes `Hash_prefix(b, Hash_prefix(3, r_enc) || confirm)[..32]`.
///
/// - `b=1` on successful decapsulation
/// - `b=0` on CCA failure (r_enc replaced with rho)
///
/// # Arguments
/// - `b`: Domain separator byte (0 for failure, 1 for success)
/// - `r_enc`: Small-encoded r (191 bytes) or rho on failure
/// - `confirm`: First 32 bytes of ciphertext (confirmation hash)
pub fn hash_session(b: u8, r_enc: &[u8], confirm: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let inner = hash_prefix(3, r_enc);
    let mut x = [0u8; HASH_BYTES * 2];
    x[..HASH_BYTES].copy_from_slice(&inner);
    x[HASH_BYTES..].copy_from_slice(confirm);
    hash_prefix(b, &x)
}

// ============================================================================
// SHAKE-based KEM helpers (experimental, behind feature flags)
// ============================================================================

/// SHAKE128-based KEM hashing (single absorb, experimental).
///
/// Uses a single SHAKE128 absorb of `prefix || r_enc || confirm` to produce
/// both the confirmation hash and session key in one XOF call.
///
/// **Not NIST-compatible.** For performance comparison only.
#[cfg(feature = "ntru-shake128")]
pub mod shake128_kem {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };

    /// Produce 64 bytes from SHAKE128(prefix || data).
    pub fn shake128_xof(prefix: u8, data: &[u8]) -> [u8; 64] {
        let mut hasher = Shake128::default();
        hasher.update(&[prefix]);
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 64];
        reader.read(&mut out);
        out
    }

    /// Confirmation hash: first 32 bytes of SHAKE128(0x02 || r_enc || cache).
    pub fn hash_confirm(r_enc: &[u8], cache: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Shake128::default();
        hasher.update(&[0x02]);
        hasher.update(r_enc);
        hasher.update(cache);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    /// Session key: SHAKE128(b || r_enc || confirm)[..32].
    pub fn hash_session(b: u8, r_enc: &[u8], confirm: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Shake128::default();
        hasher.update(&[b]);
        hasher.update(r_enc);
        hasher.update(confirm);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    /// Cache hash: SHAKE128(0x04 || pk)[..32].
    pub fn hash4(pk: &[u8]) -> [u8; 32] {
        let mut hasher = Shake128::default();
        hasher.update(&[0x04]);
        hasher.update(pk);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }
}

/// SHAKE256-based KEM hashing (experimental).
///
/// Uses SHAKE256 for both confirm and session hashes. Provides two modes:
/// - Two-call: separate SHAKE256 calls for confirm and session (like NIST)
/// - Single-absorb: one SHAKE256 call producing both outputs
///
/// **Not NIST-compatible.** For performance comparison only.
#[cfg(feature = "ntru-shake256")]
pub mod shake256_kem {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    /// Confirmation hash: SHAKE256(0x02 || r_enc || cache)[..32].
    pub fn hash_confirm(r_enc: &[u8], cache: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(&[0x02]);
        hasher.update(r_enc);
        hasher.update(cache);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    /// Session key: SHAKE256(b || r_enc || confirm)[..32].
    pub fn hash_session(b: u8, r_enc: &[u8], confirm: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(&[b]);
        hasher.update(r_enc);
        hasher.update(confirm);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    /// Cache hash: SHAKE256(0x04 || pk)[..32].
    pub fn hash4(pk: &[u8]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(&[0x04]);
        hasher.update(pk);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }

    /// Single-absorb mode: produce both confirm and session key from one
    /// SHAKE256 absorb of `0x02 || r_enc || cache`.
    ///
    /// Returns (confirm[..32], session_key[32..64]).
    pub fn hash_confirm_and_session(r_enc: &[u8], cache: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = Shake256::default();
        hasher.update(&[0x02]);
        hasher.update(r_enc);
        hasher.update(cache);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 64];
        reader.read(&mut out);
        let mut confirm = [0u8; 32];
        let mut session = [0u8; 32];
        confirm.copy_from_slice(&out[..32]);
        session.copy_from_slice(&out[32..]);
        (confirm, session)
    }
}

// ============================================================================
// BLAKE3-based KEM helpers (experimental, behind feature flag)
// ============================================================================

/// BLAKE3-based KEM hashing (experimental).
///
/// Uses BLAKE3 for all KEM hash operations. BLAKE3 is ~3.4× faster than
/// SHA-2-512 at the input sizes used by NTRU Prime (191–1158 bytes).
///
/// **Not NIST-compatible.** For performance comparison and non-interop use.
///
/// # Security
///
/// BLAKE3 derives from BLAKE2 (SHA-3 finalist), provides 256-bit security,
/// and is immune to length-extension attacks. The `blake3` crate (v1.8) is
/// widely deployed and audited.
#[cfg(feature = "ntru-blake3")]
pub mod blake3_kem {
    use blake3::Hasher;

    /// Domain-separated hash: BLAKE3 with 1-byte prefix, 32-byte output.
    ///
    /// BLAKE3 supports built-in domain separation via `update`, so we
    /// prepend the prefix byte just like the NIST reference does with
    /// SHA-2-512.
    pub fn hash_prefix(prefix: u8, data: &[u8]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&[prefix]);
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Cache hash: BLAKE3(0x04 || pk)[..32].
    pub fn hash4(pk: &[u8]) -> [u8; 32] {
        hash_prefix(4, pk)
    }

    /// Confirmation hash: BLAKE3(0x02 || r_enc || cache)[..32].
    pub fn hash_confirm(r_enc: &[u8], cache: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&[0x02]);
        hasher.update(r_enc);
        hasher.update(cache);
        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Session key: BLAKE3(b || r_enc || confirm)[..32].
    pub fn hash_session(b: u8, r_enc: &[u8], confirm: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&[b]);
        hasher.update(r_enc);
        hasher.update(confirm);
        let mut out = [0u8; 32];
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Single-absorb mode: produce both confirm and session key from one
    /// BLAKE3 absorb of `0x02 || r_enc || cache`.
    ///
    /// BLAKE3's XOF mode makes this efficient — one absorb, two reads.
    /// Returns (confirm[..32], session_key[32..64]).
    pub fn hash_confirm_and_session(r_enc: &[u8], cache: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = Hasher::new();
        hasher.update(&[0x02]);
        hasher.update(r_enc);
        hasher.update(cache);
        let mut reader = hasher.finalize_xof();
        let mut out = [0u8; 64];
        reader.fill(&mut out);
        let mut confirm = [0u8; 32];
        let mut session = [0u8; 32];
        confirm.copy_from_slice(&out[..32]);
        session.copy_from_slice(&out[32..]);
        (confirm, session)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_prefix_deterministic() {
        let data = b"test data";
        let h1 = hash_prefix(1, data);
        let h2 = hash_prefix(1, data);
        assert_eq!(h1, h2, "Same prefix+data must produce same hash");
    }

    #[test]
    fn test_hash_prefix_domain_separation() {
        let data = b"test data";
        let h1 = hash_prefix(1, data);
        let h2 = hash_prefix(2, data);
        assert_ne!(h1, h2, "Different prefixes must produce different hashes");
    }

    #[test]
    fn test_hash4_deterministic() {
        let pk = [42u8; 1158];
        let h1 = hash4(&pk);
        let h2 = hash4(&pk);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_confirm_deterministic() {
        let r_enc = [99u8; 191];
        let cache = hash4(&[42u8; 1158]);
        let h1 = hash_confirm(&r_enc, &cache);
        let h2 = hash_confirm(&r_enc, &cache);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_session_success_vs_failure() {
        let r_enc = [99u8; 191];
        let confirm = [0xAA; 32];
        let k_success = hash_session(1, &r_enc, &confirm);
        let k_failure = hash_session(0, &r_enc, &confirm);
        assert_ne!(
            k_success, k_failure,
            "Success and failure session keys must differ"
        );
    }

    #[test]
    fn test_hash_session_deterministic() {
        let r_enc = [99u8; 191];
        let confirm = [0xAA; 32];
        let k1 = hash_session(1, &r_enc, &confirm);
        let k2 = hash_session(1, &r_enc, &confirm);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_hash_confirm_binds_to_pk() {
        let r_enc = [99u8; 191];
        let cache1 = hash4(&[1u8; 1158]);
        let cache2 = hash4(&[2u8; 1158]);
        let h1 = hash_confirm(&r_enc, &cache1);
        let h2 = hash_confirm(&r_enc, &cache2);
        assert_ne!(
            h1, h2,
            "Confirm hash must bind to PK via cache (different PKs → different confirms)"
        );
    }

    #[cfg(feature = "ntru-shake128")]
    #[test]
    fn test_shake128_kem_deterministic() {
        let r_enc = [99u8; 191];
        let cache = shake128_kem::hash4(&[42u8; 1158]);
        let h1 = shake128_kem::hash_confirm(&r_enc, &cache);
        let h2 = shake128_kem::hash_confirm(&r_enc, &cache);
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "ntru-shake256")]
    #[test]
    fn test_shake256_kem_deterministic() {
        let r_enc = [99u8; 191];
        let cache = shake256_kem::hash4(&[42u8; 1158]);
        let h1 = shake256_kem::hash_confirm(&r_enc, &cache);
        let h2 = shake256_kem::hash_confirm(&r_enc, &cache);
        assert_eq!(h1, h2);
    }

    #[cfg(feature = "ntru-shake256")]
    #[test]
    fn test_shake256_single_absord_produces_both() {
        let r_enc = [99u8; 191];
        let cache = [0xCC; 32];
        let (confirm, session) = shake256_kem::hash_confirm_and_session(&r_enc, &cache);
        // Both should be non-zero and different
        assert_ne!(confirm, [0u8; 32]);
        assert_ne!(session, [0u8; 32]);
        assert_ne!(confirm, session);
    }

    #[cfg(feature = "ntru-blake3")]
    #[test]
    fn test_blake3_kem_deterministic() {
        let r_enc = [99u8; 191];
        let cache = blake3_kem::hash4(&[42u8; 1158]);
        let h1 = blake3_kem::hash_confirm(&r_enc, &cache);
        let h2 = blake3_kem::hash_confirm(&r_enc, &cache);
        assert_eq!(h1, h2, "BLAKE3 confirm must be deterministic");
    }

    #[cfg(feature = "ntru-blake3")]
    #[test]
    fn test_blake3_kem_session_success_vs_failure() {
        let r_enc = [99u8; 191];
        let confirm = [0xAA; 32];
        let k_success = blake3_kem::hash_session(1, &r_enc, &confirm);
        let k_failure = blake3_kem::hash_session(0, &r_enc, &confirm);
        assert_ne!(
            k_success, k_failure,
            "BLAKE3: success and failure session keys must differ"
        );
    }

    #[cfg(feature = "ntru-blake3")]
    #[test]
    fn test_blake3_kem_binds_to_pk() {
        let r_enc = [99u8; 191];
        let cache1 = blake3_kem::hash4(&[1u8; 1158]);
        let cache2 = blake3_kem::hash4(&[2u8; 1158]);
        let h1 = blake3_kem::hash_confirm(&r_enc, &cache1);
        let h2 = blake3_kem::hash_confirm(&r_enc, &cache2);
        assert_ne!(h1, h2, "BLAKE3: confirm must bind to PK via cache");
    }

    #[cfg(feature = "ntru-blake3")]
    #[test]
    fn test_blake3_single_absorb_produces_both() {
        let r_enc = [99u8; 191];
        let cache = [0xCC; 32];
        let (confirm, session) = blake3_kem::hash_confirm_and_session(&r_enc, &cache);
        assert_ne!(confirm, [0u8; 32]);
        assert_ne!(session, [0u8; 32]);
        assert_ne!(confirm, session);
    }

    #[cfg(feature = "ntru-blake3")]
    #[test]
    fn test_blake3_differs_from_nist() {
        // BLAKE3 and SHA-2-512 must produce different outputs (different algorithms)
        let cache_nist = hash4(&[42u8; 1158]);
        let cache_blake3 = blake3_kem::hash4(&[42u8; 1158]);
        assert_ne!(
            cache_nist, cache_blake3,
            "BLAKE3 and SHA-2-512 must produce different hashes"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Domain-separated subkey derivation for the hybrid KDF constructions.
//!
//! One master seed + one domain string yields three independent 32-byte
//! subkeys via HKDF-SHA3-256 with fixed labels (`ed25519`, `chacha20`,
//! `hash`). The labels are part of the construction's wire semantics —
//! changing them would change every derived key.

use crate::error::Result;

use super::combinators::hkdf_combine;

/// The three domain-separated subkeys used by the KDF hybrid constructions.
///
/// Field names name the *role* each subkey plays in
/// [`super::constructions::Ed25519ChaCha20Blake3Sha3_256`]:
/// `ed25519` seeds the Ed25519 signing key, `chacha20` keys the BLAKE3
/// keyed hash, `hash` keys the HMAC-SHA3-256.
#[derive(Clone)]
pub struct HybridSubkeys {
    /// Subkey for the Ed25519 signing key (label `"ed25519"`).
    pub ed25519: [u8; 32],
    /// Subkey for the BLAKE3 keyed hash (label `"chacha20"`).
    pub chacha20: [u8; 32],
    /// Subkey for the HMAC-SHA3-256 (label `"hash"`).
    pub hash: [u8; 32],
}

impl std::fmt::Debug for HybridSubkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derived subkeys are secret key material — redact all fields.
        f.debug_struct("HybridSubkeys")
            .field("ed25519", &"<redacted>")
            .field("chacha20", &"<redacted>")
            .field("hash", &"<redacted>")
            .finish()
    }
}

/// Derive the three domain-separated subkeys for hybrid KDF constructions
/// (e.g., `Ed25519_ChaCha20-Blake3_SHA3-256`).
///
/// Uses HKDF-SHA3-256 with the `"hybrid-kdf"` salt and per-role labels, so
/// the same master seed can be reused across domains safely.
///
/// Derived bytes are identical to the pre-0.7.x variable-length form of
/// this function when all lengths were 32 (the only call pattern the SDK
/// ever used); the named-struct return replaces the `(Vec, Vec, Vec)`
/// triple of magic lengths.
pub fn derive_hybrid_keys(master_seed: &[u8], domain: &str) -> Result<HybridSubkeys> {
    let mut ed25519 = [0u8; 32];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"ed25519"].concat(),
        &mut ed25519,
    )?;

    let mut chacha20 = [0u8; 32];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"chacha20"].concat(),
        &mut chacha20,
    )?;

    let mut hash = [0u8; 32];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"hash"].concat(),
        &mut hash,
    )?;

    Ok(HybridSubkeys {
        ed25519,
        chacha20,
        hash,
    })
}

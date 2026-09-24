// SPDX-License-Identifier: Apache-2.0

//! Single-call hybrid signing bundle — the canonical signing API.
//!
//! [`HybridSigningKeyBundle`] derives the Ed25519 + Falcon-1024 keypairs
//! for the canonical hybrid from one master seed + domain string via
//! HKDF-SHA3-256. Falcon-1024 keygen is expensive (~4s), so a bounded
//! process-wide cache lives in [`super::cache`] and is reached through
//! [`HybridSigningKeyBundle::from_seed_cached`].

use std::sync::Arc;

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use crate::pqc::ed448::{SigningKey as Ed448SigningKey, VerifyingKey as Ed448VerifyingKey};
use crate::pqc::falcon1024::{
    generate_keypair_from_seed as falcon_keygen, FalconPrivateKey, FalconPublicKey,
};
use crate::pqc::falcon512::{Falcon512PrivateKey, Falcon512PublicKey};

use super::combinators::hkdf_combine;
use super::constructions::Ed25519Falcon1024;
use super::{Ed25519SigningKey, Ed25519VerifyingKey};

/// Convenience alias for Falcon-1024 keygen
pub fn falcon1024_keygen(seed: &[u8; 32]) -> Result<(FalconPublicKey, FalconPrivateKey)> {
    falcon_keygen(seed)
}

/// Single-call hybrid signing key for the canonical hybrid construction
/// (Ed25519 + Falcon-1024). Derives both keypairs from a seed handle and
/// domain string via HKDF-SHA3-256.
#[derive(Clone)]
pub struct HybridSigningKeyBundle {
    ed25519: (Ed25519SigningKey, Ed25519VerifyingKey),
    falcon1024: (FalconPrivateKey, FalconPublicKey),
    /// Reserved for future expansion (Falcon-512 hybrid family).
    falcon512: Option<(Falcon512PrivateKey, Falcon512PublicKey)>,
    /// Reserved for future expansion (Ed448 hybrid family).
    ed448: Option<(Ed448SigningKey, Ed448VerifyingKey)>,
    domain: String,
}

impl std::fmt::Debug for HybridSigningKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Surface `domain` (semi-public — used as a routing label, not a secret).
        // All key-bearing fields redact via `<redacted>`. The `Option` presence
        // for `falcon512` / `ed448` is preserved as `None` vs `Some(<redacted>)` —
        // these are reserved-family expansions and their presence is not a leak.
        f.debug_struct("HybridSigningKeyBundle")
            .field("domain", &self.domain)
            .field("ed25519", &"<redacted>")
            .field("falcon1024", &"<redacted>")
            .field(
                "falcon512",
                &if self.falcon512.is_some() {
                    "Some(<redacted>)"
                } else {
                    "None"
                },
            )
            .field(
                "ed448",
                &if self.ed448.is_some() {
                    "Some(<redacted>)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl HybridSigningKeyBundle {
    /// Derive a hybrid signing bundle from a master seed and domain.
    ///
    /// This is the "single call" API — pass a 32-byte seed, get back a bundle
    /// that can sign with any of the hybrid constructions in this module.
    pub fn from_seed(master_seed: &[u8; 32], domain: &str) -> Result<Self> {
        // Ed25519 — derive 32-byte seed with domain separation
        let mut ed25519_seed = [0u8; 32];
        hkdf_combine(
            Some(b"hybrid-bundle"),
            master_seed,
            &[domain.as_bytes(), b"ed25519"].concat(),
            &mut ed25519_seed,
        )?;
        let ed25519_sk = Ed25519SigningKey::from_bytes(&ed25519_seed);
        let ed25519_pk = ed25519_sk.verifying_key();
        ed25519_seed.zeroize();

        // Falcon-1024 — derive seed with domain separation, then run Falcon keygen
        let mut falcon_seed = [0u8; 32];
        hkdf_combine(
            Some(b"hybrid-bundle"),
            master_seed,
            &[domain.as_bytes(), b"falcon1024"].concat(),
            &mut falcon_seed,
        )?;
        let (falcon1024_pk, falcon1024_sk) =
            falcon_keygen(&falcon_seed).map_err(|e| CryptoError::Pqc(e.to_string()))?;
        falcon_seed.zeroize();

        Ok(Self {
            ed25519: (ed25519_sk, ed25519_pk),
            falcon1024: (falcon1024_sk, falcon1024_pk),
            falcon512: None,
            ed448: None,
            domain: domain.to_string(),
        })
    }

    /// Sign with the canonical Ed25519 + Falcon-1024 hybrid
    ///
    /// # Panics
    /// Panics if Falcon signing fails. Use [`HybridSigningKeyBundle::try_sign_hybrid`]
    /// for a fallible variant.
    pub fn sign_hybrid(&self, message: &[u8]) -> Ed25519Falcon1024 {
        Ed25519Falcon1024::sign(&self.ed25519.0, &self.falcon1024.0, message)
    }

    /// Sign with the canonical Ed25519 + Falcon-1024 hybrid, returning an error on failure.
    pub fn try_sign_hybrid(&self, message: &[u8]) -> Result<Ed25519Falcon1024> {
        Ed25519Falcon1024::try_sign(&self.ed25519.0, &self.falcon1024.0, message)
    }

    /// Get the Ed25519 verifying key
    pub fn ed25519_pk(&self) -> &Ed25519VerifyingKey {
        &self.ed25519.1
    }

    /// Get the Falcon-1024 public key
    pub fn falcon1024_pk(&self) -> &FalconPublicKey {
        &self.falcon1024.1
    }

    /// Get the domain this bundle was derived for
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get a bundle from a process-wide cache, or derive it if not cached.
    ///
    /// Falcon-1024 keygen is expensive (~4s on a desktop CPU — the NTRU lattice
    /// key generation runs a rejection-sampling loop over random polynomial
    /// pairs until one satisfies the Gram-Schmidt norm bound). When you sign
    /// many messages with the same (seed, domain), use this to avoid
    /// re-deriving the bundle on every call.
    ///
    /// The cache is bounded by [`super::bundle_cache_configure`]. Expired and
    /// oldest entries are evicted automatically on each access. Use
    /// [`super::bundle_cache_clear`] to force full eviction.
    pub fn from_seed_cached(master_seed: &[u8; 32], domain: &str) -> Result<Arc<Self>> {
        super::cache::get_or_insert(master_seed, domain, || Self::from_seed(master_seed, domain))
    }
}

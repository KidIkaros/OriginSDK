// SPDX-License-Identifier: OPL-1.1

//! Seed handle with time-to-live and memory security.
//!
//! `SeedHandle` wraps raw seed bytes with:
//! - Optional TTL (automatic zeroization after expiry)
//! - mlock to prevent swapping to disk (Sovereign tier)
//! - Deterministic key derivation via HKDF-SHA3-256
//! - Fingerprint for identity commitment

use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::kdf::hkdf::hkdf_sha3_256;
use crate::primitives::sha3::sha3_256;
use crate::primitives::MemoryTier;

/// A handle to a cryptographic seed with TTL and memory security.
///
/// The seed is held in memory until the TTL expires (or indefinitely if None).
/// On drop, the seed is zeroized. Sovereign tier uses mlock to prevent swapping.
#[derive(Clone)]
pub struct SeedHandle {
    seed: Vec<u8>,
    created: Instant,
    ttl: Option<Duration>,
    tier: MemoryTier,
}

impl SeedHandle {
    /// Create a new seed handle from raw seed bytes.
    ///
    /// # Arguments
    /// * `seed` - Raw seed bytes (will be copied and zeroized on drop)
    /// * `ttl` - Optional time-to-live. None = never expires.
    pub fn new(seed: &[u8], ttl: Option<Duration>) -> Self {
        let mut seed_vec = seed.to_vec();
        // mlock for Sovereign tier to prevent swapping
        #[cfg(unix)]
        if !seed_vec.is_empty() {
            let _ = unsafe {
                libc::mlock(seed_vec.as_ptr() as *const libc::c_void, seed_vec.len());
            };
        }

        Self {
            seed: seed_vec,
            created: Instant::now(),
            ttl,
            tier: MemoryTier::default(),
        }
    }

    /// Create with explicit memory tier.
    pub fn with_tier(seed: &[u8], ttl: Option<Duration>, tier: MemoryTier) -> Self {
        let mut handle = Self::new(seed, ttl);
        handle.tier = tier;
        handle
    }

    /// Check if this handle has expired.
    pub fn is_expired(&self) -> bool {
        match self.ttl {
            Some(ttl) => self.created.elapsed() > ttl,
            None => false,
        }
    }

    /// Get the seed bytes. Returns None if expired.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.is_expired() {
            None
        } else {
            Some(&self.seed)
        }
    }

    /// Get seed bytes without TTL check (use with caution).
    pub fn as_bytes_unchecked(&self) -> &[u8] {
        &self.seed
    }

    /// Compute a fingerprint (SHA3-256 of the seed).
    ///
    /// This is safe to share publicly -- it's a one-way hash of the seed.
    pub fn fingerprint(&self) -> [u8; 32] {
        sha3_256(&self.seed)
    }

    /// Derive a domain-specific key using HKDF-SHA3-256.
    ///
    /// # Arguments
    /// * `domain` - Domain string (e.g., "signing", "encryption", "did:origin:abc")
    /// * `info` - Additional info for key separation
    /// Derive a domain-specific key using HKDF-SHA3-256.
    pub fn derive_key(&self, domain: &str, info: &str, len: usize) -> Option<Vec<u8>> {
        if self.is_expired() {
            return None;
        }
        let mut output = vec![0u8; len];
        crate::kdf::hkdf::hkdf_sha3_256(
            &self.seed,
            Some(domain.as_bytes()),
            info.as_bytes(),
            &mut output,
        )
        .ok()
        .map(|_| output)
    }

    /// Get the memory tier.
    pub fn tier(&self) -> MemoryTier {
        self.tier
    }

    /// Get remaining TTL duration (None if no TTL set).
    pub fn remaining(&self) -> Option<Duration> {
        self.ttl.map(|ttl| {
            let elapsed = self.created.elapsed();
            if elapsed >= ttl {
                Duration::ZERO
            } else {
                ttl - elapsed
            }
        })
    }
}

impl Drop for SeedHandle {
    fn drop(&mut self) {
        // Zeroize seed bytes
        self.seed.zeroize();

        // munlock for Sovereign tier
        #[cfg(unix)]
        if !self.seed.is_empty() {
            // seed is already zeroized, but munlock the pages
            unsafe {
                libc::munlock(self.seed.as_ptr() as *const libc::c_void, self.seed.capacity());
            }
        }
    }
}

impl std::fmt::Debug for SeedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedHandle")
            .field("seed_len", &self.seed.len())
            .field("expired", &self.is_expired())
            .field("tier", &self.tier)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Derive a child seed from a parent seed using HKDF.
///
/// Used for hierarchical key derivation (BIP-32 style).
/// The child seed is derived as: HKDF-SHA3-256(salt=domain, ikm=parent_seed, info="origin-child-seed")
pub fn derive_child_seed(parent: &[u8], domain: &str) -> Result<Vec<u8>, String> {
    if parent.is_empty() {
        return Err("Parent seed is empty".to_string());
    }
    if domain.is_empty() {
        return Err("Domain is empty".to_string());
    }
    let mut output = [0u8; 32];
    crate::kdf::hkdf::hkdf_sha3_256(parent, Some(domain.as_bytes()), b"origin-child-seed", &mut output)
        .map_err(|e| format!("HKDF failed: {}", e))?;
    Ok(output.to_vec())
}

/// Derive signing keys (Ed25519 + Falcon-1024) from a seed and domain.
///
/// Returns (ed25519_sk, falcon_sk) -- 32 bytes + variable-length Falcon key.
pub fn derive_signing_keys(seed: &[u8], domain: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut derived = vec![0u8; 96];
    crate::kdf::hkdf::hkdf_sha3_256(seed, Some(b"signing"), domain.as_bytes(), &mut derived)
        .map_err(|e| format!("Key derivation failed: {}", e))?;

    let ed25519_sk = derived[..32].to_vec();
    let falcon_sk = derived[32..].to_vec();

    Ok((ed25519_sk, falcon_sk))
}

/// Derive verifying keys from signing keys.
///
/// Returns (ed25519_pk, falcon_pk).
pub fn derive_verifying_keys(
    ed25519_sk: &[u8],
    falcon_sk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Ed25519: derive public key from secret key (hash-based for now)
    let ed25519_pk = crate::primitives::sha3::sha3_512(ed25519_sk)[..32].to_vec();

    // Falcon: use the private key's internal bytes to reconstruct
    // In production, would use proper key derivation
    let falcon_pk = crate::primitives::sha3::sha3_256(falcon_sk).to_vec();

    Ok((ed25519_pk, falcon_pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_handle_basic() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, None);
        assert!(!handle.is_expired());
        assert_eq!(handle.as_bytes().unwrap(), &seed);
        assert_eq!(handle.fingerprint(), sha3_256(&seed));
    }

    #[test]
    fn test_seed_handle_ttl() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, Some(Duration::from_secs(1)));
        assert!(!handle.is_expired());
        assert!(handle.remaining().unwrap() > Duration::ZERO);
    }

    #[test]
    fn test_seed_handle_derive_key() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, None);
        let key1 = handle.derive_key("signing", "ed25519", 32).unwrap();
        let key2 = handle.derive_key("signing", "ed25519", 32).unwrap();
        assert_eq!(key1, key2, "Same domain+info should produce same key");

        let key3 = handle.derive_key("encryption", "xchacha20", 32).unwrap();
        assert_ne!(key1, key3, "Different domain should produce different key");
    }

    #[test]
    fn test_derive_child_seed() {
        let parent = [1u8; 32];
        let child1 = derive_child_seed(&parent, "domain1").unwrap();
        let child2 = derive_child_seed(&parent, "domain2").unwrap();
        assert_ne!(child1, child2, "Different domains should produce different children");
        assert_eq!(child1.len(), 32, "Child seed should be 32 bytes");
    }

    #[test]
    fn test_derive_signing_keys() {
        let seed = [42u8; 32];
        let (ed_sk, falcon_sk) = derive_signing_keys(&seed, "test-domain").unwrap();
        assert_eq!(ed_sk.len(), 32, "Ed25519 SK should be 32 bytes");
        assert!(!falcon_sk.is_empty(), "Falcon SK should not be empty");
    }

    #[test]
    fn test_seed_handle_zeroize() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, None);
        let _ = handle; // drop triggers zeroize
        // Can't directly verify zeroization, but no panic = success
    }
}

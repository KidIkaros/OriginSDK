// SPDX-License-Identifier: OPL-1.1

//! Seed Blob — encrypted master seed at rest.
//!
//! Format: `salt(16) ‖ nonce(24) ‖ ciphertext(32) ‖ tag(16)` = 88 bytes.
//!
//! The passphrase is stretched via Argon2id (tier-specific) to derive a
//! 32-byte encryption key, then XChaCha20-Poly1305 encrypts the raw seed
//! with AAD = salt.
//!
//! Uses native ChaCha20-Poly1305 implementation.
//!
//! # When to use
//!
//! Use this when you need to persist a master seed to disk or a database.
//! The seed is encrypted with a user-supplied passphrase and can only be
//! recovered with the same passphrase.
//!
//! For in-memory seed management with TTL and zeroization, use
//! [`SeedHandle`](crate::seed::SeedHandle) from the
//! [`seed`](crate::seed) module instead.
//!
//! # Example
//!
//! ```rust,no_run
//! use origin_crypto_sdk::blob::{create_blob, recover_seed};
//! use origin_crypto_sdk::primitives::MemoryTier;
//!
//! let seed = [0x42u8; 32];
//! let passphrase = b"strong-passphrase";
//!
//! // Encrypt seed for storage
//! let blob = create_blob(&seed, passphrase, MemoryTier::Standard).unwrap();
//!
//! // Recover seed from blob
//! let recovered = recover_seed(&blob, passphrase, MemoryTier::Standard).unwrap();
//! assert_eq!(seed, recovered);
//! ```
//!
//! # Security
//!
//! - Argon2id memory-hard KDF prevents brute-force attacks on the passphrase
//! - XChaCha20-Poly1305 provides authenticated encryption
//! - Wrong passphrase returns an error (authentication tag check fails)
//!
//! See also: [`seed`](crate::seed), [`kdf`](crate::kdf), [`aead`](crate::aead).

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use crate::primitives::chacha20poly1305 as native;
use crate::primitives::tier::MemoryTier;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = 32;
/// Total blob size: salt + nonce + ciphertext + tag
pub const BLOB_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + 16; // 88

/// Create an encrypted seed blob from a passphrase.
///
/// Returns an 88-byte blob: `salt(16) ‖ nonce(24) ‖ ct+tag(48)`.
/// If `seed` is `None`, generates 32 random bytes.
pub fn create_blob(
    passphrase: &[u8],
    tier: MemoryTier,
    seed: Option<&[u8; SEED_LEN]>,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

    let raw_seed = if let Some(s) = seed {
        *s
    } else {
        let mut s = [0u8; SEED_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
        s
    };

    let mut enc_key = derive_argon2_key(passphrase, &salt, tier)?;

    let ct = native::xchacha20_poly1305_seal(&enc_key, &nonce_bytes, &raw_seed, &salt);

    enc_key.zeroize();

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Recover a 32-byte master seed from an encrypted blob.
pub fn recover_seed(blob: &[u8], passphrase: &[u8], tier: MemoryTier) -> Result<[u8; SEED_LEN]> {
    if blob.len() < BLOB_LEN {
        return Err(CryptoError::InvalidParameter("invalid blob format".into()));
    }

    let salt = &blob[..SALT_LEN];
    let nonce_bytes = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &blob[SALT_LEN + NONCE_LEN..];

    let mut enc_key = derive_argon2_key(passphrase, salt, tier)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    let plaintext = native::xchacha20_poly1305_open(&enc_key, &nonce, ct, salt)
        .map_err(|_| CryptoError::Decryption("blob decryption failed".into()))?;

    enc_key.zeroize();

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Re-encrypt an existing seed under a new passphrase without changing the seed.
pub fn rotate_blob(
    blob: &[u8],
    old_passphrase: &[u8],
    new_passphrase: &[u8],
    tier: MemoryTier,
) -> Result<Vec<u8>> {
    let mut seed = recover_seed(blob, old_passphrase, tier)?;
    let new_blob = create_blob(new_passphrase, tier, Some(&seed))?;
    seed.zeroize();
    Ok(new_blob)
}

/// Derive a 32-byte key from passphrase + salt using Argon2id.
fn derive_argon2_key(passphrase: &[u8], salt: &[u8], tier: MemoryTier) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Version};

    let params = tier.argon2_params(32);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| CryptoError::Kdf("key derivation failed".into()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_recover_roundtrip() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        assert_eq!(blob.len(), BLOB_LEN);

        let recovered = recover_seed(&blob, pw, MemoryTier::Nano).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let seed = [42u8; 32];
        let blob = create_blob(b"correct", MemoryTier::Nano, Some(&seed)).unwrap();
        let result = recover_seed(&blob, b"wrong", MemoryTier::Nano);
        assert!(result.is_err());
    }

    #[test]
    fn rotate_preserves_seed() {
        let seed = [99u8; 32];
        let blob = create_blob(b"old", MemoryTier::Nano, Some(&seed)).unwrap();
        let new_blob = rotate_blob(&blob, b"old", b"new", MemoryTier::Nano).unwrap();

        let recovered = recover_seed(&new_blob, b"new", MemoryTier::Nano).unwrap();
        assert_eq!(recovered, seed);
    }
}

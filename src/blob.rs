// SPDX-License-Identifier: Apache-2.0

//! Seed Blob — encrypted master seed at rest.
//!
//! ## Format versions
//!
//! **v1 (legacy):** `salt(16) ‖ nonce(24) ‖ ct+tag(48)` = 88 bytes.
//! No magic bytes, no version field, no embedded tier. The caller must
//! supply the correct `MemoryTier` to `recover_seed`. Still readable for
//! backward compatibility; no longer written by `create_blob`.
//!
//! **v2 (current):** `magic(4) ‖ version(1) ‖ tier(1) ‖ salt(16) ‖ nonce(24) ‖ ct+tag(48)` = 94 bytes.
//! Magic = `"ORGB"` (Origin Game Blob). Version = `0x02`. The tier is embedded
//! so `recover_seed` can derive the correct Argon2id parameters without the
//! caller remembering which tier was used at creation time. AAD covers the
//! full header (`magic + version + tier + salt`) to prevent header tampering.
//!
//! The passphrase is stretched via Argon2id (tier-specific) to derive a
//! 32-byte encryption key, then XChaCha20-Poly1305 encrypts the raw seed.
//!
//! Uses native ChaCha20-Poly1305 implementation.
//!
//! # Experimental
//!
//! This is a custom persistence format. While it uses established primitives
//! (XChaCha20-Poly1305, Argon2id), the format itself has not undergone
//! independent review. The format may change before 1.0.0. Migration tooling
//! for existing v1/v2 blobs will be provided with any format change.
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
//! ```ignore
//! use origin_crypto_sdk::blob::{create_blob, recover_seed};
//! use origin_crypto_sdk::primitives::MemoryTier;
//!
//! let seed = [0x42u8; 32];
//! let passphrase = b"strong-passphrase";
//!
//! // Encrypt seed for storage (writes v2 format)
//! let blob = create_blob(passphrase, MemoryTier::Standard, Some(&seed)).unwrap();
//!
//! // Recover seed from blob (auto-detects v1/v2, reads tier from v2 header)
//! let recovered = recover_seed(&blob, passphrase, MemoryTier::Standard).unwrap();
//! assert_eq!(seed, recovered);
//! ```
//!
//! # Security
//!
//! - Argon2id memory-hard KDF prevents brute-force attacks on the passphrase
//! - XChaCha20-Poly1305 provides authenticated encryption
//! - v2 AAD covers magic + version + tier + salt, preventing header tampering
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
const TAG_LEN: usize = 16;

/// v1 blob size: salt + nonce + ciphertext + tag (no header).
pub const BLOB_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN; // 88

/// v2 magic bytes: `"ORGB"` (Origin Game Blob).
pub const BLOB_MAGIC: &[u8; 4] = b"ORGB";

/// v2 version byte.
pub const BLOB_VERSION: u8 = 0x02;

/// v2 header size: magic + version + tier + salt + nonce.
const V2_HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + NONCE_LEN; // 46

/// v2 blob size: header + ciphertext + tag.
pub const BLOB_V2_LEN: usize = V2_HEADER_LEN + SEED_LEN + TAG_LEN; // 94

/// Create an encrypted seed blob from a passphrase.
///
/// Writes the v2 format: `magic(4) ‖ version(1) ‖ tier(1) ‖ salt(16) ‖ nonce(24) ‖ ct+tag(48)` = 94 bytes.
/// The tier is embedded in the blob so [`recover_seed`] can auto-detect the
/// correct Argon2id parameters without the caller remembering.
///
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

    // v2 AAD = magic + version + tier + salt (binds header to ciphertext).
    let mut aad = Vec::with_capacity(4 + 1 + 1 + SALT_LEN);
    aad.extend_from_slice(BLOB_MAGIC);
    aad.push(BLOB_VERSION);
    aad.push(tier as u8);
    aad.extend_from_slice(&salt);

    let ct = native::xchacha20_poly1305_seal(&enc_key, &nonce_bytes, &raw_seed, &aad);

    enc_key.zeroize();

    let mut blob = Vec::with_capacity(BLOB_V2_LEN);
    blob.extend_from_slice(BLOB_MAGIC);
    blob.push(BLOB_VERSION);
    blob.push(tier as u8);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Recover a 32-byte master seed from an encrypted blob.
///
/// Auto-detects v1 and v2 formats:
/// - **v2** (starts with `ORGB` magic): reads the tier from the blob header.
///   The `tier` parameter is ignored — the embedded tier is used.
/// - **v1** (88 bytes, no magic): uses the caller-supplied `tier` for Argon2id.
///
/// This means existing v1 blobs remain readable. Use [`rotate_blob`] to
/// migrate v1 blobs to v2.
pub fn recover_seed(blob: &[u8], passphrase: &[u8], tier: MemoryTier) -> Result<[u8; SEED_LEN]> {
    // v2 detection: check for magic bytes.
    if blob.len() >= 4 && &blob[..4] == BLOB_MAGIC {
        return recover_seed_v2(blob, passphrase);
    }

    // v1 fallback: legacy 88-byte format without header.
    recover_seed_v1(blob, passphrase, tier)
}

/// Recover from a v1 (legacy) blob: `salt(16) ‖ nonce(24) ‖ ct+tag(48)`.
fn recover_seed_v1(blob: &[u8], passphrase: &[u8], tier: MemoryTier) -> Result<[u8; SEED_LEN]> {
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

/// Recover from a v2 blob: `magic(4) ‖ version(1) ‖ tier(1) ‖ salt(16) ‖ nonce(24) ‖ ct+tag(48)`.
fn recover_seed_v2(blob: &[u8], passphrase: &[u8]) -> Result<[u8; SEED_LEN]> {
    if blob.len() < BLOB_V2_LEN {
        return Err(CryptoError::InvalidParameter(format!(
            "v2 blob too short ({} bytes, need {BLOB_V2_LEN})",
            blob.len()
        )));
    }

    let version = blob[4];
    if version != BLOB_VERSION {
        return Err(CryptoError::InvalidParameter(format!(
            "unsupported blob version: {version} (expected {BLOB_VERSION})"
        )));
    }

    let tier_byte = blob[5];
    let tier = tier_from_byte(tier_byte)
        .ok_or_else(|| CryptoError::InvalidParameter(format!("invalid tier byte: {tier_byte}")))?;

    let salt = &blob[6..6 + SALT_LEN];
    let nonce_bytes = &blob[6 + SALT_LEN..6 + SALT_LEN + NONCE_LEN];
    let ct = &blob[6 + SALT_LEN + NONCE_LEN..];

    let mut enc_key = derive_argon2_key(passphrase, salt, tier)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    // v2 AAD = magic + version + tier + salt.
    let mut aad = Vec::with_capacity(4 + 1 + 1 + SALT_LEN);
    aad.extend_from_slice(BLOB_MAGIC);
    aad.push(BLOB_VERSION);
    aad.push(tier_byte);
    aad.extend_from_slice(salt);

    let plaintext = native::xchacha20_poly1305_open(&enc_key, &nonce, ct, &aad)
        .map_err(|_| CryptoError::Decryption("blob decryption failed".into()))?;

    enc_key.zeroize();

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Re-encrypt an existing seed under a new passphrase without changing the seed.
///
/// Reads v1 or v2 input (auto-detected) and always writes v2 output.
/// This is the recommended migration path from v1 to v2.
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

/// Detect the blob format version.
///
/// Returns `Some(2)` for v2 blobs, `Some(1)` for v1 blobs, or `None` if the
/// input is too short or unrecognized.
pub fn detect_blob_version(blob: &[u8]) -> Option<u8> {
    if blob.len() >= 4 && &blob[..4] == BLOB_MAGIC {
        Some(2)
    } else if blob.len() >= BLOB_LEN {
        Some(1)
    } else {
        None
    }
}

/// Read the embedded tier from a v2 blob.
///
/// Returns `None` for v1 blobs (which do not embed a tier).
pub fn blob_tier(blob: &[u8]) -> Option<MemoryTier> {
    if blob.len() >= 6 && &blob[..4] == BLOB_MAGIC {
        tier_from_byte(blob[5])
    } else {
        None
    }
}

/// Map a tier byte to `MemoryTier`.
fn tier_from_byte(byte: u8) -> Option<MemoryTier> {
    match byte {
        0 => Some(MemoryTier::Nano),
        1 => Some(MemoryTier::Standard),
        2 => Some(MemoryTier::Sovereign),
        _ => None,
    }
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
    fn create_writes_v2_format() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();
        assert_eq!(blob.len(), BLOB_V2_LEN);
        assert_eq!(&blob[..4], BLOB_MAGIC);
        assert_eq!(blob[4], BLOB_VERSION);
        assert_eq!(blob[5], MemoryTier::Nano as u8);
    }

    #[test]
    fn v2_roundtrip() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Standard, Some(&seed)).unwrap();
        assert_eq!(detect_blob_version(&blob), Some(2));

        let recovered = recover_seed(&blob, pw, MemoryTier::Nano).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn v2_tier_is_self_describing() {
        // Create with Standard tier, recover with Nano tier — the embedded
        // tier must be used, not the caller-supplied one.
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Standard, Some(&seed)).unwrap();
        assert_eq!(blob_tier(&blob), Some(MemoryTier::Standard));

        // Wrong caller tier should still work because v2 reads tier from blob.
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

    #[test]
    fn rotate_migrates_v1_to_v2() {
        // Simulate a v1 blob by constructing it manually.
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let salt = [0xAAu8; 16];
        let nonce = [0xBBu8; 24];

        let mut enc_key = derive_argon2_key(pw, &salt, MemoryTier::Nano).unwrap();
        let ct = native::xchacha20_poly1305_seal(&enc_key, &nonce, &seed, &salt);
        enc_key.zeroize();

        let mut v1_blob = Vec::with_capacity(BLOB_LEN);
        v1_blob.extend_from_slice(&salt);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);

        assert_eq!(detect_blob_version(&v1_blob), Some(1));

        // Rotate to v2.
        let v2_blob = rotate_blob(&v1_blob, pw, b"new-pw", MemoryTier::Nano).unwrap();
        assert_eq!(detect_blob_version(&v2_blob), Some(2));
        assert_eq!(v2_blob.len(), BLOB_V2_LEN);

        // Recover from the v2 blob with the new passphrase.
        let recovered = recover_seed(&v2_blob, b"new-pw", MemoryTier::Nano).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn v1_blob_still_readable() {
        // Simulate a v1 blob.
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let salt = [0xAAu8; 16];
        let nonce = [0xBBu8; 24];

        let mut enc_key = derive_argon2_key(pw, &salt, MemoryTier::Nano).unwrap();
        let ct = native::xchacha20_poly1305_seal(&enc_key, &nonce, &seed, &salt);
        enc_key.zeroize();

        let mut v1_blob = Vec::with_capacity(BLOB_LEN);
        v1_blob.extend_from_slice(&salt);
        v1_blob.extend_from_slice(&nonce);
        v1_blob.extend_from_slice(&ct);

        // Must be readable with the correct tier.
        let recovered = recover_seed(&v1_blob, pw, MemoryTier::Nano).unwrap();
        assert_eq!(recovered, seed);

        // Must fail with the wrong tier (different Argon2 params).
        let result = recover_seed(&v1_blob, pw, MemoryTier::Standard);
        assert!(result.is_err());
    }

    #[test]
    fn v2_rejects_wrong_version() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();

        // Tamper with version byte.
        let mut bad = blob.clone();
        bad[4] = 0x99;
        let result = recover_seed(&bad, pw, MemoryTier::Nano);
        assert!(result.is_err());
    }

    #[test]
    fn v2_rejects_tampered_tier() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();

        // Tamper with tier byte — AAD check should fail.
        let mut bad = blob.clone();
        bad[5] = MemoryTier::Sovereign as u8;
        let result = recover_seed(&bad, pw, MemoryTier::Nano);
        assert!(result.is_err());
    }

    #[test]
    fn v2_rejects_truncated() {
        let pw = b"test passphrase";
        let seed = [42u8; 32];
        let blob = create_blob(pw, MemoryTier::Nano, Some(&seed)).unwrap();

        let truncated = &blob[..50];
        let result = recover_seed(truncated, pw, MemoryTier::Nano);
        assert!(result.is_err());
    }

    #[test]
    fn detect_blob_version_works() {
        // v2 blob
        let blob = create_blob(b"pw", MemoryTier::Nano, Some(&[1u8; 32])).unwrap();
        assert_eq!(detect_blob_version(&blob), Some(2));

        // v1 blob (88 bytes, no magic)
        let v1 = vec![0u8; BLOB_LEN];
        assert_eq!(detect_blob_version(&v1), Some(1));

        // Too short
        let short = vec![0u8; 10];
        assert_eq!(detect_blob_version(&short), None);
    }

    #[test]
    fn blob_tier_returns_embedded_tier() {
        let blob = create_blob(b"pw", MemoryTier::Sovereign, Some(&[1u8; 32])).unwrap();
        assert_eq!(blob_tier(&blob), Some(MemoryTier::Sovereign));

        // v1 blob has no embedded tier.
        let v1 = vec![0u8; BLOB_LEN];
        assert_eq!(blob_tier(&v1), None);
    }
}

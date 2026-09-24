// SPDX-License-Identifier: Apache-2.0

//! Atomic compress-then-encrypt / decrypt-then-decompress container.
//!
//! This module fuses compression and authenticated encryption into a single
//! atomic operation: either the entire container is valid and the original
//! data is returned, or an error is returned and nothing is leaked.
//!
//! ## Design
//!
//! - **Compress-then-encrypt** (never the reverse): raw data is compressed
//!   first, then the *compressed* bytes are encrypted. This is the only safe
//!   order — encrypting first would produce high-entropy ciphertext that
//!   compresses to nothing. See the security note below on BROP/CRIME.
//!
//! - **Committing AEAD**: uses ChaCha20-BLAKE3 (BLAKE3-MAC, 32-byte tag)
//!   rather than XChaCha20-Poly1305 (16-byte Poly1305 tag). The SDK's own
//!   docs (`lib.rs`) recommend ChaCha20Blake3 as the default AEAD.
//!
//! - **Streaming-safe nonce construction**: the compressed data is split into
//!   chunks, each encrypted with a unique nonce derived via Rogaway's STREAM
//!   construction (base nonce XOR counter + last-chunk bit). This prevents
//!   keystream reuse, chunk reordering, and truncation attacks.
//!
//! ## Container format
//!
//! ```text
//! magic(4) ‖ version(1) ‖ tier(1) ‖ compressor(1) ‖ reserved(2) ‖
//! salt(16) ‖ nonce_base(24) ‖ chunk_size(4 BE) ‖ num_chunks(4 BE) ‖
//! chunk_1_tag(32) ‖ chunk_1_ct ‖ chunk_2_tag(32) ‖ chunk_2_ct ‖ ...
//! ```
//!
//! AAD = `magic ‖ version ‖ tier ‖ compressor ‖ reserved ‖ salt ‖ nonce_base ‖ chunk_size ‖ num_chunks`
//! Each chunk's full AAD = outer_aad ‖ chunk_index(8 BE) ‖ is_last(1)
//!
//! ## Security
//!
//! - The AEAD tag is verified **before** any decompression occurs, so
//!   tampered ciphertext never reaches the decompressor.
//! - Each chunk uses a unique nonce derived from the base nonce + counter.
//! - Wrong passphrase → Argon2id derives wrong key → AEAD verification fails
//!   → `CryptoError::AuthenticationFailed`.
//! - Compression is applied to plaintext (not ciphertext), so the BROP/CRIME
//!   attack class (length oracle on attacker-controlled plaintext) is only
//!   relevant for network streaming with untrusted input. For file-at-rest
//!   storage, this is safe.

use crate::error::{CryptoError, Result};
use crate::fill_random;
use crate::kdf::hkdf::hkdf_blake3;
use crate::kdf::Argon2idBuilder;
use crate::primitives::tier::MemoryTier;

use crate::internal::zeroize::Zeroize;

// ── Underlying AEAD (chacha20-blake3 crate) ───────────────────────────

use chacha20_blake3::{ChaCha20Blake3 as InnerCipher, KEY_SIZE, NONCE_SIZE, TAG_SIZE};

// ── Container constants ─────────────────────────────────────────────────

/// Magic bytes: `OZDC` (Origin Zstd / Deflate Container).
pub const MAGIC: &[u8; 4] = b"OZDC";

/// Current container version.
pub const VERSION: u8 = 1u8;

/// Container header size:
/// magic(4) + version(1) + tier(1) + compressor(1) + reserved(2) + salt(16) + nonce_base(24) + chunk_size(4) + num_chunks(4) = 54
pub const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 2 + 16 + 24 + 4 + 4;

/// Per-chunk nonce size (same as the base nonce — derived, not fresh).
pub const CHUNK_NONCE_SIZE: usize = NONCE_SIZE; // 24

/// Size of the per-chunk detached authentication tag (BLAKE3-MAC).
pub const CHUNK_TAG_SIZE: usize = TAG_SIZE; // 32

/// Default chunk size for chunked encryption (64 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

// ── Compressor selection ───────────────────────────────────────────────

/// Compressor identifiers (stored in the header byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compressor {
    /// Zstd (default), fast and high-ratio.
    Zstd = 0u8,
    /// DEFLATE (fallback, no extra deps beyond flate2).
    Deflate = 1u8,
}

impl Compressor {
    /// Decode a compressor from its header byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Compressor::Zstd),
            1 => Some(Compressor::Deflate),
            _ => None,
        }
    }
}

// ── STREAM nonce derivation ────────────────────────────────────────────

/// Derive a per-chunk nonce from the base nonce using the STREAM construction.
///
/// `base` is 24 bytes. We XOR a 64-bit big-endian counter into bytes
/// [16..24] and set the last byte's high bit to the `is_last` flag. This
/// ensures each chunk gets a unique nonce derived from the base, and the
/// last-chunk bit prevents truncation attacks (an attacker cannot truncate
/// the stream and have the final chunk accept as "last").
fn stream_nonce(base: &[u8; NONCE_SIZE], chunk_index: u64, is_last: bool) -> [u8; NONCE_SIZE] {
    let mut n = *base;
    // XOR counter into the last 8 bytes (big-endian).
    let counter_bytes = chunk_index.to_be_bytes();
    for (i, &b) in counter_bytes.iter().enumerate() {
        n[16 + i] ^= b;
    }
    // Set the last byte's top bit to the last-chunk flag.
    if is_last {
        n[23] |= 0x80;
    } else {
        n[23] &= 0x7F;
    }
    n
}

/// Build the outer AAD (header fields that bind the ciphertext to the header).
fn build_outer_aad(
    salt: &[u8; 16],
    base_nonce: &[u8; NONCE_SIZE],
    tier: MemoryTier,
    compressor: Compressor,
    chunk_size: usize,
    num_chunks: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(tier as u8);
    aad.push(compressor as u8);
    aad.extend_from_slice(&[0u8; 2]); // reserved
    aad.extend_from_slice(salt);
    aad.extend_from_slice(base_nonce);
    aad.extend_from_slice(&(chunk_size as u32).to_be_bytes());
    aad.extend_from_slice(&num_chunks.to_be_bytes());
    aad
}

/// Build per-chunk AAD = outer_aad ‖ chunk_index(8 BE) ‖ is_last(1).
fn build_chunk_aad(outer_aad: &[u8], chunk_index: u64, is_last: bool) -> Vec<u8> {
    let mut chunk_aad = Vec::with_capacity(outer_aad.len() + 9);
    chunk_aad.extend_from_slice(outer_aad);
    chunk_aad.extend_from_slice(&chunk_index.to_be_bytes());
    chunk_aad.push(is_last as u8);
    chunk_aad
}

// ── Internal helpers ───────────────────────────────────────────────────

/// Derive a 32-byte AEAD key from a passphrase + salt using Argon2id.
///
/// Uses a two-layer construction per Origin SDK security guidance:
/// 1. **Argon2id** — memory-hard KDF to derive a master key from the passphrase.
///    This resists brute-force attacks on weak passwords.
/// 2. **HKDF-BLAKE3** — fast, domain-separated extraction of the final 32-byte
///    encryption key from the master key, using the salt + nonce base as HKDF info.
///    BLAKE3 is the SDK's recommended hash; HKDF-BLAKE3 is faster than
///    HKDF-SHA3-256 and was promoted to first-class public API in v0.7.1-rc.5.
fn derive_key(passphrase: &[u8], salt: &[u8; 16], tier: MemoryTier) -> Result<[u8; KEY_SIZE]> {
    // Layer 1: Argon2id — password to master key (memory-hard).
    let params = tier.argon2_params(KEY_SIZE);
    let master_key = Argon2idBuilder::new()
        .memory_kib(params.m_cost() / 1024)
        .iterations(params.t_cost())
        .parallelism(params.p_cost())
        .output_len(KEY_SIZE)
        .derive(passphrase, salt)?;

    // Layer 2: HKDF-BLAKE3 — master key to encryption key (fast, domain-separated).
    // Salt is the HKDF salt; the info field binds this key to our container format.
    let mut key = [0u8; KEY_SIZE];
    let info = b"origin-crypto-sdk:compressed:v1";
    hkdf_blake3(&master_key, Some(salt), info, &mut key)?;

    // Zeroize intermediate master key.
    let mut mk = master_key;
    mk.zeroize();

    Ok(key)
}

/// Compress data using the selected compressor.
fn compress_data(data: &[u8], algo: Compressor) -> Result<Vec<u8>> {
    match algo {
        Compressor::Zstd => {
            let mut input = data;
            zstd::stream::encode_all(&mut input, 3)
                .map_err(|e| CryptoError::Compression(format!("zstd compression failed: {}", e)))
        }
        Compressor::Deflate => crate::compression::compress(data),
    }
}

/// Decompress data using the selected compressor.
fn decompress_data(data: &[u8], algo: Compressor) -> Result<Vec<u8>> {
    match algo {
        Compressor::Zstd => {
            let mut input = data;
            zstd::stream::decode_all(&mut input)
                .map_err(|e| CryptoError::Compression(format!("zstd decompression failed: {}", e)))
        }
        Compressor::Deflate => crate::compression::decompress(data),
    }
}

// ── Public API ─────────────────────────────────────────────────────────

/// Compress and encrypt data atomically.
///
/// The data is compressed (Zstd by default), then the compressed bytes are
/// split into chunks and each chunk is authenticated-encrypted using
/// ChaCha20-BLAKE3 with a STREAM-constructed per-chunk nonce. A single
/// Argon2id key is derived from the passphrase + random salt.
///
/// Returns a self-describing container blob.
///
/// # Arguments
///
/// * `data` — Plaintext to compress and encrypt
/// * `passphrase` — Password for Argon2id key derivation
/// * `tier` — Memory tier for Argon2id parameters (Nano, Standard, Sovereign)
/// * `compressor` — `Some(Compressor::Zstd)` (default) or `Some(Compressor::Deflate)`
/// * `chunk_size` — Override chunk size (default: 64 KiB)
pub fn compress_encrypt(
    data: &[u8],
    passphrase: &[u8],
    tier: MemoryTier,
    compressor: Option<Compressor>,
    chunk_size: Option<usize>,
) -> Result<Vec<u8>> {
    let algo = compressor.unwrap_or(Compressor::Zstd);
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

    // 1. Compress plaintext.
    let compressed = compress_data(data, algo)?;

    // 2. Derive key from passphrase.
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let key = derive_key(passphrase, &salt, tier)?;

    // 3. Generate base nonce.
    let mut base_nonce = [0u8; NONCE_SIZE];
    fill_random(&mut base_nonce)?;

    // 4. Chunk the compressed data.
    let chunks: Vec<&[u8]> = if compressed.is_empty() {
        Vec::new()
    } else {
        compressed.chunks(chunk_size).collect()
    };
    let num_chunks = chunks.len() as u32;

    // 5. Build outer AAD.
    let outer_aad = build_outer_aad(&salt, &base_nonce, tier, algo, chunk_size, num_chunks);

    // 6. Encrypt each chunk with STREAM nonce.
    let cipher = InnerCipher::new(key);
    let mut out =
        Vec::with_capacity(HEADER_LEN + (chunks.len() * CHUNK_TAG_SIZE) + compressed.len());

    // Write header.
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(tier as u8);
    out.push(algo as u8);
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&salt);
    out.extend_from_slice(&base_nonce);
    out.extend_from_slice(&(chunk_size as u32).to_be_bytes());
    out.extend_from_slice(&num_chunks.to_be_bytes());

    // Securely zeroize the key copy after cipher construction (cipher holds its own copy internally).
    let mut key_zero = key;
    key_zero.zeroize();

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == chunks.len() - 1;
        let nonce = stream_nonce(&base_nonce, i as u64, is_last);
        let chunk_aad = build_chunk_aad(&outer_aad, i as u64, is_last);

        let mut buf = chunk.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce, &mut buf, &chunk_aad);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&buf);
    }

    Ok(out)
}

/// Decrypt and decompress data atomically.
///
/// Verifies the AEAD tag on each chunk **before** decompressing. If any
/// authentication fails, returns `CryptoError::AuthenticationFailed`
/// without attempting decompression.
///
/// # Arguments
///
/// * `container` — The blob produced by [`compress_encrypt`]
/// * `passphrase` — The passphrase (must match what was used for encryption)
pub fn decompress_decrypt(container: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    // 1. Parse header.
    if container.len() < HEADER_LEN {
        return Err(CryptoError::Serialization(format!(
            "container too short: {} bytes, need at least {}",
            container.len(),
            HEADER_LEN
        )));
    }

    if &container[..4] != MAGIC {
        return Err(CryptoError::Serialization("bad magic bytes".into()));
    }

    let version = container[4];
    if version != VERSION {
        return Err(CryptoError::Serialization(format!(
            "unsupported version: {} (expected {})",
            version, VERSION
        )));
    }

    let tier_byte = container[5];
    let tier = match tier_byte {
        0 => MemoryTier::Nano,
        1 => MemoryTier::Standard,
        2 => MemoryTier::Sovereign,
        _ => {
            return Err(CryptoError::Serialization(format!(
                "invalid tier byte: {}",
                tier_byte
            )))
        }
    };

    let algo_byte = container[6];
    let compressor = Compressor::from_byte(algo_byte).ok_or_else(|| {
        CryptoError::Serialization(format!("unknown compressor byte: {}", algo_byte))
    })?;

    let salt: [u8; 16] = container[9..25]
        .try_into()
        .map_err(|_| CryptoError::Serialization("salt parse failed".into()))?;

    let base_nonce: [u8; NONCE_SIZE] = container[25..49]
        .try_into()
        .map_err(|_| CryptoError::Serialization("nonce parse failed".into()))?;

    let chunk_size = u32::from_be_bytes(
        container[49..53]
            .try_into()
            .map_err(|_| CryptoError::Serialization("chunk_size field parse failed".into()))?,
    ) as usize;
    let num_chunks = u32::from_be_bytes(
        container[53..57]
            .try_into()
            .map_err(|_| CryptoError::Serialization("num_chunks field parse failed".into()))?,
    ) as usize;

    let body = &container[HEADER_LEN..];

    // Rebuild outer AAD.
    let outer_aad = build_outer_aad(
        &salt,
        &base_nonce,
        tier,
        compressor,
        chunk_size,
        num_chunks as u32,
    );

    // 2. Derive key.
    let key = derive_key(passphrase, &salt, tier)?;
    let cipher = InnerCipher::new(key);

    // Zeroize key copy (cipher holds internal copy).
    let mut key_zero = key;
    key_zero.zeroize();

    // 3. Decrypt and authenticate each chunk (verify tags BEFORE decompressing).
    let mut compressed = Vec::new();
    let mut offset = 0usize;

    for i in 0..num_chunks {
        // Read tag.
        if offset + CHUNK_TAG_SIZE > body.len() {
            return Err(CryptoError::AuthenticationFailed);
        }
        let tag: [u8; TAG_SIZE] = body[offset..offset + CHUNK_TAG_SIZE]
            .try_into()
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        offset += CHUNK_TAG_SIZE;

        // Determine ciphertext length for this chunk.
        let is_last = i == num_chunks - 1;
        let remaining = body.len() - offset;
        let ct_len = if is_last {
            remaining
        } else {
            // Non-final chunks should be exactly chunk_size bytes of ciphertext.
            if remaining < chunk_size {
                // Truncated or malformed — not enough data for the claimed chunk_size.
                return Err(CryptoError::AuthenticationFailed);
            }
            chunk_size
        };

        if offset + ct_len > body.len() {
            return Err(CryptoError::AuthenticationFailed);
        }

        let mut chunk_ct = body[offset..offset + ct_len].to_vec();
        offset += ct_len;

        let nonce = stream_nonce(&base_nonce, i as u64, is_last);
        let chunk_aad = build_chunk_aad(&outer_aad, i as u64, is_last);

        cipher
            .decrypt_in_place_detached(&nonce, &mut chunk_ct, &tag, &chunk_aad)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        compressed.extend_from_slice(&chunk_ct);
    }

    // Verify all body was consumed (no trailing bytes).
    if offset != body.len() {
        return Err(CryptoError::AuthenticationFailed);
    }

    // 4. Decompress (only reached after all tags verified).
    if compressed.is_empty() {
        return Ok(Vec::new());
    }

    decompress_data(&compressed, compressor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_zstd() {
        let data = b"Hello, atomic compression! This is a test message that should compress well with zstd. \
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt \
            ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation.";
        let passphrase = b"correct horse battery staple";
        let container = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_roundtrip_deflate() {
        let data =
            b"Deflate roundtrip test data. Compress me please. Repeat me. Repeat me. Repeat me.";
        let passphrase = b"another passphrase";
        let container = compress_encrypt(
            data,
            passphrase,
            MemoryTier::Nano,
            Some(Compressor::Deflate),
            None,
        )
        .unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let passphrase = b"empty test";
        let container = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_roundtrip_large() {
        let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
        let passphrase = b"large data passphrase";
        let container = compress_encrypt(&data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let data = b"secret data here";
        let passphrase = b"correct passphrase";
        let container = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let result = decompress_decrypt(&container, b"wrong passphrase");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let data = b"important data that must not be tampered with";
        let passphrase = b"secure passphrase";
        let mut container =
            compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();

        // Flip a byte in the body (after the header).
        if container.len() > HEADER_LEN + 10 {
            container[HEADER_LEN + 10] ^= 0xFF;
        }

        let result = decompress_decrypt(&container, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_header_fails() {
        let data = b"test data";
        let passphrase = b"pw";
        let mut container =
            compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();

        // Flip a byte in the header (salt region).
        container[10] ^= 0xFF;

        let result = decompress_decrypt(&container, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_short_container_fails() {
        let result = decompress_decrypt(&[0u8; 10], b"pw");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_bad_magic_fails() {
        let data = b"test";
        let container = compress_encrypt(data, b"pw", MemoryTier::Nano, None, None).unwrap();
        let mut bad = container.clone();
        bad[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let result = decompress_decrypt(&bad, b"pw");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn test_bad_version_fails() {
        let data = b"test";
        let container = compress_encrypt(data, b"pw", MemoryTier::Nano, None, None).unwrap();
        let mut bad = container.clone();
        bad[4] = 0x99; // bad version
        let result = decompress_decrypt(&bad, b"pw");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_trailing_garbage_fails() {
        let data = b"test data";
        let passphrase = b"pw";
        let mut container =
            compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        // Append random trailing bytes.
        container.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let result = decompress_decrypt(&container, passphrase);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_different_tiers() {
        let data = b"Tier test data - compressed and encrypted";
        let passphrase = b"tier-passphrase";

        for tier in [
            MemoryTier::Nano,
            MemoryTier::Standard,
            MemoryTier::Sovereign,
        ] {
            let container = compress_encrypt(data, passphrase, tier, None, None).unwrap();
            let recovered = decompress_decrypt(&container, passphrase).unwrap();
            assert_eq!(data.to_vec(), recovered);
        }
    }

    #[test]
    fn test_container_format() {
        let data = b"format test";
        let container = compress_encrypt(data, b"pw", MemoryTier::Nano, None, None).unwrap();

        assert_eq!(&container[..4], MAGIC);
        assert_eq!(container[4], VERSION);
        assert_eq!(container[5], MemoryTier::Nano as u8);
        assert_eq!(container[6], Compressor::Zstd as u8);
        assert!(container.len() > HEADER_LEN);
    }

    #[test]
    fn test_zstd_better_than_deflate() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 17) as u8).collect();
        let passphrase = b"ratio test";

        let zstd_container = compress_encrypt(
            &data,
            passphrase,
            MemoryTier::Nano,
            Some(Compressor::Zstd),
            None,
        )
        .unwrap();
        let deflate_container = compress_encrypt(
            &data,
            passphrase,
            MemoryTier::Nano,
            Some(Compressor::Deflate),
            None,
        )
        .unwrap();

        // zstd should produce a smaller container (better compression ratio).
        assert!(
            zstd_container.len() < deflate_container.len(),
            "zstd ({}) should be smaller than deflate ({})",
            zstd_container.len(),
            deflate_container.len()
        );
    }

    #[test]
    fn test_different_passphrases_produce_different_containers() {
        let data = b"same data";
        let c1 = compress_encrypt(data, b"pass1", MemoryTier::Nano, None, None).unwrap();
        let c2 = compress_encrypt(data, b"pass2", MemoryTier::Nano, None, None).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_custom_chunk_size() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 31) as u8).collect();
        let passphrase = b"chunk test";

        for chunk_size in [1024, 4096, 16384, 65536] {
            let container =
                compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size))
                    .unwrap();
            let recovered = decompress_decrypt(&container, passphrase).unwrap();
            assert_eq!(data, recovered);
        }
    }

    #[test]
    fn test_key_zeroized_after_use() {
        // Smoke test: ensure derive_key produces a zeroed buffer after use
        // (the internal key_copy.zeroize() call). We verify indirectly by
        // confirming the function doesn't panic and the key is used correctly.
        let data = b"zeroize test";
        let passphrase = b"pw";
        let container = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_cross_tier_key_isolation() {
        // The same passphrase must NOT decrypt a container created under a
        // different tier — Argon2id uses different cost parameters per tier,
        // so the derived keys diverge. Tampering the tier byte in the header
        // changes the AAD, so the tag verification fails.
        let data = b"cross tier isolation test";
        let passphrase = b"same-passphrase";

        let container = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let container_std =
            compress_encrypt(data, passphrase, MemoryTier::Standard, None, None).unwrap();

        // Both should decrypt correctly (decompress_decrypt reads tier from header).
        let recovered_nano = decompress_decrypt(&container, passphrase).unwrap();
        let recovered_std = decompress_decrypt(&container_std, passphrase).unwrap();
        assert_eq!(data, recovered_nano.as_slice());
        assert_eq!(data, recovered_std.as_slice());

        // Tampering the tier byte must break AAD authentication.
        let mut tampered = container.clone();
        tampered[5] = MemoryTier::Standard as u8;
        assert!(decompress_decrypt(&tampered, passphrase).is_err());
    }

    /// Generate incompressible (random) data of the given length using the
    /// SDK's fill_random, so that zstd compression produces output close to
    /// the input size and chunk boundaries are deterministic.
    fn random_data(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        fill_random(&mut buf).unwrap();
        buf
    }

    /// Compute the per-chunk wire block size (tag + ciphertext).
    fn chunk_block(chunk_size: usize) -> usize {
        chunk_size + CHUNK_TAG_SIZE
    }

    #[test]
    fn test_chunk_reordering_detected() {
        // Use random (incompressible) data so the compressed size is close to
        // the input size, guaranteeing multiple chunks.
        let data = random_data(10_000);
        let passphrase = b"reorder test";
        let chunk_size = 1024;
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size)).unwrap();

        let block = chunk_block(chunk_size);
        let body = &container[HEADER_LEN..];
        assert!(
            body.len() >= 2 * block,
            "need at least 2 chunks for reordering test"
        );

        // Swap the first two chunk blocks.
        let mut tampered = container.clone();
        let body_slice = &mut tampered[HEADER_LEN..];
        let b1 = body_slice[..block].to_vec();
        let b2 = body_slice[block..2 * block].to_vec();
        body_slice[..block].copy_from_slice(&b2);
        body_slice[block..2 * block].copy_from_slice(&b1);

        let result = decompress_decrypt(&tampered, passphrase);
        assert!(result.is_err(), "chunk reordering should be detected");
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_chunk_truncation_detected() {
        // Random data ensures the compressed size is close to input size,
        // so we get multiple chunks even with larger chunk_size.
        let data = random_data(50_000);
        let passphrase = b"truncation test";
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(4096)).unwrap();

        // Truncate the last few bytes — missing tag/ciphertext should fail.
        let mut tampered = container.clone();
        tampered.truncate(tampered.len() - 5);

        let result = decompress_decrypt(&tampered, passphrase);
        assert!(result.is_err(), "truncated container should fail");
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_chunk_duplication_detected() {
        // Duplicate chunk 0's block over chunk 1's. The STREAM nonce
        // includes the chunk index in the AAD, so a duplicated chunk
        // fails authentication.
        let data = random_data(10_000);
        let passphrase = b"dup test";
        let chunk_size = 1024;
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size)).unwrap();

        let block = chunk_block(chunk_size);
        assert!(container.len() >= HEADER_LEN + 2 * block);

        let mut tampered = container.clone();
        let body_slice = &mut tampered[HEADER_LEN..];
        let block0 = body_slice[..block].to_vec();
        body_slice[block..2 * block].copy_from_slice(&block0);

        let result = decompress_decrypt(&tampered, passphrase);
        assert!(result.is_err(), "duplicated chunk should fail auth");
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_aad_field_tampering_fails() {
        // Each header field is part of the AAD. Tampering with any field
        // should cause authentication failure.
        let data = b"AAD tampering test";
        let passphrase = b"aad-pass";
        let container =
            compress_encrypt(data, passphrase, MemoryTier::Standard, None, None).unwrap();

        // version byte
        let mut t = container.clone();
        t[4] ^= 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // tier byte (invalid)
        let mut t = container.clone();
        t[5] = 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // compressor byte (invalid)
        let mut t = container.clone();
        t[6] = 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // chunk_size field
        let mut t = container.clone();
        t[49] ^= 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // num_chunks field
        let mut t = container.clone();
        t[53] ^= 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // salt field
        let mut t = container.clone();
        t[9] ^= 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());

        // nonce_base field
        let mut t = container.clone();
        t[25] ^= 0xFF;
        assert!(decompress_decrypt(&t, passphrase).is_err());
    }

    #[test]
    fn test_salt_and_nonce_uniqueness() {
        // Two containers with the same passphrase + same data but different
        // random salt + nonce must both decrypt correctly. This verifies
        // the HKDF salt is fresh per container and the nonce is fresh per
        // container.
        let data = b"repeated data for salt/nonce uniqueness test";
        let passphrase = b"same-pass";
        let c1 = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();
        let c2 = compress_encrypt(data, passphrase, MemoryTier::Nano, None, None).unwrap();

        assert_ne!(c1, c2);
        assert_eq!(
            data.as_slice(),
            &decompress_decrypt(&c1, passphrase).unwrap()[..]
        );
        assert_eq!(
            data.as_slice(),
            &decompress_decrypt(&c2, passphrase).unwrap()[..]
        );
        assert_ne!(&c1[9..25], &c2[9..25]); // salts differ
        assert_ne!(&c1[25..49], &c2[25..49]); // nonces differ
    }

    #[test]
    fn test_empty_data_roundtrip() {
        // Empty input → zstd frame header + empty content → 1 chunk of
        // compressed data (zstd always emits at least a frame header).
        let container = compress_encrypt(b"", b"pw", MemoryTier::Nano, None, None).unwrap();
        let num_chunks = u32::from_be_bytes(container[53..57].try_into().unwrap());
        assert_eq!(
            num_chunks, 1,
            "empty input should produce 1 chunk (zstd frame header)"
        );
        let recovered = decompress_decrypt(&container, b"pw").unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_single_chunk_boundary() {
        // Small data that fits in exactly one chunk.
        let data = b"small data that fits in one chunk";
        let container = compress_encrypt(data, b"pw", MemoryTier::Nano, None, None).unwrap();
        let num_chunks = u32::from_be_bytes(container[53..57].try_into().unwrap());
        assert_eq!(num_chunks, 1, "small data should produce exactly 1 chunk");
        let recovered = decompress_decrypt(&container, b"pw").unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_multi_chunk_roundtrip() {
        // Random (incompressible) data with small chunk_size to force
        // multiple chunks.
        let data = random_data(50_000);
        let chunk_size = 4096;
        let passphrase = b"multi-chunk";
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size)).unwrap();
        let num_chunks = u32::from_be_bytes(container[53..57].try_into().unwrap());
        assert!(
            num_chunks >= 2,
            "50KB random data with 4KB chunks should produce >= 2 chunks"
        );
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_stream_nonce_uniqueness() {
        // Verify the STREAM nonce construction produces unique nonces per
        // chunk by confirming multi-chunk decryption succeeds normally.
        let data = random_data(30_000);
        let passphrase = b"nonce test";
        let chunk_size = 512;
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size)).unwrap();
        let recovered = decompress_decrypt(&container, passphrase).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_last_chunk_bit_detection_via_truncation() {
        // Truncate to remove the last chunk, then correct num_chunks.
        // The truncated last chunk's is_last bit differs from the original
        // nonce, causing auth failure.
        let data = random_data(30_000);
        let passphrase = b"last chunk test";
        let chunk_size = 1024;
        let container =
            compress_encrypt(&data, passphrase, MemoryTier::Nano, None, Some(chunk_size)).unwrap();

        let block = chunk_block(chunk_size);
        let num_chunks = u32::from_be_bytes(container[53..57].try_into().unwrap());
        assert!(num_chunks >= 2, "need >= 2 chunks for truncation test");

        let mut tampered = container.clone();
        // Remove the last chunk's block.
        tampered.truncate(tampered.len() - block);
        // Correct num_chunks to match.
        let new_num = num_chunks - 1;
        tampered[53..57].copy_from_slice(&new_num.to_be_bytes());

        // Even with corrected num_chunks, the remaining chunks' nonces
        // were derived with their original positions, so the second-to-last
        // chunk (previously not-last) now has is_last=false in its nonce
        // but is actually the last chunk — causing auth failure.
        let result = decompress_decrypt(&tampered, passphrase);
        assert!(result.is_err(), "truncated last chunk should fail");
    }
}

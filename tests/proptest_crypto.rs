// SPDX-License-Identifier: Apache-2.0

//! Property-based tests using proptest.
//!
//! These tests verify algebraic properties that should hold for ALL inputs:
//! - Encrypt/decrypt is a roundtrip
//! - Key derivation is deterministic
//! - Wrong key/message always fails decryption
//! - Type validation rejects wrong-length inputs

use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;
use origin_crypto_sdk::error::CryptoError;
use origin_crypto_sdk::kdf::hkdf::hkdf_sha3_256;
use origin_crypto_sdk::types::{CNonce, Seed, XNonce};

use proptest::prelude::*;

// ── Strategies ───────────────────────────────────────────────────────

fn any_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max)
}

fn any_32_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop::collection::vec(any::<u8>(), 32).prop_map(|v| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        arr
    })
}

fn any_24_bytes() -> impl Strategy<Value = [u8; 24]> {
    prop::collection::vec(any::<u8>(), 24).prop_map(|v| {
        let mut arr = [0u8; 24];
        arr.copy_from_slice(&v);
        arr
    })
}

// ── ChaCha20-BLAKE3 ─────────────────────────────────────────────────

proptest! {
    /// Encrypt then decrypt must return the original plaintext.
    #[test]
    fn prop_chacha20_blake3_roundtrip(
        key in any_32_bytes(),
        nonce in any_24_bytes(),
        plaintext in any_bytes(4096),
        aad in any_bytes(256),
    ) {
        let ciphertext =
            ChaCha20Blake3::encrypt(&key, &nonce, &plaintext, &aad)
                .expect("encrypt should succeed");
        let decrypted =
            ChaCha20Blake3::decrypt(&key, &nonce, &ciphertext, &aad)
                .expect("decrypt with correct key must succeed");
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Wrong key must always fail decryption.
    #[test]
    fn prop_chacha20_blake3_wrong_key_fails(
        key1 in any_32_bytes(),
        key2 in any_32_bytes(),
        nonce in any_24_bytes(),
        plaintext in any_bytes(512),
    ) {
        prop_assume!(key1 != key2);
        let aad = b"";
        let ciphertext =
            ChaCha20Blake3::encrypt(&key1, &nonce, &plaintext, aad)
                .expect("encrypt");
        let result = ChaCha20Blake3::decrypt(&key2, &nonce, &ciphertext, aad);
        prop_assert!(result.is_err());
    }

    /// Wrong AAD must always fail decryption.
    #[test]
    fn prop_chacha20_blake3_wrong_aad_fails(
        key in any_32_bytes(),
        nonce in any_24_bytes(),
        plaintext in any_bytes(512),
        aad1 in any_bytes(64),
        aad2 in any_bytes(64),
    ) {
        prop_assume!(aad1 != aad2);
        let ciphertext =
            ChaCha20Blake3::encrypt(&key, &nonce, &plaintext, &aad1)
                .expect("encrypt");
        let result = ChaCha20Blake3::decrypt(&key, &nonce, &ciphertext, &aad2);
        prop_assert!(result.is_err());
    }

    /// Any single-byte flip in the ciphertext must cause decryption failure.
    #[test]
    fn prop_chacha20_blake3_tamper_detected(
        key in any_32_bytes(),
        nonce in any_24_bytes(),
        plaintext in any_bytes(256),
        flip_pos in 0usize..512,
    ) {
        let ciphertext =
            ChaCha20Blake3::encrypt(&key, &nonce, &plaintext, b"")
                .expect("encrypt");
        if flip_pos >= ciphertext.len() {
            return Ok(());
        }
        let mut tampered = ciphertext.clone();
        tampered[flip_pos] ^= 0x01;
        let result = ChaCha20Blake3::decrypt(&key, &nonce, &tampered, b"");
        prop_assert!(result.is_err(), "tampered ciphertext must not decrypt");
    }
}

// ── HKDF-SHA3-256 ────────────────────────────────────────────────────

proptest! {
    /// HKDF is deterministic: same inputs always produce same output.
    #[test]
    fn prop_hkdf_deterministic(
        ikm in any_bytes(64),
        salt in any_bytes(32),
        info in any_bytes(32),
    ) {
        let mut out1 = vec![0u8; 64];
        let mut out2 = vec![0u8; 64];
        hkdf_sha3_256(&ikm, Some(&salt), &info, &mut out1).expect("hkdf");
        hkdf_sha3_256(&ikm, Some(&salt), &info, &mut out2).expect("hkdf");
        prop_assert_eq!(out1, out2);
    }

    /// Different IKM must produce different output.
    #[test]
    fn prop_hkdf_different_ikm_different_output(
        ikm1 in any_bytes(32),
        ikm2 in any_bytes(32),
        salt in any_bytes(16),
        info in any_bytes(16),
    ) {
        prop_assume!(ikm1 != ikm2);
        let mut out1 = vec![0u8; 32];
        let mut out2 = vec![0u8; 32];
        hkdf_sha3_256(&ikm1, Some(&salt), &info, &mut out1).expect("hkdf");
        hkdf_sha3_256(&ikm2, Some(&salt), &info, &mut out2).expect("hkdf");
        prop_assert_ne!(out1, out2);
    }
}

// ── Type validation ──────────────────────────────────────────────────

proptest! {
    /// Seed::from_slice rejects any input that isn't exactly 32 bytes.
    #[test]
    fn prop_seed_rejects_wrong_len(len in 0usize..128) {
        if len == 32 {
            return Ok(());
        }
        let bytes = vec![0xABu8; len];
        let result = Seed::from_slice(&bytes);
        match result {
            Err(CryptoError::InvalidKeyLength { expected: 32, got, .. }) => {
                prop_assert_eq!(got, len);
            }
            _ => panic!("expected InvalidKeyLength(32, {len}), got {result:?}"),
        }
    }

    /// XNonce::from_slice rejects any input that isn't exactly 24 bytes.
    #[test]
    fn prop_xnonce_rejects_wrong_len(len in 0usize..64) {
        if len == 24 {
            return Ok(());
        }
        let bytes = vec![0x99u8; len];
        let result = XNonce::from_slice(&bytes);
        match result {
            Err(CryptoError::InvalidNonceLength { expected: 24, got, .. }) => {
                prop_assert_eq!(got, len);
            }
            _ => panic!("expected InvalidNonceLength(24, {len}), got {result:?}"),
        }
    }

    /// CNonce::from_slice rejects any input that isn't exactly 12 bytes.
    #[test]
    fn prop_cnonce_rejects_wrong_len(len in 0usize..64) {
        if len == 12 {
            return Ok(());
        }
        let bytes = vec![0x77u8; len];
        let result = CNonce::from_slice(&bytes);
        match result {
            Err(CryptoError::InvalidNonceLength { expected: 12, got, .. }) => {
                prop_assert_eq!(got, len);
            }
            _ => panic!("expected InvalidNonceLength(12, {len}), got {result:?}"),
        }
    }

    /// Seed accepts exactly 32 bytes.
    #[test]
    fn prop_seed_accepts_32_bytes(bytes in any_32_bytes()) {
        let seed = Seed::from_slice(&bytes).expect("32 bytes should be valid");
        prop_assert_eq!(seed.as_bytes(), &bytes);
    }
}

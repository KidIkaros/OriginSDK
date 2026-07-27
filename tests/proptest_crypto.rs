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

// ── Reed-Solomon error correction ──────────────────────────────────

proptest! {
    /// Encode then decode must restore the original data.
    #[test]
    fn prop_reed_solomon_roundtrip(
        data in any_bytes(256),
    ) {
        prop_assume!(!data.is_empty());
        let codec = origin_crypto_sdk::error_correction::ReedSolomonCodec::new(4, 2);
        let encoded = codec.encode(&data).expect("encode");
        let decoded = codec.decode(&encoded).expect("decode");
        prop_assert_eq!(decoded, data);
    }

    /// Decode with corrupted data should not panic (may succeed or fail gracefully).
    #[test]
    fn prop_reed_solomon_corruption_no_panic(
        data in any_bytes(128),
        flip_pos in 0usize..1024,
    ) {
        prop_assume!(!data.is_empty());
        let codec = origin_crypto_sdk::error_correction::ReedSolomonCodec::new(2, 1);
        if let Ok(encoded) = codec.encode(&data) {
            if flip_pos < encoded.len() {
                let mut corrupted = encoded.clone();
                corrupted[flip_pos] ^= 0xFF;
                // Should not panic — may succeed (recoverable) or fail with error
                let _ = codec.decode(&corrupted);
            }
        }
    }
}

// ── Compression ──────────────────────────────────────────────────────

proptest! {
    /// Compress then decompress must restore the original data.
    #[test]
    fn prop_compress_decompress_roundtrip(
        data in any_bytes(4096),
    ) {
        use origin_crypto_sdk::compression::{compress, decompress};
        let compressed = compress(&data)
            .expect("compress");
        let decompressed = decompress(&compressed)
            .expect("decompress");
        prop_assert_eq!(decompressed, data);
    }

    /// Decompress random garbage must not panic (may fail gracefully).
    #[test]
    fn prop_decompress_garbage_no_panic(
        garbage in any_bytes(256),
    ) {
        use origin_crypto_sdk::compression::decompress;
        // Should not panic — only return Err
        let _ = decompress(&garbage);
    }
}

// ── Poly1305 ─────────────────────────────────────────────────────────

proptest! {
    /// Poly1305 is deterministic: same key + message produces same tag.
    #[test]
    fn prop_poly1305_deterministic(
        msg in any_bytes(512),
    ) {
        let key = [0x42u8; 32];
        let tag1 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key);
        let tag2 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key);
        prop_assert_eq!(tag1, tag2);
    }

    /// Different key produces different tag (with high probability).
    ///
    /// NOTE: Empty messages will produce identical tags if the `s` pad
    /// portion of the key (bytes 16..32) is the same. We test with non-empty
    /// messages to exercise the `r`-based multiplication path.
    #[test]
    fn prop_poly1305_key_sensitivity(
        msg in any_bytes(64),
    ) {
        prop_assume!(!msg.is_empty());
        let key1 = [0x42u8; 32];
        let mut key2 = [0x42u8; 32];
        key2[0] ^= 0x01;
        let tag1 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key1);
        let tag2 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key2);
        prop_assert_ne!(tag1, tag2);
    }

    /// Incremental update produces same tag as one-shot.
    #[test]
    fn prop_poly1305_incremental(
        a in any_bytes(64),
        b in any_bytes(64),
        c in any_bytes(64),
    ) {
        use origin_crypto_sdk::poly1305::Poly1305;
        let key = [0xABu8; 32];

        let one_shot = origin_crypto_sdk::poly1305::poly1305_mac(
            &[a.as_slice(), b.as_slice(), c.as_slice()].concat(), &key
        );

        let mut poly = Poly1305::new(&key);
        poly.update(&a);
        poly.update(&b);
        poly.update(&c);
        let incremental = poly.finalize();
        prop_assert_eq!(one_shot, incremental);
    }
}

// ── SipHash ──────────────────────────────────────────────────────────

proptest! {
    /// SipHash expansion is deterministic.
    #[test]
    fn prop_siphash_deterministic(
        msg in any_bytes(64),
    ) {
        let key = [0x42u8; 16];
        let result = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key, &msg);
        prop_assert_eq!(result.len(), 16);
        let expected = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key, &msg);
        prop_assert_eq!(result, expected);
    }

    /// Different key produces different output.
    #[test]
    fn prop_siphash_key_sensitivity(
        msg in any_bytes(32),
    ) {
        let key1 = [0x42u8; 16];
        let mut key2 = [0x42u8; 16];
        key2[0] ^= 0x01;
        let a = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key1, &msg);
        let b = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key2, &msg);
        prop_assert_ne!(a, b);
    }
}

// ── Seed Blob ────────────────────────────────────────────────────────

proptest! {
    /// Blob roundtrip: create + recover preserves seed.
    #[test]
    fn prop_blob_roundtrip(
        passphrase in any_bytes(64),
    ) {
        prop_assume!(!passphrase.is_empty());
        let seed = [0x42u8; 32];
        let blob = origin_crypto_sdk::blob::create_blob(
            &passphrase,
            origin_crypto_sdk::tier::MemoryTier::Nano,
            Some(&seed),
        ).expect("create_blob");
        let recovered = origin_crypto_sdk::blob::recover_seed(
            &blob,
            &passphrase,
            origin_crypto_sdk::tier::MemoryTier::Nano,
        ).expect("recover_seed");
        prop_assert_eq!(recovered, seed);
    }

    /// Wrong passphrase must fail recovery.
    #[test]
    fn prop_blob_wrong_passphrase_fails(
        good_pw in any_bytes(32),
        bad_pw in any_bytes(32),
    ) {
        prop_assume!(!good_pw.is_empty() && !bad_pw.is_empty() && good_pw != bad_pw);
        let seed = [0x42u8; 32];
        let blob = origin_crypto_sdk::blob::create_blob(
            &good_pw,
            origin_crypto_sdk::tier::MemoryTier::Nano,
            Some(&seed),
        ).expect("create_blob");
        let result = origin_crypto_sdk::blob::recover_seed(
            &blob,
            &bad_pw,
            origin_crypto_sdk::tier::MemoryTier::Nano,
        );
        prop_assert!(result.is_err());
    }
}

// ── DRBG ─────────────────────────────────────────────────────────────

proptest! {
    /// DRBG is deterministic from seed.
    #[test]
    fn prop_drbg_deterministic(
        seed in any_32_bytes(),
        n in 1usize..256,
    ) {
        let mut a = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed);
        let mut b = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed);
        prop_assert_eq!(a.random_bytes(n), b.random_bytes(n));
    }

    /// Different seeds produce different output.
    #[test]
    fn prop_drbg_seed_sensitivity(
        seed in any_32_bytes(),
    ) {
        let mut a = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed);
        let mut seed2 = seed;
        seed2[0] ^= 0x01;
        let mut b = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed2);
        let bytes_a = a.random_bytes(64);
        let bytes_b = b.random_bytes(64);
        prop_assert_ne!(bytes_a, bytes_b);
    }
}

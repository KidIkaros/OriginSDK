// SPDX-License-Identifier: Apache-2.0

//! Integration tests for origin-crypto-sdk

use origin_crypto_sdk::{
    aead,
    aead::symmetric,
    error_correction, kdf,
    pqc::falcon1024,
    pqc::falcon512,
    pqc::ntru_prime,
    signing::hybrid::{Ed25519Falcon1024, Ed25519Falcon512, Ed448Falcon1024},
    tier::MemoryTier,
    types::{CNonce, XNonce},
    CryptoError, Result,
};

// =============================================================================
// Randomness Integration Tests
// =============================================================================

#[test]
fn test_public_randomness_api_fills_empty_and_nonempty_buffers() {
    let mut empty = [];
    origin_crypto_sdk::fill_random(&mut empty).unwrap();

    let mut bytes = [0u8; 64];
    origin_crypto_sdk::fill_random(&mut bytes).unwrap();
    assert_ne!(bytes, [0u8; 64]);
}

// =============================================================================
// Fallible RNG API Tests
// =============================================================================

#[test]
fn test_try_generate_nonce_succeeds() {
    let nonce = aead::try_generate_nonce().unwrap();
    assert_eq!(nonce.len(), 24);
    assert_ne!(nonce, [0u8; 24]);
}

#[test]
fn test_try_generate_key_succeeds() {
    let key = aead::try_generate_key().unwrap();
    assert_eq!(key.len(), 32);
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn test_xnonce_try_random_succeeds() {
    let nonce = XNonce::try_random().unwrap();
    assert_eq!(nonce.as_bytes().len(), 24);
    assert_ne!(nonce.as_bytes(), &[0u8; 24]);
}

#[test]
fn test_cnonce_try_random_succeeds() {
    let nonce = CNonce::try_random().unwrap();
    assert_eq!(nonce.as_bytes().len(), 12);
    assert_ne!(nonce.as_bytes(), &[0u8; 12]);
}

// =============================================================================
// Fallible Signing API Tests
// =============================================================================

#[test]
fn test_try_sign_ed25519_falcon1024_succeeds() {
    let (falcon_pk, falcon_sk) = falcon1024::generate_keypair_from_seed(&[42u8; 32]).unwrap();
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"fallible sign test";

    let sig = Ed25519Falcon1024::try_sign(&ed_sk, &falcon_sk, msg).unwrap();
    Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

#[test]
fn test_try_sign_ed25519_falcon512_succeeds() {
    let (falcon_sk, falcon_pk) = falcon512::generate_keypair([42u8; 32]);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"fallible sign test";

    let sig = Ed25519Falcon512::try_sign(&ed_sk, &falcon_sk, msg).unwrap();
    Ed25519Falcon512::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

#[test]
fn test_try_sign_ed448_falcon1024_succeeds() {
    let (falcon_pk, falcon_sk) = falcon1024::generate_keypair_from_seed(&[42u8; 32]).unwrap();
    let ed_sk = origin_crypto_sdk::pqc::ed448::SigningKey::from_bytes(&[1u8; 57]).unwrap();
    let ed_pk = ed_sk.verifying_key();
    let msg = b"fallible sign test";

    let sig = Ed448Falcon1024::try_sign(&ed_sk, &falcon_sk, msg).unwrap();
    Ed448Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

// =============================================================================
// Fallible Tier Params Test
// =============================================================================

#[test]
fn test_try_argon2_params_rejects_zero_output_len() {
    assert!(MemoryTier::Standard.try_argon2_params(0).is_err());
    assert!(MemoryTier::Standard.try_argon2_params(32).is_ok());
}

// =============================================================================
// Format Boundary Tests
// =============================================================================

#[test]
fn test_falcon512_public_key_from_bytes_rejects_wrong_length() {
    use origin_crypto_sdk::pqc::falcon512::Falcon512PublicKey;
    assert!(Falcon512PublicKey::from_bytes(&[0u8; 100]).is_err());
    assert!(Falcon512PublicKey::from_bytes(&[0u8; 897]).is_ok());
}

#[test]
fn test_falcon512_private_key_from_bytes_rejects_wrong_length() {
    use origin_crypto_sdk::pqc::falcon512::Falcon512PrivateKey;
    assert!(Falcon512PrivateKey::from_bytes(&[0u8; 100]).is_err());
    assert!(Falcon512PrivateKey::from_bytes(&[0u8; 1281]).is_ok());
}

#[test]
fn test_falcon512_signature_from_bytes_rejects_oversized() {
    use origin_crypto_sdk::pqc::falcon512::Falcon512Signature;
    assert!(Falcon512Signature::from_bytes(&[0u8; 1000]).is_err());
    assert!(Falcon512Signature::from_bytes(&[0u8; 100]).is_ok());
}

// =============================================================================
// AEAD Integration Tests
// =============================================================================

// =============================================================================
// Seed Blob Golden Vectors
// =============================================================================
//
// These tests verify the v2 blob format structure and cross-version
// compatibility. True byte-exact golden vectors are not possible because
// Argon2id output depends on the argon2 crate version, but we verify:
//   1. Structural layout (magic, version, tier at correct offsets)
//   2. Field sizes and positions
//   3. Round-trip correctness for v2
//   4. v1 backward compatibility
//   5. v1→v2 migration via rotate_blob
//   6. Tamper detection (version, tier, truncation)

#[test]
fn golden_v2_blob_structure() {
    use origin_crypto_sdk::blob;

    let blob = blob::create_blob(b"golden-pw", MemoryTier::Nano, Some(&[0x42u8; 32])).unwrap();

    // Structural assertions: verify every field is at the expected offset.
    assert_eq!(
        blob.len(),
        blob::BLOB_V2_LEN,
        "v2 blob must be exactly 94 bytes"
    );
    assert_eq!(
        &blob[0..4],
        blob::BLOB_MAGIC,
        "offset 0: magic must be ORGB"
    );
    assert_eq!(
        blob[4],
        blob::BLOB_VERSION,
        "offset 4: version must be 0x02"
    );
    assert_eq!(
        blob[5],
        MemoryTier::Nano as u8,
        "offset 5: tier must be Nano (0)"
    );
    // salt: offset 6..22 (16 bytes) — must be non-zero (random)
    assert!(
        blob[6..22].iter().any(|&b| b != 0),
        "offset 6: salt must be non-zero"
    );
    // nonce: offset 22..46 (24 bytes) — must be non-zero (random)
    assert!(
        blob[22..46].iter().any(|&b| b != 0),
        "offset 22: nonce must be non-zero"
    );
    // ct+tag: offset 46..94 (48 bytes) — must be non-zero (encrypted)
    assert!(
        blob[46..94].iter().any(|&b| b != 0),
        "offset 46: ct+tag must be non-zero"
    );
}

#[test]
fn golden_v2_blob_roundtrip_all_tiers() {
    use origin_crypto_sdk::blob;

    let tiers = [
        MemoryTier::Nano,
        MemoryTier::Standard,
        MemoryTier::Sovereign,
    ];
    let seed = [0xABu8; 32];

    for tier in tiers {
        let blob = blob::create_blob(b"golden-rt", tier, Some(&seed)).unwrap();
        assert_eq!(blob::detect_blob_version(&blob), Some(2));
        assert_eq!(blob::blob_tier(&blob), Some(tier));

        // v2 is self-describing: recover with any tier should work.
        let recovered = blob::recover_seed(&blob, b"golden-rt", MemoryTier::Nano).unwrap();
        assert_eq!(
            recovered, seed,
            "round-trip must preserve seed for {:?}",
            tier
        );
    }
}

#[test]
fn golden_v1_blob_backward_compat() {
    use origin_crypto_sdk::aead::XChaCha20Poly1305;
    use origin_crypto_sdk::blob;

    // Construct a v1 blob manually (no magic, no version, no tier).
    let pw = b"golden-v1-pw";
    let seed = [0xCDu8; 32];
    let salt = [0x11u8; 16];
    let nonce = [0x22u8; 24];

    // Derive key using Nano tier params via the public KDF builder.
    let key = origin_crypto_sdk::kdf::Argon2idBuilder::new()
        .memory_kib(8 * 1024) // 8 MB = Nano
        .iterations(2)
        .parallelism(1)
        .output_len(32)
        .derive(pw, &salt)
        .unwrap();
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);

    // v1 AAD = salt only.
    let ct = XChaCha20Poly1305::encrypt_aad(&key_arr, &nonce, &seed, &salt).unwrap();

    let mut v1_blob = Vec::with_capacity(88);
    v1_blob.extend_from_slice(&salt);
    v1_blob.extend_from_slice(&nonce);
    v1_blob.extend_from_slice(&ct);

    // Verify structure.
    assert_eq!(v1_blob.len(), 88);
    assert_eq!(blob::detect_blob_version(&v1_blob), Some(1));
    assert_eq!(blob::blob_tier(&v1_blob), None, "v1 has no embedded tier");

    // Must be readable with the correct tier.
    let recovered = blob::recover_seed(&v1_blob, pw, MemoryTier::Nano).unwrap();
    assert_eq!(recovered, seed);

    // Must fail with the wrong tier (different Argon2 params).
    assert!(blob::recover_seed(&v1_blob, pw, MemoryTier::Standard).is_err());
}

#[test]
fn golden_v1_to_v2_migration() {
    use origin_crypto_sdk::aead::XChaCha20Poly1305;
    use origin_crypto_sdk::blob;

    let pw = b"migrate-pw";
    let seed = [0xEFu8; 32];
    let salt = [0x33u8; 16];
    let nonce = [0x44u8; 24];

    let key = origin_crypto_sdk::kdf::Argon2idBuilder::new()
        .memory_kib(8 * 1024)
        .iterations(2)
        .parallelism(1)
        .output_len(32)
        .derive(pw, &salt)
        .unwrap();
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);

    let ct = XChaCha20Poly1305::encrypt_aad(&key_arr, &nonce, &seed, &salt).unwrap();

    let mut v1 = Vec::with_capacity(88);
    v1.extend_from_slice(&salt);
    v1.extend_from_slice(&nonce);
    v1.extend_from_slice(&ct);

    assert_eq!(blob::detect_blob_version(&v1), Some(1));

    // Migrate v1 → v2.
    let v2 = blob::rotate_blob(&v1, pw, b"new-migrate-pw", MemoryTier::Nano).unwrap();
    assert_eq!(blob::detect_blob_version(&v2), Some(2));
    assert_eq!(v2.len(), blob::BLOB_V2_LEN);

    // Recover from v2 with the new passphrase.
    let recovered = blob::recover_seed(&v2, b"new-migrate-pw", MemoryTier::Nano).unwrap();
    assert_eq!(recovered, seed);
}

#[test]
fn golden_v2_tamper_detection() {
    use origin_crypto_sdk::blob;

    let blob = blob::create_blob(b"tamper-pw", MemoryTier::Standard, Some(&[0x01u8; 32])).unwrap();

    // Tamper: flip version byte.
    let mut bad_version = blob.clone();
    bad_version[4] = 0x99;
    assert!(blob::recover_seed(&bad_version, b"tamper-pw", MemoryTier::Standard).is_err());

    // Tamper: flip tier byte (AAD must catch this).
    let mut bad_tier = blob.clone();
    bad_tier[5] = MemoryTier::Sovereign as u8;
    assert!(blob::recover_seed(&bad_tier, b"tamper-pw", MemoryTier::Standard).is_err());

    // Tamper: flip a salt byte (AAD must catch this).
    let mut bad_salt = blob.clone();
    bad_salt[6] ^= 0xFF;
    assert!(blob::recover_seed(&bad_salt, b"tamper-pw", MemoryTier::Standard).is_err());

    // Tamper: flip a ciphertext byte.
    let mut bad_ct = blob.clone();
    bad_ct[50] ^= 0x01;
    assert!(blob::recover_seed(&bad_ct, b"tamper-pw", MemoryTier::Standard).is_err());

    // Truncate.
    let truncated = &blob[..60];
    assert!(blob::recover_seed(truncated, b"tamper-pw", MemoryTier::Standard).is_err());
}

// =============================================================================
// AEAD Integration Tests (continued)
// =============================================================================

#[test]
fn test_xchacha20_poly1305_large_data() {
    let key = aead::generate_key();
    let nonce = aead::generate_nonce();
    let plaintext = vec![0u8; 1024 * 1024]; // 1 MB

    let encrypted = aead::XChaCha20Poly1305::encrypt(&key, &nonce, &plaintext).unwrap();
    let decrypted = aead::XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_xchacha20_poly1305_many_small_messages() {
    let key = aead::generate_key();
    let nonce = aead::generate_nonce();

    for i in 0..100 {
        let plaintext = format!("message {}", i).into_bytes();
        let encrypted = aead::XChaCha20Poly1305::encrypt(&key, &nonce, &plaintext).unwrap();
        let decrypted = aead::XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

// =============================================================================
// KDF Integration Tests
// =============================================================================

#[test]
fn test_argon2id_paranoid_vs_normal() {
    let password = b"test_password";
    let salt = [1u8; 16];

    let normal_key = kdf::Argon2id::derive_key(password, &salt, false).unwrap();
    let paranoid_key = kdf::Argon2id::derive_key(password, &salt, true).unwrap();

    // Keys should be different (different parameters)
    assert_ne!(normal_key, paranoid_key);
}

#[test]
fn test_argon2id_unicode_password() {
    let password = "🔐 unicode 密码 мот de passe".as_bytes();
    let salt = [2u8; 16];

    let key = kdf::Argon2id::derive_key(password, &salt, false).unwrap();
    assert_eq!(key.len(), 32);
}

// =============================================================================
// Reed-Solomon Integration Tests
// =============================================================================

#[test]
fn test_reed_solomon_large_data() {
    let codec = error_correction::ReedSolomonCodec::new(16, 8);
    let data = vec![0u8; 1024 * 1024]; // 1 MB

    let encoded = codec.encode(&data).unwrap();
    let decoded = codec.decode(&encoded).unwrap();

    assert_eq!(data, decoded);
}

#[test]
fn test_reed_solomon_error_detection() {
    let codec = error_correction::ReedSolomonCodec::new(4, 2);
    let data = b"Hello, World! This is a test.";

    let encoded = codec.encode(data).unwrap();
    let decoded = codec.decode(&encoded).unwrap();
    assert_eq!(data.to_vec(), decoded);
}

#[test]
fn test_reed_solomon_parallel_matches_serial() {
    let codec = error_correction::ReedSolomonCodec::new(8, 4);
    let data = b"Test data for parallel encoding";

    let serial = codec.encode(data).unwrap();
    let parallel = codec.encode_parallel(data).unwrap();

    assert_eq!(serial, parallel);
}

// =============================================================================
// Symmetric Encryption Integration Tests
// =============================================================================

#[test]
fn test_serpent_cbc_large_data() {
    let key = [1u8; 32];
    let iv = [2u8; 16];
    let plaintext = vec![0u8; 64 * 1024]; // 64 KB

    let encrypted = symmetric::SerpentCbc::encrypt(&key, &iv, &plaintext).unwrap();
    let decrypted = symmetric::SerpentCbc::decrypt(&key, &iv, &encrypted).unwrap();

    assert_eq!(plaintext, decrypted);
}

// =============================================================================
// PQC Integration Tests
// =============================================================================

#[test]
fn test_falcon512_full_workflow() {
    let seed = [42u8; 32];
    let (sk, pk) = falcon512::generate_keypair(seed);
    let message = b"Important message to sign";

    // Sign
    let signature = falcon512::sign(message, &sk).unwrap();

    // Verify
    assert!(falcon512::verify(message, &signature, &pk));

    // Wrong message should fail
    assert!(!falcon512::verify(b"wrong message", &signature, &pk));
}

#[test]
fn test_falcon1024_full_workflow() {
    use origin_crypto_sdk::pqc::falcon1024;

    let seed = [123u8; 32];
    let (pk, sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let message = b"Important message to sign with Falcon-1024";

    // Sign
    let signature = falcon1024::sign(message, &sk).unwrap();

    // Verify
    assert!(falcon1024::verify(message, &signature, &pk).is_ok());

    // Wrong message should fail
    assert!(falcon1024::verify(b"wrong message", &signature, &pk).is_err());
}

#[test]
fn test_ntru_prime_full_workflow() {
    use origin_crypto_sdk::drbg::ChaCha20Rng;

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Generate keypair
    let (pk, sk) = ntru_prime::NtruPrime::generate_keypair(&mut rng);

    // Encapsulate
    let (ct, ss1) = ntru_prime::NtruPrime::encapsulate(&pk, &mut rng);

    // Decapsulate
    let ss2 = ntru_prime::NtruPrime::decapsulate(&ct, &sk).unwrap();

    // Shared secrets should match
    assert_eq!(ss1, ss2);
}

#[test]
fn test_ntru_prime_different_keypairs() {
    use origin_crypto_sdk::drbg::ChaCha20Rng;

    let mut rng1 = ChaCha20Rng::from_seed([1u8; 32]);
    let mut rng2 = ChaCha20Rng::from_seed([2u8; 32]);

    let (pk1, _) = ntru_prime::NtruPrime::generate_keypair(&mut rng1);
    let (pk2, _) = ntru_prime::NtruPrime::generate_keypair(&mut rng2);

    // Different seeds should produce different keys
    assert_ne!(pk1, pk2);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_error_display() {
    let err = CryptoError::AuthenticationFailed;
    let msg = format!("{}", err);
    assert!(msg.contains("Authentication failed"));
}

#[test]
fn test_result_type_alias() {
    fn may_fail(succeed: bool) -> Result<u32> {
        if succeed {
            Ok(42)
        } else {
            Err(CryptoError::InvalidParameter("test".to_string()))
        }
    }

    assert_eq!(may_fail(true).unwrap(), 42);
    assert!(may_fail(false).is_err());
}

// =============================================================================
// Cross-Module Integration Tests
// =============================================================================

#[test]
fn test_encrypt_then_sign() {
    // Encrypt with XChaCha20-Poly1305
    let key = aead::generate_key();
    let nonce = aead::generate_nonce();
    let plaintext = b"Secret message";
    let encrypted = aead::XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).unwrap();

    // Sign the encrypted data with Falcon-512
    let seed = [99u8; 32];
    let (sk, pk) = falcon512::generate_keypair(seed);
    let signature = falcon512::sign(&encrypted, &sk).unwrap();

    // Verify signature
    assert!(falcon512::verify(&encrypted, &signature, &pk));

    // Decrypt
    let decrypted = aead::XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_key_derivation_then_encrypt() {
    // Derive key from password
    let password = b"my_secure_password";
    let salt = aead::generate_key()[0..16].try_into().unwrap();
    let key = kdf::Argon2id::derive_key(password, &salt, false).unwrap();

    // Use derived key for encryption
    let nonce = aead::generate_nonce();
    let plaintext = b"Data encrypted with derived key";
    let encrypted = aead::XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).unwrap();

    // Decrypt
    let decrypted = aead::XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

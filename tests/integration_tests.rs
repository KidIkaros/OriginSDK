// SPDX-License-Identifier: OPL-1.1

//! Integration tests for origin-crypto-sdk

use origin_crypto_sdk::{
    aead, kdf, error_correction, symmetric,
    pqc::falcon512, pqc::falcon1024, pqc::ntru_prime,
    CryptoError, Result,
};

// =============================================================================
// AEAD Integration Tests
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
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

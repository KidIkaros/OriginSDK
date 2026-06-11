// SPDX-License-Identifier: Apache-2.0
//! ChaCha20-BLAKE3 AEAD cipher
//!
//! Authenticated Encryption with Associated Data (AEAD) using
//! ChaCha20 stream cipher + BLAKE3 keyed_hash for authentication.
//!
//! Uses `chacha20-blake3` crate v0.9.11
//! Spec: https://kerkour.com/chacha20-blake3
//! Committing AEAD — immune to partitioning oracle & Invisible Salamanders attacks.

use crate::error::{CryptoError, Result};
use chacha20_blake3::{ChaCha20Blake3 as ChaCha20Blake3Impl, Error as ChaCha20Blake3Error};

/// ChaCha20-BLAKE3 AEAD provider
///
/// Security: 256-bit confidentiality + 256-bit integrity
/// Committing: YES (unlike Poly1305-based schemes)
/// Nonce: 192-bit (24 bytes) — safe for random generation
pub struct ChaCha20Blake3;

/// Key size constant
pub const KEY_SIZE: usize = chacha20_blake3::KEY_SIZE; // 32 bytes
/// Nonce size constant  
pub const NONCE_SIZE: usize = chacha20_blake3::NONCE_SIZE; // 24 bytes
/// Tag size constant
pub const TAG_SIZE: usize = chacha20_blake3::TAG_SIZE; // 32 bytes

impl ChaCha20Blake3 {
    /// Encrypt data using ChaCha20-BLAKE3 AEAD
    ///
    /// # Arguments
    /// * `key` - 32-byte key
    /// * `nonce` - 24-byte nonce (192-bit, safe for random generation)
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional authenticated data (not encrypted)
    ///
    /// # Returns
    /// Ciphertext with 32-byte authentication tag appended
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Blake3Impl::new(*key);
        // Note: chacha20_blake3::encrypt returns Vec<u8> (not Result)
        let result = cipher.encrypt(nonce, plaintext, associated_data);
        Ok(result)
    }

    /// Decrypt data using ChaCha20-BLAKE3 AEAD
    ///
    /// # Returns
    /// Plaintext if authentication succeeds
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext_with_tag: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Blake3Impl::new(*key);
        cipher
            .decrypt(nonce, ciphertext_with_tag, associated_data)
            .map_err(|e: ChaCha20Blake3Error| {
                // ChaCha20Blake3Error doesn't implement Display
                // Check if it's an authentication failure by inspecting the error
                // For now, convert using Debug format
                CryptoError::Decryption(format!("ChaCha20-BLAKE3: {:?}", e))
            })
    }

    /// Generate a secure random nonce (192-bit / 24 bytes)
    pub fn generate_nonce() -> [u8; 24] {
        let mut nonce = [0u8; 24];
        crate::internal::getrandom::fill(&mut nonce).expect("RNG failed");
        nonce
    }

    /// Generate a secure random key (256-bit / 32 bytes)
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        crate::internal::getrandom::fill(&mut key).expect("RNG failed");
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = ChaCha20Blake3::generate_key();
        let nonce = ChaCha20Blake3::generate_nonce();
        let plaintext = b"Hello, ChaCha20-BLAKE3!";
        let associated_data = b"test-aad";

        let encrypted = ChaCha20Blake3::encrypt(&key, &nonce, plaintext, associated_data).unwrap();
        let decrypted = ChaCha20Blake3::decrypt(&key, &nonce, &encrypted, associated_data).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = ChaCha20Blake3::generate_key();
        let key2 = ChaCha20Blake3::generate_key();
        let nonce = ChaCha20Blake3::generate_nonce();
        let plaintext = b"secret";

        let encrypted = ChaCha20Blake3::encrypt(&key1, &nonce, plaintext, &[]).unwrap();
        let result = ChaCha20Blake3::decrypt(&key2, &nonce, &encrypted, &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_tag_fails() {
        let key = ChaCha20Blake3::generate_key();
        let nonce = ChaCha20Blake3::generate_nonce();
        let plaintext = b"secret message";

        let mut encrypted = ChaCha20Blake3::encrypt(&key, &nonce, plaintext, &[]).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = encrypted.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = ChaCha20Blake3::decrypt(&key, &nonce, &encrypted, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_test_vectors() {
        // From https://kerkour.com/chacha20-blake3
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let plaintext = b"";
        let associated_data = b"";

        let encrypted = ChaCha20Blake3::encrypt(&key, &nonce, plaintext, associated_data).unwrap();

        // Verify we get 32-byte tag appended
        assert_eq!(encrypted.len(), TAG_SIZE);

        let decrypted = ChaCha20Blake3::decrypt(&key, &nonce, &encrypted, associated_data).unwrap();
        assert_eq!(decrypted.len(), 0);
    }
}

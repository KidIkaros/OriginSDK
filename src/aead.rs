// SPDX-License-Identifier: OPL-1.1

//! Authenticated Encryption with Associated Data (AEAD)
//!
//! Provides XChaCha20-Poly1305 encryption with 256-bit keys and 192-bit nonces.

use crate::error::{CryptoError, Result};
use crate::internal::getrandom;
use crate::primitives::chacha20poly1305::{
    xchacha20_poly1305_open, xchacha20_poly1305_seal,
};

/// XChaCha20-Poly1305 AEAD encryption provider
pub struct XChaCha20Poly1305;

impl XChaCha20Poly1305 {
    /// Encrypt data using XChaCha20-Poly1305
    /// Returns ciphertext with 16-byte authentication tag appended
    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Result<Vec<u8>> {
        let sealed = xchacha20_poly1305_seal(key, nonce, plaintext, &[]);
        Ok(sealed)
    }

    /// Decrypt data using XChaCha20-Poly1305
    /// Expects ciphertext with 16-byte authentication tag appended
    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Vec<u8>> {
        xchacha20_poly1305_open(key, nonce, ciphertext, &[])
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Generate a secure random nonce
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("RNG failed");
    nonce
}

/// Generate a secure random key
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("RNG failed");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, World!";

        let encrypted = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = generate_key();
        let wrong_key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"secret";

        let encrypted = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).unwrap();
        let result = XChaCha20Poly1305::decrypt(&wrong_key, &nonce, &encrypted);

        assert!(result.is_err());
    }
}

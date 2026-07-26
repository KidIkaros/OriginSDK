// SPDX-License-Identifier: Apache-2.0

//! Symmetric encryption (non-AEAD)
//!
//! Provides Serpent CBC for paranoid mode.
//! Note: Serpent is currently provided by external crate (to be replaced in future phase).

use crate::error::{CryptoError, Result};
use cipher::{
    generic_array::typenum::U16, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut,
    KeyInit,
};
use serpent::Serpent;

/// Serpent CBC mode encryption provider
#[derive(Debug)]
pub struct SerpentCbc;

impl SerpentCbc {
    /// Encrypt data using Serpent in CBC mode
    pub fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
        let key_array = GenericArray::<u8, U16>::from_slice(&key[..16]);
        let mut cipher = Serpent::new(key_array);

        // Pad to 16-byte boundary using PKCS7
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let mut ciphertext = Vec::with_capacity(padded.len());
        let mut prev_block: [u8; 16] = *iv;

        for chunk in padded.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            // XOR with previous block (CBC)
            for i in 0..16 {
                block[i] ^= prev_block[i];
            }

            let mut block_ga = GenericArray::<u8, U16>::from_mut_slice(&mut block);
            cipher.encrypt_block_mut(&mut block_ga);
            ciphertext.extend_from_slice(&block_ga);
            prev_block = block;
        }

        Ok(ciphertext)
    }

    /// Decrypt data using Serpent in CBC mode
    pub fn decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % 16 != 0 {
            return Err(CryptoError::Decryption(
                "Invalid ciphertext length".to_string(),
            ));
        }

        let key_array = GenericArray::<u8, U16>::from_slice(&key[..16]);
        let mut cipher = Serpent::new(key_array);

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block: [u8; 16] = *iv;

        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);

            let encrypted_block = block.clone();
            let mut block_ga = GenericArray::<u8, U16>::from_mut_slice(&mut block);
            cipher.decrypt_block_mut(&mut block_ga);

            // XOR with previous block (CBC)
            for i in 0..16 {
                block[i] ^= prev_block[i];
            }

            plaintext.extend_from_slice(&block);
            prev_block = encrypted_block;
        }

        // Remove PKCS7 padding
        if let Some(&pad_len) = plaintext.last() {
            let pad_len = pad_len as usize;
            if pad_len > 0 && pad_len <= 16 && pad_len <= plaintext.len() {
                plaintext.truncate(plaintext.len() - pad_len);
            }
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serpent_cbc_roundtrip() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let plaintext = b"Hello, World! Secret message.";

        let encrypted = SerpentCbc::encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = SerpentCbc::decrypt(&key, &iv, &encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}

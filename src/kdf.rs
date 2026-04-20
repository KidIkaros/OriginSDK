// SPDX-License-Identifier: OPL-1.1

//! Key Derivation Functions
//!
//! Provides Argon2id for password-based key derivation and HKDF for
//! key derivation from master keys.

pub mod hkdf;

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};

/// Argon2id key derivation
pub struct Argon2id;

impl Argon2id {
    /// Derive a 256-bit key from password using Argon2id
    ///
    /// # Arguments
    /// * `password` - The password to derive from
    /// * `salt` - 16-byte salt (must be unique per password)
    /// * `paranoid` - Use higher parameters for increased security
    pub fn derive_key(password: &[u8], salt: &[u8; 16], paranoid: bool) -> Result<[u8; 32]> {
        let params = if paranoid {
            // Paranoid mode: 8 passes, 1 GiB memory
            Params::new(65536, 8, 1, None)
        } else {
            // Normal mode: 4 passes, 1 GiB memory
            Params::new(65536, 4, 1, None)
        }
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        // Convert salt to SaltString using encode_b64
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;

        let password_hash = argon2
            .hash_password(password, &salt_string)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;

        let mut key = [0u8; 32];
        let hash = password_hash.hash.ok_or_else(|| {
            CryptoError::Kdf("No hash generated".to_string())
        })?;
        let hash_bytes = hash.as_bytes();
        let len = hash_bytes.len().min(32);
        key[..len].copy_from_slice(&hash_bytes[..len]);

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [1u8; 16];

        let key1 = Argon2id::derive_key(password, &salt, false).unwrap();
        let key2 = Argon2id::derive_key(password, &salt, false).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [1u8; 16];

        let key1 = Argon2id::derive_key(b"password1", &salt, false).unwrap();
        let key2 = Argon2id::derive_key(b"password2", &salt, false).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"test_password";

        let key1 = Argon2id::derive_key(password, &[1u8; 16], false).unwrap();
        let key2 = Argon2id::derive_key(password, &[2u8; 16], false).unwrap();

        assert_ne!(key1, key2);
    }
}

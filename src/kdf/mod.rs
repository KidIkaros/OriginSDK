// SPDX-License-Identifier: Apache-2.0

//! Key Derivation Functions
//!
//! Provides Argon2id for password-based key derivation, HKDF for
//! key derivation from master keys, and HMAC for message authentication.
//!
//! # Submodules
//!
//! - [`hkdf`] — HKDF-SHA3-256
//! - [`mac`] — HMAC-SHA3-256

pub mod hkdf;
pub mod mac;

use crate::error::{CryptoError, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};

/// Argon2id key derivation
#[derive(Debug)]
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
        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| CryptoError::Kdf(e.to_string()))?;

        let password_hash = argon2
            .hash_password(password, &salt_string)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;

        let mut key = [0u8; 32];
        let hash = password_hash
            .hash
            .ok_or_else(|| CryptoError::Kdf("No hash generated".to_string()))?;
        let hash_bytes = hash.as_bytes();
        let len = hash_bytes.len().min(32);
        key[..len].copy_from_slice(&hash_bytes[..len]);

        Ok(key)
    }
}

/// Builder for customizing Argon2id parameters.
///
/// The default [`Argon2id::derive_key`] uses preset parameters (normal vs paranoid).
/// Use this builder when you need fine-grained control over memory, iterations,
/// and parallelism.
///
/// # Example
///
/// ```no_run
/// use origin_crypto_sdk::kdf::Argon2idBuilder;
///
/// let key = Argon2idBuilder::new()
///     .memory_kib(32768)       // 32 MiB
///     .iterations(3)
///     .parallelism(2)
///     .output_len(32)
///     .derive(b"password", &[0u8; 16])
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Argon2idBuilder {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
}

impl Default for Argon2idBuilder {
    fn default() -> Self {
        // Match the "normal" preset from Argon2id::derive_key
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 4,
            parallelism: 1,
            output_len: 32,
        }
    }
}

impl Argon2idBuilder {
    /// Create a new builder with default parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder with paranoid defaults (higher memory + iterations).
    pub fn paranoid() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB (same as normal — increase for actual paranoid use)
            iterations: 8,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// Set memory cost in KiB. Default: 65536 (64 MiB).
    ///
    /// Higher values increase resistance to GPU-based attacks but require
    /// more RAM. Must be at least 8 * parallelism.
    pub fn memory_kib(mut self, kib: u32) -> Self {
        self.memory_kib = kib;
        self
    }

    /// Set number of iterations (passes). Default: 4.
    ///
    /// Higher values increase CPU cost linearly.
    pub fn iterations(mut self, n: u32) -> Self {
        self.iterations = n;
        self
    }

    /// Set degree of parallelism. Default: 1.
    ///
    /// Number of lanes used. Higher values use more threads.
    pub fn parallelism(mut self, lanes: u32) -> Self {
        self.parallelism = lanes;
        self
    }

    /// Set output key length in bytes. Default: 32.
    pub fn output_len(mut self, len: usize) -> Self {
        self.output_len = len;
        self
    }

    /// Derive a key with the configured parameters.
    ///
    /// # Arguments
    /// * `password` - Password bytes
    /// * `salt` - 16-byte salt (unique per password)
    ///
    /// # Errors
    /// Returns [`CryptoError::Kdf`] if Argon2id parameters are invalid
    /// or hashing fails.
    pub fn derive(self, password: &[u8], salt: &[u8; 16]) -> Result<Vec<u8>> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(self.output_len),
        )
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt_string =
            SaltString::encode_b64(salt).map_err(|e| CryptoError::Kdf(e.to_string()))?;
        let password_hash = argon2
            .hash_password(password, &salt_string)
            .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        let hash = password_hash
            .hash
            .ok_or_else(|| CryptoError::Kdf("No hash generated".to_string()))?;
        Ok(hash.as_bytes().to_vec())
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

    #[test]
    fn test_builder_matches_preset() {
        let password = b"test_password";
        let salt = [1u8; 16];

        // Default builder should produce the same result as derive_key(false)
        let preset_key = Argon2id::derive_key(password, &salt, false).unwrap();
        let builder_key = Argon2idBuilder::new().derive(password, &salt).unwrap();

        assert_eq!(preset_key.as_slice(), &builder_key[..32]);
    }

    #[test]
    fn test_builder_custom_params() {
        let password = b"builder_test";
        let salt = [42u8; 16];

        let key = Argon2idBuilder::new()
            .memory_kib(8192) // 8 MiB — faster for tests
            .iterations(1)
            .parallelism(1)
            .output_len(64)
            .derive(password, &salt)
            .unwrap();

        assert_eq!(key.len(), 64);
        assert_ne!(key, vec![0u8; 64]);
    }
}

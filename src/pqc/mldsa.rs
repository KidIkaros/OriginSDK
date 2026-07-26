// SPDX-License-Identifier: Apache-2.0

//! ML-DSA (FIPS 204) wrapper for Origin SDK — Dilithium2-equivalent (MlDsa44).
//!
//! ML-DSA is a module-lattice-based signature scheme. MlDsa44 provides NIST Level 2
//! security with 1312-byte public keys and 2420-byte signatures.

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa44, SigningKey, VerifyingKey};

pub mod sizes {
    /// Public key size in bytes (MlDsa44: 1312 bytes)
    pub const PUBLIC_KEY: usize = 1312;
    /// Private key (seed) size in bytes (MlDsa44: 32 bytes)
    pub const PRIVATE_KEY: usize = 32;
    /// Signature size in bytes (MlDsa44: 2420 bytes)
    pub const SIGNATURE: usize = 2420;
}

/// ML-DSA public key (serialized encoded verifying key bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct MldsaPublicKey(pub(crate) Vec<u8>);

/// ML-DSA private key (32-byte seed that reconstructs the signing key)
#[derive(Clone)]
pub struct MldsaPrivateKey(pub(crate) Vec<u8>);

impl Drop for MldsaPrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl MldsaPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PUBLIC_KEY {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "ML-DSA",
                expected: sizes::PUBLIC_KEY,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Key size in bytes
    pub const fn size() -> usize {
        sizes::PUBLIC_KEY
    }
}

impl MldsaPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PRIVATE_KEY {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "ML-DSA",
                expected: sizes::PRIVATE_KEY,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes (sensitive!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Key size in bytes
    pub const fn size() -> usize {
        sizes::PRIVATE_KEY
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        sign(message, self)
    }
}

/// Deterministic key generation from a 32-byte seed.
/// Uses `SigningKey::from_seed` which implements FIPS 204 Algorithm 6.
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Result<(MldsaPublicKey, MldsaPrivateKey)> {
    let seed_array: ml_dsa::Seed = (*seed).into();
    let sk = SigningKey::<MlDsa44>::from_seed(&seed_array);
    let vk = sk.verifying_key();

    let pk_bytes = vk.encode().as_slice().to_vec();
    let sk_bytes = sk.to_seed().as_slice().to_vec();

    Ok((MldsaPublicKey(pk_bytes), MldsaPrivateKey(sk_bytes)))
}

/// Sign a message with an ML-DSA private key.
pub fn sign(message: &[u8], private_key: &MldsaPrivateKey) -> Result<Vec<u8>> {
    let sk_bytes: [u8; sizes::PRIVATE_KEY] =
        private_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                algorithm: "ML-DSA",
                expected: sizes::PRIVATE_KEY,
                got: private_key.as_bytes().len(),
            })?;

    let seed: ml_dsa::Seed = sk_bytes.into();
    let sk = SigningKey::<MlDsa44>::from_seed(&seed);

    let sig = Signer::try_sign(&sk, message)
        .map_err(|e| CryptoError::Pqc(format!("ML-DSA signing failed: {:?}", e)))?;

    Ok(sig.encode().as_slice().to_vec())
}

/// Verify an ML-DSA signature.
pub fn verify(message: &[u8], signature: &[u8], public_key: &MldsaPublicKey) -> Result<()> {
    let pk_bytes: [u8; sizes::PUBLIC_KEY] =
        public_key
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                algorithm: "ML-DSA",
                expected: sizes::PUBLIC_KEY,
                got: public_key.as_bytes().len(),
            })?;

    let enc_pk: ml_dsa::EncodedVerifyingKey<MlDsa44> = pk_bytes.into();
    let vk = VerifyingKey::<MlDsa44>::decode(&enc_pk);

    let sig = ml_dsa::Signature::<MlDsa44>::try_from(signature)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid ML-DSA signature: {:?}", e)))?;

    if vk.verify_with_context(message, &[], &sig) {
        Ok(())
    } else {
        Err(CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_keypair_deterministic() {
        let seed = [42u8; 32];
        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let seed = [0xabu8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let msg = b"hello ml-dsa";
        let sig = sign(msg, &sk).unwrap();
        assert!(verify(msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_mldsa_verify_wrong_message() {
        let seed = [0xabu8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let sig = sign(b"original", &sk).unwrap();
        assert!(verify(b"tampered", &sig, &pk).is_err());
    }

    #[test]
    fn test_mldsa_verify_wrong_key() {
        let seed1 = [0xabu8; 32];
        let seed2 = [0xcd_u8; 32];
        let (_, sk) = generate_keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = generate_keypair_from_seed(&seed2).unwrap();
        let sig = sign(b"message", &sk).unwrap();
        assert!(verify(b"message", &sig, &pk2).is_err());
    }
}

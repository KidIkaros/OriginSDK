// SPDX-License-Identifier: OPL-1.1

//! SLH-DSA (FIPS 205) wrapper for Origin SDK.
//!
//! SLH-DSA is a stateless hash-based signature scheme with inherent SCA resistance.
//! This module wraps the RustCrypto `slh-dsa` crate using the `Shake128f` parameter set.

use crate::error::{CryptoError, Result};

use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Shake128f, SigningKey, VerifyingKey};

pub mod sizes {
    /// Public key size in bytes (Shake128f: pk_seed + pk_root = 16 + 16 = 32)
    pub const PUBLIC_KEY: usize = 32;
    /// Private key size in bytes (Shake128f: sk_seed + sk_prf + verifying_key = 16 + 16 + 32 = 64)
    pub const PRIVATE_KEY: usize = 64;
    /// Signature size in bytes (Shake128f fast: 7856 bytes)
    pub const SIGNATURE: usize = 7856;
}

/// SLH-DSA public key (serialized VerifyingKey bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct SlhDsaPublicKey(pub(crate) Vec<u8>);

/// SLH-DSA private key (serialized SigningKey bytes)
#[derive(Clone)]
pub struct SlhDsaPrivateKey(pub(crate) Vec<u8>);

impl SlhDsaPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PUBLIC_KEY {
            return Err(CryptoError::InvalidKey(format!(
                "SLH-DSA public key must be {} bytes, got {}",
                sizes::PUBLIC_KEY,
                bytes.len()
            )));
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

impl SlhDsaPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PRIVATE_KEY {
            return Err(CryptoError::InvalidKey(format!(
                "SLH-DSA private key must be {} bytes, got {}",
                sizes::PRIVATE_KEY,
                bytes.len()
            )));
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
/// Derives three 16-byte seeds (sk_seed, sk_prf, pk_seed) via SHA3-256 and
/// uses `slh_keygen_internal` for fully deterministic key generation.
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Result<(SlhDsaPublicKey, SlhDsaPrivateKey)> {
    // Derive three 16-byte seeds from the 32-byte input using SHA3-256
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(seed);
    hasher.update(b"slh-dsa-sk-seed");
    let sk_seed = &hasher.finalize_reset()[..16];

    hasher.update(seed);
    hasher.update(b"slh-dsa-sk-prf");
    let sk_prf = &hasher.finalize_reset()[..16];

    hasher.update(seed);
    hasher.update(b"slh-dsa-pk-seed");
    let pk_seed = &hasher.finalize()[..16];

    let sk = SigningKey::<Shake128f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let vk = sk.verifying_key();

    let pk_bytes = vk.to_vec();
    let sk_bytes = sk.to_vec();

    Ok((SlhDsaPublicKey(pk_bytes), SlhDsaPrivateKey(sk_bytes)))
}

/// Sign a message with an SLH-DSA private key.
pub fn sign(message: &[u8], private_key: &SlhDsaPrivateKey) -> Result<Vec<u8>> {
    let sk_bytes: [u8; sizes::PRIVATE_KEY] = private_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("SLH-DSA private key length mismatch".into()))?;

    let sk = SigningKey::<Shake128f>::try_from(&sk_bytes[..])
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid SLH-DSA secret key: {:?}", e)))?;

    let sig = sk.try_sign(message)
        .map_err(|e| CryptoError::Pqc(format!("SLH-DSA signing failed: {:?}", e)))?;

    Ok(sig.to_bytes().to_vec())
}

/// Verify an SLH-DSA signature.
pub fn verify(message: &[u8], signature: &[u8], public_key: &SlhDsaPublicKey) -> Result<()> {
    let pk_bytes: [u8; sizes::PUBLIC_KEY] = public_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("SLH-DSA public key length mismatch".into()))?;

    let vk = VerifyingKey::<Shake128f>::try_from(&pk_bytes[..])
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid SLH-DSA public key: {:?}", e)))?;

    let sig = slh_dsa::Signature::<Shake128f>::try_from(signature)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid SLH-DSA signature: {:?}", e)))?;

    vk.verify(message, &sig)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slhdsa_keypair_deterministic() {
        let seed = [42u8; 32];
        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_slhdsa_sign_verify() {
        let seed = [0xabu8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let msg = b"hello slh-dsa";
        let sig = sign(msg, &sk).unwrap();
        assert!(verify(msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_slhdsa_verify_wrong_message() {
        let seed = [0xabu8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let sig = sign(b"original", &sk).unwrap();
        assert!(verify(b"tampered", &sig, &pk).is_err());
    }

    #[test]
    fn test_slhdsa_verify_wrong_key() {
        let seed1 = [0xabu8; 32];
        let seed2 = [0xcd_u8; 32];
        let (_, sk) = generate_keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = generate_keypair_from_seed(&seed2).unwrap();
        let sig = sign(b"message", &sk).unwrap();
        assert!(verify(b"message", &sig, &pk2).is_err());
    }
}
// SPDX-License-Identifier: Apache-2.0

//! Falcon-1024 (FN-DSA-1024) Digital Signature wrapper
//!
//! Falcon is a NIST-standardized post-quantum signature scheme (FIPS 206)
//! based on NTRU lattices. This wrapper uses the `falcon-rs` crate which
//! passes all NIST KAT vectors and has been security audited.

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use falcon::safe_api::{DomainSeparation, FalconError, FnDsaKeyPair, FnDsaSignature};

/// FN-DSA logn parameter for Falcon-1024.
const LOGN_1024: u32 = 10;

/// Falcon-1024 size constants
pub mod sizes {
    /// Public key size (1793 bytes)
    pub const PUBLIC_KEY: usize = 1793;
    /// Private key size (2305 bytes)
    pub const PRIVATE_KEY: usize = 2305;
    /// Maximum signature size (1577 bytes, constant-time format).
    /// The CT format is 1577 bytes; NIST padded format is 1280 bytes.
    /// We produce CT format for side-channel resistance; verify accepts all formats.
    pub const SIGNATURE_MAX: usize = 1577;
}

/// Falcon-1024 public key (1793 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct FalconPublicKey(pub(crate) Vec<u8>);

/// Falcon-1024 private key (2305 bytes)
#[derive(Clone)]
pub struct FalconPrivateKey(pub(crate) Vec<u8>);

impl Zeroize for FalconPrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for FalconPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Falcon-1024 signature (variable length, max 1577 bytes CT format)
#[derive(Clone)]
pub struct FalconSignature(pub(crate) Vec<u8>);

impl FalconPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PUBLIC_KEY {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "Falcon-1024",
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

impl FalconPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != sizes::PRIVATE_KEY {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "Falcon-1024",
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
        let sig = sign(message, self)?;
        Ok(sig.as_bytes().to_vec())
    }
}

impl FalconSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > sizes::SIGNATURE_MAX {
            return Err(CryptoError::InvalidParameter(format!(
                "Falcon-1024 signature too large: {} bytes (max {})",
                bytes.len(),
                sizes::SIGNATURE_MAX
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Maximum signature size in bytes
    pub const fn max_size() -> usize {
        sizes::SIGNATURE_MAX
    }
}

impl std::fmt::Debug for FalconPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconPublicKey({} bytes)", self.0.len())
    }
}

impl std::fmt::Debug for FalconPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconPrivateKey [REDACTED]")
    }
}

impl std::fmt::Debug for FalconSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FalconSignature({} bytes)", self.0.len())
    }
}

/// Convert falcon-rs error to CryptoError.
fn map_falcon_err(e: FalconError) -> CryptoError {
    match e {
        FalconError::BadArgument => CryptoError::InvalidParameter("Falcon bad argument".into()),
        FalconError::BadSignature => CryptoError::AuthenticationFailed,
        FalconError::FormatError => CryptoError::InvalidKey("Falcon format error".into()),
        FalconError::RandomError => CryptoError::Pqc("Falcon RNG failure".into()),
        FalconError::SizeError => CryptoError::InvalidParameter("Falcon buffer size error".into()),
        FalconError::InternalError => CryptoError::InvalidParameter("Falcon internal error".into()),
    }
}

/// Generate Falcon-1024 keypair from a 32-byte seed.
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Result<(FalconPublicKey, FalconPrivateKey)> {
    let kp = FnDsaKeyPair::generate_deterministic(seed, LOGN_1024)
        .map_err(|e| CryptoError::InvalidKey(format!("Falcon-1024 keygen failed: {:?}", e)))?;

    Ok((
        FalconPublicKey(kp.public_key().to_vec()),
        FalconPrivateKey(kp.private_key().to_vec()),
    ))
}

/// Sign a message using Falcon-1024 private key.
///
/// Uses OS entropy for the signing nonce (standard FN-DSA behavior).
pub fn sign(message: &[u8], private_key: &FalconPrivateKey) -> Result<FalconSignature> {
    let kp = FnDsaKeyPair::from_private_key(&private_key.0)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid Falcon secret key: {:?}", e)))?;
    let sig = kp
        .sign(message, &DomainSeparation::None)
        .map_err(map_falcon_err)?;
    Ok(FalconSignature(sig.to_bytes().to_vec()))
}

/// Sign a message using Falcon-1024 private key with a deterministic nonce.
///
/// The same `(sk, message, nonce_seed)` always produces the same signature.
pub fn sign_deterministic(
    message: &[u8],
    private_key: &FalconPrivateKey,
    nonce_seed: &[u8],
) -> Result<FalconSignature> {
    let kp = FnDsaKeyPair::from_private_key(&private_key.0)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid Falcon secret key: {:?}", e)))?;
    let sig = kp
        .sign_deterministic(message, nonce_seed, &DomainSeparation::None)
        .map_err(map_falcon_err)?;
    Ok(FalconSignature(sig.to_bytes().to_vec()))
}

/// Verify a Falcon-1024 signature.
pub fn verify(
    message: &[u8],
    signature: &FalconSignature,
    public_key: &FalconPublicKey,
) -> Result<()> {
    match FnDsaSignature::verify(
        &signature.0,
        &public_key.0,
        message,
        &DomainSeparation::None,
    ) {
        Ok(()) => Ok(()),
        Err(FalconError::BadSignature) => Err(CryptoError::AuthenticationFailed),
        Err(e) => Err(CryptoError::InvalidKey(format!(
            "Falcon verify error: {:?}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_size() {
        assert_eq!(FalconPublicKey::size(), 1793);
    }

    #[test]
    fn test_private_key_size() {
        assert_eq!(FalconPrivateKey::size(), 2305);
    }

    #[test]
    fn test_signature_max_size() {
        assert_eq!(FalconSignature::max_size(), 1577);
    }

    #[test]
    fn test_invalid_key_size() {
        let result = FalconPublicKey::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_falcon_keygen_deterministic() {
        let seed = [42u8; 32];

        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();

        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_falcon_keygen_different_seeds() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let (pk1, _) = generate_keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = generate_keypair_from_seed(&seed2).unwrap();

        assert_ne!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_falcon_sign_verify() {
        let seed = [123u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();

        let message = b"Hello, post-quantum world!";
        let signature = sign(message, &sk).unwrap();

        assert!(verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_falcon_verify_wrong_message() {
        let seed = [99u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();

        let message = b"Original message";
        let signature = sign(message, &sk).unwrap();

        let wrong_message = b"Different message";
        assert!(verify(wrong_message, &signature, &pk).is_err());
    }

    #[test]
    fn test_falcon_verify_wrong_key() {
        let seed1 = [11u8; 32];
        let seed2 = [22u8; 32];

        let (_, sk1) = generate_keypair_from_seed(&seed1).unwrap();
        let (pk2, _) = generate_keypair_from_seed(&seed2).unwrap();

        let message = b"Test message";
        let signature = sign(message, &sk1).unwrap();

        assert!(verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_falcon_deterministic_sign() {
        let seed = [77u8; 32];
        let (pk, sk) = generate_keypair_from_seed(&seed).unwrap();
        let message = b"deterministic test";
        let nonce = [88u8; 32];

        let sig1 = sign_deterministic(message, &sk, &nonce).unwrap();
        let sig2 = sign_deterministic(message, &sk, &nonce).unwrap();

        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
        assert!(verify(message, &sig1, &pk).is_ok());
    }
}

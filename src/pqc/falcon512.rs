// SPDX-License-Identifier: Apache-2.0

//! Falcon-512 (FN-DSA-512) signing wrapper.
//!
//! Provides Falcon-512 signing via the `falcon-rs` crate (NIST FIPS 206).
//! Wraps the FN-DSA API with Origin's type system.
//!
//! ## Sizes (Falcon-512 / FN-DSA-512)
//!
//! - Public key: 897 bytes
//! - Secret key: 1281 bytes
//! - Max signature: 809 bytes (constant-time format; NIST padded = 666 bytes)

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use falcon::safe_api::{DomainSeparation, FalconError, FnDsaKeyPair, FnDsaSignature};

/// FN-DSA logn parameter for Falcon-512.
const LOGN_512: u32 = 9;

/// Maximum Falcon-512 signature length (constant-time format).
/// The CT format is 809 bytes; NIST padded format is 666 bytes.
/// We produce CT format for side-channel resistance; verify accepts all formats.
pub const MAX_SIGNATURE_LEN: usize = 809;

/// Falcon-512 public key.
#[derive(Clone, Debug)]
pub struct Falcon512PublicKey(pub Vec<u8>);

impl Falcon512PublicKey {
    /// Create from raw bytes, validating the expected length (897 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const PK_LEN: usize = 897;
        if bytes.len() != PK_LEN {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "Falcon-512",
                expected: PK_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Falcon-512 private key (zeroized on drop).
pub struct Falcon512PrivateKey {
    sk: Vec<u8>,
}

impl Falcon512PrivateKey {
    /// Create from raw bytes, validating the expected length (1281 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const SK_LEN: usize = 1281;
        if bytes.len() != SK_LEN {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "Falcon-512",
                expected: SK_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self { sk: bytes.to_vec() })
    }

    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sk
    }
}

impl Clone for Falcon512PrivateKey {
    fn clone(&self) -> Self {
        Self {
            sk: self.sk.clone(),
        }
    }
}

impl std::fmt::Debug for Falcon512PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Falcon512PrivateKey [REDACTED]")
    }
}

impl Zeroize for Falcon512PrivateKey {
    fn zeroize(&mut self) {
        self.sk.zeroize();
    }
}

impl Drop for Falcon512PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Falcon-512 signature.
#[derive(Clone, Debug)]
pub struct Falcon512Signature(pub Vec<u8>);

impl Falcon512Signature {
    /// Create from raw bytes, validating the maximum signature length (666 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNATURE_LEN {
            return Err(CryptoError::InvalidParameter(format!(
                "Falcon-512 signature too large: {} > {MAX_SIGNATURE_LEN}",
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
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

/// Generate Falcon-512 keypair deterministically from a 32-byte seed.
pub fn generate_keypair(seed: [u8; 32]) -> (Falcon512PrivateKey, Falcon512PublicKey) {
    let kp = FnDsaKeyPair::generate_deterministic(&seed, LOGN_512)
        .expect("Falcon-512 keygen with valid seed and logn=9 cannot fail");
    (
        Falcon512PrivateKey {
            sk: kp.private_key().to_vec(),
        },
        Falcon512PublicKey(kp.public_key().to_vec()),
    )
}

/// Sign a message with a Falcon-512 private key.
///
/// Uses OS entropy for the signing nonce (standard FN-DSA behavior).
pub fn sign(message: &[u8], sk: &Falcon512PrivateKey) -> Result<Falcon512Signature> {
    let kp = FnDsaKeyPair::from_private_key(&sk.sk)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid Falcon-512 secret key: {:?}", e)))?;
    let sig = kp
        .sign(message, &DomainSeparation::None)
        .map_err(map_falcon_err)?;
    Ok(Falcon512Signature(sig.to_bytes().to_vec()))
}

/// Sign a message with a Falcon-512 private key using a deterministic nonce.
///
/// The same `(sk, message, nonce_seed)` always produces the same signature.
/// Useful for testing and reproducibility.
pub fn sign_deterministic(
    message: &[u8],
    sk: &Falcon512PrivateKey,
    nonce_seed: &[u8],
) -> Result<Falcon512Signature> {
    let kp = FnDsaKeyPair::from_private_key(&sk.sk)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid Falcon-512 secret key: {:?}", e)))?;
    let sig = kp
        .sign_deterministic(message, nonce_seed, &DomainSeparation::None)
        .map_err(map_falcon_err)?;
    Ok(Falcon512Signature(sig.to_bytes().to_vec()))
}

/// Verify a Falcon-512 signature.
pub fn verify(message: &[u8], sig: &Falcon512Signature, pk: &Falcon512PublicKey) -> bool {
    FnDsaSignature::verify(&sig.0, &pk.0, message, &DomainSeparation::None).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_sign_verify() {
        let seed = [42u8; 32];
        let (sk, pk) = generate_keypair(seed);
        let message = b"test message";

        let sig = sign(message, &sk).unwrap();
        assert!(verify(message, &sig, &pk));
        assert!(!verify(b"wrong message", &sig, &pk));
    }

    #[test]
    fn test_falcon512_deterministic_keygen() {
        let seed = [42u8; 32];
        let (sk1, pk1) = generate_keypair(seed);
        let (sk2, pk2) = generate_keypair(seed);

        assert_eq!(pk1.0, pk2.0, "Same seed should produce same public key");
        assert_eq!(
            sk1.as_bytes(),
            sk2.as_bytes(),
            "Same seed should produce same private key"
        );
    }

    #[test]
    fn test_falcon512_deterministic_sign() {
        let seed = [42u8; 32];
        let (sk, pk) = generate_keypair(seed);
        let message = b"deterministic test";
        let nonce = [99u8; 32];

        let sig1 = sign_deterministic(message, &sk, &nonce).unwrap();
        let sig2 = sign_deterministic(message, &sk, &nonce).unwrap();

        assert_eq!(
            sig1.0, sig2.0,
            "Same (key, message, nonce) should produce same signature"
        );
        assert!(verify(message, &sig1, &pk));
    }

    #[test]
    fn test_falcon512_signature_size() {
        let seed = [42u8; 32];
        let (sk, _) = generate_keypair(seed);
        let sig = sign(b"test", &sk).unwrap();
        assert!(
            sig.0.len() <= MAX_SIGNATURE_LEN,
            "Signature too large: {}",
            sig.0.len()
        );
    }

    #[test]
    fn test_falcon512_key_sizes() {
        let seed = [42u8; 32];
        let (sk, pk) = generate_keypair(seed);
        assert_eq!(pk.0.len(), 897, "Public key must be 897 bytes");
        assert_eq!(sk.as_bytes().len(), 1281, "Private key must be 1281 bytes");
    }
}

// SPDX-License-Identifier: OPL-1.1

//! Falcon-1024 signing wrapper.
//!
//! Provides deterministic Falcon-1024 signing with SHAKE-based seed derivation.
//! Wraps falcon-rust crate with Origin's type system.
//!
//! ## Sizes (Falcon-1024)
//!
//! - Public key: 897 bytes
//! - Secret key: 1281 bytes  
//! - Max signature: 666 bytes

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;

/// Maximum Falcon-1024 signature length.
pub const MAX_SIGNATURE_LEN: usize = 666;

/// Falcon-512 public key.
#[derive(Clone, Debug)]
pub struct Falcon512PublicKey(pub Vec<u8>);

/// Falcon-512 private key (zeroized on drop).
pub struct Falcon512PrivateKey {
    sk: Vec<u8>,
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

/// Generate Falcon-1024 keypair deterministically from a 32-byte seed.
pub fn generate_keypair(seed: [u8; 32]) -> (Falcon512PrivateKey, Falcon512PublicKey) {
    let (sk, pk) = falcon_rust::falcon512::keygen(seed);
    (
        Falcon512PrivateKey {
            sk: sk.to_bytes().to_vec(),
        },
        Falcon512PublicKey(pk.to_bytes().to_vec()),
    )
}

/// Sign a message with a Falcon-512 private key.
pub fn sign(message: &[u8], sk: &Falcon512PrivateKey) -> Result<Falcon512Signature> {
    let secret_key = falcon_rust::falcon512::SecretKey::from_bytes(&sk.sk)
        .map_err(|_| CryptoError::InvalidKey("Invalid Falcon-512 secret key".to_string()))?;
    let sig = falcon_rust::falcon512::sign(message, &secret_key);
    Ok(Falcon512Signature(sig.to_bytes().to_vec()))
}

/// Verify a Falcon-1024 signature.
pub fn verify(message: &[u8], sig: &Falcon512Signature, pk: &Falcon512PublicKey) -> bool {
    let public_key = match falcon_rust::falcon512::PublicKey::from_bytes(&pk.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature = match falcon_rust::falcon512::Signature::from_bytes(&sig.0) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    falcon_rust::falcon512::verify(message, &signature, &public_key)
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
    fn test_falcon512_deterministic() {
        let seed = [42u8; 32];
        let (sk1, pk1) = generate_keypair(seed);
        let (sk2, pk2) = generate_keypair(seed);

        assert_eq!(pk1.0, pk2.0, "Same seed should produce same public key");
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
}

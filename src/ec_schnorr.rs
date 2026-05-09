// SPDX-License-Identifier: OPL-1.1

//! EC-Schnorr proof system over secp256k1 (k256 crate).
//!
//! Provides zero-knowledge proofs of knowledge of a discrete logarithm
//! using the Schnorr identification protocol with Fiat-Shamir heuristic.

use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::{Choice, ConstantTimeEq};

use crate::error::{CryptoError, Result};

/// An EC-Schnorr proof of knowledge of a discrete logarithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcSchnorrProof {
    /// Commitment point R = r*G (compressed SEC1 encoding, 33 bytes)
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    /// Response scalar s = r + e*x (32 bytes, big-endian)
    #[serde(with = "serde_bytes")]
    pub response: Vec<u8>,
}

/// Errors specific to EC-Schnorr operations.
#[derive(Debug, thiserror::Error)]
pub enum SchnorrError {
    #[error("Invalid commitment point: {0}")]
    InvalidCommitment(String),
    #[error("Invalid response scalar: {0}")]
    InvalidResponse(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("Random number generation failed")]
    RngFailed,
}

impl From<SchnorrError> for CryptoError {
    fn from(e: SchnorrError) -> Self {
        CryptoError::InvalidParameter(e.to_string())
    }
}

fn ct_option_to_option<T>(ct: subtle::CtOption<T>) -> Option<T> {
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// Create an EC-Schnorr proof of knowledge of the discrete log of `public_key`.
pub fn prove(
    secret_key: &[u8; 32],
    public_key: &[u8],
    message: &[u8],
) -> Result<EcSchnorrProof> {
    let x = ct_option_to_option(Scalar::from_repr((*secret_key).into()))
        .ok_or_else(|| CryptoError::InvalidParameter("Invalid secret key scalar".into()))?;

    // Generate random nonce r
    let r = {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        ct_option_to_option(Scalar::from_repr(buf.into()))
            .ok_or(SchnorrError::RngFailed)?
    };

    // R = r*G
    let r_point = ProjectivePoint::GENERATOR * r;
    let r_compressed = r_point.to_encoded_point(true);

    // e = H(R || P || message)
    let challenge = compute_challenge(r_compressed.as_bytes(), public_key, message);

    // s = r + e*x  (mod n)
    let s = r + challenge * x;

    Ok(EcSchnorrProof {
        commitment: r_compressed.as_bytes().to_vec(),
        response: s.to_bytes().to_vec(),
    })
}

/// Verify an EC-Schnorr proof.
pub fn verify(proof: &EcSchnorrProof, public_key: &[u8], message: &[u8]) -> Result<bool> {
    // Parse commitment point R
    let r_encoded = k256::EncodedPoint::from_bytes(&proof.commitment)
        .map_err(|e| SchnorrError::InvalidCommitment(e.to_string()))?;
    let r_affine = ct_option_to_option(AffinePoint::from_encoded_point(&r_encoded))
        .ok_or_else(|| SchnorrError::InvalidCommitment("Identity point".into()))?;

    // Parse response scalar s
    let s_bytes: [u8; 32] = proof
        .response
        .as_slice()
        .try_into()
        .map_err(|_| SchnorrError::InvalidResponse("Wrong length".into()))?;
    let s = ct_option_to_option(Scalar::from_repr(s_bytes.into()))
        .ok_or_else(|| SchnorrError::InvalidResponse("Not a valid scalar".into()))?;

    // Parse public key P
    let p_encoded = k256::EncodedPoint::from_bytes(public_key)
        .map_err(|e| SchnorrError::InvalidPublicKey(e.to_string()))?;
    let p_affine = ct_option_to_option(AffinePoint::from_encoded_point(&p_encoded))
        .ok_or_else(|| SchnorrError::InvalidPublicKey("Identity point".into()))?;

    // Recompute challenge e = H(R || P || message)
    let challenge = compute_challenge(&proof.commitment, public_key, message);

    // Verify: s*G == R + e*P
    let s_g = ProjectivePoint::GENERATOR * s;
    let e_p = ProjectivePoint::from(p_affine) * challenge;
    let r_plus_ep = ProjectivePoint::from(r_affine) + e_p;

    let equal = s_g.ct_eq(&r_plus_ep);
    Ok(bool::from(equal))
}

/// Batch verify multiple EC-Schnorr proofs.
pub fn batch_verify(
    proofs: &[EcSchnorrProof],
    public_keys: &[Vec<u8>],
    messages: &[Vec<u8>],
) -> Result<bool> {
    if proofs.len() != public_keys.len() || proofs.len() != messages.len() {
        return Err(CryptoError::InvalidParameter(
            "Mismatched input lengths for batch verify".into(),
        ));
    }
    for i in 0..proofs.len() {
        if !verify(&proofs[i], &public_keys[i], &messages[i])? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Compute the Fiat-Shamir challenge: e = SHA3-256(R || P || message)
fn compute_challenge(commitment: &[u8], public_key: &[u8], message: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(b"ec-schnorr-challenge-v1");
    hasher.update(commitment);
    hasher.update(public_key);
    hasher.update(message);
    let hash: [u8; 32] = hasher.finalize().into();

    ct_option_to_option(Scalar::from_repr(hash.into())).unwrap_or_else(|| {
        let mut hasher2 = Sha3_256::new();
        hasher2.update(b"ec-schnorr-rehash");
        hasher2.update(&hash);
        let hash2: [u8; 32] = hasher2.finalize().into();
        ct_option_to_option(Scalar::from_repr(hash2.into()))
            .unwrap_or(Scalar::ONE)
    })
}

/// Generate a secp256k1 keypair from a 32-byte seed.
pub fn generate_keypair(seed: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let mut hasher = Sha3_256::new();
    hasher.update(b"ec-schnorr-keygen-v1");
    hasher.update(seed);
    let hash: [u8; 32] = hasher.finalize().into();

    let secret = ct_option_to_option(Scalar::from_repr(hash.into()))
        .unwrap_or(Scalar::ONE);

    let public = ProjectivePoint::GENERATOR * secret;
    let public_compressed = public.to_encoded_point(true);

    (
        secret.to_bytes().into(),
        public_compressed.as_bytes().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_verify_roundtrip() {
        let seed = [42u8; 32];
        let (sk_bytes, pk_bytes) = generate_keypair(&seed);
        let message = b"test message for EC-Schnorr";
        let proof = prove(&sk_bytes, &pk_bytes, message).unwrap();
        assert!(verify(&proof, &pk_bytes, message).unwrap());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let seed = [42u8; 32];
        let (sk_bytes, pk_bytes) = generate_keypair(&seed);
        let proof = prove(&sk_bytes, &pk_bytes, b"original message").unwrap();
        assert!(!verify(&proof, &pk_bytes, b"different message").unwrap());
    }

    #[test]
    fn test_verify_wrong_public_key_fails() {
        let (sk1, pk1) = generate_keypair(&[42u8; 32]);
        let (_, pk2) = generate_keypair(&[99u8; 32]);
        let proof = prove(&sk1, &pk1, b"test message").unwrap();
        assert!(!verify(&proof, &pk2, b"test message").unwrap());
    }

    #[test]
    fn test_deterministic_keypair() {
        let (sk1, pk1) = generate_keypair(&[7u8; 32]);
        let (sk2, pk2) = generate_keypair(&[7u8; 32]);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let (sk1, pk1) = generate_keypair(&[1u8; 32]);
        let (sk2, pk2) = generate_keypair(&[2u8; 32]);
        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_batch_verify_all_valid() {
        let mut proofs = Vec::new();
        let mut pks = Vec::new();
        let mut msgs = Vec::new();
        for i in 0..10u8 {
            let (sk, pk) = generate_keypair(&[i; 32]);
            let msg = format!("message {}", i).into_bytes();
            proofs.push(prove(&sk, &pk, &msg).unwrap());
            pks.push(pk);
            msgs.push(msg);
        }
        assert!(batch_verify(&proofs, &pks, &msgs).unwrap());
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let mut proofs = Vec::new();
        let mut pks = Vec::new();
        let mut msgs = Vec::new();
        for i in 0..3u8 {
            let (sk, pk) = generate_keypair(&[i; 32]);
            let msg = format!("message {}", i).into_bytes();
            proofs.push(prove(&sk, &pk, &msg).unwrap());
            pks.push(pk);
            msgs.push(msg);
        }
        let (sk, pk) = generate_keypair(&[99u8; 32]);
        proofs.push(prove(&sk, &pk, b"correct message").unwrap());
        pks.push(pk);
        msgs.push(b"wrong message".to_vec());
        assert!(!batch_verify(&proofs, &pks, &msgs).unwrap());
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let (sk, pk) = generate_keypair(&[42u8; 32]);
        let proof = prove(&sk, &pk, b"serialization test").unwrap();
        let json = serde_json::to_vec(&proof).unwrap();
        let deserialized: EcSchnorrProof = serde_json::from_slice(&json).unwrap();
        assert!(verify(&deserialized, &pk, b"serialization test").unwrap());
    }

    #[test]
    fn test_empty_message() {
        let (sk, pk) = generate_keypair(&[42u8; 32]);
        let proof = prove(&sk, &pk, b"").unwrap();
        assert!(verify(&proof, &pk, b"").unwrap());
    }

    #[test]
    fn test_large_message() {
        let (sk, pk) = generate_keypair(&[42u8; 32]);
        let message = vec![0xABu8; 1_000_000];
        let proof = prove(&sk, &pk, &message).unwrap();
        assert!(verify(&proof, &pk, &message).unwrap());
    }
}

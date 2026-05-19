// SPDX-License-Identifier: OPL-1.1

//! EC-Schnorr proof system over secp256k1 (k256 crate).
//!
//! Provides zero-knowledge proofs of knowledge of a discrete logarithm
//! using the Schnorr identification protocol with Fiat-Shamir heuristic.

use crate::error::{CryptoError, Result};
use crate::primitives::sha3::sha3_256;
use crate::internal::secp256k1::{AffinePoint, ProjectivePoint, Scalar, EncodedPoint};
use crate::internal::subtle::{ConstantTimeEq, CtOption, ct_option_to_option};
use rand::RngCore;

/// An EC-Schnorr proof of knowledge of a discrete logarithm.
#[derive(Debug, Clone)]
pub struct EcSchnorrProof {
    /// Commitment point R = r*G (compressed SEC1 encoding, 33 bytes)
    pub commitment: Vec<u8>,
    /// Response scalar s = r + e*x (32 bytes, big-endian)
    pub response: Vec<u8>,
}

/// Errors specific to EC-Schnorr operations.
#[derive(Debug)]
pub enum SchnorrError {
    InvalidCommitment(String),
    InvalidResponse(String),
    InvalidPublicKey(String),
    VerificationFailed,
    RngFailed,
}

impl std::fmt::Display for SchnorrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchnorrError::InvalidCommitment(msg) => write!(f, "Invalid commitment point: {msg}"),
            SchnorrError::InvalidResponse(msg) => write!(f, "Invalid response scalar: {msg}"),
            SchnorrError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {msg}"),
            SchnorrError::VerificationFailed => write!(f, "Proof verification failed"),
            SchnorrError::RngFailed => write!(f, "Random number generation failed"),
        }
    }
}

impl std::error::Error for SchnorrError {}

impl From<SchnorrError> for CryptoError {
    fn from(e: SchnorrError) -> Self {
        CryptoError::InvalidParameter(e.to_string())
    }
}

/// Create an EC-Schnorr proof of knowledge of the discrete log of `public_key`.
pub fn prove(
    secret_key: &[u8; 32],
    public_key: &[u8],
    message: &[u8],
) -> Result<EcSchnorrProof> {
    let x = ct_option_to_option(Scalar::from_repr(secret_key))
        .ok_or_else(|| CryptoError::InvalidParameter("Invalid secret key scalar".into()))?;

    // Generate random nonce r
    let r = {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        ct_option_to_option(Scalar::from_repr(&buf))
            .ok_or(SchnorrError::RngFailed)?
    };

    // R = r*G
    let r_point = ProjectivePoint::GENERATOR.mul(&r);
    let r_compressed = r_point.to_encoded_point(true);

    // e = H(R || P || message)
    let challenge = compute_challenge(r_compressed.as_bytes(), public_key, message);

    // s = r + e*x  (mod n)
    let ex = challenge.mul(&x);
    let s = r.add(&ex);

    Ok(EcSchnorrProof {
        commitment: r_compressed.as_bytes().to_vec(),
        response: s.to_bytes().to_vec(),
    })
}

/// Verify an EC-Schnorr proof.
pub fn verify(proof: &EcSchnorrProof, public_key: &[u8], message: &[u8]) -> Result<bool> {
    // Parse commitment point R
    let r_ctoption = EncodedPoint::from_bytes(&proof.commitment);
    if !bool::from(r_ctoption.is_some()) {
        return Err(SchnorrError::InvalidCommitment("Invalid encoding".into()).into());
    }
    let r_encoded = r_ctoption.unwrap();
    let r_affine = ct_option_to_option(AffinePoint::from_encoded_point(&r_encoded))
        .ok_or_else(|| SchnorrError::InvalidCommitment("Identity point".into()))?;

    // Parse response scalar s
    let s_bytes: [u8; 32] = proof
        .response
        .as_slice()
        .try_into()
        .map_err(|_| SchnorrError::InvalidResponse("Wrong length".into()))?;
    let s = ct_option_to_option(Scalar::from_repr(&s_bytes))
        .ok_or_else(|| SchnorrError::InvalidResponse("Not a valid scalar".into()))?;

    // Parse public key P
    let p_ctoption = EncodedPoint::from_bytes(public_key);
    if !bool::from(p_ctoption.is_some()) {
        return Err(SchnorrError::InvalidPublicKey("Invalid encoding".into()).into());
    }
    let p_encoded = p_ctoption.unwrap();
    let p_affine = ct_option_to_option(AffinePoint::from_encoded_point(&p_encoded))
        .ok_or_else(|| SchnorrError::InvalidPublicKey("Identity point".into()))?;

    // Recompute challenge e = H(R || P || message)
    let challenge = compute_challenge(&proof.commitment, public_key, message);

    // Verify: s*G == R + e*P
    let s_g = ProjectivePoint::GENERATOR.mul(&s);
    let p_projective = ProjectivePoint::from(p_affine);
    let e_p = p_projective.mul(&challenge);
    let r_projective = ProjectivePoint::from(r_affine);
    let r_plus_ep = r_projective.add(&e_p);

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
    // Build input: domain || commitment || public_key || message
    let mut input = Vec::with_capacity(23 + commitment.len() + public_key.len() + message.len());
    input.extend_from_slice(b"ec-schnorr-challenge-v1");
    input.extend_from_slice(commitment);
    input.extend_from_slice(public_key);
    input.extend_from_slice(message);
    let hash = sha3_256(&input);

    ct_option_to_option(Scalar::from_repr(&hash)).unwrap_or_else(|| {
        let mut rehash_input = Vec::with_capacity(22 + 32);
        rehash_input.extend_from_slice(b"ec-schnorr-rehash");
        rehash_input.extend_from_slice(&hash);
        let hash2 = sha3_256(&rehash_input);
        ct_option_to_option(Scalar::from_repr(&hash2))
            .unwrap_or(Scalar::ONE)
    })
}

/// Generate a secp256k1 keypair from a 32-byte seed.
pub fn generate_keypair(seed: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let mut input = Vec::with_capacity(22 + 32);
    input.extend_from_slice(b"ec-schnorr-keygen-v1");
    input.extend_from_slice(seed);
    let hash = sha3_256(&input);

    let secret = ct_option_to_option(Scalar::from_repr(&hash))
        .unwrap_or(Scalar::ONE);

    let public = ProjectivePoint::GENERATOR.mul(&secret);
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

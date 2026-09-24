// SPDX-License-Identifier: Apache-2.0

//! EC-Schnorr proof system over secp256k1 (k256 crate).
//!
//! Provides zero-knowledge proofs of knowledge of a discrete logarithm
//! using the Schnorr identification protocol with Fiat-Shamir heuristic.

use crate::error::{CryptoError, Result};
use crate::primitives::sha3::sha3_256;
use k256::{
    elliptic_curve::{
        ff::PrimeField,
        ops::Reduce,
        sec1::{FromSec1Point, ToSec1Point},
        CurveAffine,
    },
    AffinePoint, FieldBytes, ProjectivePoint, Scalar,
};
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
    /// The commitment point is malformed or not on the curve.
    InvalidCommitment(String),
    /// The response scalar is out of range.
    InvalidResponse(String),
    /// The public key is malformed or not on the curve.
    InvalidPublicKey(String),
    /// The signature failed to verify.
    VerificationFailed,
    /// The CSPRNG failed to produce randomness.
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
        match e {
            // Malformed proof components are bad input, not auth failures.
            SchnorrError::InvalidCommitment(msg) | SchnorrError::InvalidResponse(msg) => {
                CryptoError::InvalidParameter(msg)
            }
            SchnorrError::InvalidPublicKey(msg) => CryptoError::InvalidKey(msg),
            SchnorrError::VerificationFailed => CryptoError::AuthenticationFailed,
            SchnorrError::RngFailed => {
                CryptoError::Io(std::io::Error::other("Schnorr RNG failure"))
            }
        }
    }
}

fn scalar_from_repr(bytes: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_repr(FieldBytes::from(*bytes)).into_option()
}

/// Parse a SEC1-encoded point, rejecting malformed encodings and the
/// identity point. `err` selects the error variant for the field.
fn parse_non_identity_point(bytes: &[u8], err: fn(String) -> SchnorrError) -> Result<AffinePoint> {
    let point = AffinePoint::from_sec1_bytes(bytes).map_err(|_| err("Invalid encoding".into()))?;
    if bool::from(point.is_identity()) {
        return Err(err("Identity point".into()).into());
    }
    Ok(point)
}

/// Create an EC-Schnorr proof of knowledge of the discrete log of the
/// public key corresponding to `secret_key`.
///
/// The public key is derived internally — a caller-supplied pk could be
/// mismatched, producing a proof that can never verify.
// CT note (Phase 12.1): scalar mul goes through k256's primeorder
// implementation (fiat-crypto field arithmetic + complete formulas), which
// is constant-time by construction. The `Scalar::from_repr` rejection on a
// uniform nonce is fine (failure is ~2^-128 and reveals nothing about the key).
pub fn prove(secret_key: &[u8; 32], message: &[u8]) -> Result<EcSchnorrProof> {
    let x = scalar_from_repr(secret_key)
        .ok_or_else(|| CryptoError::InvalidKey("Invalid secret key scalar".into()))?;

    // Generate random nonce r
    let r = {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        scalar_from_repr(&buf).ok_or(SchnorrError::RngFailed)?
    };

    // R = r*G, P = x*G
    let r_point = ProjectivePoint::GENERATOR * r;
    let r_compressed = r_point.to_affine().to_sec1_point(true);
    let public_key = (ProjectivePoint::GENERATOR * x)
        .to_affine()
        .to_sec1_point(true);

    // e = H(R || P || message)
    let challenge = compute_challenge(r_compressed.as_bytes(), public_key.as_bytes(), message);

    // s = r + e*x  (mod n)
    let s = r + challenge * x;

    Ok(EcSchnorrProof {
        commitment: r_compressed.as_bytes().to_vec(),
        response: s.to_bytes().as_slice().to_vec(),
    })
}

/// Verify an EC-Schnorr proof.
pub fn verify(proof: &EcSchnorrProof, public_key: &[u8], message: &[u8]) -> Result<bool> {
    // Parse commitment point R
    let r_affine = parse_non_identity_point(&proof.commitment, SchnorrError::InvalidCommitment)?;

    // Parse response scalar s
    let s_bytes: [u8; 32] = proof
        .response
        .as_slice()
        .try_into()
        .map_err(|_| SchnorrError::InvalidResponse("Wrong length".into()))?;
    let s = scalar_from_repr(&s_bytes)
        .ok_or_else(|| SchnorrError::InvalidResponse("Not a valid scalar".into()))?;

    // Parse public key P
    let p_affine = parse_non_identity_point(public_key, SchnorrError::InvalidPublicKey)?;

    // Recompute challenge e = H(R || P || message)
    let challenge = compute_challenge(&proof.commitment, public_key, message);

    // Verify: s*G == R + e*P
    let s_g = ProjectivePoint::GENERATOR * s;
    let e_p = ProjectivePoint::from(p_affine) * challenge;
    let r_plus_ep = ProjectivePoint::from(r_affine) + e_p;

    Ok(s_g == r_plus_ep)
}

/// Batch verify multiple EC-Schnorr proofs.
pub fn batch_verify(
    proofs: &[EcSchnorrProof],
    public_keys: &[impl AsRef<[u8]>],
    messages: &[impl AsRef<[u8]>],
) -> Result<bool> {
    if proofs.len() != public_keys.len() || proofs.len() != messages.len() {
        return Err(CryptoError::InvalidParameter(
            "Mismatched input lengths for batch verify".into(),
        ));
    }
    for (proof, (pk, msg)) in proofs.iter().zip(public_keys.iter().zip(messages.iter())) {
        if !verify(proof, pk.as_ref(), msg.as_ref())? {
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

    // Reduce the digest mod n deterministically. This avoids the earlier
    // bug where digests >= n fell back to Scalar::ONE, which collapsed
    // distinct messages onto the same challenge and let verify accept
    // tampered messages.
    Scalar::reduce(&FieldBytes::from(hash))
}

/// Generate a secp256k1 keypair from a 32-byte seed.
pub fn generate_keypair(seed: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let mut input = Vec::with_capacity(23 + 32);
    input.extend_from_slice(b"ec-schnorr-keygen-v2");
    input.extend_from_slice(seed);
    let prefix_len = input.len();
    let mut counter = 0u32;

    let secret = loop {
        let hash = sha3_256(&input);
        if let Some(s) = scalar_from_repr(&hash) {
            break s;
        }
        counter += 1;
        input.truncate(prefix_len);
        input.extend_from_slice(&counter.to_le_bytes());
    };

    let public = ProjectivePoint::GENERATOR * secret;
    let public_compressed = public.to_affine().to_sec1_point(true);

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
        let proof = prove(&sk_bytes, message).unwrap();
        assert!(verify(&proof, &pk_bytes, message).unwrap());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let seed = [42u8; 32];
        let (sk_bytes, pk_bytes) = generate_keypair(&seed);
        let proof = prove(&sk_bytes, b"original message").unwrap();
        assert!(!verify(&proof, &pk_bytes, b"different message").unwrap());
    }

    #[test]
    fn test_verify_wrong_public_key_fails() {
        let (sk1, pk1) = generate_keypair(&[42u8; 32]);
        let (_, pk2) = generate_keypair(&[99u8; 32]);
        let proof = prove(&sk1, b"test message").unwrap();
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
            proofs.push(prove(&sk, &msg).unwrap());
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
            proofs.push(prove(&sk, &msg).unwrap());
            pks.push(pk);
            msgs.push(msg);
        }
        let (sk, pk) = generate_keypair(&[99u8; 32]);
        proofs.push(prove(&sk, b"correct message").unwrap());
        pks.push(pk);
        msgs.push(b"wrong message".to_vec());
        assert!(!batch_verify(&proofs, &pks, &msgs).unwrap());
    }

    #[test]
    fn test_empty_message() {
        let seed = [42u8; 32];
        let (sk_bytes, pk_bytes) = generate_keypair(&seed);
        let proof = prove(&sk_bytes, b"").unwrap();
        assert!(verify(&proof, &pk_bytes, b"").unwrap());
    }

    #[test]
    fn test_large_message() {
        let seed = [42u8; 32];
        let (sk_bytes, pk_bytes) = generate_keypair(&seed);
        let message = vec![0xABu8; 1_000_000];
        let proof = prove(&sk_bytes, &message).unwrap();
        assert!(verify(&proof, &pk_bytes, &message).unwrap());
    }
}

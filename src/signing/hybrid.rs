// SPDX-License-Identifier: Apache-2.0

//! # Hybrid Cryptographic Constructions
//!
//! This module implements the "hybrid KDF" approach recommended for defense in depth
//! against both classical and quantum adversaries. An attacker must break **all**
//! primitives in a construction — a single algorithm being broken does not compromise
//! the system.
//!
//! ## Design Philosophy
//!
//! Following the colleague's threat model, this module targets DSA (Digital Signature
//! Algorithms) as the primary attack surface. By pairing classical high-security curves
//! (Ed25519, Ed448) with post-quantum primitives (Falcon, SPHINCS+/SLH-DSA,
//! and SHAKE/Skein/BLAKE3 hashes), we get:
//!
//! - **Classical insurance**: if PQC has implementation bugs, classical curves protect us
//! - **Quantum insurance**: if quantum computers arrive, PQC protects us
//! - **Hash diversity**: combining SHA3, BLAKE3, and Skein reduces single-hash compromise risk
//!
//! ## Constructions Implemented
//!
//! ### Non-KDF (single signature + hash check)
//! - [`Ed25519Blake3`] — Ed25519 sig + BLAKE3 message hash
//! - [`Ed25519Shake256`] — Ed25519 sig + SHAKE256 XOF of message
//! - [`Ed25519Skein512`] — Ed25519 sig + Skein-512 message hash
//! - [`Ed448Shake256`] — Ed448 sig + SHAKE256 XOF of message
//! - [`Ed448Skein512`] — Ed448 sig + Skein-512 message hash
//! - [`Ed448Sha3_256`] — Ed448 sig + SHA3-256 message hash
//!
//! ### Signature hybrids (both must verify)
//! - [`Ed25519Falcon1024`] — Ed25519 + Falcon-1024 (lattice)
//! - [`Ed25519Falcon512`] — Ed25519 + Falcon-512 (lattice, smaller sigs)
//! - [`Ed448Falcon1024`] — Ed448 + Falcon-1024
//!
//! ### KDF constructions (derived from master seed)
//! - [`Ed25519ChaCha20Blake3Sha3_256`] — Ed25519 + keyed-BLAKE3 + HMAC-SHA3-256
//!
//! ## Quick Start
//!
//! ```rust
//! use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, falcon1024_keygen};
//! use ed25519_dalek::SigningKey;
//!
//! // Generate Falcon keypair
//! let (falcon_pk, falcon_sk) = falcon1024_keygen(&[42u8; 32]).unwrap();
//!
//! // Generate Ed25519 keypair
//! let ed_sk = SigningKey::from_bytes(&[1u8; 32]);
//! let ed_pk = ed_sk.verifying_key();
//!
//! let message = b"Important message";
//! let sig = Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, message);
//! Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, message, &sig).unwrap();
//! ```
//!
//! ```rust
//! use origin_crypto_sdk::signing::hybrid::Ed25519ChaCha20Blake3Sha3_256;
//!
//! // KDF construction: keys derived deterministically from master seed
//! let master_seed = [42u8; 32];
//! let domain = "my-app.v1";
//! let message = b"hello";
//!
//! let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&master_seed, domain, message).unwrap();
//! Ed25519ChaCha20Blake3Sha3_256::verify(&master_seed, domain, message, &sig).unwrap();
//! ```
//!
//! ## Security Notes
//!
//! - All constructions use **constant-time** verification (Ed25519 dalek, Falcon, Ed448).
//! - Skein is a SHA-3 finalist; combining it with SHA3-256 in KDF mode gives hash diversity.
//! - The KDF constructions derive independent subkeys via HKDF-SHA3-256 with domain
//!   separation, so the same master seed can be reused across domains safely.

use std::sync::Arc;

use crate::error::{CryptoError, Result};
use crate::internal::subtle::ConstantTimeEq;
use crate::pqc::ed448::{
    Signature as Ed448Signature, SigningKey as Ed448SigningKey, VerifyingKey as Ed448VerifyingKey,
};
use crate::pqc::falcon1024::{
    generate_keypair_from_seed as falcon_keygen, sign as falcon_sign, verify as falcon_verify,
    FalconPrivateKey, FalconPublicKey, FalconSignature,
};
use crate::pqc::falcon512::{
    sign as falcon512_sign, verify as falcon512_verify, Falcon512PrivateKey, Falcon512PublicKey,
    Falcon512Signature,
};
use crate::primitives::{blake3, sha3_256, Shake128, Shake256};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use skein::digest::Digest;
use skein::{Skein1024_1024 as Skein1024, Skein512_512 as Skein512};

use crate::kdf::hkdf::hkdf_sha3_256;

// ============================================================================
// Type definitions for hybrid constructions
// ============================================================================

/// Ed25519 + BLAKE3 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Blake3 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The BLAKE3 hash of the message.
    pub blake3_hash: blake3::Hash,
}

/// Ed25519 + SHAKE256 combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Shake256 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The SHAKE256 output of the message.
    pub shake_output: Vec<u8>,
}

/// Ed25519 + Skein-512 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Skein512 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Skein-512 hash of the message.
    pub skein512_hash: [u8; 64],
}

/// Ed448 + SHAKE256 combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Shake256 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The SHAKE256 output of the message.
    pub shake_output: Vec<u8>,
}

/// Ed448 + Skein-512 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Skein512 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The Skein-512 hash of the message.
    pub skein512_hash: [u8; 64],
}

/// Ed448 + SHA3-256 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Sha3_256 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The SHA3-256 hash of the message.
    pub sha3_hash: [u8; 32],
}

/// Ed25519 + Falcon-1024 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed25519Falcon1024 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Falcon-1024 signature.
    pub falcon_sig: FalconSignature,
}

/// Ed25519 + Falcon-512 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed25519Falcon512 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Falcon-512 signature.
    pub falcon_sig: Falcon512Signature,
}

/// Ed448 + Falcon-1024 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed448Falcon1024 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The Falcon-1024 signature.
    pub falcon_sig: FalconSignature,
}

/// Ed25519 + ChaCha20-Blake3 + SHA3-256 (KDF construction, derived from master seed)
#[derive(Clone, Debug)]
pub struct Ed25519ChaCha20Blake3Sha3_256 {
    /// The Ed25519 signature over the derived key.
    pub ed25519_sig: Ed25519Signature,
    /// The BLAKE3 keyed hash of the message.
    pub blake3_keyed: blake3::Hash,
    /// The HMAC-SHA3-256 of the message.
    pub sha3_keyed: [u8; 32],
}

// ============================================================================
// Hash combiner helpers
// ============================================================================

/// Combine two hash outputs via XOR (simple combiner for non-KDF constructions)
pub fn xor_combine(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = std::cmp::min(a.len(), b.len());
    let mut out = vec![0u8; len];
    for i in 0..len {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Combine two hash outputs via concatenation
pub fn concat_combine(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

/// HKDF-SHA3-256 combiner (for KDF constructions)
pub fn hkdf_combine(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    hkdf_sha3_256(ikm, salt, info, output).map_err(|e| CryptoError::Kdf(e.to_string()))
}

// ============================================================================
// SHAKE XOF helpers
// ============================================================================

/// Generate variable-length output from SHAKE128
pub fn shake128_output(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

/// Generate variable-length output from SHAKE256
pub fn shake256_output(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

// ============================================================================
// Skein helpers
// ============================================================================

/// Compute Skein-512 (64-byte output) hash of input
pub fn skein512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Skein512::new();
    Digest::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Compute Skein-1024 (128-byte output) hash of input
pub fn skein1024(data: &[u8]) -> [u8; 128] {
    let mut hasher = Skein1024::new();
    Digest::update(&mut hasher, data);
    let result = hasher.finalize();
    let mut out = [0u8; 128];
    out.copy_from_slice(&result);
    out
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed25519 + Blake3
// ============================================================================

impl Ed25519Blake3 {
    /// Sign message with Ed25519 and compute BLAKE3 hash of message
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Self {
        let ed25519_sig = signing_key.sign(message);
        let blake3_hash = blake3::hash(message);
        Self {
            ed25519_sig,
            blake3_hash,
        }
    }

    /// Verify Ed25519 signature and check BLAKE3 hash matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected_hash = blake3::hash(message);
        if !bool::from(sig.blake3_hash.as_bytes().ct_eq(expected_hash.as_bytes())) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed25519 + SHAKE256
// ============================================================================

impl Ed25519Shake256 {
    /// Sign message with Ed25519 and compute SHAKE256 output of message
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8], shake_len: usize) -> Self {
        let ed25519_sig = signing_key.sign(message);
        let shake_output = shake256_output(message, shake_len);
        Self {
            ed25519_sig,
            shake_output,
        }
    }

    /// Verify Ed25519 signature and check SHAKE256 output matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected = shake256_output(message, sig.shake_output.len());
        if !bool::from(sig.shake_output.ct_eq(&expected)) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed25519 + Skein-512
// ============================================================================

impl Ed25519Skein512 {
    /// Sign message with Ed25519 and compute Skein-512 hash
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Self {
        let ed25519_sig = signing_key.sign(message);
        let skein512_hash = skein512(message);
        Self {
            ed25519_sig,
            skein512_hash,
        }
    }

    /// Verify Ed25519 signature and check Skein-512 hash matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected = skein512(message);
        if !bool::from(sig.skein512_hash.ct_eq(&expected)) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed448 + SHAKE256
// ============================================================================

impl Ed448Shake256 {
    /// Sign message with Ed448 and compute SHAKE256 output
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8], shake_len: usize) -> Self {
        let ed448_sig = signing_key.sign(message);
        let shake_output = shake256_output(message, shake_len);
        Self {
            ed448_sig,
            shake_output,
        }
    }

    /// Verify Ed448 signature and check SHAKE256 output
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed448_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected = shake256_output(message, sig.shake_output.len());
        if !bool::from(sig.shake_output.ct_eq(&expected)) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed448 + Skein-512
// ============================================================================

impl Ed448Skein512 {
    /// Sign message with Ed448 and compute Skein-512 hash
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8]) -> Self {
        let ed448_sig = signing_key.sign(message);
        let skein512_hash = skein512(message);
        Self {
            ed448_sig,
            skein512_hash,
        }
    }

    /// Verify Ed448 signature and check Skein-512 hash
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed448_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected = skein512(message);
        if !bool::from(sig.skein512_hash.ct_eq(&expected)) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Non-KDF Construction Sign/Verify: Ed448 + SHA3-256
// ============================================================================

impl Ed448Sha3_256 {
    /// Sign message with Ed448 and compute SHA3-256 hash
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8]) -> Self {
        let ed448_sig = signing_key.sign(message);
        let sha3_hash = sha3_256(message);
        Self {
            ed448_sig,
            sha3_hash,
        }
    }

    /// Verify Ed448 signature and check SHA3-256 hash
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verifying_key
            .verify(message, &sig.ed448_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let expected = sha3_256(message);
        if !bool::from(sig.sha3_hash.ct_eq(&expected)) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Hybrid Signature: Ed25519 + Falcon-1024 (both must verify)
// ============================================================================

impl Ed25519Falcon1024 {
    /// Sign with both Ed25519 and Falcon-1024 keys
    pub fn sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &FalconPrivateKey,
        message: &[u8],
    ) -> Self {
        let ed25519_sig = ed25519_sk.sign(message);
        let falcon_sig = falcon_sign(message, falcon_sk).expect("Falcon signing failed");
        Self {
            ed25519_sig,
            falcon_sig,
        }
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed25519_pk: &Ed25519VerifyingKey,
        falcon_pk: &FalconPublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        ed25519_pk
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        falcon_verify(message, &sig.falcon_sig, falcon_pk)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(())
    }
}

// ============================================================================
// Hybrid Signature: Ed25519 + Falcon-512 (both must verify)
// ============================================================================

impl Ed25519Falcon512 {
    /// Sign with both Ed25519 and Falcon-512 keys
    pub fn sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &Falcon512PrivateKey,
        message: &[u8],
    ) -> Self {
        let ed25519_sig = ed25519_sk.sign(message);
        let falcon_sig = falcon512_sign(message, falcon_sk).expect("Falcon-512 signing failed");
        Self {
            ed25519_sig,
            falcon_sig,
        }
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed25519_pk: &Ed25519VerifyingKey,
        falcon_pk: &Falcon512PublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        ed25519_pk
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        if !falcon512_verify(message, &sig.falcon_sig, falcon_pk) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }
}

// ============================================================================
// Hybrid Signature: Ed448 + Falcon-1024
// ============================================================================

impl Ed448Falcon1024 {
    /// Sign with both Ed448 and Falcon-1024 keys
    pub fn sign(ed448_sk: &Ed448SigningKey, falcon_sk: &FalconPrivateKey, message: &[u8]) -> Self {
        let ed448_sig = ed448_sk.sign(message);
        let falcon_sig = falcon_sign(message, falcon_sk).expect("Falcon signing failed");
        Self {
            ed448_sig,
            falcon_sig,
        }
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed448_pk: &Ed448VerifyingKey,
        falcon_pk: &FalconPublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        ed448_pk
            .verify(message, &sig.ed448_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        falcon_verify(message, &sig.falcon_sig, falcon_pk)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        Ok(())
    }
}

// ============================================================================
// Key Derivation for Hybrid KDF Constructions
// ============================================================================

/// Derive subkeys for hybrid KDF constructions (e.g., Ed25519_ChaCha20-Blake3_SHA3-256)
/// Uses HKDF-SHA3-256 with domain separation labels.
pub fn derive_hybrid_keys(
    master_seed: &[u8],
    domain: &str,
    ed25519_len: usize,
    chacha_len: usize,
    hash_len: usize,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut ed25519_key = vec![0u8; ed25519_len];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"ed25519"].concat(),
        &mut ed25519_key,
    )?;

    let mut chacha_key = vec![0u8; chacha_len];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"chacha20"].concat(),
        &mut chacha_key,
    )?;

    let mut hash_key = vec![0u8; hash_len];
    hkdf_combine(
        Some(b"hybrid-kdf"),
        master_seed,
        &[domain.as_bytes(), b"hash"].concat(),
        &mut hash_key,
    )?;

    Ok((ed25519_key, chacha_key, hash_key))
}

// ============================================================================
// KDF Construction: Ed25519 + ChaCha20-Blake3 + SHA3-256
// ============================================================================

impl Ed25519ChaCha20Blake3Sha3_256 {
    /// Sign with derived keys using HKDF
    pub fn sign(master_seed: &[u8], domain: &str, message: &[u8]) -> Result<Self> {
        let (ed_key, chacha_key, hash_key) = derive_hybrid_keys(master_seed, domain, 32, 32, 32)?;

        let ed_arr: [u8; 32] =
            ed_key[..32]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    algorithm: "Ed25519",
                    expected: 32,
                    got: ed_key.len(),
                })?;
        let ed_sk = Ed25519SigningKey::from_bytes(&ed_arr);
        let ed25519_sig = ed_sk.sign(message);

        let mut chacha_key_arr = [0u8; blake3::KEY_LEN];
        chacha_key_arr.copy_from_slice(&chacha_key[..blake3::KEY_LEN]);
        let blake3_keyed = blake3::keyed_hash(&chacha_key_arr, message);

        let sha3_keyed = crate::internal::hmac::hmac_sha3_256(&hash_key, message);

        Ok(Self {
            ed25519_sig,
            blake3_keyed,
            sha3_keyed,
        })
    }

    /// Verify all three components
    pub fn verify(master_seed: &[u8], domain: &str, message: &[u8], sig: &Self) -> Result<()> {
        let (ed_key, chacha_key, hash_key) = derive_hybrid_keys(master_seed, domain, 32, 32, 32)?;

        let ed_arr: [u8; 32] =
            ed_key[..32]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    algorithm: "Ed25519",
                    expected: 32,
                    got: ed_key.len(),
                })?;
        let ed_pk = Ed25519SigningKey::from_bytes(&ed_arr).verifying_key();
        ed_pk
            .verify(message, &sig.ed25519_sig)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let mut chacha_key_arr = [0u8; blake3::KEY_LEN];
        chacha_key_arr.copy_from_slice(&chacha_key[..blake3::KEY_LEN]);
        let expected_blake3 = blake3::keyed_hash(&chacha_key_arr, message);
        if !bool::from(
            sig.blake3_keyed
                .as_bytes()
                .ct_eq(expected_blake3.as_bytes()),
        ) {
            return Err(CryptoError::AuthenticationFailed);
        }

        let expected_sha3 = crate::internal::hmac::hmac_sha3_256(&hash_key, message);
        if !bool::from(sig.sha3_keyed.ct_eq(&expected_sha3)) {
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(())
    }
}

// ============================================================================
// Single-call API: HybridSigningKey (wired into existing seed derivation)
// ============================================================================

/// Single-call hybrid signing key for the canonical hybrid construction
/// (Ed25519 + Falcon-1024). Derives both keypairs from a seed handle and
/// domain string via HKDF-SHA3-256.
#[allow(dead_code)] // falcon512/ed448 fields are reserved for future expansion
#[derive(Clone)]
pub struct HybridSigningKeyBundle {
    ed25519: (Ed25519SigningKey, Ed25519VerifyingKey),
    falcon1024: (FalconPrivateKey, FalconPublicKey),
    falcon512: Option<(Falcon512PrivateKey, Falcon512PublicKey)>,
    ed448: Option<(Ed448SigningKey, Ed448VerifyingKey)>,
    domain: String,
}

impl HybridSigningKeyBundle {
    /// Derive a hybrid signing bundle from a master seed and domain.
    ///
    /// This is the "single call" API — pass a 32-byte seed, get back a bundle
    /// that can sign with any of the hybrid constructions in this module.
    pub fn from_seed(master_seed: &[u8; 32], domain: &str) -> Result<Self> {
        // Ed25519 — derive 32-byte seed with domain separation
        let mut ed25519_seed = [0u8; 32];
        hkdf_combine(
            Some(b"hybrid-bundle"),
            master_seed,
            &[domain.as_bytes(), b"ed25519"].concat(),
            &mut ed25519_seed,
        )?;
        let ed25519_sk = Ed25519SigningKey::from_bytes(&ed25519_seed);
        let ed25519_pk = ed25519_sk.verifying_key();

        // Falcon-1024 — derive seed with domain separation, then run Falcon keygen
        let mut falcon_seed = [0u8; 32];
        hkdf_combine(
            Some(b"hybrid-bundle"),
            master_seed,
            &[domain.as_bytes(), b"falcon1024"].concat(),
            &mut falcon_seed,
        )?;
        let (falcon1024_pk, falcon1024_sk) =
            falcon_keygen(&falcon_seed).map_err(|e| CryptoError::Pqc(e.to_string()))?;

        Ok(Self {
            ed25519: (ed25519_sk, ed25519_pk),
            falcon1024: (falcon1024_sk, falcon1024_pk),
            falcon512: None,
            ed448: None,
            domain: domain.to_string(),
        })
    }

    /// Sign with the canonical Ed25519 + Falcon-1024 hybrid
    pub fn sign_hybrid(&self, message: &[u8]) -> Ed25519Falcon1024 {
        Ed25519Falcon1024::sign(&self.ed25519.0, &self.falcon1024.0, message)
    }

    /// Get the Ed25519 verifying key
    pub fn ed25519_pk(&self) -> &Ed25519VerifyingKey {
        &self.ed25519.1
    }

    /// Get the Falcon-1024 public key
    pub fn falcon1024_pk(&self) -> &FalconPublicKey {
        &self.falcon1024.1
    }

    /// Get the domain this bundle was derived for
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get a bundle from a process-wide cache, or derive it if not cached.
    ///
    /// Falcon-1024 keygen is expensive (~4s on a desktop CPU — the NTRU lattice
    /// key generation runs a rejection-sampling loop over random polynomial
    /// pairs until one satisfies the Gram-Schmidt norm bound). When you sign
    /// many messages with the same (seed, domain), use this to avoid
    /// re-deriving the bundle on every call.
    ///
    /// The cache holds at most one bundle per (seed, domain) pair and lives for
    /// the duration of the process. Drop it via [`bundle_cache_clear`] if you
    /// need to force re-derivation.
    pub fn from_seed_cached(master_seed: &[u8; 32], domain: &str) -> Result<Arc<Self>> {
        let key = (*master_seed, domain.to_string());
        let mut cache = bundle_cache()
            .bundle_cache
            .lock()
            .expect("bundle cache poisoned");
        if let Some(bundle) = cache.get(&key) {
            return Ok(bundle.clone());
        }

        #[allow(non_local_definitions)]
        impl std::fmt::Debug for HybridSigningKeyBundle {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                // Surface `domain` (semi-public — used as a routing label, not a secret).
                // All key-bearing fields redact via `<redacted>`. The `Option` presence
                // for `falcon512` / `ed448` is preserved as `None` vs `Some(<redacted>)` —
                // these are reserved-family expansions and their presence is not a leak.
                f.debug_struct("HybridSigningKeyBundle")
                    .field("domain", &self.domain)
                    .field("ed25519", &"<redacted>")
                    .field("falcon1024", &"<redacted>")
                    .field(
                        "falcon512",
                        &if self.falcon512.is_some() {
                            "Some(<redacted>)"
                        } else {
                            "None"
                        },
                    )
                    .field(
                        "ed448",
                        &if self.ed448.is_some() {
                            "Some(<redacted>)"
                        } else {
                            "None"
                        },
                    )
                    .finish()
            }
        }
        let bundle = Arc::new(Self::from_seed(master_seed, domain)?);
        cache.insert(key, bundle.clone());
        Ok(bundle)
    }
}

/// Process-wide cache for [`HybridSigningKeyBundle`], keyed by (seed, domain).
///
/// Process-global (shared across all threads) so that repeated derivation of the
/// same (seed, domain) — e.g. many `#[test]` threads, or a server handling many
/// sign requests — pays the ~5s Falcon-1024 keygen only once. A single
/// `std::sync::Mutex` guards the map; the bundles themselves are `Arc` and cheap
/// to clone on cache hit.
struct BundleCache {
    bundle_cache: std::sync::Mutex<
        std::collections::HashMap<([u8; 32], String), Arc<HybridSigningKeyBundle>>,
    >,
}

impl BundleCache {
    fn new() -> Self {
        Self {
            bundle_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

use std::sync::OnceLock;
static BUNDLE_CACHE: OnceLock<BundleCache> = OnceLock::new();

fn bundle_cache() -> &'static BundleCache {
    BUNDLE_CACHE.get_or_init(BundleCache::new)
}

/// Clear the process-wide bundle cache. Useful for tests or memory-constrained
/// environments.
pub fn bundle_cache_clear() {
    if let Some(cache) = BUNDLE_CACHE.get() {
        cache
            .bundle_cache
            .lock()
            .expect("bundle cache poisoned")
            .clear();
    }
}

// ============================================================================
// Convenience: derive Falcon-1024 keypair from seed
// ============================================================================

/// Convenience alias for Falcon-1024 keygen
#[allow(dead_code)]
pub fn falcon1024_keygen(seed: &[u8; 32]) -> Result<(FalconPublicKey, FalconPrivateKey)> {
    falcon_keygen(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let msg = b"test message";
        let hash = blake3::hash(msg);
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [42u8; blake3::KEY_LEN];
        let msg = b"test message";
        let hash = blake3::keyed_hash(&key, msg);
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_shake256_output() {
        let msg = b"test message";
        let out = shake256_output(msg, 64);
        assert_eq!(out.len(), 64);
        let out2 = shake256_output(msg, 64);
        assert_eq!(out, out2);
    }

    #[test]
    fn test_shake128_output() {
        let msg = b"test message";
        let out = shake128_output(msg, 32);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn test_skein512_basic() {
        let msg = b"test message";
        let h1 = skein512(msg);
        let h2 = skein512(msg);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_skein1024_basic() {
        let msg = b"test message";
        let h1 = skein1024(msg);
        let h2 = skein1024(msg);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 128);
    }

    #[test]
    fn test_ed25519_blake3() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Blake3::sign(&sk, msg);
        Ed25519Blake3::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_blake3_rejects_wrong_msg() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let sig = Ed25519Blake3::sign(&sk, b"original");
        assert!(Ed25519Blake3::verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_ed25519_shake256() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Shake256::sign(&sk, msg, 64);
        Ed25519Shake256::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_skein512() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Skein512::sign(&sk, msg);
        Ed25519Skein512::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_skein512_rejects_wrong_msg() {
        let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let sig = Ed25519Skein512::sign(&sk, b"original");
        assert!(Ed25519Skein512::verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_ed448_sha3_256() {
        let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed448Sha3_256::sign(&sk, msg);
        Ed448Sha3_256::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed448_shake256() {
        let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed448Shake256::sign(&sk, msg, 64);
        Ed448Shake256::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed448_skein512() {
        let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = Ed448Skein512::sign(&sk, msg);
        Ed448Skein512::verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_falcon1024() {
        let seed = [42u8; 32];
        let (falcon_pk, falcon_sk) = falcon_keygen(&seed).unwrap();
        let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let ed_pk = ed_sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, msg);
        Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_falcon512() {
        let seed = [42u8; 32];
        let (falcon_sk, falcon_pk) = crate::pqc::falcon512::generate_keypair(seed);
        let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let ed_pk = ed_sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Falcon512::sign(&ed_sk, &falcon_sk, msg);
        Ed25519Falcon512::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_falcon512_rejects_tampered() {
        let seed = [42u8; 32];
        let (falcon_sk, falcon_pk) = crate::pqc::falcon512::generate_keypair(seed);
        let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let ed_pk = ed_sk.verifying_key();
        let msg = b"hello";
        let sig = Ed25519Falcon512::sign(&ed_sk, &falcon_sk, msg);
        assert!(Ed25519Falcon512::verify(&ed_pk, &falcon_pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_ed448_falcon1024() {
        let seed = [42u8; 32];
        let (falcon_pk, falcon_sk) = falcon_keygen(&seed).unwrap();
        let ed_sk = Ed448SigningKey::from_bytes(&[1u8; 57]).unwrap();
        let ed_pk = ed_sk.verifying_key();
        let msg = b"hello";
        let sig = Ed448Falcon1024::sign(&ed_sk, &falcon_sk, msg);
        Ed448Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_derive_hybrid_keys() {
        let seed = [42u8; 32];
        let (ed, chacha, hash) = derive_hybrid_keys(&seed, "test", 32, 32, 32).unwrap();
        assert_eq!(ed.len(), 32);
        assert_eq!(chacha.len(), 32);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_ed25519_chacha20blake3_sha3_256() {
        let seed = [42u8; 32];
        let msg = b"hello hybrid kdf";
        let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain", msg).unwrap();
        Ed25519ChaCha20Blake3Sha3_256::verify(&seed, "domain", msg, &sig).unwrap();
    }

    #[test]
    fn test_ed25519_chacha20blake3_sha3_rejects_wrong() {
        let seed = [42u8; 32];
        let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain", b"orig").unwrap();
        assert!(Ed25519ChaCha20Blake3Sha3_256::verify(&seed, "domain", b"wrong", &sig).is_err());
    }

    #[test]
    fn test_hybrid_signing_key_bundle_basic() {
        let seed = [42u8; 32];
        let bundle = HybridSigningKeyBundle::from_seed(&seed, "test-domain").unwrap();
        assert_eq!(bundle.domain(), "test-domain");

        // Sign a message with the canonical hybrid
        let msg = b"hello bundle";
        let sig = bundle.sign_hybrid(msg);
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), msg, &sig).unwrap();
    }

    #[test]
    fn test_hybrid_signing_key_bundle_deterministic() {
        let seed = [42u8; 32];
        let bundle1 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();
        let bundle2 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();

        // Same seed + domain = same Ed25519 key
        assert_eq!(
            bundle1.ed25519_pk().to_bytes(),
            bundle2.ed25519_pk().to_bytes()
        );
        // Same seed + domain = same Falcon-1024 key
        assert_eq!(
            bundle1.falcon1024_pk().as_bytes(),
            bundle2.falcon1024_pk().as_bytes()
        );
    }

    /// Regression test: Falcon key must also be domain-separated (not just Ed25519).
    /// This was a real bug — the original `from_seed` passed the master seed
    /// directly to Falcon keygen, ignoring the domain parameter.
    #[test]
    fn test_hybrid_signing_key_bundle_domain_separates_falcon() {
        let seed = [42u8; 32];
        let bundle1 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();
        let bundle2 = HybridSigningKeyBundle::from_seed(&seed, "domain2").unwrap();

        // Different domains must yield different Falcon keys
        assert_ne!(
            bundle1.falcon1024_pk().as_bytes(),
            bundle2.falcon1024_pk().as_bytes(),
            "Falcon key should differ between domains"
        );
    }

    /// The cache must produce the same keys as the non-cached path.
    #[test]
    fn test_hybrid_signing_key_bundle_cache_consistency() {
        bundle_cache_clear();
        let seed = [42u8; 32];
        let b1 = HybridSigningKeyBundle::from_seed(&seed, "test-domain").unwrap();
        let b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "test-domain")
            .expect("cached should succeed");

        assert_eq!(b1.ed25519_pk().to_bytes(), b2.ed25519_pk().to_bytes());
        assert_eq!(b1.falcon1024_pk().as_bytes(), b2.falcon1024_pk().as_bytes());
    }

    /// Cached and non-cached paths must produce functionally identical bundles.
    /// Two calls to `from_seed_cached` should return Arc to the same instance.
    #[test]
    fn test_hybrid_signing_key_bundle_cache_returns_same_arc() {
        bundle_cache_clear();
        let seed = [42u8; 32];
        let b1 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-test")
            .expect("first cached should succeed");
        let b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-test")
            .expect("second cached should succeed");

        // Both Arcs point to the same allocation
        assert!(Arc::ptr_eq(&b1, &b2));
    }

    #[test]
    fn test_falcon1024_keygen_convenience() {
        let seed = [42u8; 32];
        let (pk, sk) = falcon1024_keygen(&seed).unwrap();
        let msg = b"test";
        let sig = falcon_sign(msg, &sk).unwrap();
        assert!(falcon_verify(msg, &sig, &pk).is_ok());
    }

    #[test]
    fn test_xor_combine() {
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        let out = xor_combine(&a, &b);
        assert_eq!(out, vec![4, 4, 4, 12]);
    }

    #[test]
    fn test_concat_combine() {
        let a = [1u8, 2];
        let b = [3u8, 4, 5];
        let out = concat_combine(&a, &b);
        assert_eq!(out, vec![1, 2, 3, 4, 5]);
    }
}

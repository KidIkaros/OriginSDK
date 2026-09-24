// SPDX-License-Identifier: Apache-2.0

//! The hybrid constructions.
//!
//! Every construction is a unit struct of named component fields — the
//! field names are the public record of *which* primitive produced each
//! part — over the shared combinators in [`super::combinators`], which
//! encode the security contract once:
//!
//! - non-KDF constructions: `verify = signature check ∧ ct_eq(recomputed digest)`
//! - signature hybrids: `verify = both_must_verify(component_a, component_b)`
//! - KDF construction: derive subkeys, then `signature check ∧ ct_eq × 2`
//!
//! `sign`/`try_sign` pairs follow the crate convention: the infallible
//! `sign` delegates to the fallible `try_sign` and documents its panic.

use ed25519_dalek::{Signer, Verifier};

use crate::error::{CryptoError, Result};
use crate::pqc::ed448::{
    Signature as Ed448Signature, SigningKey as Ed448SigningKey, VerifyingKey as Ed448VerifyingKey,
};
use crate::pqc::falcon1024::{
    sign as falcon_sign, verify as falcon_verify, FalconPrivateKey, FalconPublicKey,
    FalconSignature,
};
use crate::pqc::falcon512::{
    sign as falcon512_sign, verify as falcon512_verify, Falcon512PrivateKey, Falcon512PublicKey,
    Falcon512Signature,
};
use crate::primitives::{blake3, sha3_256};

use super::combinators::{
    both_must_verify, ct_eq_or_failed, shake256_output, skein512, verify_sig_and_digest,
};
use super::kdf::derive_hybrid_keys;

// Ed25519 signature types — re-exported at `signing::hybrid` via `mod.rs`.
use super::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};

// ============================================================================
// Component checks — normalize each primitive's verify shape to `Result<()>`
// ============================================================================

fn ed25519_check(pk: &Ed25519VerifyingKey, msg: &[u8], sig: &Ed25519Signature) -> Result<()> {
    pk.verify(msg, sig)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn ed448_check(pk: &Ed448VerifyingKey, msg: &[u8], sig: &Ed448Signature) -> Result<()> {
    pk.verify(msg, sig)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn falcon1024_check(pk: &FalconPublicKey, msg: &[u8], sig: &FalconSignature) -> Result<()> {
    falcon_verify(msg, sig, pk).map_err(|_| CryptoError::AuthenticationFailed)
}

fn falcon512_check(pk: &Falcon512PublicKey, msg: &[u8], sig: &Falcon512Signature) -> Result<()> {
    if falcon512_verify(msg, sig, pk) {
        Ok(())
    } else {
        Err(CryptoError::AuthenticationFailed)
    }
}

// ============================================================================
// Non-KDF constructions: signature + message digest, both must verify
// ============================================================================

/// Ed25519 + BLAKE3 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Blake3 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The BLAKE3 hash of the message.
    pub blake3_hash: blake3::Hash,
}

impl Ed25519Blake3 {
    /// Sign message with Ed25519 and compute BLAKE3 hash of message
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Self {
        Self {
            ed25519_sig: signing_key.sign(message),
            blake3_hash: blake3::hash(message),
        }
    }

    /// Verify Ed25519 signature and check BLAKE3 hash matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed25519_check(verifying_key, message, &sig.ed25519_sig),
            message,
            sig.blake3_hash.as_bytes(),
            |m| blake3::hash(m).as_bytes().to_vec(),
        )
    }
}

/// Ed25519 + SHAKE256 combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Shake256 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The SHAKE256 output of the message.
    pub shake_output: Vec<u8>,
}

impl Ed25519Shake256 {
    /// Sign message with Ed25519 and compute SHAKE256 output of message
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8], shake_len: usize) -> Self {
        Self {
            ed25519_sig: signing_key.sign(message),
            shake_output: shake256_output(message, shake_len),
        }
    }

    /// Verify Ed25519 signature and check SHAKE256 output matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed25519_check(verifying_key, message, &sig.ed25519_sig),
            message,
            &sig.shake_output,
            |m| shake256_output(m, sig.shake_output.len()),
        )
    }
}

/// Ed25519 + Skein-512 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed25519Skein512 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Skein-512 hash of the message.
    pub skein512_hash: [u8; 64],
}

impl Ed25519Skein512 {
    /// Sign message with Ed25519 and compute Skein-512 hash
    pub fn sign(signing_key: &Ed25519SigningKey, message: &[u8]) -> Self {
        Self {
            ed25519_sig: signing_key.sign(message),
            skein512_hash: skein512(message),
        }
    }

    /// Verify Ed25519 signature and check Skein-512 hash matches message
    pub fn verify(verifying_key: &Ed25519VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed25519_check(verifying_key, message, &sig.ed25519_sig),
            message,
            &sig.skein512_hash,
            |m| skein512(m).to_vec(),
        )
    }
}

/// Ed448 + SHAKE256 combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Shake256 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The SHAKE256 output of the message.
    pub shake_output: Vec<u8>,
}

impl Ed448Shake256 {
    /// Sign message with Ed448 and compute SHAKE256 output
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8], shake_len: usize) -> Self {
        Self {
            ed448_sig: signing_key.sign(message),
            shake_output: shake256_output(message, shake_len),
        }
    }

    /// Verify Ed448 signature and check SHAKE256 output
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed448_check(verifying_key, message, &sig.ed448_sig),
            message,
            &sig.shake_output,
            |m| shake256_output(m, sig.shake_output.len()),
        )
    }
}

/// Ed448 + Skein-512 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Skein512 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The Skein-512 hash of the message.
    pub skein512_hash: [u8; 64],
}

impl Ed448Skein512 {
    /// Sign message with Ed448 and compute Skein-512 hash
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8]) -> Self {
        Self {
            ed448_sig: signing_key.sign(message),
            skein512_hash: skein512(message),
        }
    }

    /// Verify Ed448 signature and check Skein-512 hash
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed448_check(verifying_key, message, &sig.ed448_sig),
            message,
            &sig.skein512_hash,
            |m| skein512(m).to_vec(),
        )
    }
}

/// Ed448 + SHA3-256 hash combiner (non-KDF)
#[derive(Clone, Debug)]
pub struct Ed448Sha3_256 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The SHA3-256 hash of the message.
    pub sha3_hash: [u8; 32],
}

impl Ed448Sha3_256 {
    /// Sign message with Ed448 and compute SHA3-256 hash
    pub fn sign(signing_key: &Ed448SigningKey, message: &[u8]) -> Self {
        Self {
            ed448_sig: signing_key.sign(message),
            sha3_hash: sha3_256(message),
        }
    }

    /// Verify Ed448 signature and check SHA3-256 hash
    pub fn verify(verifying_key: &Ed448VerifyingKey, message: &[u8], sig: &Self) -> Result<()> {
        verify_sig_and_digest(
            ed448_check(verifying_key, message, &sig.ed448_sig),
            message,
            &sig.sha3_hash,
            |m| sha3_256(m).to_vec(),
        )
    }
}

// ============================================================================
// Signature hybrids: two full signatures, both must verify
// ============================================================================

/// Ed25519 + Falcon-1024 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed25519Falcon1024 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Falcon-1024 signature.
    pub falcon_sig: FalconSignature,
}

impl Ed25519Falcon1024 {
    /// Sign with both Ed25519 and Falcon-1024 keys
    ///
    /// # Panics
    /// Panics if Falcon signing fails (e.g. malformed private key).
    /// Use [`Ed25519Falcon1024::try_sign`] for a fallible variant.
    pub fn sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &FalconPrivateKey,
        message: &[u8],
    ) -> Self {
        Self::try_sign(ed25519_sk, falcon_sk, message).expect("Falcon signing failed")
    }

    /// Sign with both Ed25519 and Falcon-1024 keys, returning an error on failure.
    pub fn try_sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &FalconPrivateKey,
        message: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            ed25519_sig: ed25519_sk.sign(message),
            falcon_sig: falcon_sign(message, falcon_sk)?,
        })
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed25519_pk: &Ed25519VerifyingKey,
        falcon_pk: &FalconPublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        both_must_verify(
            || ed25519_check(ed25519_pk, message, &sig.ed25519_sig),
            || falcon1024_check(falcon_pk, message, &sig.falcon_sig),
        )
    }
}

/// Ed25519 + Falcon-512 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed25519Falcon512 {
    /// The Ed25519 signature.
    pub ed25519_sig: Ed25519Signature,
    /// The Falcon-512 signature.
    pub falcon_sig: Falcon512Signature,
}

impl Ed25519Falcon512 {
    /// Sign with both Ed25519 and Falcon-512 keys
    ///
    /// # Panics
    /// Panics if Falcon-512 signing fails (e.g. malformed private key).
    /// Use [`Ed25519Falcon512::try_sign`] for a fallible variant.
    pub fn sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &Falcon512PrivateKey,
        message: &[u8],
    ) -> Self {
        Self::try_sign(ed25519_sk, falcon_sk, message).expect("Falcon-512 signing failed")
    }

    /// Sign with both Ed25519 and Falcon-512 keys, returning an error on failure.
    pub fn try_sign(
        ed25519_sk: &Ed25519SigningKey,
        falcon_sk: &Falcon512PrivateKey,
        message: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            ed25519_sig: ed25519_sk.sign(message),
            falcon_sig: falcon512_sign(message, falcon_sk)?,
        })
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed25519_pk: &Ed25519VerifyingKey,
        falcon_pk: &Falcon512PublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        both_must_verify(
            || ed25519_check(ed25519_pk, message, &sig.ed25519_sig),
            || falcon512_check(falcon_pk, message, &sig.falcon_sig),
        )
    }
}

/// Ed448 + Falcon-1024 hybrid signature (both must verify)
#[derive(Clone, Debug)]
pub struct Ed448Falcon1024 {
    /// The Ed448 signature.
    pub ed448_sig: Ed448Signature,
    /// The Falcon-1024 signature.
    pub falcon_sig: FalconSignature,
}

impl Ed448Falcon1024 {
    /// Sign with both Ed448 and Falcon-1024 keys
    ///
    /// # Panics
    /// Panics if Falcon signing fails (e.g. malformed private key).
    /// Use [`Ed448Falcon1024::try_sign`] for a fallible variant.
    pub fn sign(ed448_sk: &Ed448SigningKey, falcon_sk: &FalconPrivateKey, message: &[u8]) -> Self {
        Self::try_sign(ed448_sk, falcon_sk, message).expect("Falcon signing failed")
    }

    /// Sign with both Ed448 and Falcon-1024 keys, returning an error on failure.
    pub fn try_sign(
        ed448_sk: &Ed448SigningKey,
        falcon_sk: &FalconPrivateKey,
        message: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            ed448_sig: ed448_sk.sign(message),
            falcon_sig: falcon_sign(message, falcon_sk)?,
        })
    }

    /// Verify both signatures - both MUST be valid
    pub fn verify(
        ed448_pk: &Ed448VerifyingKey,
        falcon_pk: &FalconPublicKey,
        message: &[u8],
        sig: &Self,
    ) -> Result<()> {
        both_must_verify(
            || ed448_check(ed448_pk, message, &sig.ed448_sig),
            || falcon1024_check(falcon_pk, message, &sig.falcon_sig),
        )
    }
}

// ============================================================================
// KDF construction: Ed25519 + ChaCha20-Blake3 + SHA3-256
// ============================================================================

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

impl Ed25519ChaCha20Blake3Sha3_256 {
    /// Derive the component keys for `domain` from `master_seed`.
    /// Shared by `sign` and `verify` so the two can never drift apart.
    fn derive_component_keys(
        master_seed: &[u8],
        domain: &str,
    ) -> Result<(Ed25519SigningKey, [u8; blake3::KEY_LEN], [u8; 32])> {
        let sub = derive_hybrid_keys(master_seed, domain)?;
        Ok((
            Ed25519SigningKey::from_bytes(&sub.ed25519),
            sub.chacha20,
            sub.hash,
        ))
    }

    /// Sign with derived keys using HKDF
    pub fn sign(master_seed: &[u8], domain: &str, message: &[u8]) -> Result<Self> {
        let (ed_sk, chacha_key, hash_key) = Self::derive_component_keys(master_seed, domain)?;
        Ok(Self {
            ed25519_sig: ed_sk.sign(message),
            blake3_keyed: blake3::keyed_hash(&chacha_key, message),
            sha3_keyed: crate::internal::hmac::hmac_sha3_256(&hash_key, message),
        })
    }

    /// Verify all three components
    pub fn verify(master_seed: &[u8], domain: &str, message: &[u8], sig: &Self) -> Result<()> {
        let (ed_sk, chacha_key, hash_key) = Self::derive_component_keys(master_seed, domain)?;
        ed25519_check(&ed_sk.verifying_key(), message, &sig.ed25519_sig)?;
        ct_eq_or_failed(
            sig.blake3_keyed.as_bytes(),
            blake3::keyed_hash(&chacha_key, message).as_bytes(),
        )?;
        ct_eq_or_failed(
            &sig.sha3_keyed,
            &crate::internal::hmac::hmac_sha3_256(&hash_key, message),
        )
    }
}

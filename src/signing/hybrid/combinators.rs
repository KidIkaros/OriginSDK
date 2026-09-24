// SPDX-License-Identifier: Apache-2.0

//! Combiners and verification combinators shared by the hybrid constructions.
//!
//! The two `pub(crate)` combinators encode the constructions' security
//! contract once instead of repeating it per construction:
//!
//! - [`both_must_verify`] — AND-combinator for component signatures: a
//!   hybrid signature is valid only if *every* component verifies.
//! - [`verify_sig_and_digest`] — signature check followed by a
//!   constant-time recomputation of the construction's message digest
//!   (the non-KDF pattern: `sign = sign ∘ hash`, `verify = verify ∧ ct_eq`).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use skein::digest::Digest;
use skein::{Skein1024_1024 as Skein1024, Skein512_512 as Skein512};

use crate::error::{CryptoError, Result};
use crate::internal::subtle::ConstantTimeEq;
use crate::kdf::hkdf::hkdf_sha3_256;
use crate::primitives::{Shake128, Shake256};

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
///
/// Thin alias over [`crate::kdf::hkdf::hkdf_sha3_256`] kept as a
/// **deprecated** compatibility shim: the old signature took
/// `(salt, ikm, info, out)` — the opposite order of the public KDF API —
/// which made cross-boundary calls error-prone (audit CC-3). New code
/// should call `kdf::hkdf::hkdf_sha3_256(ikm, salt, info, out)` directly.
#[deprecated(
    since = "0.7.1",
    note = "argument order swaps at the boundary (audit CC-3); use kdf::hkdf::hkdf_sha3_256(ikm, salt, info, out) directly"
)]
pub fn hkdf_combine(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    hkdf_sha3_256(ikm, salt, info, output)
}

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

/// AND-combinator for component verifications.
///
/// `a` runs first; `b` runs only if `a` passed (lazy, matching the
/// historical short-circuit order of the handwritten constructions).
/// `Ok(())` only when every component verifies.
pub(crate) fn both_must_verify(
    a: impl FnOnce() -> Result<()>,
    b: impl FnOnce() -> Result<()>,
) -> Result<()> {
    a()?;
    b()
}

/// Verify a component signature, then recompute the construction's digest
/// of `message` and constant-time-compare it against `presented`.
///
/// This is the shared body of every non-KDF hybrid construction: the
/// signature check runs first (fast reject), then the digest is recomputed
/// and compared in constant time.
pub(crate) fn verify_sig_and_digest(
    sig_result: Result<()>,
    message: &[u8],
    presented: &[u8],
    recompute: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<()> {
    sig_result?;
    let expected = recompute(message);
    if !bool::from(presented.ct_eq(expected.as_slice())) {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

/// Constant-time byte comparison lifted to `Result`.
///
/// Used by the KDF construction, which verifies several derived digests
/// after the component signature has already passed.
pub(crate) fn ct_eq_or_failed(presented: &[u8], expected: &[u8]) -> Result<()> {
    if !bool::from(presented.ct_eq(expected)) {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

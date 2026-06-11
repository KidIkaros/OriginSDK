// SPDX-License-Identifier: OPL-1.1
#![cfg_attr(docsrs, warn(missing_docs))]

//! Origin Crypto SDK — Post-quantum and classical cryptographic primitives.
//!
//! A standalone Rust SDK for signing, encryption, key derivation, and
//! key encapsulation, with first-class support for both classical
//! (Ed25519, X25519) and post-quantum (Falcon-1024, SLH-DSA, ML-DSA,
//! NTRU Prime, Curve41417) primitives.
//!
//! # Quick start
//!
//! For most users, importing the [`prelude`] gives you everything:
//!
//! ```rust
//! use origin_crypto_sdk::prelude::*;
//!
//! // Hybrid Ed25519 + Falcon-1024 signature (recommended default)
//! let master_seed = [0x42u8; 32];
//! let bundle = HybridSigningKeyBundle::from_seed(&master_seed, "my-app")
//!     .expect("valid seed");
//! let msg = b"sign this";
//! let sig = bundle.sign_hybrid(msg);
//! // sig is an Ed25519 + Falcon-1024 hybrid signature
//! ```
//!
//! For users who only need a single primitive:
//!
//! ```rust
//! use origin_crypto_sdk::signing::classical::Ed25519Signer;
//! use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;
//!
//! // Just Ed25519
//! let ed = Ed25519Signer::from_seed(&[1u8; 32]);
//! let sig = ed.sign(b"hello");
//! assert!(ed.verify(b"hello", &sig));
//!
//! // Just Falcon-1024
//! let falcon = Falcon1024Signer::from_seed(&[1u8; 32]);
//! let sig = falcon.sign(b"hello").expect("Falcon sign");
//! assert!(falcon.verify(b"hello", &sig));
//! ```
//!
//! # Module organization
//!
//! - [`signing`] — Direct access to signing primitives, organized by family:
//!   - [`signing::classical`] — Ed25519 (no PQ dependencies)
//!   - [`signing::postquantum`] — Falcon-512/1024, SLH-DSA, ML-DSA
//!   - [`signing::hybrid`] — Recommended default. Ed25519 + PQ combined.
//! - [`aead`] / [`chacha20_blake3`] — Symmetric encryption (committing & non-committing)
//! - [`kdf`] — Key derivation (Argon2id, HKDF-SHA3-256)
//! - [`pqc`] — Raw post-quantum primitives (advanced use)
//! - [`ec_schnorr`] — secp256k1 Schnorr signatures (native, no external deps)
//! - [`prelude`] — One-line import for common types
//!
//! # Security defaults
//!
//! - For **signatures**: use the hybrid (Ed25519 + PQ) — see [`signing::hybrid`].
//!   Both must verify, so a vulnerability in one primitive does not break security.
//! - For **encryption**: prefer [`chacha20_blake3`] (committing AEAD).
//!   Avoid XChaCha20-Poly1305 unless you specifically need the smaller tag
//!   and accept the partitioning-oracle risk.
//! - For **key derivation**: use Argon2id (memory-hard) for password-based KDF,
//!   HKDF-SHA3-256 for HKDF-style derivation.
//!
//! # Cargo features
//!
//! | Feature   | Enables                                | Default |
//! |-----------|----------------------------------------|---------|
//! | `parallel`  | Rayon-based parallel processing      | **yes** |
//! | `slh-dsa`   | SLH-DSA / SPHINCS+ signatures (FIPS 205) | no  |
//! | `ml-dsa`    | ML-DSA / Dilithium signatures (FIPS 204)  | no  |
//! | `pqc-simd`  | SIMD acceleration for NTRU Prime    | no      |
//!
//! Low-level PQC primitives are always available through their modules
//! (`pqc::falcon1024`, `pqc::ed448`, etc.) — the features only gate the
//! optional FIPS schemes that pull in extra dependencies.

#![doc(html_root_url = "https://docs.rs/origin-crypto-sdk/0.4.0")]
#![allow(clippy::result_large_err)]

// ──────────────────────────────────────────────────────────────────────
// Public modules
// ──────────────────────────────────────────────────────────────────────

/// Error types and `Result` alias.
pub mod types;
pub mod error;
pub use error::{CryptoError, Result};

/// Test utilities for downstream users.
///
/// **Feature-gated** — enable with `features = ["test-utils"]`.
///
/// Provides deterministic seeds, keys, nonces, and byte generators so
/// users can write tests against the SDK without hitting real randomness.
///
/// # Example
///
/// ```ignore
/// use origin_crypto_sdk::test_utils::deterministic_seed;
/// let seed = deterministic_seed(42);
/// ```
#[cfg(feature = "test-utils")]
pub mod test_utils;

/// Prelude — re-exports common types for `use origin_crypto_sdk::prelude::*`.
pub mod prelude;

// ── Symmetric encryption ──
pub mod aead;
pub mod chacha20_blake3;
pub mod symmetric;
pub mod streaming;

// ── Hashing & KDF ──
pub mod kdf;
pub mod mac;
pub mod compression;
pub mod siphash;
pub mod primitives;

// ── Signatures ──
/// Signing primitives: classical, post-quantum, and hybrid.
///
/// **Recommended**: use [`signing::hybrid::HybridSigningKeyBundle`] for
/// new applications. It pairs Ed25519 with a post-quantum primitive so
/// the signature remains unforgeable even if one primitive is broken.
pub mod signing;
pub mod pqc;
pub mod ec_schnorr;

// Legacy flat `signing` API (pre-restructuring). Re-exported as
// `origin_crypto_sdk::signing_legacy` for callers that imported the
// old types directly. **Deprecated in 0.4, will be removed in 0.5**.
// See `signing_legacy` module docs for migration instructions.
#[deprecated(
    since = "0.4.0",
    note = "use signing::hybrid::HybridSigningKeyBundle instead. This module will be removed in 0.5."
)]
pub mod signing_legacy;

// ── Randomness & DRBG ──
pub mod drbg;

// ── Entropy analysis & secret management (utility) ──
pub mod entropy;
pub mod otp;
pub mod seed;
pub mod seed_gen;
pub mod blob;
pub mod mmr;
pub mod stealth_kdf;
pub mod stealth_pow;

// ── Error correction ──
pub mod error_correction;

// ── Hybrid construction types (re-exports of [`signing::hybrid`]) ──
pub mod hybrid;

// ──────────────────────────────────────────────────────────────────────
// Internal modules (not part of public API; use at your own risk)
// ──────────────────────────────────────────────────────────────────────
#[doc(hidden)]
pub mod internal;

// ──────────────────────────────────────────────────────────────────────
// Re-exports at crate root for convenience
// ──────────────────────────────────────────────────────────────────────

// Errors
pub use error::{CryptoError as Error, Result as StdResult};

// Encryption
pub use aead::XChaCha20Poly1305;

// KDF
pub use kdf::Argon2id;
pub use kdf::hkdf::{derive_subkeys, hkdf_sha3_256};

// MAC
pub use mac::hmac_sha3_256;

// Hashes
pub use primitives::blake3;
pub use primitives::sha3;
pub use primitives::MemoryTier;

// DRBG
pub use drbg::ChaCha20Drbg;

// Seed handling
pub use seed::{derive_child_seed, derive_signing_keys, derive_verifying_keys, SeedHandle};

// SipHash
pub use siphash::siphash_expand;

// Compression
pub use compression::{compress, decompress};

// Signatures — re-exports (DEPRECATED, will be removed in 0.5)
#[allow(deprecated)]
#[deprecated(
    since = "0.4.0",
    note = "use signing::hybrid::HybridSigningKeyBundle instead"
)]
pub use signing::HybridSignatureOutput;
#[allow(deprecated)]
#[deprecated(
    since = "0.4.0",
    note = "use signing::hybrid::HybridSigningKeyBundle instead"
)]
pub use signing::HybridSigningKey;
#[allow(deprecated)]
#[deprecated(
    since = "0.4.0",
    note = "use signing::hybrid::HybridSigningKeyBundle instead"
)]
pub use signing::HybridVerifyingKey;

// Hybrid bundle (canonical PQ-hybrid signing)
pub use signing::hybrid::HybridSigningKeyBundle;
pub use signing::hybrid::falcon1024_keygen;
pub use signing::hybrid::{skein1024, skein512};

// PQC direct access
pub use pqc::falcon1024::{
    self as falcon_1024, FalconPrivateKey as Falcon1024PrivateKey,
    FalconPublicKey as Falcon1024PublicKey, FalconSignature as Falcon1024Signature,
};
pub use pqc::falcon512::{
    self as falcon_512, Falcon512PrivateKey, Falcon512PublicKey, Falcon512Signature,
};

// Ed448 — RFC 8032 signature scheme on the 448-bit Goldilocks curve.
// Exposed at `origin_crypto_sdk::pqc::ed448`.
// Ed41417 — Daniel J. Bernstein's signature scheme on curve41417.
pub use pqc::curve41417::ed41417 as ed41417_raw;

// SLH-DSA direct access (feature-gated)
#[cfg(feature = "slh-dsa")]
pub use pqc::slhdsa::{sign as slhdsa_sign, verify as slhdsa_verify, SlhDsaPrivateKey, SlhDsaPublicKey};

// ML-DSA direct access (feature-gated)
#[cfg(feature = "ml-dsa")]
pub use pqc::mldsa::{MldsaPrivateKey, MldsaPublicKey};

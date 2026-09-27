// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(docsrs, warn(missing_docs))]

//! Origin Crypto SDK — Post-quantum and classical cryptographic primitives.
//!
//! > **⚠️ EXPERIMENTAL — NOT FOR PRODUCTION USE ⚠️**
//! >
//! > This SDK has **not** undergone independent security audit or formal
//! > review. Do not use it to protect real funds, identities, or data.
//! > API, wire formats, and on-disk formats may change without notice,
//! > including in ways that break compatibility with existing data.
//! > Use for research and experimentation only.
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
//! let ed = Ed25519Signer::from_seed(&[1u8; 32]);  // from_seed returns Self
//! let sig = ed.sign(b"hello");
//! assert!(ed.verify(b"hello", &sig));
//!
//! // Just Falcon-1024
//! let falcon = Falcon1024Signer::from_seed(&[1u8; 32]).expect("valid seed");
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
//! - [`x25519`] — X25519 key agreement (RFC 7748); the counterpart to signing.
//! - [`aead`] / [`chacha20_blake3`] — Symmetric encryption (committing & non-committing)
//! - [`chacha40`] — Post-quantum hardened stream cipher (512-bit key, 40 rounds, dual-state)
//! - [`chacha20`] — Standard ChaCha20 stream cipher (RFC 8439)
//! - [`kdf`] — Key derivation (Argon2id, HKDF-SHA3-256)
//! - [`compressed`] — Atomic compress-then-encrypt / decrypt-then-decompress container
//! - [`pqc`] — Raw post-quantum primitives (advanced use)
//! - [`ec_schnorr`] — secp256k1 Schnorr signatures (arithmetic via the `k256` crate)
//! - [`prelude`] — One-line import for common types
//!
//! # Security defaults
//!
//! - For **signatures**: use the hybrid (Ed25519 + PQ) — see [`signing::hybrid`].
//!   Both must verify, so a vulnerability in one primitive does not break security.
//! - For **encryption**: prefer [`chacha20_blake3`] (committing AEAD).
//!   Avoid XChaCha20-Poly1305 unless you specifically need the smaller tag
//!   and accept the partitioning-oracle risk.
//! - For **PQ-hardened stream cipher**: use [`chacha40`] when 256-bit post-quantum
//!   security against Grover's algorithm is desired. Note that ChaCha40 is a bare
//!   stream cipher — pair with Poly1305 or BLAKE3 for authenticated encryption.
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

//! # Threat modeling for application authors
//!
//! For applications that wrap this SDK and serve users facing legal
//! compulsion or physical coercion (journalists, dissidents, civil-society
//! organizers), see the application-level guidance in
//! <https://github.com/KidIkaros/OriginSDK/blob/HEAD/docs/duress-pattern.md>.
//! **The SDK deliberately ships no duress or self-destruct primitive**;
//! applications compose existing primitives (`create_blob`, `recover_seed`,
//! `SeedHandle::with_tier`, `MemoryTier::Standard`/`Sovereign`) following
//! the patterns documented there.
//!
//! See also `SECURITY.md` for the implementation source table.

#![doc(html_root_url = "https://docs.rs/origin-crypto-sdk/0.7.1")]
#![allow(clippy::result_large_err)]

// ──────────────────────────────────────────────────────────────────────
// Public modules (matching the README map exactly)
// ──────────────────────────────────────────────────────────────────────

/// Algorithm identifiers for downgrade resistance.
pub mod algorithm_id;
pub mod error;
/// Error types and `Result` alias.
pub mod types;
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

// ── Hashing & KDF ──
pub mod kdf;

// ── Signatures ──
pub mod ec_schnorr;
pub mod pqc;
/// Signing primitives: classical, post-quantum, and hybrid.
///
/// **Recommended**: use [`signing::hybrid::HybridSigningKeyBundle`] for
/// new applications. It pairs Ed25519 with a post-quantum primitive so
/// the signature remains unforgeable even if one primitive is broken.
pub mod signing;

// ── Key agreement ──
/// X25519 Diffie-Hellman key agreement (RFC 7748, `algorithm_id 0x0602`).
///
/// The key-agreement counterpart to the signing surfaces: byte-array
/// interchange, seed-based deterministic derivation, zeroize-on-drop.
pub mod x25519;

// ── Randomness & DRBG ──
pub mod drbg;

// ── OCRA (RFC 6287: OATH Challenge-Response Algorithms) ──
/// RFC 6287 OCRA core — challenge → response.
///
/// Implements RFC 6287 §7.1 with explicitly-named fields. No
/// suite-string parsing (not implemented; fields are explicit). Uses
/// [`crate::drbg::otp::HashAlgorithm`] for the underlying HMAC family.
pub mod ocra;

// ── Recovery phrases ──
///
/// BIP-39-shaped Unicode recovery phrases. NOT BIP-39-compatible —
/// uses a curated Unicode codepoint wordlist and SHA-3-256 (not
/// SHA-256). For interop with other wallets, use the `bip39` crate.
pub mod recovery;

// ── Utility modules ──
/// Entropy analysis — Shannon/min/collision entropy, chi-squared, serial
/// correlation, and bit-bias metrics for auditing randomness quality.
///
/// Public so downstream tools (and the origin-web browser teaser) can use the
/// SDK's real analysis rather than reimplementing it.
pub mod entropy;

/// Seed handling with TTL and memory security.
pub mod seed;

/// Stealth address primitives (KDF + PoW).
pub mod stealth;

/// Error correction codes (Reed-Solomon over GF(2^8)).
///
/// **Experimental utility** — exposed for sharded backup/recovery
/// compositions and exercised by the test suite. Wire format is not yet
/// frozen; see the module docs for decoder limitations.
pub mod error_correction;

/// Low-level cryptographic primitives (hashes, ciphers, etc.).
///
/// **Internal use only.** Application code should use the higher-level
/// modules ([`chacha20_blake3`], [`kdf`], etc.) instead.
#[doc(hidden)]
pub(crate) mod primitives;

/// SipHash-c-d compute-hardener used in the entropy pipeline.
///
/// **Experimental utility** — not a security boundary; see module docs.
pub mod siphash;

/// DEFLATE compression helpers used by [`compressed`].
///
/// **Experimental utility** — most callers want [`compressed`]'s
/// authenticated container instead of raw compression.
pub mod compression;

/// Atomic compress-then-encrypt / decrypt-then-decompress container.
pub mod compressed;

/// Seed-blob storage format (v1/v2, tier-aware).
///
/// **Experimental** — see `FORMAT_REGISTRY.md` for the wire-format
/// guarantees and version-detection contract.
pub mod blob;

// ──────────────────────────────────────────────────────────────────────
// Internal modules (crate-private implementation details)
// ──────────────────────────────────────────────────────────────────────
//
// `internal` holds vendored primitive implementations (SHA-3, HMAC, HKDF,
// ChaCha20 CSPRNG, secp256k1, mlock, OS entropy). It is crate-private —
// not `#[doc(hidden)] pub` — so the layering boundary is enforced by the
// compiler. Public consumers reach deterministic RNG through
// [`drbg::ChaCha20Rng`] and OS entropy through [`fill_random`].
pub(crate) mod internal;

// ── Hash function re-exports (primitives is pub(crate); these are the public surface) ──
/// BLAKE3 hash module — fast, parallelizable.
pub use primitives::blake3;
/// ChaCha40 — post-quantum hardened stream cipher (512-bit key, 40 rounds, dual-state).
///
/// Provides 256-bit post-quantum security against Grover's algorithm.
/// See [`primitives::chacha40`] for full documentation.
pub use primitives::chacha40;
/// SHA-256 hash (raw SHA-2 — WebAuthn/TLS interop, not SHA-3).
pub use primitives::sha256;
/// SHA3-256 hash.
pub use primitives::sha3_256;
/// SHA3-512 hash.
pub use primitives::sha3_512;
/// SHA-512 hash (raw SHA-2).
pub use primitives::sha512;

// ── Additional cipher module re-exports ──
/// ChaCha20 stream cipher module.
pub use primitives::chacha20;
/// Poly1305 message authentication code.
#[doc(hidden)]
pub use primitives::poly1305;
/// Memory tier configuration for Argon2id KDF.
#[doc(hidden)]
pub use primitives::tier;

// ──────────────────────────────────────────────────────────────────────
// Re-exports at crate root for convenience
// ──────────────────────────────────────────────────────────────────────

// Errors
pub use error::{CryptoError as Error, Result as StdResult};

// Encryption
pub use aead::{try_generate_key, try_generate_nonce, XChaCha20Poly1305};

// KDF
pub use kdf::hkdf::{derive_subkeys, derive_subkeys_blake3, hkdf_blake3, hkdf_sha3_256};
pub use kdf::Argon2id;

// Key agreement
pub use x25519::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

// MAC
pub use kdf::mac::{hmac_blake3, hmac_sha3_256};

// DRBG
pub use drbg::ChaCha20Drbg;

// Atomic compression
pub use compressed::{compress_encrypt, decompress_decrypt, Compressor, DEFAULT_CHUNK_SIZE};

/// Fill a buffer with bytes from the SDK's operating-system CSPRNG.
///
/// This is the stable downstream randomness boundary. It is fallible so
/// callers can handle an unavailable or failed operating-system entropy source
/// without inheriting a panic from the SDK.
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    internal::getrandom::fill(dest).map_err(|error| CryptoError::Io(std::io::Error::other(error)))
}

// Seed handling
pub use seed::{derive_child_seed, derive_signing_keys, derive_verifying_keys, SeedHandle};

// Hybrid bundle (canonical PQ-hybrid signing)
pub use signing::hybrid::falcon1024_keygen;
pub use signing::hybrid::{
    bundle_cache_clear, bundle_cache_configure, bundle_cache_len, HybridSigningKeyBundle,
    DEFAULT_BUNDLE_CACHE_MAX_ENTRIES,
};
pub use signing::hybrid::{skein1024, skein512};
// Ed25519 type aliases (for parsing wire-format keys/signatures without direct ed25519_dalek import)
pub use signing::hybrid::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};

// PQC direct access — use `pqc::{falcon1024, falcon512, ed448, ...}::module` for raw types.
// Re-exports at crate root are intentionally omitted to keep the surface clean.
// Advanced users access via `origin_crypto_sdk::pqc::falcon1024::FalconPrivateKey` etc.

// Ed448 — RFC 8032 signature scheme on the 448-bit Goldilocks curve.
// Exposed at `origin_crypto_sdk::pqc::ed448`.
// Ed41417 — Daniel J. Bernstein's signature scheme on curve41417.
// pub use pqc::curve41417::ed41417 as ed41417_raw;  // intentionally not re-exported

// SLH-DSA direct access (feature-gated)
#[cfg(feature = "slh-dsa")]
pub use pqc::slhdsa::{
    sign as slhdsa_sign, verify as slhdsa_verify, SlhDsaPrivateKey, SlhDsaPublicKey,
};

// ML-DSA direct access (feature-gated)
#[cfg(feature = "ml-dsa")]
pub use pqc::mldsa::{MldsaPrivateKey, MldsaPublicKey};

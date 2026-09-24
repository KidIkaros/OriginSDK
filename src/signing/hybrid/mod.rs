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
//! # Experimental
//!
//! These hybrid constructions are novel compositions that have not undergone
//! independent cryptographic review. While individual components (Ed25519,
//! Falcon, BLAKE3, SHA3) are well-studied, the composition itself — including
//! domain separation, key binding, and downgrade resistance — requires formal
//! analysis before production use. The "both must verify" property has been
//! tested with 25+ adversarial tests, but a security proof is not available.
//!
//! ## Module layout
//!
//! - `constructions` — the ten public construction types; struct fields name
//!   the component algorithms, impls delegate to `combinators`
//! - `combinators` — hash/XOF helpers plus the shared verification
//!   combinators (`both_must_verify`, `verify_sig_and_digest`) that encode
//!   the "every component must verify" contract once
//! - `kdf` — [`derive_hybrid_keys`] domain-separated subkey derivation
//! - `bundle` — [`HybridSigningKeyBundle`], the canonical single-call API
//! - `cache` — bounded process-global bundle cache (see
//!   `docs/ARCHITECTURE.md` for why this is the one allowed global)
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

mod bundle;
mod cache;
mod combinators;
mod constructions;
mod kdf;

#[cfg(test)]
mod tests;

// ============================================================================
// Public re-exports: allow consumers to parse Ed25519 keys/signatures without
// importing ed25519_dalek directly (keeps the "single crypto provider" discipline).
// ============================================================================

pub use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};

pub use bundle::{falcon1024_keygen, HybridSigningKeyBundle};
pub use cache::{
    bundle_cache_clear, bundle_cache_configure, bundle_cache_len, BundleCache,
    DEFAULT_BUNDLE_CACHE_MAX_ENTRIES,
};
pub use combinators::{
    concat_combine, hkdf_combine, shake128_output, shake256_output, skein1024, skein512,
    xor_combine,
};
pub use constructions::{
    Ed25519Blake3, Ed25519ChaCha20Blake3Sha3_256, Ed25519Falcon1024, Ed25519Falcon512,
    Ed25519Shake256, Ed25519Skein512, Ed448Falcon1024, Ed448Sha3_256, Ed448Shake256, Ed448Skein512,
};
pub use kdf::{derive_hybrid_keys, HybridSubkeys};

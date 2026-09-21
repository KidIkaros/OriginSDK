// SPDX-License-Identifier: Apache-2.0

//! Signing primitives — classical, post-quantum, and hybrid.
//!
//! Signet defaults to **hybrid** signing for new applications. A hybrid
//! signature is unforgeable as long as **either** primitive holds; a
//! vulnerability in one (e.g. a future quantum attack on Ed25519, or a
//! bug in Falcon) does not break the scheme.
//!
//! # Quick reference
//!
//! | Need | Use |
//! |------|-----|
//! | Recommended for new code | [`signing::hybrid::HybridSigningKeyBundle`] |
//! | Pure Ed25519 (no PQ) | [`signing::classical::Ed25519Signer`] |
//! | Pure Falcon-1024 (PQ only) | [`signing::postquantum::Falcon1024Signer`] |
//! | Pure SLH-DSA (hash-based) | \[`pqc::slhdsa`\] |
//! | secp256k1 Schnorr | [`ec_schnorr`] |
//!
//! # Submodule organization
//!
//! - [`signing::classical`] — Ed25519 (32-byte keys, 64-byte signatures)
//! - [`signing::postquantum`] — Falcon-512/1024, SLH-DSA, ML-DSA
//! - [`signing::hybrid`] — Ed25519 + PQ constructions (canonical signing API)
//!
//! # Design: static methods, not traits
//!
//! Unlike many crypto crates, this module does **not** expose a `Signer` /
//! `Verifier` trait. Instead, every signing algorithm is implemented as
//! a unit struct with static `sign` / `verify` methods:
//!
//! ```no_run
//! use origin_crypto_sdk::signing::classical::Ed25519Signer;
//!
//! let signer = Ed25519Signer::from_seed(&[1u8; 32]);
//! let sig = signer.sign(b"message");
//! assert!(signer.verify(b"message", &sig));
//! ```
//!
//! This has two benefits:
//!
//! 1. **No "blanket impl" attacks** — a downstream crate cannot
//!    implement `Signer` for a custom type and silently intercept
//!    signatures. The compiler refuses anything not defined here.
//! 2. **No `dyn` dispatch overhead** — all paths are monomorphized.
//!
//! The cost is that generic code (e.g. accepting "any signer") needs to
//! be a function on the algorithm enum (`HybridSigningKeyBundle`) or
//! an explicit match. For 99% of use cases this is the right tradeoff.

pub mod classical;
pub mod hybrid;
pub mod postquantum;

/// Hybrid-signature wire format (Ed25519 + Falcon-1024 serialization).
pub mod wire;

/// Legacy compatibility shim for code that used `origin_crypto_sdk::hybrid::*`.
/// **Deprecated.** Use `signing::hybrid` directly instead.
#[deprecated(note = "use signing::hybrid instead.")]
pub mod legacy_shim;

// ──────────────────────────────────────────────────────────────────────
// Legacy re-exports
//
// These types used to live at `origin_crypto_sdk::signing::*` (a flat
// module). The new structure puts them in `signing::{classical,hybrid}`.
// We re-export them at this level for backward compat with callers that
// did `use origin_crypto_sdk::signing::{HybridSigningKey, ...};`.
// ──────────────────────────────────────────────────────────────────────

// (Removed in 0.6.0: the pre-0.4 flat-namespace `HybridSigningKey` /
// `HybridVerifyingKey` / `HybridSignatureOutput` re-exports previously
// surfaced here via `pub use crate::signing_legacy::{...}`. With
// `signing_legacy` removed in 0.6.0, those types are gone entirely.
// Use `signing::hybrid::HybridSigningKeyBundle` for all new code.)

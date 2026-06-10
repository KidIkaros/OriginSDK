// SPDX-License-Identifier: OPL-1.1

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
//! | Recommended for new code | [`hybrid::HybridSigningKeyBundle`] |
//! | Pure Ed25519 (no PQ) | [`classical::Ed25519Signer`] |
//! | Pure Falcon-1024 (PQ only) | [`postquantum::Falcon1024Signer`] |
//! | Pure SLH-DSA (hash-based) | [`crate::pqc::slhdsa`] |
//! | secp256k1 Schnorr | [`crate::ec_schnorr`] |
//!
//! # Submodule organization
//!
//! - [`classical`] — Ed25519 (32-byte keys, 64-byte signatures)
//! - [`postquantum`] — Falcon-512/1024, SLH-DSA, ML-DSA
//! - [`hybrid`] — Ed25519 + PQ constructions (canonical signing API)

pub mod classical;
pub mod postquantum;
pub mod hybrid;

// ──────────────────────────────────────────────────────────────────────
// Legacy re-exports
//
// These types used to live at `origin_crypto_sdk::signing::*` (a flat
// module). The new structure puts them in `signing::{classical,hybrid}`.
// We re-export them at this level for backward compat with callers that
// did `use origin_crypto_sdk::signing::{HybridSigningKey, ...};`.
// ──────────────────────────────────────────────────────────────────────

// `HybridSigningKey` (the OOP wrapper around HybridSigningKeyBundle) was
// the main public type from the old `signing.rs`. It's now in the
// `signing_legacy` top-level module.
pub use crate::signing_legacy::{HybridSignatureOutput, HybridSigningKey, HybridVerifyingKey};

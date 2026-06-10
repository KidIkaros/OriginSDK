// SPDX-License-Identifier: OPL-1.1

//! Hybrid construction types and utilities.
//!
//! **This module is a thin compatibility shim.** The full implementation
//! lives in [`crate::signing::hybrid`]. New code should import from there.
//!
//! Re-exports:
//! - [`Ed25519Falcon1024`], [`Ed25519Falcon512`], [`Ed448Falcon1024`] —
//!   combined-primitive signature constructions.
//! - [`Ed25519Blake3`], [`Ed25519Shake256`], [`Ed25519Skein512`] —
//!   Ed25519 with hash combiners (non-KDF constructions).
//! - [`Ed448Blake3`], [`Ed448Shake256`], [`Ed448Skein512`], [`Ed448Sha3_256`] —
//!   Ed448 with hash combiners.
//! - [`Ed25519ChaCha20Blake3Sha3_256`] — Ed25519 + ChaCha20-BLAKE3 + SHA3-256
//!   (KDF-based construction).
//! - [`HybridSigningKeyBundle`] — the canonical seed-derived bundle.
//! - [`falcon1024_keygen`], [`skein512`], [`skein1024`] — utility functions.

pub use crate::signing::hybrid::*;

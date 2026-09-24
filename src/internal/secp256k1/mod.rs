// SPDX-License-Identifier: Apache-2.0

//! Native secp256k1 elliptic curve implementation.
//!
//! This module provides secp256k1 field arithmetic, scalar arithmetic,
//! and point operations without external dependencies.
//!
//! Based on the secp256k1 curve parameters:
//! - Field prime p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
//! - Curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//! - Generator point G as defined in SECG standards
//!
//! CT-REVIEW(12.1): this is a hand-rolled curve implementation — field
//! and scalar arithmetic must be verified constant-time (no
//! secret-dependent branches, no compiler-inserted division or early
//! exits) before any 1.0 release. External review should pay particular
//! attention to `field.rs` reduction paths and `scalar.rs` inversion.

mod field;
mod point;
mod scalar;

pub use field::FieldElement;
pub use point::{AffinePoint, EncodedPoint, ProjectivePoint};
pub use scalar::Scalar;

// NOTE: mirror constants (CURVE_ORDER, FIELD_PRIME, GENERATOR_X/Y) used to
// live here and were kept in sync with `scalar::N`, `field::P`, and
// `point::G_*` only by a regression test. They were removed outright — the
// submodule constants are the single source of truth, so the drift bug the
// test guarded against is now structurally impossible.

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
//! CT note (Phase 12.1 sweep, resolved): scalar multiplication, point
//! add/double, and the field/scalar reduction paths are now branchless
//! (mask selects, fixed trip counts, borrow-chain comparisons). Remaining
//! data-dependent branches operate only on *public* values: `pow`'s
//! square-and-multiply on the fixed public exponents (p-2, n-2,
//! (p+1)/4), point decoding of untrusted input, and `verify`'s
//! malformed-input early returns. External review (Phase 13) should
//! still verify compiler codegen — hand-rolled curve arithmetic gets no
//! upstream assurance.

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

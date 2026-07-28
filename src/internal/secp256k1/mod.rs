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

mod field;
mod point;
mod scalar;

pub use field::FieldElement;
pub use point::{AffinePoint, EncodedPoint, ProjectivePoint};
pub use scalar::Scalar;

/// secp256k1 curve order n (little-endian limbs, matches `scalar::N`).
pub const CURVE_ORDER: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 field prime p (little-endian limbs, matches `field::P`).
pub const FIELD_PRIME: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// secp256k1 generator point G (x, y), in Montgomery form (x/y * R mod p),
/// little-endian limbs. Matches `point::G_X`/`point::G_Y`.
pub const GENERATOR_X: [u64; 4] = [
    0xd7362e5a487e2097,
    0x231e295329bc66db,
    0x979f48c033fd129c,
    0x9981e643e9089f48,
];

pub const GENERATOR_Y: [u64; 4] = [
    0xb15ea6d2d3dbabe2,
    0x8dfc5d5d1f1dc64d,
    0x70b6b59aac19c136,
    0xcf3f851fd4a582d6,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: these public constants were previously wrong
    /// (didn't match the internal, verified-correct representations used
    /// by `Scalar`, `FieldElement`, and `ProjectivePoint::GENERATOR`).
    /// Cross-check against those single sources of truth so the two can't
    /// silently drift apart again.
    #[test]
    fn public_constants_match_internal_representations() {
        assert_eq!(CURVE_ORDER, scalar::N);
        assert_eq!(FIELD_PRIME, field::P);
        assert_eq!(GENERATOR_X, point::G_X);
        assert_eq!(GENERATOR_Y, point::G_Y);
    }
}

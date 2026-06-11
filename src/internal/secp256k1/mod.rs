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

/// secp256k1 curve order n
pub const CURVE_ORDER: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
];

/// secp256k1 field prime p
pub const FIELD_PRIME: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
];

/// secp256k1 generator point G (x, y)
pub const GENERATOR_X: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

pub const GENERATOR_Y: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

// SPDX-License-Identifier: Apache-2.0

//! Curve41417 implementation
//!
//! This is a pure-Rust implementation of Curve41417, a high-security
//! elliptic curve designed by Bernstein, Chuengsatiansup, and Lange.
//!
//! # Curve Parameters
//! - Prime field: p = 2^414 - 17
//! - Security level: ~207 bits (exceeds 2^128 security target)
//! - Cofactor: 8 (twist-secure)
//!
//! # Implementation Notes
//! This implementation follows the optimization strategies described in
//! Chuengsatiansup's PhD thesis (2017), including:
//! - Small-radix limb representation for delayed carries
//! - Karatsuba multiplication for field elements
//! - Prime-specific fast reduction
//! - Constant-time Montgomery ladder for scalar multiplication
//!
//! # Status
//! This is a work-in-progress implementation. The field arithmetic and
//! scalar multiplication are being developed with correctness and
//! constant-time properties as primary goals.
//!
//! # References
//! - SafeCurves: <https://safecurves.cr.yp.to/>
//! - Original paper: Bernstein, Chuengsatiansup, Lange. "Curve41417:
//!   Karatsuba revisited" (CHES 2014)
//! - Thesis: Chuengsatiansup. "Optimizing Cryptographic Computation" (2017)

// Crypto implementation uses explicit indexing loops for clarity
// and consistency with reference implementations.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]

pub mod ed41417;
mod edwards;
mod fe;
mod mont;
mod scalar;

pub use ed41417::{Signature, SigningKey, VerifyingKey, SIGNATURE_SIZE};
pub use edwards::{
    EdwardsPoint, EDWARDS_BASE_X_BYTES, EDWARDS_BASE_Y_BYTES, EDWARDS_D_BYTES, EDWARDS_L_BYTES,
};
pub use fe::FieldElem;
pub use mont::{scalar_mult, scalar_mult_base, PublicKey, SecretKey};
pub use scalar::Scalar;

/// Size of a scalar value in bytes (414 bits, rounded to 52 bytes)
pub const SCALAR_SIZE: usize = 52;

/// Size of a packed field element / point coordinate in bytes
pub const BYTES_SIZE: usize = 52;

/// Clamp a 52-byte scalar for use with Curve41417
///
/// Sets the scalar in the range 8.{1,2,3,...,2^410-1} + 2^413
/// This ensures the scalar is a multiple of the cofactor (8) and
/// has the high bit set for constant-time ladder execution.
#[inline]
pub fn clamp_scalar(scalar: &mut [u8; SCALAR_SIZE]) {
    // Clear low 3 bits (multiply by cofactor 8)
    scalar[0] &= 248;
    // Clear top 2 bits, set bit 413
    scalar[51] = (scalar[51] & 63) | 32;
}

/// Constant-time conditional swap
///
/// Swaps `x` and `y` if `cond == 1`, leaves them unchanged if `cond == 0`.
/// This is a critical primitive for constant-time implementations.
#[inline]
pub fn cswap_bytes(cond: u8, x: &mut [u8], y: &mut [u8]) {
    debug_assert_eq!(x.len(), y.len());
    debug_assert!(cond == 0 || cond == 1);

    let mask = 0u8.wrapping_sub(cond);
    for i in 0..x.len() {
        let t = mask & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_scalar() {
        let mut s = [0u8; SCALAR_SIZE];
        s[0] = 0xFF;
        s[51] = 0xFF;
        clamp_scalar(&mut s);
        // Low 3 bits cleared
        assert_eq!(s[0] & 7, 0);
        // Top 2 bits cleared, bit 5 set
        assert_eq!(s[51] & 0xC0, 0);
        assert_eq!(s[51] & 0x20, 0x20);
    }

    #[test]
    fn test_cswap_bytes() {
        let mut x = [1u8, 2, 3, 4];
        let mut y = [5u8, 6, 7, 8];

        // cond=0: no swap
        cswap_bytes(0, &mut x, &mut y);
        assert_eq!(x, [1, 2, 3, 4]);
        assert_eq!(y, [5, 6, 7, 8]);

        // cond=1: swap
        cswap_bytes(1, &mut x, &mut y);
        assert_eq!(x, [5, 6, 7, 8]);
        assert_eq!(y, [1, 2, 3, 4]);
    }
}

// SPDX-License-Identifier: OPL-1.1

//! Montgomery ladder for Curve41417 scalar multiplication
//!
//! This module implements constant-time scalar multiplication using the
//! Montgomery ladder algorithm on the x-coordinate only representation.
//!
//! # Curve Parameters (Montgomery form)
//! The Montgomery curve By² = x³ + Ax² + x where:
//! - A = 3617 (the curve constant)
//! - B (not needed for x-only ladder)
//! - Base point x-coordinate: defined by BASEX
//!
//! # Constant-Time Properties
//! The Montgomery ladder processes every bit of the scalar in constant time,
//! with no secret-dependent branches or memory accesses.

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::fe::FieldElem;
use super::{clamp_scalar, BYTES_SIZE, SCALAR_SIZE};

/// The x-coordinate of the base point (generator) in packed form
/// This is the Montgomery x-coordinate for Curve41417's base point
const BASEX: [u8; BYTES_SIZE] = [
    0x0e, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f,
    0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c,
    0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0, 0xc1, 0x07, 0x1f, 0x7c, 0xf0,
    0xc1, 0x07, 0x1f, 0x3c,
];

/// (A + 2) / 4 = (3617 + 2) / 4 = 904.75 -> precomputed for ladder
/// Actually for Curve41417: A24 = (A + 2) / 4 where A comes from the curve
const A24: [u8; BYTES_SIZE] = [
    0x54, 0x36, 0x68, 0xf2, 0x65, 0x83, 0x26, 0x5f, 0x36, 0x68, 0xf2, 0x65, 0x83, 0x26, 0x5f, 0x36,
    0x68, 0xf2, 0x65, 0x83, 0x26, 0x5f, 0x36, 0x68, 0xf2, 0x65, 0x83, 0x26, 0x5f, 0x36, 0x68, 0xf2,
    0x65, 0x83, 0x26, 0x5f, 0x36, 0x68, 0xf2, 0x65, 0x83, 0x26, 0x5f, 0x36, 0x68, 0xf2, 0x65, 0x83,
    0x26, 0x5f, 0x36, 0x26,
];

/// A secret key for Curve41417 DH
#[derive(Clone)]
pub struct SecretKey {
    scalar: [u8; SCALAR_SIZE],
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    /// Create a secret key from raw bytes (will be clamped)
    pub fn from_bytes(bytes: [u8; SCALAR_SIZE]) -> Self {
        let mut scalar = bytes;
        clamp_scalar(&mut scalar);
        Self { scalar }
    }

    /// Generate a new random secret key
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; SCALAR_SIZE];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Get the raw scalar bytes
    pub fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.scalar
    }

    /// Derive the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let pk_bytes = scalar_mult_base(&self.scalar);
        PublicKey { point: pk_bytes }
    }

    /// Perform ECDH with a peer's public key
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        let shared = scalar_mult(&self.scalar, &peer_public.point);
        SharedSecret { secret: shared }
    }
}

/// A public key for Curve41417 DH
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    point: [u8; BYTES_SIZE],
}

impl PublicKey {
    /// Create a public key from raw bytes
    pub fn from_bytes(bytes: [u8; BYTES_SIZE]) -> Self {
        Self { point: bytes }
    }

    /// Get the raw point bytes
    pub fn as_bytes(&self) -> &[u8; BYTES_SIZE] {
        &self.point
    }
}

/// A shared secret resulting from ECDH
pub struct SharedSecret {
    secret: [u8; BYTES_SIZE],
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SharedSecret {
    /// Get the raw shared secret bytes
    pub fn as_bytes(&self) -> &[u8; BYTES_SIZE] {
        &self.secret
    }
}

/// Compute scalar multiplication: q = n * p
///
/// This is the core Montgomery ladder implementation.
/// The scalar `n` is clamped before use.
/// The point `p` is the x-coordinate of a point on the curve.
///
/// Returns the x-coordinate of the resulting point.
pub fn scalar_mult(n: &[u8; SCALAR_SIZE], p: &[u8; BYTES_SIZE]) -> [u8; BYTES_SIZE] {
    // Clamp the scalar
    let mut scalar = *n;
    clamp_scalar(&mut scalar);

    // Unpack the point
    let px = FieldElem::unpack(p);

    // Load A24 constant
    let a24 = FieldElem::unpack(&A24);

    // Montgomery ladder state
    // (x2, z2) represents the x-coordinate of 2P in projective form
    // (x3, z3) represents the x-coordinate of 3P in projective form
    let mut x2 = FieldElem::one();
    let mut z2 = FieldElem::zero();
    let mut x3 = px.clone();
    let mut z3 = FieldElem::one();

    // Process bits from high to low
    for i in (0..414).rev() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = ((scalar[byte_idx] >> bit_idx) & 1) as i64;

        // Conditional swap based on the bit
        x2.cswap(bit, &mut x3);
        z2.cswap(bit, &mut z3);

        // Montgomery ladder step
        let a = &x2 + &z2;
        let b = &x2 - &z2;
        let c = &x3 + &z3;
        let d = &x3 - &z3;

        let aa = a.square();
        let bb = b.square();

        let e = &aa - &bb;
        let da = d.mul(&a);
        let cb = c.mul(&b);

        let da_plus_cb = &da + &cb;
        let da_minus_cb = &da - &cb;

        x3 = da_plus_cb.square();
        let temp = da_minus_cb.square();
        z3 = px.mul(&temp);

        x2 = aa.mul(&bb);
        let e_times_a24 = e.mul(&a24);
        let aa_plus_e_a24 = &aa + &e_times_a24;
        z2 = e.mul(&aa_plus_e_a24);

        // Swap back
        x2.cswap(bit, &mut x3);
        z2.cswap(bit, &mut z3);
    }

    // Convert from projective to affine: x = x2 / z2
    let z2_inv = z2.inv();
    let result = x2.mul(&z2_inv);

    result.pack()
}

/// Compute scalar multiplication with the base point: q = n * G
///
/// This is a convenience function that uses the standard base point.
pub fn scalar_mult_base(n: &[u8; SCALAR_SIZE]) -> [u8; BYTES_SIZE] {
    scalar_mult(n, &BASEX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from the original curve41417.rs repository
    #[test]
    fn test_scalar_mult_base_vector() {
        let n: [u8; 52] = [
            0x75, 0x47, 0x77, 0x21, 0xf3, 0xa2, 0x5f, 0x89, 0x4b, 0x1d, 0x96, 0x01, 0xf5, 0xcb,
            0x7b, 0x16, 0xc9, 0x91, 0x95, 0x33, 0xc6, 0x2f, 0x54, 0x9a, 0x4a, 0x8c, 0x4c, 0x1b,
            0xd3, 0xef, 0xd3, 0x2d, 0x59, 0x54, 0xcc, 0x76, 0xa2, 0x4f, 0x01, 0x87, 0x41, 0x3e,
            0x97, 0x41, 0x8d, 0x5b, 0x15, 0xf2, 0x71, 0x4b, 0x71, 0x97,
        ];

        let expected: [u8; 52] = [
            0xce, 0x75, 0x76, 0x43, 0x9e, 0x55, 0x05, 0x27, 0x69, 0x92, 0xc0, 0x47, 0x4f, 0x30,
            0x57, 0x52, 0x36, 0x1a, 0xd8, 0x75, 0x20, 0xb2, 0x20, 0xb9, 0x56, 0xb6, 0xa1, 0x04,
            0xe7, 0x1f, 0xaa, 0x23, 0xc1, 0x8c, 0xc1, 0x40, 0x00, 0x18, 0x6f, 0xdd, 0x79, 0x26,
            0x67, 0x18, 0xa9, 0x07, 0x11, 0x21, 0x84, 0xb8, 0xd7, 0x1c,
        ];

        let result = scalar_mult_base(&n);
        assert_eq!(result, expected, "Test vector mismatch");
    }

    /// Test Diffie-Hellman key agreement
    #[test]
    fn test_dh_agreement() {
        // Two parties generate keypairs
        let sk1_bytes: [u8; 52] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
        ];

        let sk2_bytes: [u8; 52] = [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
            0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
            0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
            0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
        ];

        let sk1 = SecretKey::from_bytes(sk1_bytes);
        let sk2 = SecretKey::from_bytes(sk2_bytes);

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        // Both parties compute the shared secret
        let shared1 = sk1.diffie_hellman(&pk2);
        let shared2 = sk2.diffie_hellman(&pk1);

        // They should agree
        assert_eq!(
            shared1.as_bytes(),
            shared2.as_bytes(),
            "DH key agreement failed"
        );
    }

    /// Test that different keys produce different public keys
    #[test]
    fn test_different_keys() {
        let sk1_bytes: [u8; 52] = [1u8; 52];
        let sk2_bytes: [u8; 52] = [2u8; 52];

        let sk1 = SecretKey::from_bytes(sk1_bytes);
        let sk2 = SecretKey::from_bytes(sk2_bytes);

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        assert_ne!(
            pk1, pk2,
            "Different secrets should produce different public keys"
        );
    }
}

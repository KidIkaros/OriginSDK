// SPDX-License-Identifier: OPL-1.1

//! Field element arithmetic for Curve41417 (matching seb-m representation)
//!
//! This module implements arithmetic in the prime field Fp where p = 2^414 - 17.
//!
//! # Representation
//! Field elements use 26 limbs of 16 bits each, stored in i64 for signed
//! arithmetic during carry propagation. This matches the seb-m/curve41417.rs
//! reference implementation.
//!
//! Total bits: 26 × 16 = 416 bits (covers 414-bit prime with room for carries)
//!
//! # Constant-Time Properties
//! All operations use arithmetic masking for conditional operations.

use core::ops::{Add, Mul, Neg, Sub};
use zeroize::Zeroize;

use super::BYTES_SIZE;

/// Number of limbs in a field element (26 × 16 bits = 416 bits)
const FE_SIZE: usize = 26;

/// A field element in Fp where p = 2^414 - 17
///
/// Internally represented as 26 limbs of 16 bits each (stored in i64).
#[derive(Clone, Debug)]
pub struct FieldElem {
    limbs: [i64; FE_SIZE],
}

impl Zeroize for FieldElem {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl Drop for FieldElem {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FieldElem {
    /// Create a new zero field element
    #[inline]
    pub const fn zero() -> Self {
        Self {
            limbs: [0i64; FE_SIZE],
        }
    }

    /// Create the multiplicative identity (1)
    #[inline]
    pub const fn one() -> Self {
        let mut limbs = [0i64; FE_SIZE];
        limbs[0] = 1;
        Self { limbs }
    }

    /// Unpack a field element from 52 bytes (little-endian)
    ///
    /// Each limb gets 2 bytes. Top 2 bits of byte 51 are masked off.
    pub fn unpack(bytes: &[u8; BYTES_SIZE]) -> Self {
        let mut result = Self::zero();
        for i in 0..FE_SIZE {
            result.limbs[i] = bytes[2 * i] as i64 + ((bytes[2 * i + 1] as i64) << 8);
        }
        // Mask top 2 bits (limb 25 holds bits 400-415, we want 400-413)
        result.limbs[25] &= 0x3fff;
        result
    }

    /// Pack a field element to 52 bytes (little-endian)
    ///
    /// The element is fully reduced before packing.
    pub fn pack(&self) -> [u8; BYTES_SIZE] {
        let mut t = self.clone();
        t.reduce();

        let mut result = [0u8; BYTES_SIZE];
        for i in 0..FE_SIZE {
            result[2 * i] = (t.limbs[i] & 0xff) as u8;
            result[2 * i + 1] = (t.limbs[i] >> 8) as u8;
        }
        result
    }

    /// Constant-time conditional swap
    ///
    /// Swaps `self` with `other` if `cond == 1`, no-op if `cond == 0`.
    #[inline]
    pub fn cswap(&mut self, cond: i64, other: &mut Self) {
        debug_assert!(cond == 0 || cond == 1);
        let mask = !(cond - 1);
        for i in 0..FE_SIZE {
            let t = mask & (self.limbs[i] ^ other.limbs[i]);
            self.limbs[i] ^= t;
            other.limbs[i] ^= t;
        }
    }

    /// Propagate carries through the limbs
    ///
    /// Each limb is reduced to 16 bits, with carry propagating to the next.
    /// Carry out of limb 25 wraps around with factor 67 (since 2^416 ≡ 68 mod p,
    /// but we handle the +1 bias separately).
    #[inline]
    pub fn carry(&mut self) {
        let mut c: i64;
        for i in 0..FE_SIZE {
            self.limbs[i] += 1i64 << 16;
            c = self.limbs[i] >> 16;
            // If i < 25, add carry to next limb
            // If i == 25, add (c-1)*67 + (c-1) = (c-1)*68 to limb 0, but actually
            // the formula is: limb[(i+1) * (i<25)] += c - 1 + 67*(c-1)*(i==25)
            self.limbs[(i + 1) * ((i < 25) as usize)] += c - 1 + 67 * (c - 1) * ((i == 25) as i64);
            self.limbs[i] -= c << 16;
        }
    }

    /// Fully reduce modulo p = 2^414 - 17
    ///
    /// After this operation, the element is in canonical form [0, p-1].
    pub fn reduce(&mut self) {
        self.carry();
        self.carry();
        self.carry();

        let mut m = Self::zero();

        for _ in 0..3 {
            // m = self - p = self - (2^414 - 17) = self + 17 - 2^414
            // p in our representation: limbs 0-24 are 0xffff, limb 25 is 0x3fff
            // So m[0] = self[0] - 0xffef (since p[0] = 0xffff - 17 + 1 for borrow... actually simpler)
            // p = 2^414 - 17, in 16-bit limbs:
            // limb 0: (2^414 - 17) mod 2^16 = -17 mod 2^16 = 0xffef
            // limbs 1-24: 0xffff (with borrow propagation)
            // limb 25: 0x3fff
            m.limbs[0] = self.limbs[0] - 0xffef;
            for j in 1..25 {
                m.limbs[j] = self.limbs[j] - 0xffff - ((m.limbs[j - 1] >> 16) & 1);
                m.limbs[j - 1] &= 0xffff;
            }
            m.limbs[25] = self.limbs[25] - 0x3fff - ((m.limbs[24] >> 16) & 1);
            m.limbs[24] &= 0xffff;

            // If m[25] < 0 (borrow occurred), then self < p, keep self
            // If m[25] >= 0, then self >= p, use m
            let b = (m.limbs[25] >> 16) & 1;
            m.limbs[25] &= 0xffff;
            self.cswap(1 - b, &mut m);
        }
    }

    /// Add two field elements
    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..FE_SIZE {
            self.limbs[i] += other.limbs[i];
        }
    }

    /// Subtract a field element
    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..FE_SIZE {
            self.limbs[i] -= other.limbs[i];
        }
    }

    /// Square a field element
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Multiply two field elements
    ///
    /// Uses schoolbook multiplication with reduction mod p = 2^414 - 17.
    pub fn mul(&self, other: &Self) -> Self {
        let mut u: i64;
        let mut result = Self::zero();

        for i in 0..FE_SIZE {
            u = 0;
            // Lower part: j in [0, i]
            for j in 0..=i {
                u += self.limbs[j] * other.limbs[i - j];
            }
            // Upper part: j in [i+1, FE_SIZE-1], with reduction factor 68
            // These terms contribute to limb i with factor 68 (since 2^416 ≡ 68 mod p)
            for j in (i + 1)..FE_SIZE {
                u += 68 * self.limbs[j] * other.limbs[i + FE_SIZE - j];
            }
            result.limbs[i] = u;
        }

        result.carry();
        result.carry();
        result
    }

    /// Check if the element is zero
    pub fn is_zero(&self) -> bool {
        let mut t = self.clone();
        t.reduce();
        for limb in t.limbs.iter() {
            if *limb != 0 {
                return false;
            }
        }
        true
    }

    /// Get the parity bit (LSB of the canonical representation)
    pub fn parity(&self) -> u8 {
        let packed = self.pack();
        packed[0] & 1
    }

    /// Compute the multiplicative inverse using Fermat's little theorem
    ///
    /// a^(-1) = a^(p-2) mod p
    /// where p - 2 = 2^414 - 19
    pub fn inv(&self) -> Self {
        // p - 2 = 2^414 - 19
        // 19 = 10011 in binary, 18 = 10010
        // 2^414 - 19 = (2^414 - 1) - 18
        // (2^414 - 1) is all 1s, subtracting 18 (10010):
        // Low 5 bits: 11111 - 10010 = 01101
        // So bit 1 = 0, bit 4 = 0, all other bits = 1

        let mut result = self.clone();

        for i in (0..413).rev() {
            result = result.square();
            // Multiply by self for each bit that is 1 in (p-2)
            // Bits 1 and 4 are 0; all others are 1
            if i != 1 && i != 4 {
                result = result.mul(self);
            }
        }

        result
    }
}

impl Add for &FieldElem {
    type Output = FieldElem;

    fn add(self, other: &FieldElem) -> FieldElem {
        let mut result = self.clone();
        result.add_assign(other);
        result
    }
}

impl Sub for &FieldElem {
    type Output = FieldElem;

    fn sub(self, other: &FieldElem) -> FieldElem {
        let mut result = self.clone();
        result.sub_assign(other);
        result
    }
}

impl Mul for &FieldElem {
    type Output = FieldElem;

    fn mul(self, other: &FieldElem) -> FieldElem {
        self.mul(other)
    }
}

impl PartialEq for FieldElem {
    fn eq(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.reduce();
        b.reduce();
        a.limbs == b.limbs
    }
}

impl Eq for FieldElem {}

impl Neg for &FieldElem {
    type Output = FieldElem;

    fn neg(self) -> FieldElem {
        let mut result = FieldElem::zero();
        for i in 0..FE_SIZE {
            result.limbs[i] = -self.limbs[i];
        }
        result
    }
}

impl Neg for FieldElem {
    type Output = FieldElem;

    fn neg(self) -> FieldElem {
        -&self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack() {
        let mut bytes = [0u8; BYTES_SIZE];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[50] = 0xAB;
        bytes[51] = 0x3F; // Top 2 bits will be masked

        let fe = FieldElem::unpack(&bytes);
        let repacked = fe.pack();

        // Top 2 bits are masked, so compare with that expectation
        let mut expected = bytes;
        expected[51] &= 0x3F;
        assert_eq!(repacked, expected);
    }

    #[test]
    fn test_add_sub_inverse() {
        let mut a_bytes = [0u8; BYTES_SIZE];
        a_bytes[0] = 100;
        let a = FieldElem::unpack(&a_bytes);

        let mut b_bytes = [0u8; BYTES_SIZE];
        b_bytes[0] = 50;
        let b = FieldElem::unpack(&b_bytes);

        let sum = &a + &b;
        let diff = &sum - &b;

        assert_eq!(a, diff);
    }

    #[test]
    fn test_mul_one() {
        let mut a_bytes = [0u8; BYTES_SIZE];
        a_bytes[0] = 42;
        let a = FieldElem::unpack(&a_bytes);

        let one = FieldElem::one();
        let prod = a.mul(&one);

        assert_eq!(a, prod);
    }

    #[test]
    fn test_mul_zero() {
        let mut a_bytes = [0u8; BYTES_SIZE];
        a_bytes[0] = 42;
        let a = FieldElem::unpack(&a_bytes);

        let zero = FieldElem::zero();
        let prod = a.mul(&zero);

        assert!(prod.is_zero());
    }

    #[test]
    fn test_square() {
        let mut a_bytes = [0u8; BYTES_SIZE];
        a_bytes[0] = 7;
        let a = FieldElem::unpack(&a_bytes);

        let sq = a.square();
        let mul = a.mul(&a);

        assert_eq!(sq, mul);
    }

    #[test]
    fn test_cswap() {
        let mut a_bytes = [0u8; BYTES_SIZE];
        a_bytes[0] = 1;
        let mut a = FieldElem::unpack(&a_bytes);

        let mut b_bytes = [0u8; BYTES_SIZE];
        b_bytes[0] = 2;
        let mut b = FieldElem::unpack(&b_bytes);

        let a_orig = a.clone();
        let b_orig = b.clone();

        // No swap
        a.cswap(0, &mut b);
        assert_eq!(a, a_orig);
        assert_eq!(b, b_orig);

        // Swap
        a.cswap(1, &mut b);
        assert_eq!(a, b_orig);
        assert_eq!(b, a_orig);
    }
}

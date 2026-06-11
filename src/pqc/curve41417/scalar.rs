// SPDX-License-Identifier: Apache-2.0

//! Curve41417 scalar field arithmetic.
//!
//! This module uses explicit indexing loops which are intentional for
//! clarity and consistency with reference implementations.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]

use core::ops::{Add, Mul, Neg, Sub};

use rand::{CryptoRng, RngCore};

use crate::internal::zeroize::Zeroize;

use super::{EDWARDS_L_BYTES, SCALAR_SIZE};

const LD: [u8; 27] = [
    0xe0, 0x10, 0x2a, 0xdf, 0x43, 0xcb, 0x31, 0x9e, 0xfc, 0x1c, 0x86, 0x53, 0xea, 0x98, 0x7f, 0x1c,
    0x92, 0xa9, 0xfb, 0xf3, 0x11, 0x66, 0x7d, 0xdb, 0x66, 0x98, 0x02,
];

/// A scalar modulo the Curve41417 prime subgroup order.
#[derive(Clone, Debug)]
pub struct Scalar {
    limbs: [i64; SCALAR_SIZE],
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.limbs.zeroize();
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Scalar {
    /// The additive identity.
    #[inline]
    pub const fn zero() -> Self {
        Self {
            limbs: [0i64; SCALAR_SIZE],
        }
    }

    /// The multiplicative identity.
    #[inline]
    pub fn one() -> Self {
        let mut limbs = [0i64; SCALAR_SIZE];
        limbs[0] = 1;
        Self { limbs }
    }

    #[inline]
    fn cswap(&mut self, cond: i64, other: &mut Self) {
        debug_assert!(cond == 0 || cond == 1);
        let mask = !(cond - 1);
        for i in 0..SCALAR_SIZE {
            let t = mask & (self.limbs[i] ^ other.limbs[i]);
            self.limbs[i] ^= t;
            other.limbs[i] ^= t;
        }
    }

    fn carry(&mut self) {
        for i in 0..(SCALAR_SIZE - 1) {
            self.limbs[i] += 1i64 << 8;
            let carry = self.limbs[i] >> 8;
            self.limbs[i + 1] += carry - 1;
            self.limbs[i] -= carry << 8;
        }

        let top = SCALAR_SIZE - 1;
        self.limbs[top] += 1i64 << 8;
        let carry = self.limbs[top] >> 8;
        for i in 0..27 {
            self.limbs[i] += (carry - 1) * (LD[i] as i64);
        }
        self.limbs[top] -= carry << 8;
    }

    fn reduce_weak(&mut self, n: &[i64]) {
        debug_assert!(n.len() > SCALAR_SIZE);
        debug_assert!(n.len() <= 104);

        let mut t = [0i64; 78];
        for i in 0..SCALAR_SIZE {
            t[i] = n[i];
        }

        for i in SCALAR_SIZE..n.len() {
            for j in 0..27 {
                t[i + j - SCALAR_SIZE] += n[i] * (LD[j] as i64);
            }
        }

        for i in SCALAR_SIZE..(n.len() - 26) {
            for j in 0..27 {
                t[i + j - SCALAR_SIZE] += t[i] * (LD[j] as i64);
            }
        }

        for i in 0..SCALAR_SIZE {
            self.limbs[i] = t[i];
        }

        self.carry();
        self.carry();
    }

    fn reduce(&mut self) {
        self.carry();
        self.carry();

        let k = self.limbs[SCALAR_SIZE - 1] >> 3;

        let mut carry: i64 = 0;
        for i in 0..SCALAR_SIZE {
            self.limbs[i] += carry - k * (EDWARDS_L_BYTES[i] as i64);
            carry = self.limbs[i] >> 8;
            self.limbs[i] &= 0xff;
        }

        let mut m = Scalar::zero();
        carry = 0;
        for i in 0..SCALAR_SIZE {
            m.limbs[i] = self.limbs[i] + carry - (EDWARDS_L_BYTES[i] as i64);
            carry = m.limbs[i] >> 8;
            m.limbs[i] &= 0xff;
        }
        self.cswap(1 - (carry & 1), &mut m);
    }

    /// Serialize this scalar to canonical little-endian bytes.
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        let mut t = self.clone();
        t.reduce();

        let mut out = [0u8; SCALAR_SIZE];
        for i in 0..SCALAR_SIZE {
            out[i] = (t.limbs[i] & 0xff) as u8;
        }
        out
    }

    /// Return `true` if this scalar is zero.
    pub fn is_zero(&self) -> bool {
        let mut t = self.clone();
        t.reduce();
        let mut acc = 0i64;
        for limb in &t.limbs {
            acc |= *limb;
        }
        acc == 0
    }

    /// Parse a scalar from canonical little-endian bytes.
    ///
    /// Returns `None` if `bytes` is not a canonical encoding (i.e. it is >= the subgroup order).
    pub fn from_canonical_bytes(bytes: &[u8; SCALAR_SIZE]) -> Option<Self> {
        let mut s = Self::zero();
        for i in 0..SCALAR_SIZE {
            s.limbs[i] = bytes[i] as i64;
        }

        let mut carry: i64 = 0;
        for i in 0..SCALAR_SIZE {
            let v = s.limbs[i] + carry - (EDWARDS_L_BYTES[i] as i64);
            carry = v >> 8;
        }

        if (carry & 1) == 1 {
            Some(s)
        } else {
            None
        }
    }

    /// Reduce `bytes` modulo the subgroup order and return the resulting scalar.
    pub fn from_bytes_mod_order(bytes: &[u8; SCALAR_SIZE]) -> Self {
        let mut s = Self::zero();
        for i in 0..SCALAR_SIZE {
            s.limbs[i] = bytes[i] as i64;
        }
        s.reduce();
        s
    }

    /// Reduce a wide byte string modulo the subgroup order.
    ///
    /// Accepts 64..=104 bytes and returns `None` for other lengths.
    pub fn from_bytes_mod_order_wide(bytes: &[u8]) -> Option<Self> {
        if !(64..=104).contains(&bytes.len()) {
            return None;
        }

        let mut t = [0i64; 104];
        for i in 0..bytes.len() {
            t[i] = bytes[i] as i64;
        }

        let mut s = Self::zero();
        s.reduce_weak(&t[..bytes.len()]);
        Some(s)
    }

    /// Generate a random scalar.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 104];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_mod_order_wide(&bytes).unwrap()
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Scalar {}

impl Add for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        let mut r = self.clone();
        for i in 0..SCALAR_SIZE {
            r.limbs[i] += other.limbs[i];
        }
        r
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        let mut r = self.clone();
        for i in 0..SCALAR_SIZE {
            r.limbs[i] -= other.limbs[i];
        }
        r
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        &Scalar::zero() - self
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        let mut t = [0i64; 103];
        for i in 0..SCALAR_SIZE {
            for j in 0..SCALAR_SIZE {
                t[i + j] += self.limbs[i] * other.limbs[j];
            }
        }

        let mut r = Scalar::zero();
        r.reduce_weak(&t);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_canonical_reject_l() {
        let l = EDWARDS_L_BYTES;
        assert!(Scalar::from_canonical_bytes(&l).is_none());
    }

    #[test]
    fn test_from_canonical_accept_zero_and_l_minus_one() {
        let z = [0u8; SCALAR_SIZE];
        assert!(Scalar::from_canonical_bytes(&z).is_some());

        let mut lm1 = EDWARDS_L_BYTES;
        let mut borrow = 1u16;
        for b in &mut lm1 {
            let v = (*b as u16).wrapping_sub(borrow);
            *b = v as u8;
            borrow = if v >> 8 == 1 { 1 } else { 0 };
            if borrow == 0 {
                break;
            }
        }
        assert!(Scalar::from_canonical_bytes(&lm1).is_some());
    }

    #[test]
    fn test_reduce_wide_canonical() {
        let wide = [0xffu8; 64];
        let s = Scalar::from_bytes_mod_order_wide(&wide).unwrap();
        let bytes = s.to_bytes();
        assert!(Scalar::from_canonical_bytes(&bytes).is_some());
    }

    #[test]
    fn test_ops_consistency() {
        let mut rng = rand::rngs::OsRng;
        let a = Scalar::random(&mut rng);

        let apa = &a + &a;
        let aaa1 = &a * &apa;
        let s1 = &aaa1 - &a;

        let aa = &a * &a;
        let aaa2 = &aa + &aa;
        let s2 = &aaa2 - &a;

        assert_eq!(s1, s2);
    }

    #[test]
    fn test_mul_one_zero() {
        let mut rng = rand::rngs::OsRng;
        let a = Scalar::random(&mut rng);

        assert_eq!(&a * &Scalar::one(), a);
        assert!((&a * &Scalar::zero()).is_zero());
    }
}

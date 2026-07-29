// SPDX-License-Identifier: Apache-2.0

//! secp256k1 field arithmetic.
//!
//! Field elements are 256-bit integers modulo p where:
//! p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
//!
//! Represented as 4 u64 limbs in little-endian order.

use crate::internal::subtle::{Choice, ConstantTimeEq};

/// secp256k1 field prime p
pub(crate) const P: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// secp256k1 field R = 2^256 mod p (Montgomery radix)
/// p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
/// => 2^256 mod p = 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1 = 0x1000003d1
const R: [u64; 4] = [0x0000_0001_0000_03d1, 0x0, 0x0, 0x0];

/// secp256k1 field R^2 mod p = (2^256)^2 mod p = 0x7a2000e90a1 (little-endian limb 0)
const R2: [u64; 4] = [0x0000_07a2_000e_90a1, 0x0000_0000_0000_0001, 0x0, 0x0];

/// Montgomery reduction constant: -P[0]^{-1} mod 2^64.
const INV: u64 = 0xd838_091d_d225_3531;

/// Field element in Montgomery representation
#[derive(Clone, Copy, Debug)]
pub struct FieldElement {
    limbs: [u64; 4],
}

/// Small integer constants in Montgomery form (value * R mod p).
/// Used by the point arithmetic formulas. Precomputed:
///   2 => 0x2_0000_07a2, 3 => 0x3_0000_0b73,
///   4 => 0x4_0000_0f44, 8 => 0x8_0000_1e88   (limb 0, others 0)
impl FieldElement {
    /// Integer 2 in Montgomery form.
    pub const TWO: Self = Self {
        limbs: [0x0000_0002_0000_07a2, 0, 0, 0],
    };
    /// Integer 3 in Montgomery form.
    pub const THREE: Self = Self {
        limbs: [0x0000_0003_0000_0b73, 0, 0, 0],
    };
    /// Integer 4 in Montgomery form.
    pub const FOUR: Self = Self {
        limbs: [0x0000_0004_0000_0f44, 0, 0, 0],
    };
    /// Integer 8 in Montgomery form.
    pub const EIGHT: Self = Self {
        limbs: [0x0000_0008_0000_1e88, 0, 0, 0],
    };

    /// Zero element
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// One element (in Montgomery form)
    pub const ONE: Self = Self { limbs: R };

    /// Create a field element from raw limbs (assumes Montgomery form)
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create a field element from a 32-byte big-endian representation
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            limbs[3 - i] = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        // Convert to Montgomery form: x * R mod p
        Self::from_limbs(limbs).to_montgomery()
    }

    /// Convert to 32-byte big-endian representation
    pub fn to_bytes(&self) -> [u8; 32] {
        let normalized = self.normalize();
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = i * 8;
            let limb_bytes = normalized.limbs[3 - i].to_be_bytes();
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Convert to Montgomery form (multiply by R)
    fn to_montgomery(&self) -> Self {
        self.mul(&Self::from_limbs(R2))
    }

    /// Normalize from Montgomery form (divide by R, i.e., multiply by raw 1).
    /// `mul` is Montgomery multiplication (it already divides by R once via
    /// REDC), so multiplying by the raw value 1 (not `R`, which is the
    /// Montgomery form of 1) is what actually removes the R factor.
    fn normalize(&self) -> Self {
        self.mul(&Self::from_limbs([1, 0, 0, 0]))
    }

    /// Check if the element is zero
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Addition: self + rhs mod p
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;

        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(rhs.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = u64::from(c1) + u64::from(c2);
        }

        let res = Self::from_limbs(result);
        res.reduce_if_carry_or_gte_p(carry)
    }

    /// Subtraction: self - rhs mod p
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;

        for i in 0..4 {
            let (diff1, b1) = self.limbs[i].overflowing_sub(rhs.limbs[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = u64::from(b1) + u64::from(b2);
        }

        // If we borrowed, add p back
        let res = Self::from_limbs(result);
        res.conditional_add_p(borrow)
    }

    /// Multiplication: self * rhs, interpreted as Montgomery multiplication.
    ///
    /// Computes (self * rhs) / R mod p via standard schoolbook
    /// multiplication followed by Montgomery reduction (REDC), so that
    /// if `self` and `rhs` are Montgomery representations (x*R mod p),
    /// the result is (x*y*R) mod p, also a valid Montgomery representation.
    pub fn mul(&self, rhs: &Self) -> Self {
        // t holds the running 576-bit accumulator (9 limbs) during
        // multiply + reduce; index 8 absorbs carries beyond limb 7.
        let mut t = [0u64; 9];

        // Schoolbook product into t[0..8].
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let prod = u128::from(self.limbs[i]) * u128::from(rhs.limbs[j]);
                let sum = prod + u128::from(t[i + j]) + u128::from(carry);
                t[i + j] = sum as u64;
                carry = (sum >> 64) as u64;
            }
            t[i + 4] = t[i + 4].wrapping_add(carry);
        }

        // Montgomery reduction (REDC): for each of the 4 low limbs,
        // add a multiple of p that clears that limb, then shift.
        for i in 0..4 {
            let u = t[i].wrapping_mul(INV);
            let mut carry: u128 = 0;
            for j in 0..4 {
                let prod = u128::from(u) * u128::from(P[j]) + u128::from(t[i + j]) + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }
            // Propagate remaining carry into higher limbs.
            let mut k = i + 4;
            while carry != 0 {
                let sum = u128::from(t[k]) + carry;
                t[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        let mut result = Self::from_limbs([t[4], t[5], t[6], t[7]]);

        // Account for the carry-out bit from the REDC shift: since
        // R = 2^256 mod p, a carry-out of 1 contributes exactly R.
        // Using `add` (not `sub`) here is important: `sub` auto-corrects
        // underflow by adding P back, which would cancel this
        // correction whenever `result` is already < P.
        if t[8] != 0 {
            result = result.add(&Self::from_limbs(R));
        }

        // At this point result < 2p, so at most one subtraction of p
        // is needed, and it is guaranteed not to underflow.
        if bool::from(result.is_gte_p()) {
            result = result.sub(&Self::from_limbs(P));
        }
        result
    }

    /// Modular reduction to [0, p)
    #[allow(dead_code)]
    fn reduce(&self) -> Self {
        self.reduce_if_carry_or_gte_p(0)
    }

    /// Conditional reduction
    fn reduce_if_carry_or_gte_p(&self, carry: u64) -> Self {
        let mut result = self.limbs;

        // Subtract p if result >= p or there's a carry
        let gte_p = self.is_gte_p() | Choice::from_bool(carry != 0);

        // Conditionally subtract p
        let p_limbs = P;
        let mut borrow = 0u64;
        let mut sub_result = [0u64; 4];

        for i in 0..4 {
            let (p_plus_borrow, carry) = p_limbs[i].overflowing_add(borrow);
            let (diff, b) = result[i].overflowing_sub(p_plus_borrow);
            sub_result[i] = diff;
            borrow = u64::from(b | carry);
        }

        // Select between result and sub_result based on gte_p
        for i in 0..4 {
            result[i] = if gte_p.is_true() {
                sub_result[i]
            } else {
                result[i]
            };
        }

        Self::from_limbs(result)
    }

    /// Conditionally add p if borrow occurred
    fn conditional_add_p(&self, borrow: u64) -> Self {
        if borrow == 0 {
            *self
        } else {
            let mut result = [0u64; 4];
            let mut carry = 0u64;
            for i in 0..4 {
                let (sum, c1) = self.limbs[i].overflowing_add(P[i]);
                let (sum2, c2) = sum.overflowing_add(carry);
                result[i] = sum2;
                carry = u64::from(c1) + u64::from(c2);
            }
            Self::from_limbs(result)
        }
    }

    /// Check if self >= p
    fn is_gte_p(&self) -> Choice {
        for i in (0..4).rev() {
            if self.limbs[i] > P[i] {
                return Choice::from_bool(true);
            } else if self.limbs[i] < P[i] {
                return Choice::from_bool(false);
            }
        }
        Choice::from_bool(true) // Equal
    }

    /// Inversion: self^(-1) mod p using Fermat's little theorem
    /// self^(-1) = self^(p-2) mod p
    pub fn invert(&self) -> Self {
        // p - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        let exponent: [u64; 4] = [
            0xFFFF_FFFE_FFFF_FC2D,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
        ];
        self.pow(&exponent)
    }

    /// Exponentiation: self^exp mod p
    fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;

        for word in exp.iter() {
            for i in 0..64 {
                if (word >> i) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
            }
        }

        result
    }

    /// Negation: -self mod p
    pub fn neg(&self) -> Self {
        if self.is_zero().is_true() {
            *self
        } else {
            Self::from_limbs(P).sub(self)
        }
    }

    /// Square root: sqrt(self) mod p
    /// For secp256k1, p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
    pub fn sqrt(&self) -> Self {
        // (p + 1) / 4 = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C
        let sqrt_exp: [u64; 4] = [
            0xFFFF_FFFF_BFFF_FF0C,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x3FFF_FFFF_FFFF_FFFF,
        ];
        self.pow(&sqrt_exp)
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut result = 1u8;
        for i in 0..4 {
            result &= u8::from(self.limbs[i] == other.limbs[i]);
        }
        Choice(result)
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn mul_small_values() {
        let a = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 6;
            b
        });
        let b = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        });
        let c = a.mul(&b).to_bytes();
        assert_eq!(c[31], 42);
        assert!(c[..31].iter().all(|&x| x == 0));
    }

    #[test]
    fn mul_identity_roundtrip() {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let mut ab = [0u8; 32];
            rng.fill_bytes(&mut ab);
            let a = FieldElement::from_bytes(&ab);
            assert_eq!(a.mul(&FieldElement::ONE).to_bytes(), ab);
        }
    }

    #[test]
    fn mul_is_associative_and_distributive() {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let mut ab = [0u8; 32];
            let mut bb = [0u8; 32];
            let mut cb = [0u8; 32];
            rng.fill_bytes(&mut ab);
            rng.fill_bytes(&mut bb);
            rng.fill_bytes(&mut cb);
            let a = FieldElement::from_bytes(&ab);
            let b = FieldElement::from_bytes(&bb);
            let c = FieldElement::from_bytes(&cb);
            assert!(bool::from(a.mul(&b).mul(&c).ct_eq(&a.mul(&b.mul(&c)))));
            assert!(bool::from(
                a.add(&b).mul(&c).ct_eq(&a.mul(&c).add(&b.mul(&c)))
            ));
        }
    }

    #[test]
    fn invert_roundtrip() {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let mut ab = [0u8; 32];
            rng.fill_bytes(&mut ab);
            let a = FieldElement::from_bytes(&ab);
            if bool::from(a.is_zero()) {
                continue;
            }
            let inv = a.invert();
            assert!(bool::from(a.mul(&inv).ct_eq(&FieldElement::ONE)));
        }
    }
}

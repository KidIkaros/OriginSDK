// SPDX-License-Identifier: OPL-1.1

//! secp256k1 field arithmetic.
//!
//! Field elements are 256-bit integers modulo p where:
//! p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
//!
//! Represented as 4 u64 limbs in little-endian order.

use crate::internal::subtle::{Choice, ConstantTimeEq};

/// secp256k1 field prime p
const P: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// secp256k1 field R = 2^256 mod p (Montgomery radix)
const R: [u64; 4] = [
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// secp256k1 field R^2 mod p
const R2: [u64; 4] = [
    0x0000000000000007,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
];

/// Field element in Montgomery representation
#[derive(Clone, Copy, Debug)]
pub struct FieldElement {
    limbs: [u64; 4],
}

impl FieldElement {
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

    /// Normalize from Montgomery form (divide by R, i.e., multiply by 1)
    fn normalize(&self) -> Self {
        self.mul(&Self::from_limbs(R))
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

    /// Multiplication: self * rhs mod p
    ///
    /// Uses the "wide reduction trick": a 5-limb u64 accumulator holds
    /// the full 512-bit product, reducing once at the end instead of
    /// repeatedly during multiplication. This matches the approach
    /// described in Filippo Valsorda's "A Wide Reduction Trick".
    pub fn mul(&self, rhs: &Self) -> Self {
        // 5-limb accumulator for the 512-bit intermediate product.
        // t[0..4] hold the low 256 bits, t[4] holds the overflow.
        let mut t = [0u64; 5];

        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let prod = u128::from(self.limbs[j]).wrapping_mul(u128::from(rhs.limbs[i]));
                let sum = prod + u128::from(t[j]) + u128::from(carry);
                t[j] = sum as u64;
                carry = (sum >> 64) as u64;
            }
            t[4] = t[4].wrapping_add(carry);
        }

        // Final reduction: result = low 4 limbs; if overflow limb is
        // non-zero or low 4 limbs >= p, subtract p once.
        let mut result = Self::from_limbs([t[0], t[1], t[2], t[3]]);
        let overflow = t[4];
        let gte_p = result.is_gte_p();

        // Constant-time conditional subtraction
        let needs_reduce = Choice::from_bool(overflow != 0) | gte_p;
        if bool::from(needs_reduce) {
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

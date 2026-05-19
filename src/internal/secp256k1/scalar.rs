// SPDX-License-Identifier: OPL-1.1

//! secp256k1 scalar arithmetic.
//!
//! Scalars are integers modulo n where:
//! n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//!
//! Used for secret keys, nonces, and signature components.

use crate::internal::subtle::{Choice, ConstantTimeEq, CtOption};
use core::ops::{Add, Mul, Neg, Sub};

/// Curve order n
const N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFE,
];

/// 2^256 mod n (Montgomery radix)
const R: [u64; 4] = [
    0xdf1f_2c66_1a85_ebe1,
    0x5d7f_7e9e_41d3_06ee,
    0x6b7d_eef0_443e_7d84,
    0x59e2_6b14_1a7c_5b65,
];

/// R^2 mod n
const R2: [u64; 4] = [
    0x6e2e_5476_4329_1250,
    0x1ad4_c521_d76b_831d,
    0x2845_4783_74cb_a971,
    0x48cf_1a4e_144c_4447,
];

/// Scalar element modulo curve order n
#[derive(Clone, Copy, Debug, Default)]
pub struct Scalar {
    limbs: [u64; 4],
}

impl Scalar {
    /// Zero scalar
    pub const ZERO: Self = Self { limbs: [0, 0, 0, 0] };

    /// One scalar
    pub const ONE: Self = Self {
        limbs: [
            0xdf1f_2c66_1a85_ebe1,
            0x5d7f_7e9e_41d3_06ee,
            0x6b7d_eef0_443e_7d84,
            0x59e2_6b14_1a7c_5b65,
        ],
    };

    /// Create from raw limbs
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create from 32-byte representation
    pub fn from_repr(bytes: &[u8; 32]) -> CtOption<Self> {
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

        // Check if value < n
        let is_valid = is_lt_n(&limbs);

        let val = Self::from_limbs(limbs).to_montgomery();
        CtOption::new(val, is_valid)
    }

    /// Convert to 32-byte representation
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

    /// Convert to Montgomery form
    fn to_montgomery(&self) -> Self {
        self.mul(&Self::from_limbs(R2))
    }

    /// Normalize from Montgomery form
    fn normalize(&self) -> Self {
        self.mul(&Self::from_limbs(R))
    }

    /// Addition
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
        res.reduce_if_carry_or_gte_n(carry)
    }

    /// Subtraction
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;

        for i in 0..4 {
            let (diff1, b1) = self.limbs[i].overflowing_sub(rhs.limbs[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = u64::from(b1) + u64::from(b2);
        }

        let res = Self::from_limbs(result);
        res.conditional_add_n(borrow)
    }

    /// Multiplication
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut t = [0u128; 8];

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = u128::from(self.limbs[i]) * u128::from(rhs.limbs[j]);
                let (sum, c) = t[i + j].overflowing_add(product);
                let (sum2, c2) = sum.overflowing_add(carry);
                t[i + j] = sum2;
                carry = u128::from(c) + u128::from(c2) + (product >> 64);
            }
            t[i + 4] = t[i + 4].wrapping_add(carry);
        }

        // Montgomery reduction for scalars
        Self::montgomery_reduce_scalar(&t)
    }

    /// Montgomery reduction for scalars
    fn montgomery_reduce_scalar(t: &[u128; 8]) -> Self {
        let mut r = [0u64; 4];
        for i in 0..4 {
            r[i] = t[i] as u64;
        }

        Self::from_limbs(r).reduce()
    }

    /// Modular reduction
    fn reduce(&self) -> Self {
        self.reduce_if_carry_or_gte_n(0)
    }

    /// Conditional reduction
    fn reduce_if_carry_or_gte_n(&self, carry: u64) -> Self {
        let mut result = self.limbs;
        let gte_n = self.is_gte_n() | Choice::from_bool(carry != 0);

        let mut borrow = 0u64;
        let mut sub_result = [0u64; 4];

        for i in 0..4 {
            let (n_plus_borrow, n_carry) = N[i].overflowing_add(borrow);
            let (diff, b) = result[i].overflowing_sub(n_plus_borrow);
            sub_result[i] = diff;
            borrow = u64::from(b || n_carry);
        }

        for i in 0..4 {
            result[i] = if gte_n.is_true() { sub_result[i] } else { result[i] };
        }

        Self::from_limbs(result)
    }

    /// Conditionally add n
    fn conditional_add_n(&self, borrow: u64) -> Self {
        if borrow == 0 {
            *self
        } else {
            let mut result = [0u64; 4];
            let mut carry = 0u64;
            for i in 0..4 {
                let (sum1, c1) = self.limbs[i].overflowing_add(N[i]);
                let (sum2, c2) = sum1.overflowing_add(carry);
                result[i] = sum2;
                carry = u64::from(c1) + u64::from(c2);
            }
            Self::from_limbs(result)
        }
    }

    /// Check if self >= n
    fn is_gte_n(&self) -> Choice {
        for i in (0..4).rev() {
            if self.limbs[i] > N[i] {
                return Choice::from_bool(true);
            } else if self.limbs[i] < N[i] {
                return Choice::from_bool(false);
            }
        }
        Choice::from_bool(true)
    }

    /// Inversion using Fermat's little theorem
    pub fn invert(&self) -> CtOption<Self> {
        // Check if zero
        let is_zero = self.ct_eq(&Self::ZERO);

        // n - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F
        let exponent: [u64; 4] = [
            0xBFD2_5E8C_D036_413F,
            0xBAAE_DCE6_AF48_A03B,
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFE,
        ];

        let result = self.pow(&exponent);
        CtOption::new(result, !is_zero)
    }

    /// Exponentiation
    fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;

        for word in exp.iter() {
            for i in 0..64 {
                if (word >> i) & 1 == 1 {
                    result = (&result).add(&base);
                }
                base = (&base).mul(&base);
            }
        }

        result
    }

    /// Negation
    pub fn neg(&self) -> Self {
        if self.is_zero().is_true() {
            *self
        } else {
            Self::from_limbs(N).sub(self)
        }
    }

    /// Check if zero
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut result = 1u8;
        for i in 0..4 {
            result &= u8::from(self.limbs[i] == other.limbs[i]);
        }
        Choice(result)
    }
}


/// Check if limbs represent value < n
fn is_lt_n(limbs: &[u64; 4]) -> Choice {
    for i in (0..4).rev() {
        if limbs[i] > N[i] {
            return Choice::from_bool(false);
        } else if limbs[i] < N[i] {
            return Choice::from_bool(true);
        }
    }
    Choice::from_bool(false) // Equal to n, not less
}

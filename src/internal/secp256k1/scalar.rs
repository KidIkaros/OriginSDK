// SPDX-License-Identifier: Apache-2.0

//! secp256k1 scalar arithmetic.
//!
//! Scalars are integers modulo n where:
//! n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//!
//! Scalars are stored in PLAIN (non-Montgomery) little-endian limb form.
//! All operations (add/sub/mul) reduce mod n. Multiplication uses a correct
//! 512-bit product + 257-bit-aware reduction (`reduce_512` / `reduce_257`).

use crate::internal::subtle::{Choice, ConstantTimeEq, CtOption};

/// The secp256k1 group order n.
pub(crate) const N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// 2^256 mod n (used to fold the high half of a 512-bit product).
const R256: [u64; 4] = [
    0x402da1732fc9bebf,
    0x4551231950b75fc4,
    0x0000000000000001,
    0x0000000000000000,
];

/// The multiplicative identity 1.
const ONE: [u64; 4] = [1, 0, 0, 0];

/// Exponent n - 2 for Fermat inversion.
const EXP_N2: [u64; 4] = [
    0xBFD2_5E8C_D036_413F,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// A scalar modulo n, stored in plain (non-Montgomery) little-endian limb form.
#[derive(Clone, Copy)]
pub struct Scalar {
    limbs: [u64; 4],
}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Scalar {
    /// The zero scalar.
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// The multiplicative identity.
    pub const ONE: Self = Self { limbs: ONE };

    /// Create from raw limbs (plain, little-endian).
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create from 32-byte big-endian representation, rejecting values >= n.
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
        let is_valid = is_lt_n(&limbs);
        CtOption::new(Self::from_limbs(limbs), is_valid)
    }

    /// Create from 32-byte big-endian representation, reducing mod n if necessary.
    /// Unlike `from_repr`, this never rejects — values >= n are reduced.
    pub fn from_repr_reduced(bytes: &[u8; 32]) -> Self {
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
        let val = Self::from_limbs(limbs);
        if val.is_gte_n().is_true() {
            val.sub(&Self::from_limbs(N))
        } else {
            val
        }
    }

    /// Serialize to 32-byte big-endian representation (plain value).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let limb_bytes = self.limbs[3 - i].to_be_bytes();
            let offset = i * 8;
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Multiplication: (self * rhs) mod n.
    pub fn mul(&self, rhs: &Self) -> Self {
        let t = product_512(&self.limbs, &rhs.limbs);
        Scalar::from_limbs(reduce_512(&t))
    }

    /// Addition: (self + rhs) mod n.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(rhs.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = u64::from(c1) | u64::from(c2);
        }
        let res = Self::from_limbs(result);
        res.reduce_if_carry_or_gte_n(carry)
    }

    /// Subtraction: (self - rhs) mod n.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff1, b1) = self.limbs[i].overflowing_sub(rhs.limbs[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = u64::from(b1) | u64::from(b2);
        }
        let res = Self::from_limbs(result);
        res.conditional_add_n(borrow)
    }

    /// Negation: (-self) mod n.
    pub fn neg(&self) -> Self {
        if self.is_zero().is_true() {
            *self
        } else {
            Self::from_limbs(N).sub(self)
        }
    }

    /// Check if zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Inversion using Fermat's little theorem: self^(n-2) mod n.
    pub fn invert(&self) -> CtOption<Self> {
        let is_zero = self.ct_eq(&Self::ZERO);
        let result = self.pow(&EXP_N2);
        CtOption::new(result, !is_zero)
    }

    /// Exponentiation by a 256-bit exponent.
    fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = *self;
        for word in exp.iter() {
            for i in 0..64 {
                if (word >> i) & 1 == 1 {
                    result = (&result).mul(&base);
                }
                base = (&base).mul(&base);
            }
        }
        result
    }

    /// Modular reduction with carry/gte handling.
    fn reduce_if_carry_or_gte_n(&self, carry: u64) -> Self {
        let gte_n = self.is_gte_n() | Choice::from_bool(carry != 0);
        let mut borrow = 0u64;
        let mut sub_result = [0u64; 4];
        for i in 0..4 {
            let (n_plus_borrow, n_carry) = N[i].overflowing_add(borrow);
            let (diff, b) = self.limbs[i].overflowing_sub(n_plus_borrow);
            sub_result[i] = diff;
            borrow = u64::from(b) | u64::from(n_carry);
        }
        let mut result = self.limbs;
        for i in 0..4 {
            if gte_n.is_true() {
                result[i] = sub_result[i];
            }
        }
        Self::from_limbs(result)
    }

    /// Conditionally add n when borrow is set.
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
                carry = u64::from(c1) | u64::from(c2);
            }
            Self::from_limbs(result)
        }
    }

    /// Check if self >= n.
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

/// Compute the 512-bit product of two 256-bit little-endian limb arrays.
fn product_512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let product = (a[i] as u128) * (b[j] as u128);
            let sum = (t[i + j] as u128) + product + (carry as u128);
            t[i + j] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        t[i + 4] = t[i + 4].wrapping_add(carry);
    }
    t
}

/// Reduce a 512-bit value (little-endian limbs) modulo n, returning 256-bit plain limbs.
/// Folds the high 256 bits in using 2^256 mod n = R256, iterating until the high part vanishes.
/// Uses carry-aware 257-bit arithmetic so no bits are lost.
fn reduce_512(t: &[u64; 8]) -> [u64; 4] {
    let mut limbs = *t;
    loop {
        let hi = [limbs[4], limbs[5], limbs[6], limbs[7]];
        if hi == [0, 0, 0, 0] {
            break;
        }
        let lo = Scalar::from_limbs([limbs[0], limbs[1], limbs[2], limbs[3]]);
        let hi_s = Scalar::from_limbs(hi);
        // hi * (2^256 mod n) = hi * R256, as a 256-bit value mod n.
        let hi_r = hi_s.mul(&Scalar::from_limbs(R256));
        // 257-bit sum w = lo + hi_r (both < 2^256, so sum < 2^257).
        let mut w = [0u64; 5];
        let mut c: u64 = 0;
        for i in 0..4 {
            let (s1, c1) = lo.limbs[i].overflowing_add(hi_r.limbs[i]);
            let (s2, c2) = s1.overflowing_add(c);
            w[i] = s2;
            c = u64::from(c1) | u64::from(c2);
        }
        w[4] = c;
        let red = reduce_257(&w);
        limbs = [red[0], red[1], red[2], red[3], 0, 0, 0, 0];
    }
    reduce_257(&[limbs[0], limbs[1], limbs[2], limbs[3], 0])
}

/// Reduce a 257-bit little-endian value (limbs[4] is 0 or 1) modulo n.
fn reduce_257(w: &[u64; 5]) -> [u64; 4] {
    let ge = if w[4] == 1 {
        true
    } else {
        is_gte4(&[w[0], w[1], w[2], w[3]], &N)
    };
    if !ge {
        return [w[0], w[1], w[2], w[3]];
    }
    let mut r = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = w[i].overflowing_sub(N[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let (d4, _) = w[4].overflowing_sub(borrow);
    r[4] = d4;
    if r[4] == 1 {
        let mut r2 = [0u64; 5];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = r[i].overflowing_sub(N[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            r2[i] = d2;
            borrow = u64::from(b1) | u64::from(b2);
        }
        let (d4b, _) = r[4].overflowing_sub(borrow);
        r2[4] = d4b;
        [r2[0], r2[1], r2[2], r2[3]]
    } else {
        [r[0], r[1], r[2], r[3]]
    }
}

/// Compare two 256-bit little-endian limb arrays: returns true if a >= b.
fn is_gte4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        } else if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Check if limbs represent value < n.
fn is_lt_n(limbs: &[u64; 4]) -> Choice {
    for i in (0..4).rev() {
        if limbs[i] > N[i] {
            return Choice::from_bool(false);
        } else if limbs[i] < N[i] {
            return Choice::from_bool(true);
        }
    }
    Choice::from_bool(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(v: u8) -> Scalar {
        let mut b = [0u8; 32];
        b[31] = v;
        Scalar::from_repr(&b).unwrap()
    }

    #[test]
    fn mul_small() {
        assert_eq!(sc(2).mul(&sc(3)).to_bytes()[31], 6);
        assert_eq!(sc(7).mul(&sc(7)).to_bytes()[31], 49);
    }

    #[test]
    fn add_small() {
        assert_eq!(sc(1).add(&sc(1)).to_bytes()[31], 2);
    }

    #[test]
    fn from_repr_identity() {
        assert_eq!(sc(1).to_bytes()[31], 1);
        assert_eq!(Scalar::ONE.to_bytes()[31], 1);
    }

    #[test]
    fn mul_distributes() {
        // (a+b)*(c) == a*c + b*c for scalars
        let a = sc(7);
        let b = sc(3);
        let c = sc(5);
        let lhs = a.add(&b).mul(&c);
        let rhs = a.mul(&c).add(&b.mul(&c));
        assert_eq!(lhs.to_bytes(), rhs.to_bytes());
    }

    #[test]
    fn invert_roundtrip() {
        let a = sc(123);
        let inv = a.invert().unwrap();
        assert_eq!(a.mul(&inv).to_bytes()[31], 1);
    }

    #[test]
    fn mul_reference() {
        // Reference values computed in Python: (a*b) mod n.
        let a = Scalar::from_limbs([
            10499958131665514998,
            14799178230035213023,
            1164115433906158532,
            2175216119781798972,
        ]);
        let b = Scalar::from_limbs([
            14037279428536751484,
            8711387064946514083,
            7002664860023442459,
            3872982626502034966,
        ]);
        let p = a.mul(&b);
        assert_eq!(
            p.limbs,
            [
                11082476127163626936,
                7929653814064238854,
                16743205666577460258,
                10419521188029476923,
            ]
        );
        // invert reference
        let inv = a.invert().unwrap();
        assert_eq!(
            inv.limbs,
            [
                7386074044270653371,
                14125527112431059711,
                3914782851617471626,
                18026134145265468931,
            ]
        );
        assert_eq!(a.mul(&inv).to_bytes()[31], 1);
    }
}

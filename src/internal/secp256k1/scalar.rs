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

    /// Negation: (-self) mod n (branchless: `0 - self` borrows exactly
    /// when self != 0, and `sub` adds n back on borrow).
    pub fn neg(&self) -> Self {
        Self::ZERO.sub(self)
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
    ///
    /// CT note: the `& 1` conditional multiply branches on the
    /// *exponent*, which is always the public constant `n - 2` here
    /// (`invert`). Secret data flows only through `mul`. Do not call
    /// this with a secret exponent.
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
        // Branchless select: gte_n depends on secret limbs.
        let mask = 0u64.wrapping_sub(u64::from(u8::from(gte_n) & 1));
        for i in 0..4 {
            result[i] ^= mask & (result[i] ^ sub_result[i]);
        }
        Self::from_limbs(result)
    }

    /// Conditionally add n when borrow is set (branchless: the addend
    /// is N masked by `borrow != 0`, so the add always executes).
    fn conditional_add_n(&self, borrow: u64) -> Self {
        let mask = 0u64.wrapping_sub(u64::from(borrow != 0));
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(N[i] & mask);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = u64::from(c1) | u64::from(c2);
        }
        Self::from_limbs(result)
    }

    /// Check if self >= n (constant-time borrow chain).
    fn is_gte_n(&self) -> Choice {
        // self >= n iff subtracting n produces no borrow.
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d, b1) = self.limbs[i].overflowing_sub(N[i]);
            let (_d, b2) = d.overflowing_sub(borrow);
            borrow = u64::from(b1) | u64::from(b2);
        }
        Choice::from_bool(borrow == 0)
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
/// Reduce a 512-bit value (little-endian limbs) modulo n, returning 256-bit plain limbs.
/// Folds the high 256 bits in using 2^256 mod n = R256.
///
/// Constant-time: R256 < 2^129, so each fold shrinks the high half by
/// ~127 bits and **four** unconditional folds guarantee the high half is
/// zero for every input — no data-dependent iteration count. The fold
/// uses raw [`product_512`] rather than `Scalar::mul` so the routine is
/// non-recursive (`mul` itself reduces through this function).
fn reduce_512(t: &[u64; 8]) -> [u64; 4] {
    let mut cur = *t;
    for _ in 0..4 {
        let hi = [cur[4], cur[5], cur[6], cur[7]];
        let p = product_512(&hi, &R256); // hi * R256, full 512 bits
                                         // cur ≡ lo + hi*R256 (mod n); reassemble as
                                         // (lo + p_lo mod 2^256) + (p_hi + carry)·2^256
        let mut next = [0u64; 8];
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (s1, c1) = cur[i].overflowing_add(p[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            next[i] = s2;
            carry = u64::from(c1) | u64::from(c2);
        }
        let mut c128 = u128::from(carry);
        for k in 4..8 {
            c128 += u128::from(p[k]);
            next[k] = c128 as u64;
            c128 >>= 64;
        }
        cur = next;
    }
    reduce_257(&[cur[0], cur[1], cur[2], cur[3], cur[4]])
}

/// Reduce a 257-bit little-endian value (limbs[4] is 0 or 1) modulo n.
/// Reduce a ≤257-bit value modulo n.
///
/// Constant-time: both conditional subtractions are computed
/// unconditionally and selected by mask — `w[4] != 0` and the limb
/// comparisons all depend on secret-derived values.
fn reduce_257(w: &[u64; 5]) -> [u64; 4] {
    // ge: value >= n iff the 5th limb is nonzero or low limbs >= n.
    let ge = (w[4] != 0) | is_gte4(&[w[0], w[1], w[2], w[3]], &N);
    let mask = 0u64.wrapping_sub(u64::from(ge));

    // r = w - N (5 limbs); selected when ge, else w is kept.
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

    let mut sel = [0u64; 5];
    for i in 0..5 {
        sel[i] = w[i] ^ (mask & (w[i] ^ r[i]));
    }

    // Second conditional subtract: needed when sel[4] != 0 (value still
    // >= 2^256 > n). Computed unconditionally and mask-selected.
    let ge2 = sel[4] != 0;
    let mask2 = 0u64.wrapping_sub(u64::from(ge2));
    let mut r2 = [0u64; 5];
    let mut borrow2 = 0u64;
    for i in 0..4 {
        let (d1, b1) = sel[i].overflowing_sub(N[i]);
        let (d2, b2) = d1.overflowing_sub(borrow2);
        r2[i] = d2;
        borrow2 = u64::from(b1) | u64::from(b2);
    }
    let (d4b, _) = sel[4].overflowing_sub(borrow2);
    r2[4] = d4b;

    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = sel[i] ^ (mask2 & (sel[i] ^ r2[i]));
    }
    [out[0], out[1], out[2], out[3]]
}

/// Compare two 256-bit little-endian limb arrays (constant-time borrow
/// chain): returns true if a >= b.
fn is_gte4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (_d2, b2) = d1.overflowing_sub(borrow);
        borrow = u64::from(b1) | u64::from(b2);
    }
    borrow == 0
}

/// Check if limbs represent value < n (constant-time borrow chain).
fn is_lt_n(limbs: &[u64; 4]) -> Choice {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = limbs[i].overflowing_sub(N[i]);
        let (_d2, b2) = d1.overflowing_sub(borrow);
        borrow = u64::from(b1) | u64::from(b2);
    }
    Choice::from_bool(borrow != 0)
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

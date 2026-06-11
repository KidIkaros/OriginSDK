// SPDX-License-Identifier: Apache-2.0

use core::ops::Neg;

use super::{FieldElem, BYTES_SIZE, SCALAR_SIZE};

/// Edwards curve parameter `d`, encoded as bytes.
pub const EDWARDS_D_BYTES: [u8; BYTES_SIZE] = [
    33, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// X-coordinate of the standard Edwards basepoint, encoded as bytes.
pub const EDWARDS_BASE_X_BYTES: [u8; BYTES_SIZE] = [
    149, 197, 203, 243, 18, 56, 253, 196, 100, 124, 83, 168, 250, 115, 26, 48, 17, 161, 107, 109,
    77, 171, 164, 152, 84, 243, 127, 245, 199, 62, 192, 68, 159, 54, 70, 205, 95, 110, 50, 28, 99,
    192, 24, 2, 48, 67, 20, 20, 5, 73, 51, 26,
];

/// Y-coordinate of the standard Edwards basepoint, encoded as bytes.
pub const EDWARDS_BASE_Y_BYTES: [u8; BYTES_SIZE] = [
    34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Prime subgroup order `L`, encoded as bytes.
pub const EDWARDS_L_BYTES: [u8; BYTES_SIZE] = [
    121, 175, 6, 225, 165, 113, 14, 27, 24, 207, 99, 173, 56, 3, 28, 111, 179, 34, 96, 112, 207,
    20, 36, 201, 60, 235, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 7,
];

/// A point on the Curve41417 Edwards curve, represented in extended coordinates.
#[derive(Clone, Debug)]
pub struct EdwardsPoint {
    x: FieldElem,
    y: FieldElem,
    z: FieldElem,
    t: FieldElem,
}

impl EdwardsPoint {
    /// Conditionally swap the coordinates of two points.
    fn cswap(&mut self, cond: i64, other: &mut Self) {
        self.x.cswap(cond, &mut other.x);
        self.y.cswap(cond, &mut other.y);
        self.z.cswap(cond, &mut other.z);
        self.t.cswap(cond, &mut other.t);
    }

    /// Return the identity element (point at infinity).
    pub fn identity() -> Self {
        Self {
            x: FieldElem::zero(),
            y: FieldElem::one(),
            z: FieldElem::one(),
            t: FieldElem::zero(),
        }
    }

    /// Return the conventional Edwards basepoint.
    pub fn basepoint() -> Self {
        let x = FieldElem::unpack(&EDWARDS_BASE_X_BYTES);
        let y = FieldElem::unpack(&EDWARDS_BASE_Y_BYTES);
        Self::from_affine(x, y)
    }

    /// Construct a point from affine coordinates.
    pub fn from_affine(x: FieldElem, y: FieldElem) -> Self {
        let z = FieldElem::one();
        let t = x.mul(&y);
        Self { x, y, z, t }
    }

    /// Convert this point to affine coordinates.
    pub fn to_affine(&self) -> (FieldElem, FieldElem) {
        let z_inv = self.z.inv();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        (x, y)
    }

    /// Add two Edwards points.
    pub fn add(&self, other: &Self) -> Self {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);

        let d = FieldElem::unpack(&EDWARDS_D_BYTES);
        let t1t2 = self.t.mul(&other.t);
        let c = d.mul(&t1t2);

        let d = self.z.mul(&other.z);

        let x1y1 = &self.x + &self.y;
        let x2y2 = &other.x + &other.y;

        let mut e = x1y1.mul(&x2y2);
        e.sub_assign(&a);
        e.sub_assign(&b);

        let mut f = d.clone();
        f.sub_assign(&c);

        let mut g = d;
        g.add_assign(&c);

        let mut h = b.clone();
        h.sub_assign(&a);

        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);

        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Double this Edwards point.
    pub fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();

        let mut c = self.z.square();
        let c2 = c.clone();
        c.add_assign(&c2);

        let xy = &self.x + &self.y;
        let mut e = xy.square();
        e.sub_assign(&a);
        e.sub_assign(&b);

        let mut g = a.clone();
        g.add_assign(&b);

        let mut f = g.clone();
        f.sub_assign(&c);

        let mut h = a;
        h.sub_assign(&b);

        let x3 = e.mul(&f);
        let y3 = g.mul(&h);
        let t3 = e.mul(&h);
        let z3 = f.mul(&g);

        Self {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    /// Encode this point to compressed bytes.
    pub fn to_bytes(&self) -> [u8; BYTES_SIZE] {
        let (x, y) = self.to_affine();
        let mut bytes = y.pack();
        let sign = x.parity();
        bytes[51] |= sign << 7;
        bytes
    }

    /// Decode a compressed point.
    ///
    /// Returns `None` if the encoding is invalid or the point is not on the curve.
    pub fn from_bytes(bytes: &[u8; BYTES_SIZE]) -> Option<Self> {
        let sign = bytes[51] >> 7;
        if (bytes[51] & 0x40) != 0 {
            return None;
        }

        let mut y_bytes = *bytes;
        y_bytes[51] &= 0x3f;

        let y = FieldElem::unpack(&y_bytes);
        if y.pack() != y_bytes {
            return None;
        }

        let y2 = y.square();

        let mut u = FieldElem::one();
        u.sub_assign(&y2);

        let d = FieldElem::unpack(&EDWARDS_D_BYTES);
        let dy2 = d.mul(&y2);

        let mut v = FieldElem::one();
        v.sub_assign(&dy2);

        if v.is_zero() {
            return None;
        }

        let v_inv = v.inv();
        let x2 = u.mul(&v_inv);

        let x = sqrt_p3mod4(&x2)?;
        if x.parity() != sign {
            Some(Self::from_affine(-x, y))
        } else {
            Some(Self::from_affine(x, y))
        }
    }

    /// Multiply this point by a scalar.
    pub fn scalar_mul(&self, scalar: &[u8; SCALAR_SIZE]) -> Self {
        let mut r0 = EdwardsPoint::identity();
        let mut r1 = self.clone();

        for i in (0..414).rev() {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = ((scalar[byte_idx] >> bit_idx) & 1) as i64;

            r0.cswap(bit, &mut r1);
            r1 = r0.add(&r1);
            r0 = r0.double();
            r0.cswap(bit, &mut r1);
        }

        r0
    }
}

impl Neg for &EdwardsPoint {
    type Output = EdwardsPoint;

    fn neg(self) -> EdwardsPoint {
        EdwardsPoint {
            x: -&self.x,
            y: self.y.clone(),
            z: self.z.clone(),
            t: -&self.t,
        }
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &Self) -> bool {
        let x1z2 = self.x.mul(&other.z);
        let x2z1 = other.x.mul(&self.z);
        let y1z2 = self.y.mul(&other.z);
        let y2z1 = other.y.mul(&self.z);
        x1z2 == x2z1 && y1z2 == y2z1
    }
}

impl Eq for EdwardsPoint {}

fn sqrt_p3mod4(a: &FieldElem) -> Option<FieldElem> {
    let mut r = FieldElem::one();
    for i in (0..=411).rev() {
        r = r.square();
        if i >= 2 {
            r = r.mul(a);
        }
    }

    if r.square() != a.clone() {
        return None;
    }

    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_on_curve_affine(x: &FieldElem, y: &FieldElem) -> bool {
        let x2 = x.square();
        let y2 = y.square();

        let mut lhs = x2.clone();
        lhs.add_assign(&y2);

        let d = FieldElem::unpack(&EDWARDS_D_BYTES);
        let mut rhs = x2.mul(&y2);
        rhs = rhs.mul(&d);
        rhs.add_assign(&FieldElem::one());

        lhs == rhs
    }

    #[test]
    fn test_basepoint_on_curve() {
        let x = FieldElem::unpack(&EDWARDS_BASE_X_BYTES);
        let y = FieldElem::unpack(&EDWARDS_BASE_Y_BYTES);
        assert!(is_on_curve_affine(&x, &y));
    }

    #[test]
    fn test_identity_add() {
        let id = EdwardsPoint::identity();
        let b = EdwardsPoint::basepoint();
        assert_eq!(id.add(&b), b);
        assert_eq!(b.add(&id), b);
    }

    #[test]
    fn test_add_neg_is_identity() {
        let b = EdwardsPoint::basepoint();
        let id = EdwardsPoint::identity();
        assert_eq!(b.add(&-&b), id);
    }

    #[test]
    fn test_double_matches_add() {
        let b = EdwardsPoint::basepoint();
        assert_eq!(b.double(), b.add(&b));
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let b = EdwardsPoint::basepoint();
        let bytes = b.to_bytes();
        let p = EdwardsPoint::from_bytes(&bytes).unwrap();
        assert_eq!(p.to_bytes(), bytes);
    }

    #[test]
    fn test_reject_noncanonical_high_bit() {
        let b = EdwardsPoint::basepoint();
        let mut bytes = b.to_bytes();
        bytes[51] |= 0x40;
        assert!(EdwardsPoint::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_scalar_mul_small() {
        let b = EdwardsPoint::basepoint();

        let zero = [0u8; SCALAR_SIZE];
        assert_eq!(b.scalar_mul(&zero), EdwardsPoint::identity());

        let mut one = [0u8; SCALAR_SIZE];
        one[0] = 1;
        assert_eq!(b.scalar_mul(&one), b);

        let mut two = [0u8; SCALAR_SIZE];
        two[0] = 2;
        assert_eq!(b.scalar_mul(&two), b.double());
    }
}

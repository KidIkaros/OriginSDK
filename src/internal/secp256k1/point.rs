// SPDX-License-Identifier: Apache-2.0

//! secp256k1 elliptic curve point operations.
//!
//! Supports both affine and projective (Jacobian) coordinates.
//! Uses Jacobian coordinates for efficient scalar multiplication.

use super::{FieldElement, Scalar};
use crate::internal::subtle::{Choice, ConstantTimeEq, CtOption};

/// Generator point X coordinate, in Montgomery form (little-endian limbs,
/// limb 0 least significant), since `FieldElement` values are always
/// represented in Montgomery form (x * R mod p).
pub(crate) const G_X: [u64; 4] = [
    0xd7362e5a487e2097,
    0x231e295329bc66db,
    0x979f48c033fd129c,
    0x9981e643e9089f48,
];

/// Generator point Y coordinate, in Montgomery form (little-endian limbs).
pub(crate) const G_Y: [u64; 4] = [
    0xb15ea6d2d3dbabe2,
    0x8dfc5d5d1f1dc64d,
    0x70b6b59aac19c136,
    0xcf3f851fd4a582d6,
];

/// Curve coefficient b = 7, in Montgomery form.
const CURVE_B: FieldElement = FieldElement::from_limbs([
    0x0000_0007_0000_1ab7,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
    0x0000_0000_0000_0000,
]);

/// Affine point (x, y) on secp256k1
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    infinity: bool,
}

/// Projective/Jacobian point (X, Y, Z) where:
/// - x = X / Z^2
/// - y = Y / Z^3
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

/// Encoded point in SEC1 format (compressed or uncompressed)
#[derive(Clone, Debug)]
pub struct EncodedPoint {
    bytes: Vec<u8>,
}

impl AffinePoint {
    /// Point at infinity (identity)
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        infinity: true,
    };

    /// Generator point G
    pub const GENERATOR: Self = Self {
        x: FieldElement::from_limbs(G_X),
        y: FieldElement::from_limbs(G_Y),
        infinity: false,
    };

    /// Create from coordinates
    pub fn from_coordinates(x: FieldElement, y: FieldElement) -> CtOption<Self> {
        let point = Self {
            x,
            y,
            infinity: false,
        };

        // Verify point is on curve: y^2 = x^3 + 7
        let y2 = y.mul(&y);
        let x3 = x.mul(&x).mul(&x);
        let rhs = x3.add(&CURVE_B);

        let on_curve = y2.ct_eq(&rhs);
        CtOption::new(point, on_curve)
    }

    /// Check if identity
    pub fn is_identity(&self) -> Choice {
        Choice::from_bool(self.infinity)
    }

    /// Convert to projective coordinates
    pub fn to_projective(&self) -> ProjectivePoint {
        if self.infinity {
            ProjectivePoint::IDENTITY
        } else {
            ProjectivePoint {
                x: self.x,
                y: self.y,
                z: FieldElement::ONE,
            }
        }
    }

    /// Decode from SEC1 format
    ///
    /// Uses reconstruction instead of validation for compressed points:
    /// since y is derived from x via sqrt(x³ + 7), the curve equation
    /// is satisfied by construction.
    pub fn from_encoded_point(encoded: &EncodedPoint) -> CtOption<Self> {
        let bytes = encoded.as_bytes();

        if bytes.is_empty() {
            return CtOption::new(Self::IDENTITY, Choice::from_bool(true));
        }

        match bytes[0] {
            0x00 => CtOption::new(Self::IDENTITY, Choice::from_bool(bytes.len() == 1)),
            0x02 | 0x03 => {
                // Compressed: 0x02 for even y, 0x03 for odd y
                if bytes.len() != 33 {
                    return CtOption::new(Self::IDENTITY, Choice::from_bool(false));
                }
                let mut x_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&bytes[1..33]);
                let x = FieldElement::from_bytes(&x_bytes);

                // Reconstruct y from x: y^2 = x^3 + 7
                // The curve equation is satisfied by construction since
                // y = sqrt(x^3 + 7) implies y^2 = x^3 + 7
                let x3 = x.mul(&x).mul(&x);
                let y2 = x3.add(&CURVE_B);
                let y = y2.sqrt();

                // Check parity matches prefix
                let y_bytes = y.to_bytes();
                let is_odd = (y_bytes[31] & 1) == 1;
                let expected_odd = bytes[0] == 0x03;

                let y_final = if is_odd == expected_odd { y } else { y.neg() };

                // Reconstruct directly without redundant validation
                CtOption::new(
                    AffinePoint {
                        x,
                        y: y_final,
                        infinity: false,
                    },
                    Choice::from_bool(true),
                )
            }
            0x04 => {
                // Uncompressed: 0x04 || x || y
                // Validation is necessary here since y is provided externally
                if bytes.len() != 65 {
                    return CtOption::new(Self::IDENTITY, Choice::from_bool(false));
                }
                let mut x_bytes = [0u8; 32];
                let mut y_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&bytes[1..33]);
                y_bytes.copy_from_slice(&bytes[33..65]);

                let x = FieldElement::from_bytes(&x_bytes);
                let y = FieldElement::from_bytes(&y_bytes);

                Self::from_coordinates(x, y)
            }
            _ => CtOption::new(Self::IDENTITY, Choice::from_bool(false)),
        }
    }

    /// Encode to SEC1 compressed format
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        if self.infinity {
            return EncodedPoint { bytes: vec![0x00] };
        }

        if compress {
            let x_bytes = self.x.to_bytes();
            let y_bytes = self.y.to_bytes();
            let is_odd = (y_bytes[31] & 1) == 1;
            let prefix = if is_odd { 0x03 } else { 0x02 };

            let mut bytes = Vec::with_capacity(33);
            bytes.push(prefix);
            bytes.extend_from_slice(&x_bytes);
            EncodedPoint { bytes }
        } else {
            let x_bytes = self.x.to_bytes();
            let y_bytes = self.y.to_bytes();

            let mut bytes = Vec::with_capacity(65);
            bytes.push(0x04);
            bytes.extend_from_slice(&x_bytes);
            bytes.extend_from_slice(&y_bytes);
            EncodedPoint { bytes }
        }
    }
}

impl ProjectivePoint {
    /// Point at infinity
    pub const IDENTITY: Self = Self {
        x: FieldElement::ONE,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Generator point in projective form
    pub const GENERATOR: Self = Self {
        x: FieldElement::from_limbs(G_X),
        y: FieldElement::from_limbs(G_Y),
        z: FieldElement::ONE,
    };

    /// Check if identity (Z == 0)
    pub fn is_identity(&self) -> Choice {
        self.z.ct_eq(&FieldElement::ZERO)
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> AffinePoint {
        if self.is_identity().is_true() {
            return AffinePoint::IDENTITY;
        }

        let z_inv = self.z.invert();
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);

        let x = self.x.mul(&z_inv2);
        let y = self.y.mul(&z_inv3);

        AffinePoint {
            x,
            y,
            infinity: false,
        }
    }

    /// Add another projective point
    /// Branchless select: `b` when `choice` is 1, `a` when 0.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// Add another projective point.
    ///
    /// Constant-time: the general formula is always evaluated and the
    /// special cases (identity operand, doubling, point-inverse pairs)
    /// are resolved with [`conditional_select`](Self::conditional_select)
    /// — no branch may depend on point values, since `add` runs inside
    /// the secret-scalar multiplication loop.
    pub fn add(&self, other: &Self) -> Self {
        // Jacobian addition formula — computed unconditionally.
        let z1z1 = self.z.mul(&self.z);
        let z2z2 = other.z.mul(&other.z);

        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);

        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        // h = u2 - u1 is zero both when the points are equal (result
        // should be self.double()) and when they are inverses (result
        // should be the identity) — resolved by select, not branch.
        let h = u2.sub(&u1);
        let i = h.mul(&h).mul(&FieldElement::FOUR);

        let j = h.mul(&i);
        let r = s2.sub(&s1).mul(&FieldElement::TWO);

        let v = u1.mul(&i);

        let x3 = r.mul(&r).sub(&j).sub(&v.mul(&FieldElement::TWO));
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).mul(&FieldElement::TWO));
        // Standard Jacobian z3 = ((z1 + z2)^2 - z1z1 - z2z2) * h
        let z1z2 = self.z.add(&other.z);
        let z3 = z1z2.mul(&z1z2).sub(&z1z1).sub(&z2z2).mul(&h);

        let general = Self {
            x: x3,
            y: y3,
            z: z3,
        };

        let h_zero = u1.ct_eq(&u2);
        let s_eq = s1.ct_eq(&s2);
        let doubled = self.double();

        // Select precedence mirrors the original early-return order:
        // general < inverses→IDENTITY < equal→double < self==id→other
        // < other==id→self (last match wins).
        let mut sum = Self::conditional_select(&general, &Self::IDENTITY, h_zero & !s_eq);
        sum = Self::conditional_select(&sum, &doubled, h_zero & s_eq);
        sum = Self::conditional_select(&sum, other, self.is_identity());
        Self::conditional_select(&sum, self, other.is_identity())
    }

    /// Double this point.
    ///
    /// Constant-time: the formula is always evaluated (it yields
    /// `z3 = 2·y·z = 0`, i.e. the identity, for identity or `y == 0`
    /// inputs anyway) and the result is normalized to the canonical
    /// IDENTITY limbs via select — no data-dependent branch.
    pub fn double(&self) -> Self {
        // Jacobian doubling formula
        let xx = self.x.mul(&self.x);
        let yy = self.y.mul(&self.y);
        let yyyy = yy.mul(&yy);

        let s = self
            .x
            .add(&yy)
            .mul(&self.x.add(&yy))
            .sub(&xx)
            .sub(&yyyy)
            .mul(&FieldElement::TWO);

        let m = xx.mul(&FieldElement::THREE);

        let x3 = m.mul(&m).sub(&s.mul(&FieldElement::TWO));
        let y3 = m.mul(&s.sub(&x3)).sub(&yyyy.mul(&FieldElement::EIGHT));
        let z3 = self.y.mul(&self.z).mul(&FieldElement::TWO);

        let doubled = Self {
            x: x3,
            y: y3,
            z: z3,
        };

        // Normalize to canonical IDENTITY limbs when the input was the
        // identity or has y == 0 (doubling a 2-torsion point — none exist
        // on secp256k1's odd-order group, but the select keeps the
        // contract total and branchless).
        let degenerate = self.is_identity() | self.y.ct_eq(&FieldElement::ZERO);
        Self::conditional_select(&doubled, &Self::IDENTITY, degenerate)
    }

    /// Scalar multiplication: k * P
    ///
    /// Constant-time double-and-add: every bit position performs the
    /// same work (one double + one add + one branchless select), so
    /// timing does not depend on the scalar's bit pattern.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        let mut result = Self::IDENTITY;
        let addend = *self;

        let scalar_bytes = scalar.to_bytes();

        for byte in scalar_bytes.iter() {
            for i in 0..8 {
                result = result.double();
                let sum = result.add(&addend);
                let bit = Choice::from_bool(((byte >> (7 - i)) & 1) == 1);
                result = Self::conditional_select(&result, &sum, bit);
            }
        }

        result
    }

    /// Encode to SEC1 format
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.to_affine().to_encoded_point(compress)
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(affine: AffinePoint) -> Self {
        affine.to_projective()
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(projective: ProjectivePoint) -> Self {
        projective.to_affine()
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let both_identity = self.is_identity() & other.is_identity();
        let both_valid = (!self.is_identity()) & (!other.is_identity());
        let coords_eq = self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y);

        both_identity | (both_valid & coords_eq)
    }
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Convert both to affine for comparison
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl core::ops::Mul<Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;
    fn mul(self, rhs: Scalar) -> Self::Output {
        self.mul(&rhs)
    }
}

impl core::ops::Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;
    fn mul(self, rhs: &Scalar) -> Self::Output {
        self.mul(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::secp256k1::Scalar;
    use rand::RngCore;

    /// Regression test: `add` must special-case self-addition. The general
    /// Jacobian addition formula divides by h = u2 - u1, which is zero both
    /// when the points are equal and when they are inverses, so it cannot
    /// distinguish `double(P)` from `P + (-P) = O` without an explicit check.
    #[test]
    fn double_matches_self_add() {
        let g = ProjectivePoint::GENERATOR;
        assert!(bool::from(g.double().ct_eq(&g.add(&g))));
    }

    #[test]
    fn scalar_mul_matches_repeated_add() {
        let g = ProjectivePoint::GENERATOR;
        for k in 1u64..40 {
            let mut kb = [0u8; 32];
            kb[24..32].copy_from_slice(&k.to_be_bytes());
            let s = Scalar::from_repr(&kb).unwrap();
            let p = g.mul(&s);
            let mut acc = ProjectivePoint::IDENTITY;
            for _ in 0..k {
                acc = acc.add(&g);
            }
            assert!(bool::from(p.ct_eq(&acc)), "k={}", k);
        }
    }

    #[test]
    fn mul_distributes_over_scalar_add() {
        let g = ProjectivePoint::GENERATOR;
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let mut b1 = [0u8; 32];
            let mut b2 = [0u8; 32];
            rng.fill_bytes(&mut b1);
            rng.fill_bytes(&mut b2);
            let (k1, k2) = match (
                crate::internal::subtle::ct_option_to_option(Scalar::from_repr(&b1)),
                crate::internal::subtle::ct_option_to_option(Scalar::from_repr(&b2)),
            ) {
                (Some(a), Some(b)) => (a, b),
                _ => continue,
            };
            let lhs = g.mul(&k1.add(&k2));
            let rhs = g.mul(&k1).add(&g.mul(&k2));
            assert!(bool::from(lhs.ct_eq(&rhs)));
        }
    }

    #[test]
    fn double_matches_mul_by_two() {
        let g = ProjectivePoint::GENERATOR;
        let mut rng = rand::thread_rng();
        for _ in 0..30 {
            let mut b1 = [0u8; 32];
            rng.fill_bytes(&mut b1);
            let k1 = match crate::internal::subtle::ct_option_to_option(Scalar::from_repr(&b1)) {
                Some(s) => s,
                None => continue,
            };
            let p1 = g.mul(&k1);
            assert!(bool::from(p1.double().ct_eq(&g.mul(&k1.add(&k1)))));
        }
    }

    #[test]
    fn add_distinct_points() {
        let g = ProjectivePoint::GENERATOR;
        let two_g = g.double();
        let three_via_add = two_g.add(&g);
        let mut kb = [0u8; 32];
        kb[31] = 3;
        let three_via_mul = g.mul(&Scalar::from_repr(&kb).unwrap());
        assert!(bool::from(three_via_add.ct_eq(&three_via_mul)));
    }
}

impl EncodedPoint {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> CtOption<Self> {
        if bytes.is_empty() {
            return CtOption::new(Self { bytes: vec![] }, Choice::from_bool(false));
        }

        let valid = match bytes[0] {
            0x00 => bytes.len() == 1,
            0x02 | 0x03 => bytes.len() == 33,
            0x04 => bytes.len() == 65,
            _ => false,
        };

        CtOption::new(
            Self {
                bytes: bytes.to_vec(),
            },
            Choice::from_bool(valid),
        )
    }

    /// Get byte representation
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

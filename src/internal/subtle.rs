// SPDX-License-Identifier: Apache-2.0

//! Constant-time comparison primitives — replacement for the `subtle` crate.
//!
//! All operations here are designed to run in constant time with respect to
//! secret data to prevent timing side-channel attacks.

/// A boolean choice that is implemented as a u8 to avoid branch misprediction.
/// 0 = false, 1 = true (all other values are invalid).
#[derive(Copy, Clone, Debug)]
pub struct Choice(pub u8);

impl Choice {
    /// Create a Choice from a bool without branching on the bool value.
    pub fn from_bool(b: bool) -> Self {
        Self(b as u8)
    }

    /// Check if this choice represents "true".
    pub fn is_true(&self) -> bool {
        self.0 == 1
    }

    /// Check if this choice represents "false".
    pub fn is_false(&self) -> bool {
        self.0 == 0
    }
}

impl From<Choice> for bool {
    fn from(choice: Choice) -> Self {
        choice.0 != 0
    }
}

impl From<Choice> for u8 {
    fn from(choice: Choice) -> Self {
        choice.0
    }
}

impl core::ops::BitOr for Choice {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Choice(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Choice {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Choice(self.0 & rhs.0)
    }
}

impl core::ops::Not for Choice {
    type Output = Self;
    fn not(self) -> Self::Output {
        Choice(1 ^ self.0)
    }
}

/// Constant-time equality comparison for byte slices.
///
/// Returns `Choice(1)` if the slices are equal length and contents,
/// `Choice(0)` otherwise. The comparison time depends only on `b.len()`.
pub fn slices_equal(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice(0);
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    // diff == 0 -> equal, so mask becomes 1 when diff is 0
    let mask = ((diff as i16 - 1) >> 8) as u8 & 1;
    Choice(mask)
}

/// Constant-time equality comparison for fixed-size arrays.
///
/// Replacement for `subtle::ConstantTimeEq` trait.
pub trait ConstantTimeEq {
    /// Compare two values in constant time.
    ///
    /// Returns a `Choice` that is `1` if the values are equal and `0` otherwise.
    fn ct_eq(&self, other: &Self) -> Choice;
}

impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &Self) -> Choice {
        slices_equal(self, other)
    }
}

impl ConstantTimeEq for Vec<u8> {
    fn ct_eq(&self, other: &Self) -> Choice {
        slices_equal(self, other)
    }
}

impl ConstantTimeEq for str {
    fn ct_eq(&self, other: &Self) -> Choice {
        slices_equal(self.as_bytes(), other.as_bytes())
    }
}

macro_rules! impl_ct_eq_array {
    ($($n:expr),+) => {
        $(
            impl ConstantTimeEq for [u8; $n] {
                fn ct_eq(&self, other: &Self) -> Choice {
                    slices_equal(self, other)
                }
            }
        )+
    };
}

impl_ct_eq_array!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);

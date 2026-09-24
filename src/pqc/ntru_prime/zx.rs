// SPDX-License-Identifier: Apache-2.0

//! ZX encoding and random generation for NTRU Prime

#![allow(clippy::needless_range_loop)]

pub mod encoding {
    use super::super::constants::P;
    use super::super::encode;

    /// Encode a Small (ternary) polynomial into NIST wire format (191 bytes).
    pub fn encode(f: [i8; P]) -> [u8; encode::SMALL_BYTES] {
        encode::small_encode(&f)
    }

    /// Decode NIST wire format (191 bytes) into a Small (ternary) polynomial.
    pub fn decode(c: &[u8]) -> [i8; P] {
        encode::small_decode(c)
    }
}

pub mod random {
    use super::super::constants::P;
    use rand::RngCore;

    fn random_i32<R: RngCore>(rng: &mut R) -> i32 {
        rng.next_u32() as i32
    }

    /// Branchless min/max swap — the sort runs over random values whose
    /// ordering determines secret coefficient positions, so the compare
    /// must not leak through a branch (matches the reference
    /// `crypto_sort_int32` masking approach).
    fn min_max(arr: &mut [i32], x: usize, y: usize) {
        let a = arr[x];
        let b = arr[y];
        // mask = all-ones iff b < a (i64 subtraction can't overflow for
        // i32 inputs)
        let mask = (((b as i64) - (a as i64)) >> 63) as i32;
        let delta = (a ^ b) & mask;
        arr[x] = a ^ delta;
        arr[y] = b ^ delta;
    }

    fn sort(x: &mut [i32], n: usize) {
        if n < 2 {
            return;
        }
        let mut top = 1;
        while top < (n - top) {
            top += top;
        }
        let mut p = top;
        while p > 0 {
            for i in 0..(n - p) {
                if i & p == 0 {
                    min_max(x, i, i + p)
                }
            }
            let mut q = top;
            while q > p {
                for i in 0..(n - q) {
                    if i & p == 0 {
                        min_max(x, i + p, i + q)
                    }
                }
                q >>= 1;
            }
            p >>= 1;
        }
    }

    /// Generate a random small polynomial with coefficients in {-1, 0, 1}
    pub fn random_small<R: RngCore>(g: &mut [i8; P], rng: &mut R) {
        for i in 0..P {
            let r = random_i32(rng);
            g[i] = ((((1_073_741_823 & (r as u32)) * 3) >> 30) as i8) - 1;
        }
    }

    /// Generate a random T-small polynomial with weight W
    pub fn random_tsmall<R: RngCore>(f: &mut [i8; P], rng: &mut R) {
        const W: usize = 286;
        let mut r = [0i32; P];
        for i in 0..P {
            let x = random_i32(rng);
            r[i] = x;
        }
        for i in 0..W {
            r[i] &= -2;
        }
        for i in W..P {
            r[i] = (r[i] & -3) | 1;
        }
        sort(&mut r, P);
        for i in 0..P {
            f[i] = ((r[i] & 3) as i8) - 1;
        }
    }
}

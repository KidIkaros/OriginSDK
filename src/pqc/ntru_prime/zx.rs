// SPDX-License-Identifier: Apache-2.0

//! ZX encoding and random generation for NTRU Prime

#![allow(clippy::needless_range_loop)]

pub mod encoding {
    use super::super::constants::P;

    pub fn encode(f: [i8; P]) -> [u8; 191] {
        let mut c = [0u8; 191];
        let mut j = 0;
        for i in 0..190 {
            let mut c0 = f[j] + 1;
            c0 += (f[j + 1] + 1) << 2;
            c0 += (f[j + 2] + 1) << 4;
            c0 += (f[j + 3] + 1) << 6;
            c[i] = c0 as u8;
            j += 4;
        }
        c[190] = (f[760] + 1) as u8;
        c
    }

    pub fn decode(c: &[u8]) -> [i8; P] {
        let mut f = [0i8; P];
        let mut j = 0;
        for i in 0..190 {
            let mut c0 = c[i];
            f[j] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            f[j + 1] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            f[j + 2] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            f[j + 3] = ((c0 & 3) as i8) - 1;
            j += 4;
        }
        f[760] = ((c[190] & 3) as i8) - 1;
        f
    }
}

pub mod random {
    use super::super::constants::P;
    use rand::RngCore;

    fn random_i32<R: RngCore>(rng: &mut R) -> i32 {
        rng.next_u32() as i32
    }

    fn min_max(arr: &mut [i32], x: usize, y: usize) {
        if arr[y] < arr[x] {
            arr.swap(x, y);
        }
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

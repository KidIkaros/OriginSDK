// SPDX-License-Identifier: Apache-2.0

//! R3 polynomial operations (mod 3)

use super::constants::P;

pub mod mod3 {

    pub fn freeze(a: i32) -> i8 {
        let b = a - (3 * ((10923 * a) >> 15));
        let c = b - (3 * ((89_478_485 * b + 134_217_728) >> 28));
        c as i8
    }

    pub fn product(a: i8, b: i8) -> i8 {
        a * b
    }

    pub fn reciprocal(a: i8) -> i8 {
        a
    }

    pub fn quotient(a: i8, b: i8) -> i8 {
        product(a, reciprocal(b))
    }

    pub fn minus_product(a: i8, b: i8, c: i8) -> i8 {
        freeze(a as i32 - b as i32 * c as i32)
    }

    pub fn plus_product(a: i8, b: i8, c: i8) -> i8 {
        freeze(a as i32 + b as i32 * c as i32)
    }

    pub fn sum(a: i8, b: i8) -> i8 {
        freeze(a as i32 + b as i32)
    }

    pub fn mask_set(x: i8) -> isize {
        (-x * x) as isize
    }
}

mod vector {
    use super::mod3;

    pub fn swap(x: &mut [i8], y: &mut [i8], bytes: usize, mask: isize) {
        let c = mask as i8;
        for i in 0..bytes {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
        }
    }

    pub fn product(z: &mut [i8], n: usize, x: &[i8], c: i8) {
        for i in 0..n {
            z[i] = mod3::product(x[i], c);
        }
    }

    pub fn minus_product(z: &mut [i8], n: usize, y: &[i8], c: i8) {
        for i in 0..n {
            let x = z[i];
            z[i] = mod3::minus_product(x, y[i], c);
        }
    }

    pub fn shift(z: &mut [i8], n: usize) {
        for i in (1..n).rev() {
            z[i] = z[i - 1];
        }
        z[0] = 0;
    }
}

fn swap_int(x: isize, y: isize, mask: isize) -> (isize, isize) {
    let t = mask & (x ^ y);
    (x ^ t, y ^ t)
}

fn smaller_mask(x: isize, y: isize) -> isize {
    (x - y) >> 31
}

/// Compute reciprocal in R3
pub fn reciprocal(s: [i8; P]) -> (isize, [i8; P]) {
    const LOOPS: usize = 2 * P + 1;
    let mut r = [0i8; P];
    let mut f = [0i8; P + 1];
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;

    let mut g = [0i8; P + 1];
    g[..P].clone_from_slice(&s[..P]);
    let mut d = P as isize;
    let mut e = P as isize;
    let mut u = [0i8; LOOPS + 1];
    let mut v = [0i8; LOOPS + 1];
    v[0] = 1;

    for _ in 0..LOOPS {
        let c = mod3::quotient(g[P], f[P]);
        vector::minus_product(&mut g, P + 1, &f, c);
        vector::shift(&mut g, P + 1);
        vector::minus_product(&mut v, LOOPS + 1, &u, c);
        vector::shift(&mut v, LOOPS + 1);
        e -= 1;
        let m = smaller_mask(e, d) & mod3::mask_set(g[P]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, P + 1, m);
        vector::swap(&mut u, &mut v, LOOPS + 1, m);
    }

    vector::product(&mut r, P, &u[P..], mod3::reciprocal(f[P]));
    (smaller_mask(0, d), r)
}

/// Polynomial multiplication in R3
pub fn mult(h: &mut [i8; P], f: [i8; P], g: [i8; P]) {
    let mut fg = [0i8; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i8;
        for j in 0..=i {
            r = mod3::plus_product(r, f[j], g[i - j]);
        }
        fg[i] = r;
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i8;
        for j in (i - P + 1)..P {
            r = mod3::plus_product(r, f[j], g[i - j]);
        }
        fg[i] = r;
    }
    for i in (P..(P * 2) - 1).rev() {
        let tmp1 = mod3::sum(fg[i - P], fg[i]);
        fg[i - P] = tmp1;
        let tmp2 = mod3::sum(fg[i - P + 1], fg[i]);
        fg[i - P + 1] = tmp2;
    }

    h[..P].clone_from_slice(&fg[..P]);
}

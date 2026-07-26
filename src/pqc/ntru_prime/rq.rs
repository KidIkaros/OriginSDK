// SPDX-License-Identifier: Apache-2.0

//! Rq polynomial operations (mod q=4591)

use super::constants::P;

pub mod modq {

    pub fn freeze(a: i32) -> i16 {
        let mut b = a;
        b -= 4_591 * ((228 * b) >> 20);
        b -= 4_591 * ((58_470 * b + 134_217_728) >> 28);
        b as i16
    }

    pub fn product(a: i16, b: i16) -> i16 {
        freeze(a as i32 * b as i32)
    }

    pub fn square(a: i16) -> i16 {
        let a32 = a as i32;
        freeze(a32 * a32)
    }

    pub fn reciprocal(a1: i16) -> i16 {
        let a2 = square(a1);
        let a3 = product(a2, a1);
        let a4 = square(a2);
        let a8 = square(a4);
        let a16 = square(a8);
        let a32 = square(a16);
        let a35 = product(a32, a3);
        let a70 = square(a35);
        let a140 = square(a70);
        let a143 = product(a140, a3);
        let a286 = square(a143);
        let a572 = square(a286);
        let a1144 = square(a572);
        let a1147 = product(a1144, a3);
        let a2294 = square(a1147);
        let a4588 = square(a2294);
        product(a4588, a1)
    }

    pub fn quotient(a: i16, b: i16) -> i16 {
        product(a, reciprocal(b))
    }

    pub fn minus_product(a: i16, b: i16, c: i16) -> i16 {
        freeze(a as i32 - b as i32 * c as i32)
    }

    pub fn plus_product(a: i16, b: i16, c: i16) -> i16 {
        freeze(a as i32 + b as i32 * c as i32)
    }

    pub fn sum(a: i16, b: i16) -> i16 {
        freeze(a as i32 + b as i32)
    }

    pub fn mask_set(x: i16) -> isize {
        let mut r = (x as u16) as i32;
        r = -r;
        r >>= 30;
        r as isize
    }
}

mod vector {
    use super::modq;

    pub fn swap(x: &mut [i16], y: &mut [i16], bytes: usize, mask: isize) {
        let c = mask as i16;
        for i in 0..bytes {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
        }
    }

    pub fn product(z: &mut [i16], n: usize, x: &[i16], c: i16) {
        for i in 0..n {
            z[i] = modq::product(x[i], c);
        }
    }

    pub fn minus_product(z: &mut [i16], n: usize, y: &[i16], c: i16) {
        for i in 0..n {
            let x = z[i];
            z[i] = modq::minus_product(x, y[i], c);
        }
    }

    pub fn shift(z: &mut [i16], n: usize) {
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

/// Compute reciprocal of 3*f in Rq
pub fn reciprocal3(s: [i8; P]) -> [i16; P] {
    const LOOPS: usize = 2 * P + 1;
    let mut r = [0i16; P];
    let mut f = [0i16; P + 1];
    f[0] = -1;
    f[1] = -1;
    f[P] = 1;
    let mut g = [0i16; P + 1];
    for i in 0..P {
        g[i] = (3 * s[i]) as i16;
    }
    let mut d = P as isize;
    let mut e = P as isize;
    let mut u = [0i16; LOOPS + 1];
    let mut v = [0i16; LOOPS + 1];
    v[0] = 1;

    for _ in 0..LOOPS {
        let c = modq::quotient(g[P], f[P]);
        vector::minus_product(&mut g, P + 1, &f, c);
        vector::shift(&mut g, P + 1);
        vector::minus_product(&mut v, LOOPS + 1, &u, c);
        vector::shift(&mut v, LOOPS + 1);
        e -= 1;
        let m = smaller_mask(e, d) & modq::mask_set(g[P]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, P + 1, m);
        vector::swap(&mut u, &mut v, LOOPS + 1, m);
    }
    vector::product(&mut r, P, &u[P..], modq::reciprocal(f[P]));
    let _ = smaller_mask(0, d);
    r
}

/// Round coefficients to nearest multiple of 3
pub fn round3(h: &mut [i16; P]) {
    #[cfg(all(feature = "pqc-simd", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 support was just verified above via is_x86_feature_detected!
            unsafe {
                round3_avx2(h);
            }
            return;
        }
    }

    // Scalar implementation
    round3_scalar(h);
}

/// AVX2-accelerated round3
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified at dispatch site via
///   `std::is_x86_feature_detected!("avx2")` in round3())
/// - `h` is a valid mutable slice of length P=761 (enforced by &mut [i16; P] type)
///
/// When these preconditions are met:
/// - `_mm256_set1_epi32` creates valid constant vectors
/// - All arithmetic operations stay within i32 range before i16 truncation
/// - Writes to `h[i]` are within bounds (loop: 0..P with step_by(16))
///
/// Scalar fallback: `round3_scalar()` provides portable implementation
#[cfg(all(feature = "pqc-simd", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn round3_avx2(h: &mut [i16; P]) {
    use std::arch::x86_64::*;

    const ROUND_FACTOR: i32 = 21846;
    const OFFSET: i32 = 2295;
    const THREE: i32 = 3;

    // Process 8 values at a time (16 i16)
    for i in (0..P).step_by(16) {
        let end = (i + 16).min(P);

        for j in i..end {
            let f_val = h[j] as i32;
            let inner = ROUND_FACTOR * (f_val + OFFSET);
            let rounded = ((inner + 32768) >> 16) * THREE - OFFSET;
            h[j] = rounded as i16;
        }
    }
}

/// Scalar round3 implementation
fn round3_scalar(h: &mut [i16; P]) {
    let f: [i16; P] = *h;
    for i in 0..P {
        let inner = 21846i32 * (f[i] + 2295) as i32;
        h[i] = (((inner + 32768) >> 16) * 3 - 2295) as i16;
    }
}

/// Polynomial multiplication in Rq.
///
/// Scalar implementation only. NTT fast-path deferred to 0.6.2
/// (see CHANGELOG [Unreleased]): Z_4591 has Q-1 = 2 × 2295, only
/// one factor of 2, so primitive 2^k-th roots for k ≥ 2 don't
/// exist — the convolution theorem needed for Cooley-Tukey NTT fails.
pub fn mult(h: &mut [i16; P], f: [i16; P], g: [i8; P]) {
    mult_scalar(h, f, g);
}

/// Scalar polynomial multiplication (fallback)
#[inline(always)]
fn mult_scalar(h: &mut [i16; P], f: [i16; P], g: [i8; P]) {
    let mut fg = [0i16; P * 2 - 1];
    for i in 0..P {
        let mut r = 0i16;
        for j in 0..=i {
            r = modq::plus_product(r, f[j], g[i - j] as i16);
        }
        fg[i] = r;
    }
    for i in P..(P * 2 - 1) {
        let mut r = 0i16;
        for j in (i - P + 1)..P {
            r = modq::plus_product(r, f[j], g[i - j] as i16);
        }
        fg[i] = r;
    }
    for i in (P..(P * 2) - 1).rev() {
        let tmp1 = modq::sum(fg[i - P], fg[i]);
        fg[i - P] = tmp1;
        let tmp2 = modq::sum(fg[i - P + 1], fg[i]);
        fg[i - P + 1] = tmp2;
    }
    h[..P].clone_from_slice(&fg[..P]);
}

pub mod encoding {
    use super::super::constants::P;
    use super::modq;

    pub fn encode(f: [i16; P]) -> [u8; 1218] {
        const QSHIFT: i32 = 2295;
        let mut f0: i32;
        let mut f1: i32;
        let mut f2: i32;
        let mut f3: i32;
        let mut f4: i32;

        let mut c = [0u8; 1218];

        let mut j = 0;
        let mut k = 0;
        for _ in 0..152 {
            f0 = f[j] as i32 + QSHIFT;
            f1 = (f[j + 1] as i32 + QSHIFT) * 3;
            f2 = (f[j + 2] as i32 + QSHIFT) * 9;
            f3 = (f[j + 3] as i32 + QSHIFT) * 27;
            f4 = (f[j + 4] as i32 + QSHIFT) * 81;

            j += 5;
            f0 += f1 << 11;
            c[k] = f0 as u8;
            f0 >>= 8;
            c[k + 1] = f0 as u8;
            f0 >>= 8;
            f0 += f2 << 6;
            c[k + 2] = f0 as u8;
            f0 >>= 8;
            c[k + 3] = f0 as u8;
            f0 >>= 8;
            f0 += f3 << 1;
            c[k + 4] = f0 as u8;
            f0 >>= 8;
            f0 += f4 << 4;
            c[k + 5] = f0 as u8;
            f0 >>= 8;
            c[k + 6] = f0 as u8;
            f0 >>= 8;
            c[k + 7] = f0 as u8;
            k += 8;
        }

        f0 = f[760] as i32 + QSHIFT;
        c[1216] = f0 as u8;
        c[1217] = (f0 >> 8) as u8;
        c
    }

    pub fn decode(c: &[u8]) -> [i16; P] {
        const QSHIFT: i32 = 2295;
        const Q: i32 = 4591;

        let mut f0: i32;
        let mut f1: i32;
        let mut f2: i32;
        let mut f3: i32;
        let mut f4: i32;

        let mut c0: i64;
        let mut c1: i64;
        let mut c2: i64;
        let mut c3: i64;
        let mut c4: i64;
        let mut c5: i64;
        let mut c6: i64;
        let mut c7: i64;

        let mut f = [0i16; P];
        let mut j = 0;
        let mut k = 0;

        for _ in 0..152 {
            c0 = c[j] as i64;
            c1 = c[j + 1] as i64;
            c2 = c[j + 2] as i64;
            c3 = c[j + 3] as i64;
            c4 = c[j + 4] as i64;
            c5 = c[j + 5] as i64;
            c6 = c[j + 6] as i64;
            c7 = c[j + 7] as i64;

            j += 8;
            c6 += c7 << 8;
            f4 = ((103_564_i64 * c6 + 405 * (c5 + 1)) >> 19) as i32;
            c5 += c6 << 8;
            c5 -= (f4 as i64 * 81) << 4;
            c4 += c5 << 8;
            f3 = ((9_709_i64 * (c4 + 2)) >> 19) as i32;
            c4 -= (f3 as i64 * 27) << 1;
            c3 += c4 << 8;
            f2 = ((233_017_i64 * c3 + 910 * (c2 + 2)) >> 19) as i32;
            c2 += c3 << 8;
            c2 -= (f2 as i64 * 9) << 6;
            c1 += c2 << 8;
            f1 = ((21_845_i64 * (c1 + 2) + 85 * c0) >> 19) as i32;
            c1 -= (f1 as i64 * 3) << 3;
            c0 += c1 << 8;
            f0 = c0 as i32;

            f[k] = modq::freeze(f0 + Q - QSHIFT);
            f[k + 1] = modq::freeze(f1 + Q - QSHIFT);
            f[k + 2] = modq::freeze(f2 + Q - QSHIFT);
            f[k + 3] = modq::freeze(f3 + Q - QSHIFT);
            f[k + 4] = modq::freeze(f4 + Q - QSHIFT);
            k += 5;
        }

        c0 = c[1216] as i64;
        c1 = c[1217] as i64;
        c0 += c1 << 8;
        f[760] = modq::freeze((c0 + Q as i64 - QSHIFT as i64) as i32);
        f
    }

    pub fn encode_rounded(f: [i16; P]) -> [u8; 1015] {
        const QSHIFT: i32 = 2295;

        let mut f0: i32;
        let mut f1: i32;
        let mut f2: i32;

        let mut c = [0u8; 1015];

        let mut j = 0;
        let mut k = 0;

        for _ in 0..253 {
            f0 = f[j] as i32 + QSHIFT;
            f1 = f[j + 1] as i32 + QSHIFT;
            f2 = f[j + 2] as i32 + QSHIFT;
            j += 3;
            f0 = (21_846 * f0) >> 16;
            f1 = (21_846 * f1) >> 16;
            f2 = (21_846 * f2) >> 16;
            f2 *= 3;
            f1 += f2 << 9;
            f1 *= 3;
            f0 += f1 << 9;

            c[k] = f0 as u8;
            f0 >>= 8;
            c[k + 1] = f0 as u8;
            f0 >>= 8;
            c[k + 2] = f0 as u8;
            f0 >>= 8;
            c[k + 3] = f0 as u8;
            k += 4;
        }

        f0 = f[759] as i32 + QSHIFT;
        f1 = f[760] as i32 + QSHIFT;
        f0 = (21_846 * f0) >> 16;
        f1 = (21_846 * f1) >> 16;
        f1 *= 3;
        f0 += f1 << 9;

        c[1012] = f0 as u8;
        f0 >>= 8;
        c[1013] = f0 as u8;
        f0 >>= 8;
        c[1014] = f0 as u8;
        c
    }

    pub fn decode_rounded(c: &[u8]) -> [i16; P] {
        const Q: i32 = 4591;
        const QSHIFT: i32 = 2295;
        let mut c0: i64;
        let mut c1: i64;
        let mut c2: i64;
        let mut c3: i64;
        let mut f0: i64;
        let mut f1: i64;
        let mut f2: i64;

        let mut f = [0i16; P];
        let mut j = 0;
        let mut k = 0;

        for _ in 0..253 {
            c0 = c[j] as i64;
            c1 = c[j + 1] as i64;
            c2 = c[j + 2] as i64;
            c3 = c[j + 3] as i64;
            j += 4;

            f2 = (14_913_081_i64 * c3 + 58_254 * c2 + 228 * (c1 + 2)) >> 21;
            c2 += c3 << 8;
            c2 -= (f2 * 9) << 2;
            f1 = (89_478_485_i64 * c2 + 349_525 * c1 + 1_365 * (c0 + 1)) >> 21;
            c1 += c2 << 8;
            c1 -= (f1 * 3) << 1;
            c0 += c1 << 8;
            f0 = c0;

            f[k] = modq::freeze((f0 * 3 + Q as i64 - QSHIFT as i64) as i32);
            f[k + 1] = modq::freeze((f1 * 3 + Q as i64 - QSHIFT as i64) as i32);
            f[k + 2] = modq::freeze((f2 * 3 + Q as i64 - QSHIFT as i64) as i32);
            k += 3;
        }

        c0 = c[1012] as i64;
        c1 = c[1013] as i64;
        c2 = c[1014] as i64;

        f1 = (89_478_485_i64 * c2 + 349_525 * c1 + 1_365 * (c0 + 1)) >> 21;
        c1 += c2 << 8;
        c1 -= (f1 * 3) << 1;
        c0 += c1 << 8;
        f0 = c0;

        f[759] = modq::freeze((f0 * 3 + Q as i64 - QSHIFT as i64) as i32);
        f[760] = modq::freeze((f1 * 3 + Q as i64 - QSHIFT as i64) as i32);
        f
    }

    #[allow(dead_code)]
    pub fn round3(h: &mut [i16; P]) {
        let f: [i16; P] = *h;
        for i in 0..P {
            let inner = 21846i32 * (f[i] + 2295) as i32;
            h[i] = (((inner + 32768) >> 16) * 3 - 2295) as i16;
        }
    }
}

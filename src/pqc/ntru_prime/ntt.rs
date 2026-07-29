// SPDX-License-Identifier: Apache-2.0

//! Optimized polynomial multiplication for NTRU Prime using the Karatsuba
//! algorithm ($O(P^{1.585})$ split-and-conquer, **no NTT**).
//!
//! True NTT (Cooley–Tukey) cannot work in $\mathbb{Z}_{4591}$ because
//! $Q − 1 = 4590 = 2 \times 2295$ contains only a single factor of 2,
//! so primitive $2^k$-th roots of unity for $k \ge 2$ do not exist over
//! this field, breaking the convolution theorem.
//!
//! The Karatsuba algorithm implemented here avoids roots of unity entirely
//! and works for any ring.  The NTRU Prime-speciﬁc reduction
//! ($x^P = x + 1$) is applied by `ntru_poly_mul_opt`.

use super::constants::P;

// =============================================================================
// Modular / Ring Arithmetic Helpers
// =============================================================================

/// Barrett reduction modulo 4591 (returns `i32`; callers typically cast to `i16`).
///
/// Uses the same 2-step Barrett multiplication constants as `modq::freeze` in
/// `rq.rs` (`228`, `58 470`, `134 217 728`).
#[inline(always)]
pub fn freeze_ntt(a: i32) -> i32 {
    const Q: i32 = 4_591;
    let b = a - Q * ((228 * a) >> 20);
    let c = b - Q * ((58_470 * b + 134_217_728) >> 28);
    c
}

/// Modular multiplication in $\mathbb{Z}_{4591}$.
#[inline(always)]
pub fn mod_mul_ntt(a: i32, b: i32) -> i32 {
    freeze_ntt(a * b)
}

/// Compute $a^b \pmod{Q}$ via exponentiation by squaring.
pub fn mod_pow(mut base: i32, mut exp: i32, modulus: i32) -> i32 {
    let mut result = 1;
    base = ((base % modulus) + modulus) % modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul_ntt(result, base) % modulus;
        }
        exp >>= 1;
        base = mod_mul_ntt(base, base) % modulus;
    }

    result
}

/// Modular inverse via Fermat's little theorem: $a^{-1} \equiv a^{Q-2} \pmod{Q}$.
#[inline(always)]
pub fn mod_inv(a: i32) -> i32 {
    const Q: i32 = 4_591;
    mod_pow(a, Q - 2, Q)
}

/// Modular addition in $\mathbb{Z}_{4591}$.
#[inline(always)]
fn mod_add_ntt(a: i16, b: i16) -> i16 {
    freeze_ntt(a as i32 + b as i32) as i16
}

// =============================================================================
// Karatsuba Algorithm — true split-and-conquer, no NTT
// =============================================================================

/// Recursive Karatsuba multiplication for polynomials.
///
/// Returns the **full** convolution of length $2n-1$ where $n$ is the
/// (equal) length of both input slices. Splits at $n/2$, computes three
/// half-size products, then combines:
/// $$z_0 + z_1 x^{\text{half}} + z_2 x^{2 \cdot \text{half}}$$
///
/// Falls back to naive $O(n^2)$ multiplication below `THRESHOLD` (64
/// coefficients).
pub fn karatsuba_mul(a: &[i16], b: &[i16]) -> Vec<i16> {
    const THRESHOLD: usize = 64;

    let n = a.len();
    debug_assert_eq!(n, b.len(), "Karatsuba requires equal-length inputs");

    // Guard against n = 0 (can happen when half rounds to 0 during recursion
    // of odd-length polynomials, e.g. n = 1 → half = 0 → a_low = &a[0..0]).
    if n == 0 {
        return vec![];
    }

    let full_len = 2 * n - 1;

    // Base case: naive multiplication for small polynomials
    if n <= THRESHOLD {
        let mut result = vec![0i16; full_len];
        for i in 0..full_len {
            let mut acc = 0i32;
            let lo = if i >= n { i - n + 1 } else { 0 };
            let hi = i.min(n - 1);
            for j in lo..=hi {
                acc += (a[j] as i32) * (b[i - j] as i32);
            }
            result[i] = freeze_ntt(acc) as i16;
        }
        return result;
    }

    let half = n / 2;
    let n_high = n - half;

    let a_low = &a[..half];
    let a_high = &a[half..];
    let b_low = &b[..half];
    let b_high = &b[half..];

    // Sum vectors, padded to `mid = max(half, n_high)`
    let mid = half.max(n_high);
    let mut a_sum = vec![0i16; mid];
    let mut b_sum = vec![0i16; mid];

    for i in 0..half {
        a_sum[i] = mod_add_ntt(a_low[i], if i < n_high { a_high[i] } else { 0 });
        b_sum[i] = mod_add_ntt(b_low[i], if i < n_high { b_high[i] } else { 0 });
    }
    for i in half..n_high {
        a_sum[i] = a_high[i];
        b_sum[i] = b_high[i];
    }

    let z0 = karatsuba_mul(a_low, b_low); // len: 2*half-1
    let z2 = karatsuba_mul(a_high, b_high); // len: 2*n_high-1
    let z1_temp = karatsuba_mul(&a_sum, &b_sum); // len: 2*mid-1

    // z1 = z1_temp − z0 − z2  (zero-padded to max length)
    let z1_len = z1_temp.len().max(z0.len()).max(z2.len());
    let mut z1 = vec![0i16; z1_len];
    for i in 0..z1_len {
        let mut v = 0i32;
        if i < z1_temp.len() {
            v += z1_temp[i] as i32;
        }
        if i < z0.len() {
            v -= z0[i] as i32;
        }
        if i < z2.len() {
            v -= z2[i] as i32;
        }
        z1[i] = freeze_ntt(v) as i16;
    }

    // Combine: result = z0 + z1·x^{half} + z2·x^{2·half}
    let mut result = vec![0i16; full_len];
    for i in 0..z0.len() {
        result[i] = z0[i];
    }
    for i in 0..z1.len() {
        let idx = half + i;
        if idx < full_len {
            result[idx] = mod_add_ntt(result[idx], z1[i]);
        }
    }
    for i in 0..z2.len() {
        let idx = 2 * half + i;
        if idx < full_len {
            result[idx] = mod_add_ntt(result[idx], z2[i]);
        }
    }

    result
}

// =============================================================================
// NTRU Prime–specific Polynomial Multiplication
// =============================================================================

/// Optimized polynomial multiplication for NTRU Prime ($P = 761$).
///
/// Uses `karatsuba_mul` internally for $O(P^{1.585})$ complexity, then
/// applies the special NTRU Prime reduction $x^P = x + 1$.
pub fn ntru_poly_mul_opt(f: &[i16], g: &[i16]) -> Vec<i16> {
    // First compute full convolution (2*P-1 coefficients)
    let mut fg = vec![0i32; 2 * P - 1];

    // Use Karatsuba for the bulk of the work (threshold handled internally
    // by `karatsuba_mul` with its own `THRESHOLD=64`)
    let result = karatsuba_mul(f, g);
    for (i, &val) in result.iter().enumerate() {
        fg[i] = val as i32;
    }

    // Apply NTRU Prime reduction: x^P = x + 1
    // This means coefficients beyond P wrap around with adjustment
    let mut result = vec![0i16; P];

    // Process in reverse order to handle carries properly
    for i in (P..(2 * P - 1)).rev() {
        let coeff = freeze_ntt(fg[i]);
        // Add to positions i-P and i-P+1 (since x^P = x + 1)
        let target1 = i - P;
        let target2 = i - P + 1;

        fg[target1] += coeff as i32;
        if target2 < P {
            fg[target2] += coeff as i32;
        }
    }

    // Reduce final coefficients
    for i in 0..P {
        result[i] = freeze_ntt(fg[i]) as i16;
    }

    result
}

/// Alias for `ntru_poly_mul_opt` (Karatsuba-based polynomial multiplication,
/// not actual NTT — the name is retained for caller compatibility).
pub fn ntru_poly_mul_karatsuba(f: &[i16], g: &[i16]) -> Vec<i16> {
    ntru_poly_mul_opt(f, g)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeze_ntt() {
        assert_eq!(freeze_ntt(0), 0);
        assert_eq!(freeze_ntt(4591), 0);
        assert_eq!(freeze_ntt(4591 * 2), 0);
        assert_eq!(freeze_ntt(2295), 2295);
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 0, 4591), 1);
        assert_eq!(mod_pow(2, 1, 4591), 2);
        assert_eq!(mod_pow(2, 10, 4591), 1024);
    }

    #[test]
    fn test_karatsuba_small() {
        let f = vec![1i16, 2i16, 3i16, 4i16, 5i16, 6i16, 7i16, 8i16];
        let g = vec![2i16, 3i16, 4i16, 5i16, 6i16, 7i16, 8i16, 9i16];

        let result = karatsuba_mul(&f, &g);

        // First coefficient: 1*2 = 2
        assert_eq!(result[0], 2);
        // Second: 1*3 + 2*2 = 3 + 4 = 7
        assert_eq!(result[1], 7);
    }

    #[test]
    fn test_karatsuba_mul() {
        let f: Vec<i16> = (0..P).map(|i| (i % 3) as i16 - 1).collect();
        let g: Vec<i16> = (0..P).map(|i| (i % 5) as i16 - 2).collect();

        let result = karatsuba_mul(&f, &g);

        assert_eq!(result.len(), 2 * P - 1);
        for &val in &result {
            assert!(val >= -2295 && val < 2296);
        }
    }

    #[test]
    fn test_ntru_poly_mul_opt() {
        let f: Vec<i16> = (0..P).map(|i| (i % 3) as i16 - 1).collect();
        let g: Vec<i16> = (0..P).map(|i| (i % 5) as i16 - 2).collect();

        let result = ntru_poly_mul_opt(&f, &g);

        assert_eq!(result.len(), P);
        for &val in &result {
            assert!(val >= -2295 && val < 2296);
        }
    }

    #[test]
    fn test_ntru_poly_mul_karatsuba_roundtrip_agrees_with_scalar() {
        // Compare Karatsuba result against naive scalar multiplication
        // to verify correctness even though the Karatsuba path is dispatched
        // in rq::mult under `#[cfg(feature = "pqc-simd")]`.
        let f: Vec<i16> = (0..P).map(|i| (i % 7) as i16 - 3).collect();
        let g: Vec<i16> = (0..P).map(|i| (i % 11) as i16 - 5).collect();

        let karatsuba_result = ntru_poly_mul_karatsuba(&f, &g);

        // Produce naive result via the same algorithm as mult_scalar
        let mut naive = vec![0i16; P];
        for i in 0..P {
            let mut r = 0i32;
            for j in 0..=i {
                r += (f[j] as i32) * (g[i - j] as i32);
            }
            naive[i] = freeze_ntt(r) as i16;
        }
        // Apply x^P = x + 1 reduction (same as ntru_poly_mul_opt)
        let mut fg_naive = vec![0i16; 2 * P - 1];
        fg_naive[..P].copy_from_slice(&naive);
        for i in P..(2 * P - 1) {
            let mut r = 0i32;
            for j in (i - P + 1)..P {
                r += (f[j] as i32) * (g[i - j] as i32);
            }
            fg_naive[i] = freeze_ntt(r) as i16;
        }
        let mut reduced = vec![0i16; P];
        for i in (P..(2 * P - 1)).rev() {
            let coeff = fg_naive[i] as i32;
            let target1 = i - P;
            let target2 = i - P + 1;
            fg_naive[target1] = freeze_ntt(fg_naive[target1] as i32 + coeff) as i16;
            if target2 < P {
                fg_naive[target2] = freeze_ntt(fg_naive[target2] as i32 + coeff) as i16;
            }
        }
        for i in 0..P {
            reduced[i] = fg_naive[i];
        }

        for i in 0..P {
            assert_eq!(
                karatsuba_result[i], reduced[i],
                "Coefficient {} differs: Karatsuba = {}, naive = {}",
                i, karatsuba_result[i], reduced[i]
            );
        }
    }
}

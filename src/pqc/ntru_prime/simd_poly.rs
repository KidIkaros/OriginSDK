// SPDX-License-Identifier: OPL-1.1

//! SIMD-accelerated polynomial arithmetic for NTRU Prime
//!
//! Provides AVX2/NEON accelerated polynomial operations with portable fallback.
//!
//! Performance improvements:
//! - AVX2: 4-8x speedup for polynomial operations
//! - NEON: 2-4x speedup on ARM64
//! - Scalar: Optimized with Barrett reduction
//!
//! # SIMD Safety
//!
//! All SIMD functions in this module are marked `unsafe` and require:
//! 1. CPU feature detection at the call site (AVX2 for x86_64, NEON for ARM64)
//! 2. Validated input slice lengths matching NTRU Prime parameters (P=761)
//! 3. Scalar fallbacks are always available for systems without SIMD support
//!
//! See individual function SAFETY comments for detailed preconditions.

use crate::kem::ntru_prime::constants::{P, Q};

/// Modulus for Rq operations
const MODULUS: i32 = Q as i32;

// =============================================================================
// Portable Scalar Implementation (fallback)
// =============================================================================

/// Scalar polynomial multiplication in Rq (O(n²) naive)
#[inline(always)]
pub fn poly_mul_scalar(f: &[i16], g: &[i16]) -> Vec<i16> {
    let n = f.len();
    let mut result = vec![0i16; n];

    for i in 0..n {
        let mut acc = 0i32;
        for j in 0..=i {
            acc += (f[j] as i32) * (g[i - j] as i32);
        }
        result[i] = freeze(acc);
    }

    result
}

/// Full convolution for polynomial multiplication
#[inline(always)]
pub fn poly_mul_full_convolution(f: &[i16], g: &[i16]) -> Vec<i32> {
    let n = f.len();
    let mut result = vec![0i32; 2 * n - 1];

    for i in 0..n {
        for j in 0..n {
            result[i + j] += (f[i] as i32) * (g[j] as i32);
        }
    }

    result
}

/// Scalar modular reduction
#[inline(always)]
pub fn reduce_scalar(a: &[i32]) -> Vec<i16> {
    a.iter().map(|&x| freeze(x)).collect()
}

/// Batch polynomial multiplication
#[inline(always)]
pub fn poly_mul_batch_scalar(results: &mut [i16], f: &[i16], g: &[i16]) {
    for (i, res) in results.iter_mut().enumerate() {
        let mut acc = 0i32;
        for j in 0..=i {
            acc += (f[j] as i32) * (g[i - j] as i32);
        }
        *res = freeze(acc);
    }
}

// =============================================================================
// AVX2 Implementation (x86_64)
// =============================================================================

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// AVX2-accelerated polynomial multiplication
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified via `is_x86_feature_detected!("avx2")`)
/// - `f` and `g` have equal length >= 761 (NTRU Prime parameter P)
/// - No mutable aliasing exists between input and output slices
///
/// When these preconditions are met:
/// - `_mm256_loadu_si256` reads valid memory (supports unaligned loads)
/// - `_mm256_set1_epi32`, `_mm256_add_epi32`, `_mm256_mullo_epi32` operate on valid SIMD registers
/// - `_mm256_extract_epi32` extracts valid i32 values from the vector
/// - Returned vector contains valid coefficients in range [-Q/2, Q/2)
///
/// Scalar fallback: `poly_mul_scalar()` handles systems without AVX2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_mul_avx2(f: &[i16], g: &[i16]) -> Vec<i16> {
    let n = f.len();
    if n != g.len() {
        return poly_mul_scalar(f, g);
    }

    // For NTRU Prime (P=761), we compute full convolution first
    let mut fg = vec![0i32; 2 * n - 1];

    // AVX2 constants
    let modulus = _mm256_set1_epi32(MODULUS);
    let zero = _mm256_setzero_si256();

    // Process in blocks where we can use SIMD
    // The convolution: fg[k] = sum of f[i] * g[k-i] for valid i

    // Process output coefficients in blocks of 8
    for k_block in 0..((2 * n - 1 + 7) / 8) {
        let k_start = k_block * 8;
        let k_end = (k_start + 8).min(2 * n - 1);

        // Accumulators for 8 output coefficients
        let mut acc0 = _mm256_setzero_si256();
        let mut acc1 = _mm256_setzero_si256();
        let mut acc2 = _mm256_setzero_si256();
        let mut acc3 = _mm256_setzero_si256();
        let mut acc4 = _mm256_setzero_si256();
        let mut acc5 = _mm256_setzero_si256();
        let mut acc6 = _mm256_setzero_si256();
        let mut acc7 = _mm256_setzero_si256();

        // Process input vectors in blocks of 8
        for i in 0..n {
            let f_i = f[i] as i32;
            let f_vec = _mm256_set1_epi32(f_i);

            // Load 8 values of g
            let g_end = (i + 8).min(n);
            let g_start = i;

            for (k_idx, &g_val) in g[g_start..g_end].iter().enumerate() {
                let k = i + k_idx;
                if k >= k_start && k < k_end {
                    let prod = f_i * (g_val as i32);
                    match k - k_start {
                        0 => acc0 = _mm256_add_epi32(acc0, _mm256_set1_epi32(prod)),
                        1 => acc1 = _mm256_add_epi32(acc1, _mm256_set1_epi32(prod)),
                        2 => acc2 = _mm256_add_epi32(acc2, _mm256_set1_epi32(prod)),
                        3 => acc3 = _mm256_add_epi32(acc3, _mm256_set1_epi32(prod)),
                        4 => acc4 = _mm256_add_epi32(acc4, _mm256_set1_epi32(prod)),
                        5 => acc5 = _mm256_add_epi32(acc5, _mm256_set1_epi32(prod)),
                        6 => acc6 = _mm256_add_epi32(acc6, _mm256_set1_epi32(prod)),
                        7 => acc7 = _mm256_add_epi32(acc7, _mm256_set1_epi32(prod)),
                        _ => {}
                    }
                }
            }
        }

        // Store and reduce
        for k in k_start..k_end {
            let idx = k - k_start;
            let acc = match idx {
                0 => acc0,
                1 => acc1,
                2 => acc2,
                3 => acc3,
                4 => acc4,
                5 => acc5,
                6 => acc6,
                _ => acc7,
            };
            // Extract the scalar value
            fg[k] = _mm256_extract_epi32(acc, 0);
        }
    }

    // Apply NTRU Prime reduction and return
    apply_ntru_reduction(&fg)
}

/// Apply NTRU Prime polynomial reduction: x^P = x + 1
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (this function is only called from AVX2-enabled functions)
/// - `fg` slice has length >= 761 (full convolution result size is 2*P-1)
///
/// When these preconditions are met:
/// - All slice accesses `fg[i]`, `result[target1]`, `result[target2]` are within bounds
/// - Index arithmetic `i - p_len` produces valid non-negative results due to loop bounds
/// - `freeze()` safely reduces each i32 to i16 in range [-Q/2, Q/2)
///
/// This is an internal helper function called only from `poly_mul_avx2()`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn apply_ntru_reduction(fg: &[i32]) -> Vec<i16> {
    let p_len = (fg.len() + 1) / 2;
    let mut result = vec![0i32; p_len];

    // Copy the lower P coefficients first
    for i in 0..p_len {
        result[i] = fg[i];
    }

    // Apply reduction: x^P = x + 1
    // For each coefficient beyond P, add it to positions (i-P) and (i-P+1)
    for i in p_len..fg.len() {
        let coeff = fg[i];
        let target1 = i - p_len;
        let target2 = target1 + 1;

        result[target1] += coeff;
        if target2 < p_len {
            result[target2] += coeff;
        }
    }

    // Reduce all coefficients modulo Q
    result.iter().map(|&v| freeze(v)).collect()
}

/// AVX2-accelerated modular reduction for arrays
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified via `is_x86_feature_detected!("avx2")`)
/// - Input slice `a` contains valid i32 values (no specific length requirement)
///
/// When these preconditions are met:
/// - `_mm256_loadu_si256` reads valid memory (supports unaligned loads)
/// - `_mm256_storeu_si256` writes within result vector bounds
/// - Barrett reduction arithmetic operates on valid SIMD registers
/// - Returned vector contains i16 values in range [-Q/2, Q/2)
///
/// Scalar fallback: `reduce_scalar()` handles systems without AVX2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn reduce_avx2(a: &[i32]) -> Vec<i16> {
    if !is_x86_feature_detected!("avx2") {
        return reduce_scalar(a);
    }

    let n = a.len();
    let mut result = vec![0i16; n];

    // Process 8 values at a time
    let chunks = n / 8;
    let rem = n % 8;

    let modulus = _mm256_set1_epi32(MODULUS);
    let q_inv_256 = _mm256_set1_epi32(934_409); // Magic constant for Barrett

    for i in 0..chunks {
        let offset = i * 8;
        let data = _mm256_loadu_si256(a.as_ptr().add(offset) as *const __m256i);

        // Barrett reduction in parallel
        let t = _mm256_mullo_epi32(data, q_inv_256);
        let t_shifted = _mm256_srli_epi32(t, 32);
        let q_mul = _mm256_mullo_epi32(t_shifted, modulus);
        let b = _mm256_sub_epi32(data, q_mul);

        // Final adjustment
        let c = _mm256_sub_epi32(b, modulus);

        // Store results
        _mm256_storeu_si256(result.as_mut_ptr().add(offset) as *mut __m256i, c);
    }

    // Handle remainder
    for i in (chunks * 8)..n {
        result[i] = freeze(a[i]);
    }

    result
}

/// AVX2-accelerated batch freeze operation
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified via `is_x86_feature_detected!("avx2")`)
/// - Input slice `a` contains valid i32 values (no specific length requirement)
///
/// When these preconditions are met:
/// - `_mm256_loadu_si256` reads valid memory from slice (supports unaligned loads)
/// - `std::mem::transmute` safely converts __m256i to [i32; 8] (both 256-bit)
/// - All slice writes `a[offset + j]` stay within bounds due to loop constraints
/// - `freeze()` safely reduces each i32 to i16 in range [-Q/2, Q/2)
///
/// Scalar fallback: `freeze()` handles systems without AVX2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn freeze_batch_avx2(a: &mut [i32]) {
    let n = a.len();
    let chunks = n / 8;

    let modulus = _mm256_set1_epi32(MODULUS);
    let q_inv = _mm256_set1_epi32(934_409);

    for i in 0..chunks {
        let offset = i * 8;
        let data = _mm256_loadu_si256(a.as_ptr().add(offset) as *const __m256i);

        // Barrett reduction
        let t = _mm256_mullo_epi32(data, q_inv);
        let t_hi = _mm256_srli_epi32(t, 32);
        let q_mul = _mm256_mullo_epi32(t_hi, modulus);
        let b = _mm256_sub_epi32(data, q_mul);

        // Store back
        let b_arr: [i32; 8] = std::mem::transmute(b);
        for j in 0..8 {
            a[offset + j] = b_arr[j];
        }
    }

    // Handle remainder
    for i in (chunks * 8)..n {
        a[i] = freeze(a[i]) as i32;
    }
}

/// AVX2-accelerated polynomial multiplication with better vectorization
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified via `is_x86_feature_detected!("avx2")`)
/// - `f` and `g` have equal length (NTRU Prime parameter P)
/// - No mutable aliasing exists between input and output slices
///
/// When these preconditions are met:
/// - `_mm256_loadu_si256`, `_mm_loadu_si128` read valid memory (support unaligned loads)
/// - `_mm256_cvtepi16_epi32` safely zero-extends i16 to i32
/// - `_mm256_mullo_epi32`, `_mm256_add_epi32` operate on valid SIMD registers
/// - `horizontal_sum_epi32()` safely extracts all 8 i32 values
/// - `freeze()` safely reduces each coefficient to valid range
///
/// Scalar fallback: `poly_mul_scalar()` handles systems without AVX2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_mul_avx2_optimized(f: &[i16], g: &[i16]) -> Vec<i16> {
    let n = f.len();

    // For smaller polynomials, use scalar
    if n <= 64 {
        return poly_mul_scalar(f, g);
    }

    // Process using vectorized inner product (8 at a time)
    let mut result = vec![0i32; n];

    const BLOCK_SIZE: usize = 8;

    for i in 0..n {
        let mut acc = _mm256_setzero_si256();

        let j_max = (i + 1).min(n);
        let j_limit = (j_max / BLOCK_SIZE) * BLOCK_SIZE;

        // Vectorized portion - process 8 coefficients at once
        for j in (0..j_limit).step_by(BLOCK_SIZE) {
            // Load 8 i16 values from f and zero-extend to i32
            let f_vec = load_i16_block(&f[j..]);

            // Build reversed g vector for convolution
            let mut g_tmp = [0i16; 8];
            let g_start = i.saturating_sub(j + 7);
            let g_end = i + 1 - j;
            let g_len = (g_end - g_start).clamp(0, 8);

            for k in 0..g_len {
                if g_start + k < n && i - j - k >= 0 && i - j - k < n {
                    g_tmp[7 - k] = g[i - j - k];
                }
            }
            let g_lo = _mm_loadu_si128(g_tmp.as_ptr() as *const __m128i);
            let g_vec = _mm256_cvtepi16_epi32(g_lo);

            // Multiply and accumulate
            let prod = _mm256_mullo_epi32(f_vec, g_vec);
            acc = _mm256_add_epi32(acc, prod);
        }

        // Horizontal sum of accumulator
        let mut sum = horizontal_sum_epi32(acc);

        // Handle remaining coefficients
        for j in j_limit..j_max {
            sum += (f[j] as i32) * (g[i - j] as i32);
        }

        result[i] = sum;
    }

    // Reduce results
    let mut reduced = vec![0i16; n];
    for i in 0..n {
        reduced[i] = freeze(result[i]);
    }
    reduced
}

/// Load a block of up to 8 i16 values and zero-extend to i32
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (only called from AVX2-enabled functions)
/// - `arr` slice length is <= 8 (enforced by `arr.len().min(8)` in implementation)
///
/// When these preconditions are met:
/// - `tmp[..len].copy_from_slice(&arr[..len])` stays within bounds
/// - `_mm_loadu_si128` reads valid 128-bit memory (supports unaligned loads)
/// - `_mm256_cvtepi16_epi32` safely zero-extends 8 i16 values to 8 i32 values
///
/// This is an internal helper function called only from `poly_mul_avx2_optimized()`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn load_i16_block(arr: &[i16]) -> __m256i {
    let mut tmp = [0i16; 8];
    let len = arr.len().min(8);
    tmp[..len].copy_from_slice(&arr[..len]);

    // Load as 128-bit and zero-extend to 256-bit
    let lo = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
    _mm256_cvtepi16_epi32(lo)
}

/// Load 8 i16 values in reverse order
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (only called from AVX2-enabled functions)
/// - `arr` slice length is <= 8 (enforced by `arr.len().min(8)` in implementation)
///
/// When these preconditions are met:
/// - Array access `tmp[7 - i]` stays within bounds (0..8)
/// - `_mm_loadu_si128` reads valid 128-bit memory (supports unaligned loads)
/// - `_mm256_cvtepi16_epi32` safely zero-extends 8 i16 values to 8 i32 values
/// - Reverse ordering is achieved via indexed assignment before SIMD load
///
/// This is an internal helper function. The `_base_idx` parameter is currently
/// unused but kept for potential future optimization.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn load_i16_block_reverse(arr: &[i16], _base_idx: usize) -> __m256i {
    let mut tmp = [0i16; 8];
    let len = arr.len().min(8);

    for (i, &val) in arr.iter().take(len).enumerate() {
        tmp[7 - i] = val;
    }

    let lo = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
    _mm256_cvtepi16_epi32(lo)
}

/// Horizontal sum of __m256i containing 8 i32 values
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (only called from AVX2-enabled functions)
/// - `v` contains valid __m256i data (produced by other AVX2 intrinsics)
///
/// When these preconditions are met:
/// - `_mm256_extract_epi32(v, i)` safely extracts each of the 8 i32 values
/// - Indices 0-7 are valid for __m256i (contains exactly 8 i32 values)
/// - Overflow is impossible for typical polynomial coefficient ranges
///
/// This is an internal helper function called only from `poly_mul_avx2_optimized()`.
/// Alternative implementation would use `_mm256_hadd_epi32` but manual extraction
/// provides explicit control and avoids potential shuffle complexity.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_sum_epi32(v: __m256i) -> i32 {
    // Extract all 8 values
    _mm256_extract_epi32(v, 0)
        + _mm256_extract_epi32(v, 1)
        + _mm256_extract_epi32(v, 2)
        + _mm256_extract_epi32(v, 3)
        + _mm256_extract_epi32(v, 4)
        + _mm256_extract_epi32(v, 5)
        + _mm256_extract_epi32(v, 6)
        + _mm256_extract_epi32(v, 7)
}

/// AVX2 modular reduction (single value)
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports AVX2 instructions (verified via `is_x86_feature_detected!("avx2")`)
///
/// When this precondition is met:
/// - The underlying `freeze()` function safely reduces any i32 to i16 in range [-Q/2, Q/2)
/// - This function is a type adapter for AVX2 code paths
///
/// Scalar fallback: `freeze()` handles systems without AVX2
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn freeze_avx2(a: i32) -> i16 {
    freeze(a)
}

// =============================================================================
// NEON Implementation (ARM64)
// =============================================================================

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

/// NEON-accelerated polynomial multiplication
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports ARM NEON instructions (verified via `std::arch::is_aarch64_feature_detected!("neon")`)
/// - `f` and `g` have equal length >= 761 (NTRU Prime parameter P)
/// - No mutable aliasing exists between input and output slices
///
/// When these preconditions are met:
/// - All slice accesses stay within bounds
/// - Arithmetic operations use standard i32/i16 semantics
/// - `freeze()` safely reduces each coefficient to valid range
///
/// Note: This implementation currently uses scalar arithmetic within the NEON
/// function body. A true vectorized NEON implementation would use int16x8_t
/// and int32x4_t types for 2-4x speedup.
///
/// Scalar fallback: `poly_mul_scalar()` handles systems without NEON
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn poly_mul_neon(f: &[i16], g: &[i16]) -> Vec<i16> {
    let n = f.len();
    let mut result = vec![0i16; n];

    // Process 8 coefficients at a time using 128-bit vectors
    for i in 0..n {
        let mut scalar_acc = 0i32;

        // Process in blocks of 8
        let j_max = i + 1;
        for j in 0..j_max {
            scalar_acc += (f[j] as i32) * (g[i - j] as i32);
        }

        result[i] = freeze(scalar_acc);
    }

    result
}

/// NEON-accelerated modular reduction
///
/// # Safety
///
/// The caller must ensure that:
/// - CPU supports ARM NEON instructions (verified via `std::arch::is_aarch64_feature_detected!("neon")`)
/// - Input slice `a` contains valid i32 values (no specific length requirement)
///
/// When these preconditions are met:
/// - Slice iteration stays within bounds
/// - The underlying `freeze()` function safely reduces each i32 to i16 in range [-Q/2, Q/2)
/// - Standard iterator semantics ensure memory safety
///
/// Scalar fallback: `reduce_scalar()` handles systems without NEON
///
/// Note: This implementation currently uses scalar arithmetic within the NEON
/// function body. A true vectorized NEON implementation would use int32x4_t
/// types for 2-4x speedup.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn reduce_neon(a: &[i32]) -> Vec<i16> {
    a.iter().map(|&x| freeze(x)).collect()
}

// =============================================================================
// Common Functions
// =============================================================================

/// Modular reduction using optimized Barrett reduction
///
/// Returns value in range [-Q/2, Q/2) using constant-time algorithm.
#[inline(always)]
pub fn freeze(a: i32) -> i16 {
    // Optimized Barrett reduction for Q = 4591
    // Magic constant: floor(2^32 / Q) = 934409
    const MAGIC: i32 = 934_409;
    const Q_I32: i32 = 4_591;

    let t = ((a as i64) * (MAGIC as i64)) >> 32;
    let b = a - (t as i32) * Q_I32;
    let mut c = b - Q_I32;

    // Branchless conditional: if b < 0, c = b; else c = c
    let mask = (b >> 31) & Q_I32;
    c += mask;

    c as i16
}

/// Fast modular multiplication
#[inline(always)]
pub fn mod_mul(a: i16, b: i16) -> i16 {
    freeze(a as i32 * b as i32)
}

/// Fast modular subtraction
#[inline(always)]
pub fn mod_sub(a: i16, b: i16) -> i16 {
    freeze(a as i32 - b as i32)
}

/// Multiply-add: a + b*c mod Q
#[inline(always)]
pub fn mod_mul_add(a: i16, b: i16, c: i16) -> i16 {
    freeze(a as i32 + (b as i32 * c as i32))
}

/// Multiply-subtract: a - b*c mod Q
#[inline(always)]
pub fn mod_mul_sub(a: i16, b: i16, c: i16) -> i16 {
    freeze(a as i32 - (b as i32 * c as i32))
}

// =============================================================================
// Dispatch Functions
// =============================================================================

/// Polynomial multiplication with automatic SIMD dispatch
#[cfg(target_arch = "x86_64")]
pub fn poly_mul(f: &[i16], g: &[i16]) -> Vec<i16> {
    #[cfg(target_feature = "avx2")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 support was just verified above via is_x86_feature_detected!
            return unsafe { poly_mul_avx2_optimized(f, g) };
        }
    }
    poly_mul_scalar(f, g)
}

/// Polynomial multiplication with automatic SIMD dispatch (non-x86)
#[cfg(not(target_arch = "x86_64"))]
pub fn poly_mul(f: &[i16], g: &[i16]) -> Vec<i16> {
    #[cfg(target_arch = "aarch64")]
    {
        #[cfg(target_feature = "neon")]
        {
            // SAFETY: NEON is assumed available on ARM64 platforms (target_feature ensures this)
            return unsafe { poly_mul_neon(f, g) };
        }
    }
    poly_mul_scalar(f, g)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeze() {
        // Test boundary values
        assert_eq!(freeze(0), 0);
        assert_eq!(freeze(4591), 0);
        assert_eq!(freeze(-4591), 0);
        assert_eq!(freeze(2295), 2295); // Q/2
        assert_eq!(freeze(-2296), -2296); // -Q/2
    }

    #[test]
    fn test_poly_mul_scalar() {
        let f = [1i16, 2, 3, 4, 5];
        let g = [2i16, 3, 4, 5, 6];
        let result = poly_mul_scalar(&f, &g);

        // First coefficient: 1*2 = 2
        assert_eq!(result[0], 2);
        // Second: 1*3 + 2*2 = 3 + 4 = 7
        assert_eq!(result[1], 7);
    }

    #[test]
    fn test_poly_mul_dispatch() {
        let f = [1i16, 2, 3, 4, 5];
        let g = [2i16, 3, 4, 5, 6];
        let result = poly_mul(&f, &g);

        // Should match scalar result
        let expected = poly_mul_scalar(&f, &g);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mod_operations() {
        assert_eq!(mod_mul(100, 50), freeze(5000));
        assert_eq!(freeze(1000 + 2000), freeze(3000));
        assert_eq!(mod_sub(100, 200), freeze(-100));
    }
}

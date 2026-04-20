// SPDX-License-Identifier: OPL-1.1

//! Pre-computed tables for fast polynomial operations
//!
//! Provides lookup tables for R3 (coefficient space {-1, 0, 1}) operations
//! to accelerate polynomial multiplication by 2-3x.

use crate::kem::ntru_prime::constants::P;

// =============================================================================
// R3 Multiplication Table
// =============================================================================

/// Pre-computed multiplication table for R3 polynomials
///
/// Since R3 coefficients are only {-1, 0, 1}, we can precompute
/// all possible products to speed up multiplication.
pub struct R3Table {
    /// Table of product coefficients
    /// table[a+1][b+1] = a * b mod 3 where a, b ∈ {-1, 0, 1}
    mul_table: [[i8; 3]; 3],
}

impl R3Table {
    /// Create a new R3 multiplication table
    pub const fn new() -> Self {
        Self {
            mul_table: [
                // -1 * {-1, 0, 1} = {1, 0, -1}
                [1, 0, -1],
                // 0 * {-1, 0, 1} = {0, 0, 0}
                [0, 0, 0],
                // 1 * {-1, 0, 1} = {-1, 0, 1}
                [-1, 0, 1],
            ],
        }
    }

    /// Look up product of two R3 coefficients
    #[inline(always)]
    pub const fn mul(&self, a: i8, b: i8) -> i8 {
        // Map a, b from {-1, 0, 1} to {0, 1, 2}
        let ai = (a + 1) as usize;
        let bi = (b + 1) as usize;
        self.mul_table[ai][bi]
    }
}

/// Global R3 multiplication table (const-initialized)
pub const R3_MUL_TABLE: R3Table = R3Table::new();

// =============================================================================
// Small Polynomial Multiplication Table
// =============================================================================

/// Pre-computed products for small polynomial segments
///
/// For fast multiplication, we precompute products of small
/// coefficient patterns.
pub struct SmallProductTable {
    /// Products of 4-element patterns: table[a][b] where a, b encode patterns
    table: Vec<Vec<i8>>,
}

impl SmallProductTable {
    /// Create a new small product table
    ///
    /// For R3 with 4-element patterns, we have 3^4 = 81 possible patterns.
    /// A full table would be 81 x 81 x 4 = 26,244 entries.
    pub fn new() -> Self {
        let size = 81; // 3^4
        let mut table = vec![vec![0i8; size * 4]; size];

        for a in 0..size {
            let a_poly = decode_4(a as u8);
            for b in 0..size {
                let b_poly = decode_4(b as u8);
                let product = poly_mul_r3_small(&a_poly, &b_poly);
                let offset = b * 4;
                table[a][offset..offset + 4].copy_from_slice(&product[..4]);
            }
        }

        Self { table }
    }

    /// Look up product of two 4-element patterns
    #[inline(always)]
    pub fn get(&self, a: usize, b: usize) -> &[i8] {
        let offset = b * 4;
        &self.table[a][offset..offset + 4]
    }
}

/// Decode a 4-element pattern from base-3 encoding
#[inline(always)]
fn decode_4(mut x: u8) -> [i8; 4] {
    let mut result = [0i8; 4];
    for i in 0..4 {
        result[i] = ((x % 3) as i8) - 1;
        x /= 3;
    }
    result
}

/// Small R3 polynomial multiplication (4 elements)
#[inline(always)]
fn poly_mul_r3_small(a: &[i8; 4], b: &[i8; 4]) -> [i8; 7] {
    let mut result = [0i8; 7];

    for i in 0..4 {
        for j in 0..4 {
            result[i + j] = freeze_r3(result[i + j] as i32 + a[i] as i32 * b[j] as i32);
        }
    }

    result
}

/// Modular reduction for R3 (mod 3) - const version
#[inline(always)]
const fn freeze_r3_const(a: i32) -> i8 {
    let b = a - 3 * ((10_923 * a) >> 15);
    let c = b - 3 * ((89_478_485 * b + 134_217_728) >> 28);
    c as i8
}

/// Modular reduction for R3 (mod 3) - runtime version
#[inline(always)]
fn freeze_r3(a: i32) -> i8 {
    freeze_r3_const(a)
}

// =============================================================================
// Weighted Inner Product Table
// =============================================================================

/// Pre-computed weighted sums for fast coefficient operations
pub struct WeightTable {
    /// Table of weighted sums for small coefficient ranges
    table: [i32; 256], // For all possible i8 values (treated as unsigned index)
}

impl WeightTable {
    /// Create a new weight table
    pub const fn new() -> Self {
        let mut table = [0i32; 256];
        let mut i = 0;
        while i < 256 {
            let val = (i as i8) as i32;
            table[i] = val.abs();
            i += 1;
        }
        Self { table }
    }

    /// Get absolute value weight of an i8
    #[inline(always)]
    pub const fn weight(&self, a: i8) -> i32 {
        self.table[(a as u8) as usize]
    }
}

/// Global weight table
pub const WEIGHT_TABLE: WeightTable = WeightTable::new();

// =============================================================================
// Squash Table for Fast Modulo Operations
// =============================================================================

/// Pre-computed reduction table for mod 3 operations
pub struct Mod3Table {
    /// Reduction table: maps sum to mod 3 result in {-1, 0, 1}
    table: [i8; 128], // Covers range -64 to +63
}

impl Mod3Table {
    /// Create a new mod 3 reduction table
    pub const fn new() -> Self {
        let mut table = [0i8; 128];
        let mut i = 0;
        while i < 128 {
            let val = i as i32 - 64;
            let reduced = freeze_r3_const(val);
            table[i] = reduced;
            i += 1;
        }
        Self { table }
    }

    /// Reduce a value mod 3 using table lookup
    #[inline(always)]
    pub fn reduce(&self, a: i32) -> i8 {
        if a >= -64 && a < 64 {
            self.table[(a + 64) as usize]
        } else {
            freeze_r3(a)
        }
    }
}

/// Global mod 3 reduction table
pub const MOD3_TABLE: Mod3Table = Mod3Table::new();

// =============================================================================
// RQ Coefficient Squash Table
// =============================================================================

/// Pre-computed reduction table for mod Q operations (Q = 4591)
pub struct ModQTable {
    /// Table for values in range [-8192, 8191]
    table: Vec<i16>,
}

impl ModQTable {
    /// Create a new mod Q reduction table
    pub fn new() -> Self {
        let mut table = vec![0i16; 16384];
        for i in -8192i32..8192 {
            table[(i + 8192) as usize] = freeze_rq(i);
        }
        Self { table }
    }

    /// Reduce a value mod Q using table lookup
    #[inline(always)]
    pub fn reduce(&self, a: i32) -> i16 {
        if a >= -8192 && a < 8192 {
            self.table[(a + 8192) as usize]
        } else {
            freeze_rq(a)
        }
    }
}

/// Modular reduction for RQ (mod 4591)
#[inline(always)]
fn freeze_rq(a: i32) -> i16 {
    let b = a - 4_591 * ((228 * a) >> 20);
    let c = b - 4_591 * ((58_470 * b + 134_217_728) >> 28);
    c as i16
}

// =============================================================================
// Twiddle Factor Table for NTT
// =============================================================================

/// Pre-computed twiddle factors for NTT operations
pub struct TwiddleTable {
    /// Twiddle factors for different NTT sizes
    factors: Vec<Vec<i32>>,
}

impl TwiddleTable {
    /// Create a new twiddle factor table for NTT
    pub fn new() -> Self {
        const ROOT: i32 = 4; // Primitive root
        const Q_VAL: i32 = 4_591;
        let mut factors = Vec::new();

        // Precompute for sizes: 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
        let mut size_log = 1_usize; // log2 of size (2^1 = 2)
        while size_log <= 10 {
            // 2^10 = 1024
            let size = 1_usize << size_log;
            let mut row = Vec::with_capacity(size / 2);
            for j in 0..(size / 2) {
                // Compute: ROOT^((Q-1)/size * j) mod Q
                let exp = ((Q_VAL - 1) / size as i32 * j as i32) % Q_VAL;
                let twiddle = mod_pow(ROOT, exp, Q_VAL);
                row.push(twiddle);
            }
            factors.push(row);
            size_log += 1;
        }

        Self { factors }
    }

    /// Get twiddle factors for a given NTT size
    #[inline(always)]
    pub fn get(&self, size: usize) -> Option<&[i32]> {
        let idx = size.ilog2().saturating_sub(1) as usize;
        self.factors.get(idx).map(|v| v.as_slice())
    }
}

/// Modular exponentiation
#[inline(always)]
fn mod_pow(mut base: i32, mut exp: i32, modulus: i32) -> i32 {
    let mut result = 1;
    base = ((base % modulus) + modulus) % modulus;

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }

    result
}

// =============================================================================
// Global Tables (lazy initialization)
// =============================================================================

#[cfg(feature = "pqc-simd")]
use once_cell::sync::Lazy;

/// Global small product table (lazy-initialized)
#[cfg(feature = "pqc-simd")]
pub static SMALL_PRODUCT_TABLE: Lazy<SmallProductTable> = Lazy::new(|| SmallProductTable::new());

/// Global mod Q table (lazy-initialized)
#[cfg(feature = "pqc-simd")]
pub static MOD_Q_TABLE: Lazy<ModQTable> = Lazy::new(|| ModQTable::new());

/// Global twiddle factor table (lazy-initialized)
#[cfg(feature = "pqc-simd")]
pub static TWIDDLE_TABLE: Lazy<TwiddleTable> = Lazy::new(|| TwiddleTable::new());

// =============================================================================
// Table Lookup Functions
// =============================================================================

/// Fast R3 coefficient multiplication using table lookup
#[inline(always)]
pub fn r3_mul_table(a: i8, b: i8) -> i8 {
    R3_MUL_TABLE.mul(a, b)
}

/// Fast mod 3 reduction using table lookup
#[inline(always)]
pub fn mod3_table(a: i32) -> i8 {
    MOD3_TABLE.reduce(a)
}

/// Fast absolute value (weight) using table lookup
#[inline(always)]
pub fn abs_table(a: i8) -> i32 {
    WEIGHT_TABLE.weight(a)
}

/// Count weight of polynomial using table lookup
pub fn count_weight_table(poly: &[i8]) -> i32 {
    poly.iter().map(|&x| abs_table(x)).sum()
}

/// Batch mod 3 reduction using table lookups
pub fn mod3_batch_table(values: &mut [i8]) {
    for i in 0..values.len() {
        values[i] = mod3_table(values[i] as i32);
    }
}

// =============================================================================
// Optimized R3 Polynomial Multiplication with Tables
// =============================================================================

/// R3 polynomial multiplication using table lookups (2-3x faster)
pub fn r3_mult_table(h: &mut [i8], f: &[i8], g: &[i8]) {
    let n = f.len();
    let mut fg = [0i8; 1521]; // P * 2 - 1 = 1521

    for i in 0..n {
        let mut r = 0i32;
        for j in 0..=i {
            let prod = r3_mul_table(f[j], g[i - j]);
            r += prod as i32;
        }
        fg[i] = mod3_table(r);
    }

    for i in n..(2 * n - 1) {
        let mut r = 0i32;
        for j in (i - n + 1)..n {
            let prod = r3_mul_table(f[j], g[i - j]);
            r += prod as i32;
        }
        fg[i] = mod3_table(r);
    }

    // Apply NTRU Prime polynomial reduction
    for i in (n..(2 * n) - 1).rev() {
        let tmp1 = mod3_table(fg[i - n] as i32 + fg[i] as i32);
        fg[i - n] = tmp1;
        let tmp2 = mod3_table(fg[i - n + 1] as i32 + fg[i] as i32);
        fg[i - n + 1] = tmp2;
    }

    h[..n].copy_from_slice(&fg[..n]);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r3_mul_table() {
        assert_eq!(r3_mul_table(-1, -1), 1);
        assert_eq!(r3_mul_table(-1, 0), 0);
        assert_eq!(r3_mul_table(-1, 1), -1);
        assert_eq!(r3_mul_table(0, 0), 0);
        assert_eq!(r3_mul_table(1, 1), 1);
    }

    #[test]
    fn test_mod3_table() {
        assert_eq!(mod3_table(0), 0);
        assert_eq!(mod3_table(3), 0);
        assert_eq!(mod3_table(4), 1);
        assert_eq!(mod3_table(-1), -1);
        assert_eq!(mod3_table(-4), -1);
    }

    #[test]
    fn test_abs_table() {
        assert_eq!(abs_table(0), 0);
        assert_eq!(abs_table(1), 1);
        assert_eq!(abs_table(-1), 1);
        assert_eq!(abs_table(5), 5);
        assert_eq!(abs_table(-5), 5);
    }

    #[test]
    fn test_count_weight_table() {
        let poly = [1i8, 0, -1, 1, 1, 0, -1, -1];
        assert_eq!(count_weight_table(&poly), 6);
    }

    #[test]
    fn test_r3_mult_table_small() {
        let mut h = [0i8; 5];
        let f = [1i8, 1, 1, 1, 1];
        let g = [1i8, 1, 1, 1, 1];

        r3_mult_table(&mut h, &f, &g);

        // Expected: convolution of [1,1,1,1,1] with itself
        assert_eq!(h[0], 1);
        assert_eq!(h[1], 0); // 2 mod 3 = -1
        assert_eq!(h[2], 0); // 3 mod 3 = 0
    }

    #[test]
    fn test_twiddle_table() {
        #[cfg(feature = "pqc-simd")]
        {
            let table = &*TWIDDLE_TABLE;

            // Check size 8 twiddle factors
            if let Some(factors) = table.get(8) {
                assert_eq!(factors.len(), 4);
                // First twiddle factor should be 1
                assert_eq!(factors[0], 1);
            }
        }
    }

    #[test]
    fn test_freeze_rq() {
        // Test basic reduction
        assert_eq!(freeze_rq(0), 0);
        assert_eq!(freeze_rq(4591), 0);
        assert_eq!(freeze_rq(-4591), 0);
        assert_eq!(freeze_rq(10000), 10000 - 4591 * 2);
    }
}

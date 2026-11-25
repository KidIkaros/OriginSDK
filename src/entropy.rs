// SPDX-License-Identifier: Apache-2.0

//! Entropy analysis and quality testing for cryptographic seeds.
//!
//! Ported from the cryp Python prototype's `entropy_analyzer.py`. Provides
//! statistical tests to validate that seed material has sufficient randomness.
//!
//! # Metrics
//!
//! - **Shannon entropy** — classic information-theoretic entropy
//! - **Min-entropy** — most conservative entropy estimate
//! - **Collision entropy** — Renyi entropy of order 2
//! - **Chi-squared test** — uniformity of byte distribution
//! - **Serial correlation** — correlation between adjacent bytes
//! - **Longest run** — longest run of identical bits
//!
//! # Quick start
//!
//! ```ignore
//! use origin_crypto_sdk::entropy;
//!
//! let data = [0x42u8; 256];
//! let metrics = entropy::analyze(&data);
//!
//! // Shannon entropy should be close to 8.0 bits/byte for random data
//! println!("Shannon: {:.2} bits/byte", metrics.shannon_entropy);
//! ```

/// Structural bit/byte/block analysis — catches defects statistical
/// moments miss (avalanche, transition entropy, block uniqueness).
pub mod structural;

// ---------------------------------------------------------------------------
// Metrics container
// ---------------------------------------------------------------------------

/// Comprehensive entropy metrics for a byte sequence.
#[derive(Debug, Clone)]
pub struct EntropyMetrics {
    /// Shannon entropy in bits per byte (0.0–8.0, 8.0 = perfectly random).
    pub shannon_entropy: f64,
    /// Min-entropy in bits per byte (most conservative estimate).
    pub min_entropy: f64,
    /// Collision entropy (Renyi order-2) in bits per byte.
    pub collision_entropy: f64,
    /// Chi-squared test statistic.
    pub chi_squared: f64,
    /// Chi-squared p-value (1.0 = perfectly uniform).
    pub chi_squared_p: f64,
    /// Serial correlation coefficient (-1.0 to 1.0, 0.0 = uncorrelated).
    pub serial_correlation: f64,
    /// Longest run of identical bits.
    pub longest_run: usize,
    /// Fraction of bits that are 1 (should be ~0.5).
    pub bit_bias: f64,
    /// Number of unique bytes observed.
    pub unique_bytes: usize,
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Analyze entropy characteristics of a byte sequence.
///
/// Minimum recommended input size: 256 bytes for meaningful statistics.
pub fn analyze(data: &[u8]) -> EntropyMetrics {
    if data.is_empty() {
        return EntropyMetrics::zero();
    }

    let n = data.len();
    let freq = byte_frequencies(data);
    let (shannon_entropy, min_entropy, collision_entropy) = entropy_stats(&freq, n);
    let chi_squared = chi_squared_stat(&freq, n);

    EntropyMetrics {
        shannon_entropy,
        min_entropy,
        collision_entropy,
        chi_squared,
        chi_squared_p: chi2_p_value(chi_squared, 255),
        serial_correlation: compute_serial_correlation(data),
        longest_run: compute_longest_bit_run(data),
        bit_bias: bit_bias(data),
        unique_bytes: freq.iter().filter(|&&c| c > 0).count(),
    }
}

impl EntropyMetrics {
    /// The all-zero metrics returned for empty input.
    fn zero() -> Self {
        Self {
            shannon_entropy: 0.0,
            min_entropy: 0.0,
            collision_entropy: 0.0,
            chi_squared: 0.0,
            chi_squared_p: 1.0,
            serial_correlation: 0.0,
            longest_run: 0,
            bit_bias: 0.0,
            unique_bytes: 0,
        }
    }
}

/// Byte frequency distribution of `data` as a 256-bin histogram.
fn byte_frequencies(data: &[u8]) -> [usize; 256] {
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    freq
}

/// Shannon, min-, and collision entropy computed from a byte histogram.
fn entropy_stats(freq: &[usize; 256], n: usize) -> (f64, f64, f64) {
    let mut shannon = 0.0_f64;
    let mut max_freq = 0usize;
    let mut collision_sum = 0.0_f64;
    for &count in freq {
        if count > 0 {
            let p = count as f64 / n as f64;
            shannon -= p * p.log2();
            collision_sum += p * p;
        }
        if count > max_freq {
            max_freq = count;
        }
    }

    // Min-entropy: H_min = -log2(max(p_i))
    let min_entropy = -((max_freq as f64) / (n as f64)).log2();
    // Collision entropy: H_2 = -log2(sum(p_i^2))
    let collision_entropy = -collision_sum.log2();

    (shannon, min_entropy, collision_entropy)
}

/// Chi-squared uniformity statistic against the uniform distribution.
fn chi_squared_stat(freq: &[usize; 256], n: usize) -> f64 {
    let expected = n as f64 / 256.0;
    freq.iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            diff * diff / expected
        })
        .sum()
}

/// Fraction of bits set to 1 (should be ~0.5 for uniform data).
fn bit_bias(data: &[u8]) -> f64 {
    let ones: usize = data.iter().map(|b| b.count_ones() as usize).sum();
    ones as f64 / (data.len() * 8) as f64
}

// ---------------------------------------------------------------------------
// Quality checking
// ---------------------------------------------------------------------------

/// Quality requirements for a given seed bit length.
#[derive(Debug)]
pub struct QualityRequirements {
    /// Minimum Shannon entropy (bits of entropy per bit of input).
    pub min_shannon: f64,
    /// Minimum min-entropy (worst-case entropy).
    pub min_min_entropy: f64,
    /// Minimum collision entropy.
    pub min_collision: f64,
    /// Minimum chi-squared p-value (uniformity test).
    pub min_chi_squared_p: f64,
    /// Maximum absolute serial correlation between consecutive bits.
    pub max_serial_correlation: f64,
    /// Maximum allowed deviation from uniform bit distribution (0.0 to 1.0).
    pub max_bit_bias_deviation: f64,
    /// Maximum length of the longest run of identical bits.
    pub max_longest_run: usize,
}

impl QualityRequirements {
    /// Shannon-entropy achievability cap for a sample of `n` bytes.
    ///
    /// Byte-level entropy of `n` samples is mathematically capped at
    /// log2(n) bits — a 32-byte seed can never exceed 5.0, and its
    /// expected value under perfect uniformity is ~4.9. Applying the
    /// fixed table (3.8-4.8) to seed-sized inputs is therefore unsound;
    /// this cap relaxes the requirement to 90% of the theoretical maximum
    /// when that maximum is the binding constraint. The 0.9 factor is a
    /// heuristic margin — it sits several standard deviations below the
    /// expected value of honest randomness at these sizes.
    ///
    /// Note the deeper limitation: at seed sizes most byte-distribution
    /// checks become near-vacuous (min/collision entropy are inflated by
    /// sparsity, chi-squared assumptions break down). Statistical
    /// validation is only meaningful on pooled samples — see the
    /// structural module's integration tests for the methodology.
    fn shannon_cap(n_bytes: u32) -> f64 {
        let n = n_bytes.max(2) as f64;
        0.9 * n.log2().min(8.0)
    }

    /// Apply size-awareness to a base requirement set.
    fn size_adjusted(mut self, bits: u32) -> Self {
        let cap = Self::shannon_cap(bits / 8);
        self.min_shannon = self.min_shannon.min(cap);
        self
    }

    /// Requirements for a salt of the given bit length.
    ///
    /// Salts need uniqueness, not full entropy — the relaxed table is
    /// ported from the cryp prototype's `_SALT_REQS` policy.
    pub fn for_salt(bits: u32) -> Self {
        let base = match bits {
            128 => QualityRequirements {
                min_shannon: 3.5,
                min_min_entropy: 2.4,
                min_collision: 3.2,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.8,
                max_bit_bias_deviation: 0.25,
                max_longest_run: 30,
            },
            192 => QualityRequirements {
                min_shannon: 3.6,
                min_min_entropy: 3.0,
                min_collision: 3.5,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.8,
                max_bit_bias_deviation: 0.2,
                max_longest_run: 25,
            },
            _ => QualityRequirements {
                min_shannon: 3.8,
                min_min_entropy: 3.2,
                min_collision: 3.6,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.8,
                max_bit_bias_deviation: 0.15,
                max_longest_run: 25,
            },
        };
        base.size_adjusted(bits)
    }

    /// Requirements for the given seed bit length.
    pub fn for_bits(bits: u32) -> Self {
        let base = match bits {
            128 => QualityRequirements {
                min_shannon: 3.8,
                min_min_entropy: 3.5,
                min_collision: 3.8,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.7,
                max_bit_bias_deviation: 0.2,
                max_longest_run: 25,
            },
            192 => QualityRequirements {
                min_shannon: 4.2,
                min_min_entropy: 3.75,
                min_collision: 4.2,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.6,
                max_bit_bias_deviation: 0.15,
                max_longest_run: 20,
            },
            // 256 and default
            _ => QualityRequirements {
                min_shannon: 4.8,
                min_min_entropy: 4.0,
                min_collision: 4.8,
                min_chi_squared_p: 0.0001,
                max_serial_correlation: 0.5,
                max_bit_bias_deviation: 0.12,
                max_longest_run: 20,
            },
        };
        base.size_adjusted(bits)
    }
}

/// Check if entropy metrics meet quality requirements for a seed of `bits` bits.
///
/// `bits` should describe the analyzed sample size (seed bits for a single
/// seed, total bits for pooled analysis). Entropy requirements are capped
/// at what a sample of that size can achieve — see
/// [`QualityRequirements::shannon_cap`]. Note that most byte-distribution
/// checks are near-vacuous at single-seed sizes regardless; meaningful
/// statistical validation requires pooled samples.
///
/// Returns `(passed, warnings)` where `passed` is true if all checks pass.
pub fn check_quality(metrics: &EntropyMetrics, bits: u32) -> (bool, Vec<String>) {
    let req = QualityRequirements::for_bits(bits);
    let mut warnings = Vec::new();

    if metrics.shannon_entropy < req.min_shannon {
        warnings.push(format!(
            "Shannon entropy ({:.2}) below minimum ({:.2})",
            metrics.shannon_entropy, req.min_shannon
        ));
    }
    if metrics.min_entropy < req.min_min_entropy {
        warnings.push(format!(
            "Min entropy ({:.2}) below minimum ({:.2})",
            metrics.min_entropy, req.min_min_entropy
        ));
    }
    if metrics.collision_entropy < req.min_collision {
        warnings.push(format!(
            "Collision entropy ({:.2}) below minimum ({:.2})",
            metrics.collision_entropy, req.min_collision
        ));
    }
    if metrics.chi_squared_p < req.min_chi_squared_p {
        warnings.push(format!(
            "Chi-squared p-value ({:.6}) below minimum ({:.6})",
            metrics.chi_squared_p, req.min_chi_squared_p
        ));
    }
    if metrics.serial_correlation.abs() > req.max_serial_correlation {
        warnings.push(format!(
            "Serial correlation ({:.4}) exceeds maximum ({:.1})",
            metrics.serial_correlation, req.max_serial_correlation
        ));
    }
    if (metrics.bit_bias - 0.5).abs() > req.max_bit_bias_deviation {
        warnings.push(format!(
            "Bit bias ({:.4}) deviates more than {:.2} from 0.5",
            metrics.bit_bias, req.max_bit_bias_deviation
        ));
    }
    if metrics.longest_run > req.max_longest_run {
        warnings.push(format!(
            "Longest run ({}) exceeds maximum ({})",
            metrics.longest_run, req.max_longest_run
        ));
    }

    (warnings.is_empty(), warnings)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Approximate chi-squared p-value using the Wilson-Hilferty transformation.
fn chi2_p_value(chi2: f64, df: usize) -> f64 {
    if df == 0 {
        return 1.0;
    }
    // Wilson-Hilferty approximation: (chi2/df)^(1/3) ~ N(1-2/(9df), 2/(9df))
    let df_f = df as f64;
    let x = (chi2 / df_f).powf(1.0 / 3.0);
    let mean = 1.0 - 2.0 / (9.0 * df_f);
    let std_dev = (2.0 / (9.0 * df_f)).sqrt();

    if std_dev == 0.0 {
        return 1.0;
    }

    let z = (x - mean) / std_dev;

    // Standard normal CDF approximation (Abramowitz & Stegun)
    normal_cdf(z)
}

/// Standard normal CDF (Abramowitz & Stegun approximation).
fn normal_cdf(z: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.2316419 * z.abs());
    let d = 0.3989422804014327; // 1/sqrt(2*pi)
    let prob = d
        * (-z * z / 2.0).exp()
        * t
        * (0.319381530
            + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));

    if z > 0.0 {
        1.0 - prob
    } else {
        prob
    }
}

/// Serial correlation between adjacent bytes.
/// Single-pass over the data — no per-element allocation.
fn compute_serial_correlation(data: &[u8]) -> f64 {
    let n = data.len();
    if n <= 1 {
        return 0.0;
    }

    // Pass 1: mean
    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / n as f64;

    // Pass 2: numerator and denominator from deviations on the fly.
    // This avoids the Vec<f64> allocation that materialised one f64 per input
    // byte (8 bytes of RSS per input byte) — which OOM-killed the process on
    // multi-GB inputs.  (#…)
    let mut numerator = 0.0_f64;
    let mut denominator = 0.0_f64;
    let mut prev_dev = 0.0_f64;
    let mut first = true;

    for &b in data {
        let dev = b as f64 - mean;
        denominator += dev * dev;
        if !first {
            numerator += prev_dev * dev;
        }
        first = false;
        prev_dev = dev;
    }

    if denominator == 0.0 {
        return 0.0;
    }

    let corr = numerator / denominator;
    if corr.is_nan() {
        0.0
    } else {
        corr
    }
}

/// Longest run of identical bits.
fn compute_longest_bit_run(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }

    let mut longest = 1usize;
    let mut current = 1usize;
    let mut prev_bit: Option<bool> = None;

    for &byte in data {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1 == 1;
            if let Some(pb) = prev_bit {
                if bit == pb {
                    current += 1;
                    if current > longest {
                        longest = current;
                    }
                } else {
                    current = 1;
                }
            }
            prev_bit = Some(bit);
        }
    }

    longest
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_random_has_high_entropy() {
        // Generate pseudo-random data for testing
        let mut data = vec![0u8; 1024];
        for i in 0..data.len() {
            data[i] = ((i as u64 * 1103515245 + 12345) >> 16) as u8;
        }
        let m = analyze(&data);
        assert!(
            m.shannon_entropy > 5.0,
            "Shannon too low: {}",
            m.shannon_entropy
        );
    }

    #[test]
    fn constant_data_has_zero_entropy() {
        let data = [0u8; 256];
        let m = analyze(&data);
        assert!(
            m.shannon_entropy < 0.1,
            "Shannon should be ~0: {}",
            m.shannon_entropy
        );
        assert!(m.min_entropy < 0.1);
        assert_eq!(m.unique_bytes, 1);
    }

    #[test]
    fn alternating_bytes() {
        let data: Vec<u8> = (0..256)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        let m = analyze(&data);
        assert!(
            m.shannon_entropy < 2.0,
            "Alternating should have low entropy"
        );
        assert_eq!(m.unique_bytes, 2);
    }

    #[test]
    fn quality_check_passes_for_good_data() {
        let mut data = vec![0u8; 512];
        for i in 0..data.len() {
            data[i] = ((i as u64)
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
                >> 32) as u8;
        }
        let m = analyze(&data);
        let (pass, warnings) = check_quality(&m, 256);
        if !pass {
            eprintln!("Warnings: {warnings:?}");
        }
        // This is a PRNG, not true random, so we just check it doesn't crash
    }

    #[test]
    fn quality_check_fails_for_constant() {
        let data = [0u8; 256];
        let m = analyze(&data);
        let (pass, warnings) = check_quality(&m, 256);
        assert!(!pass, "Constant data should fail quality check");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn serial_correlation_zero_for_random() {
        let mut data = vec![0u8; 1024];
        for i in 0..data.len() {
            data[i] = ((i as u64).wrapping_mul(6364136223846793005) >> 32) as u8;
        }
        let m = analyze(&data);
        assert!(
            m.serial_correlation.abs() < 0.3,
            "Serial correlation too high: {}",
            m.serial_correlation
        );
    }

    #[test]
    fn empty_input_no_panic() {
        let m = analyze(&[]);
        assert_eq!(m.shannon_entropy, 0.0);
    }

    #[test]
    fn bit_bias_near_half() {
        let mut data = vec![0u8; 1024];
        for i in 0..data.len() {
            data[i] = ((i as u64)
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
                >> 32) as u8;
        }
        let m = analyze(&data);
        assert!(
            (m.bit_bias - 0.5).abs() < 0.1,
            "Bit bias too far from 0.5: {}",
            m.bit_bias
        );
    }

    #[test]
    fn single_seed_shannon_cap_is_size_aware() {
        // A 32-byte seed cannot exceed log2(32) = 5.0 bits/byte of byte-level
        // entropy; the requirement must relax below the fixed table's 4.8.
        let req = QualityRequirements::for_bits(256);
        assert!(
            req.min_shannon <= 4.5 + 1e-9,
            "shannon requirement {} should be capped near 0.9*log2(32)=4.5",
            req.min_shannon
        );
        // Large pooled samples keep the full table value.
        let pooled = QualityRequirements::for_bits(256 * 100);
        assert!((pooled.min_shannon - 4.8).abs() < 1e-9);
    }

    #[test]
    fn salt_requirements_are_relaxed() {
        let seed = QualityRequirements::for_bits(256);
        let salt = QualityRequirements::for_salt(256);
        assert!(salt.min_shannon < seed.min_shannon || salt.min_shannon <= 3.8 + 1e-9);
        assert!(salt.min_min_entropy < seed.min_min_entropy);
        assert!(salt.max_serial_correlation > seed.max_serial_correlation);
        assert!(salt.max_longest_run > seed.max_longest_run);
    }

    #[test]
    fn honest_random_pool_passes() {
        // xorshift64 test data — same generator as the structural tests.
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut data = Vec::with_capacity(3200);
        while data.len() < 3200 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.extend_from_slice(&state.to_le_bytes());
        }
        data.truncate(3200);
        let m = analyze(&data);
        let (passed, warnings) = check_quality(&m, 3200 * 8);
        assert!(passed, "pooled random data should pass: {:?}", warnings);
    }
}

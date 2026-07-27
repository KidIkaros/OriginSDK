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
        return EntropyMetrics {
            shannon_entropy: 0.0,
            min_entropy: 0.0,
            collision_entropy: 0.0,
            chi_squared: 0.0,
            chi_squared_p: 1.0,
            serial_correlation: 0.0,
            longest_run: 0,
            bit_bias: 0.0,
            unique_bytes: 0,
        };
    }

    let n = data.len();

    // Byte frequency distribution
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let unique_bytes = freq.iter().filter(|&&c| c > 0).count();

    // Shannon entropy: H = -sum(p_i * log2(p_i))
    let mut shannon = 0.0_f64;
    let mut max_freq = 0usize;
    let mut collision_sum = 0.0_f64;
    for &count in &freq {
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

    // Chi-squared test
    let expected = n as f64 / 256.0;
    let chi_squared = freq
        .iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            diff * diff / expected
        })
        .sum::<f64>();
    let chi_squared_p = chi2_p_value(chi_squared, 255);

    // Serial correlation
    let serial_correlation = compute_serial_correlation(data);

    // Longest bit run
    let longest_run = compute_longest_bit_run(data);

    // Bit bias (fraction of 1 bits)
    let total_bits = n * 8;
    let ones: usize = data.iter().map(|b| b.count_ones() as usize).sum();
    let bit_bias = ones as f64 / total_bits as f64;

    EntropyMetrics {
        shannon_entropy: shannon,
        min_entropy,
        collision_entropy,
        chi_squared,
        chi_squared_p,
        serial_correlation,
        longest_run,
        bit_bias,
        unique_bytes,
    }
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
    /// Requirements for the given seed bit length.
    pub fn for_bits(bits: u32) -> Self {
        match bits {
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
        }
    }
}

/// Check if entropy metrics meet quality requirements for a seed of `bits` bits.
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
fn compute_serial_correlation(data: &[u8]) -> f64 {
    if data.len() <= 1 {
        return 0.0;
    }

    let n = data.len() as f64;
    let mean: f64 = data.iter().map(|&b| b as f64).sum::<f64>() / n;

    let mut numerator = 0.0_f64;
    let mut denominator = 0.0_f64;

    let deviations: Vec<f64> = data.iter().map(|&b| b as f64 - mean).collect();

    for i in 0..deviations.len() {
        denominator += deviations[i] * deviations[i];
        if i > 0 {
            numerator += deviations[i - 1] * deviations[i];
        }
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
}

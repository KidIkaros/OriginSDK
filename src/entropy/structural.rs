// SPDX-License-Identifier: Apache-2.0

//! Structural entropy analysis for cryptographic seeds.
//!
//! Ported from the cryp Python prototype's `crypto_entropy.py`. Complements
//! the statistical metrics in [`crate::entropy`] with bit-, byte-, and
//! block-level *structural* checks. These catch defects statistical moments
//! miss — a monotonic counter, for example, has near-perfect byte entropy but
//! terrible avalanche behavior between adjacent blocks.
//!
//! # Metrics
//!
//! - **Bit level** — overall bit balance, per-position bit bias, longest run
//!   of identical bits, serial correlation of adjacent bits
//! - **Byte level** — byte uniqueness, maximum byte repetition ratio,
//!   transition entropy of byte-to-byte pairs
//! - **Block level** — Hamming-weight deviation of 64-bit blocks, block
//!   uniqueness, avalanche score between adjacent blocks
//!
//! # Threshold provenance
//!
//! The Python prototype's thresholds were fixed numbers that ignored sample
//! size — statistically unsatisfiable or miscalibrated for exactly the
//! seed-sized inputs the checks exist for (this is why the prototype's own
//! crypto-quality tests permanently failed). This port derives the
//! bit-level, Hamming, avalanche, byte-uniqueness, and transition-entropy
//! bounds from the input size (normal approximation, z = 4, and an exact
//! binomial occupancy tail for byte repetition; see
//! [`StructuralThresholds::for_bits`]). `max_run_length` and
//! `block_uniqueness` remain heuristic empirical bounds — they are caps
//! on events already improbable under randomness, not sampling estimates.
//! Treat marginal failures as signals for investigation, not proof of
//! weakness.

// ---------------------------------------------------------------------------
// Metrics containers
// ---------------------------------------------------------------------------

/// Bit-level structural metrics.
#[derive(Debug, Clone)]
pub struct BitMetrics {
    /// Overall fraction of 1-bits (should be close to 0.5).
    pub bit_balance: f64,
    /// Maximum deviation from 0.5 across the 8 bit positions within bytes.
    pub max_bit_bias: f64,
    /// Longest run of identical bits in the bitstream.
    pub max_run_length: usize,
    /// Pearson correlation between adjacent bits (0.0 = uncorrelated).
    ///
    /// Defined as 0.0 when the bitstream has zero variance (all-identical
    /// bits); such input fails the balance check regardless.
    pub bit_correlation: f64,
}

/// Byte-level structural metrics.
#[derive(Debug, Clone)]
pub struct ByteMetrics {
    /// Fraction of the 256 possible byte values observed (higher = better).
    pub byte_uniqueness: f64,
    /// Maximum repetition of any single byte, as a fraction of input length.
    pub max_repetition_ratio: f64,
    /// Shannon entropy (bits) of the byte-to-byte transition distribution.
    pub transition_entropy: f64,
}

/// Block-level structural metrics over 64-bit blocks.
#[derive(Debug, Clone)]
pub struct BlockMetrics {
    /// Mean Hamming weight of 64-bit blocks, normalized to [0, 1].
    pub avg_hamming_weight: f64,
    /// Fraction of blocks that are unique.
    pub block_uniqueness: f64,
    /// Mean fraction of differing bits between adjacent blocks.
    ///
    /// 0.5 = ideal avalanche behavior; 0 when fewer than 2 blocks exist.
    pub avg_avalanche: f64,
}

/// All structural metrics for a byte sequence.
#[derive(Debug, Clone)]
pub struct StructuralMetrics {
    /// Bit-level metrics.
    pub bit: BitMetrics,
    /// Byte-level metrics.
    pub byte: ByteMetrics,
    /// Block-level metrics.
    pub block: BlockMetrics,
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Analyze bit-level structure of `data`.
pub fn analyze_bit_patterns(data: &[u8]) -> BitMetrics {
    if data.is_empty() {
        return BitMetrics {
            bit_balance: 0.0,
            max_bit_bias: 0.5,
            max_run_length: 0,
            bit_correlation: 0.0,
        };
    }

    // Per-position fraction of 1s: bit position i counts bit i of every byte,
    // MSB-first ordering matching the Python prototype's format(b, '08b').
    let n_bytes = data.len() as f64;
    let mut position_bias = [0.0f64; 8];
    for (pos, bias) in position_bias.iter_mut().enumerate() {
        let shift = 7 - pos;
        let ones = data.iter().filter(|&&b| (b >> shift) & 1 == 1).count();
        *bias = ones as f64 / n_bytes;
    }

    let bit_balance = position_bias.iter().sum::<f64>() / 8.0;
    let max_bit_bias = position_bias
        .iter()
        .map(|p| (p - 0.5).abs())
        .fold(0.0f64, f64::max);

    // Longest run of identical bits across the whole bitstream.
    let mut max_run = 1usize;
    let mut current_run = 1usize;
    let mut prev_bit = (data[0] >> 7) & 1;
    for (byte_idx, &byte) in data.iter().enumerate() {
        let start = if byte_idx == 0 { 1 } else { 0 };
        for bit_idx in start..8 {
            let bit = (byte >> (7 - bit_idx)) & 1;
            if bit == prev_bit {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 1;
            }
            prev_bit = bit;
        }
    }

    BitMetrics {
        bit_balance,
        max_bit_bias,
        max_run_length: max_run,
        bit_correlation: adjacent_bit_correlation(data),
    }
}

/// Pearson correlation between bit i and bit i+1 over the bitstream.
fn adjacent_bit_correlation(data: &[u8]) -> f64 {
    let bits: Vec<f64> = data
        .iter()
        .flat_map(|&b| (0..8).map(move |i| ((b >> (7 - i)) & 1) as f64))
        .collect();
    if bits.len() < 2 {
        return 0.0;
    }
    pearson(&bits[..bits.len() - 1], &bits[1..])
}

/// Pearson correlation coefficient of two equal-length slices.
///
/// Returns 0.0 when either input has zero variance (undefined coefficient).
fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for (&x, &y) in xs.iter().zip(ys) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    if var_x == 0.0 || var_y == 0.0 {
        return 0.0;
    }
    cov / (var_x.sqrt() * var_y.sqrt())
}

/// Analyze byte-level structure of `data`.
pub fn analyze_byte_patterns(data: &[u8]) -> ByteMetrics {
    if data.is_empty() {
        return ByteMetrics {
            byte_uniqueness: 0.0,
            max_repetition_ratio: 0.0,
            transition_entropy: 0.0,
        };
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let unique_bytes = counts.iter().filter(|&&c| c > 0).count();
    let max_repetition = counts.iter().copied().max().unwrap_or(0);

    // Transition entropy over byte-to-byte pairs.
    let mut transition_entropy = 0.0;
    if data.len() > 1 {
        let mut transitions: std::collections::HashMap<(u8, u8), usize> =
            std::collections::HashMap::new();
        for pair in data.windows(2) {
            *transitions.entry((pair[0], pair[1])).or_insert(0) += 1;
        }
        let total = (data.len() - 1) as f64;
        for &count in transitions.values() {
            let p = count as f64 / total;
            transition_entropy -= p * p.log2();
        }
    }

    ByteMetrics {
        byte_uniqueness: unique_bytes as f64 / 256.0,
        max_repetition_ratio: max_repetition as f64 / data.len() as f64,
        transition_entropy,
    }
}

/// Analyze 64-bit block structure of `data`.
pub fn analyze_block_patterns(data: &[u8]) -> BlockMetrics {
    let blocks: Vec<&[u8]> = data.chunks_exact(8).collect();
    if blocks.is_empty() {
        return BlockMetrics {
            avg_hamming_weight: 0.0,
            block_uniqueness: 0.0,
            avg_avalanche: 0.0,
        };
    }

    let total_weight: usize = blocks
        .iter()
        .flat_map(|block| block.iter().map(|b| b.count_ones() as usize))
        .sum();
    let avg_hamming_weight = total_weight as f64 / (blocks.len() * 64) as f64;

    let unique = blocks
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let block_uniqueness = unique as f64 / blocks.len() as f64;

    let avg_avalanche = if blocks.len() > 1 {
        let total: f64 = blocks
            .windows(2)
            .map(|pair| {
                let diff: usize = pair[0]
                    .iter()
                    .zip(pair[1])
                    .map(|(a, b)| (a ^ b).count_ones() as usize)
                    .sum();
                diff as f64 / 64.0
            })
            .sum();
        total / (blocks.len() - 1) as f64
    } else {
        0.0
    };

    BlockMetrics {
        avg_hamming_weight,
        block_uniqueness,
        avg_avalanche,
    }
}

/// Run all three levels of structural analysis.
pub fn analyze(data: &[u8]) -> StructuralMetrics {
    StructuralMetrics {
        bit: analyze_bit_patterns(data),
        byte: analyze_byte_patterns(data),
        block: analyze_block_patterns(data),
    }
}

// ---------------------------------------------------------------------------
// Quality thresholds and checking
// ---------------------------------------------------------------------------

/// Structural quality thresholds. See module docs for provenance caveats.
#[derive(Debug, Clone)]
pub struct StructuralThresholds {
    /// Acceptable range for overall bit balance.
    pub bit_balance: (f64, f64),
    /// Maximum per-position bit bias.
    pub max_bit_bias: f64,
    /// Maximum run of identical bits.
    pub max_run_length: usize,
    /// Maximum absolute adjacent-bit correlation.
    pub bit_correlation: f64,
    /// Minimum byte uniqueness ratio.
    pub byte_uniqueness: f64,
    /// Maximum byte repetition ratio.
    pub max_repetition: f64,
    /// Minimum transition entropy in bits.
    pub transition_entropy: f64,
    /// Maximum deviation of mean Hamming weight from 0.5.
    pub hamming_weight: f64,
    /// Minimum block uniqueness ratio.
    pub block_uniqueness: f64,
    /// Maximum deviation of mean avalanche score from 0.5.
    pub avalanche: f64,
}

impl StructuralThresholds {
    /// The 256-bit reference table (unscaled heuristic bounds).
    pub fn base() -> Self {
        StructuralThresholds {
            bit_balance: (0.45, 0.55),
            max_bit_bias: 0.15,
            max_run_length: 32,
            bit_correlation: 0.15,
            byte_uniqueness: 0.2,
            max_repetition: 0.1,
            transition_entropy: 5.5,
            hamming_weight: 0.1,
            block_uniqueness: 0.9,
            avalanche: 0.15,
        }
    }

    /// Thresholds scaled for a seed of `bits` bits.
    ///
    /// Two layers of adjustment over the base table:
    ///
    /// 1. Heuristic widening (carried from the Python prototype): inputs
    ///    smaller than 256 bits get bounds widened by up to 10%.
    /// 2. Size-aware caps (a fix for a defect in the Python original):
    ///    `byte_uniqueness` and `transition_entropy` have hard ceilings set
    ///    by input length — a 32-byte input can never contain 52 distinct
    ///    byte values, and `n - 1` transitions can never have entropy above
    ///    `log2(n - 1)`. The prototype's fixed thresholds were therefore
    ///    unsatisfiable for exactly the seed-sized inputs the checks exist
    ///    for. Here the requirement is capped at a fraction of what uniform
    ///    random data of that size *expectedly* achieves:
    ///    - uniqueness: 75% of `1 - (255/256)^n` (expected unique fraction)
    ///    - transition entropy: 80% of `log2(n - 1)`
    pub fn for_bits(bits: u32) -> Self {
        let scale = bits as f64 / 256.0;
        let slack = 0.1 * (1.0 - scale).max(0.0);
        let widen = 1.0 + slack;
        let base = Self::base();

        let n = (bits / 8).max(2) as f64;
        let expected_unique_fraction = 1.0 - (255.0f64 / 256.0).powf(n);
        let uniqueness_cap = 0.75 * expected_unique_fraction;
        let max_transition_entropy = ((n - 1.0).max(2.0)).log2();
        let transition_cap = 0.8 * max_transition_entropy;

        // Bit-level and block-level bounds use normal-approximation z-scores
        // instead of the prototype's fixed numbers. The fixed values are
        // statistically miscalibrated for seed-sized inputs: e.g. per-position
        // bit bias over 32 samples exceeds the fixed 0.15 in ~half of all
        // honest random seeds (std dev of the estimate is 0.5/sqrt(32) ~
        // 0.088, so 0.15 is only 1.7 sigma). z = 4 keeps the per-check false
        // positive rate at ~6e-5, so a full `check_quality` run almost never
        // fails on genuinely random data. The cost is honest: small inputs
        // simply cannot detect small biases, and the wide bounds reflect that.
        const Z: f64 = 4.0;
        let total_bits = 8.0 * n;
        // Bit balance: mean of 8n Bernoulli(0.5) samples.
        let balance_width = Z * 0.5 / total_bits.sqrt();
        // Per-position bit bias: mean of n samples per position.
        let bias_bound = Z * 0.5 / n.sqrt();
        // Serial correlation of N adjacent bit pairs: std ~ 1/sqrt(N).
        let corr_bound = Z / total_bits.sqrt();
        // Hamming weight: same sampling structure as bit balance.
        let hamming_width = Z * 0.5 / total_bits.sqrt();
        // Avalanche: mean of m independent 64-bit-diff fractions, each with
        // std sqrt(64 * 0.25) / 64 = 0.0625.
        let blocks = (n / 8.0).floor();
        let avalanche_width = if blocks > 1.0 {
            Z * 0.0625 / (blocks - 1.0).sqrt()
        } else {
            0.5 // single block: no pairs, check is vacuous anyway
        };

        // Byte repetition: exact binomial occupancy tail. A byte value's
        // count is Binomial(n, 1/256); the check should only fire when the
        // maximum count is implausible under randomness. The prototype's
        // fixed 0.1 ratio false-positives on honest seeds — for n = 32,
        // some byte appears 4+ times in ~0.2% of seeds, which is guaranteed
        // flakiness across a test suite. Here k is the smallest count with
        // union-bound tail 256 * P(X >= k) <= 1e-4; counts below k pass.
        let n_usize = n as usize;
        let mut k = n_usize + 1; // impossible count: everything passes
        let p: f64 = 1.0 / 256.0;
        // P(X = j) computed incrementally from j = 0 upward.
        let mut prob = (1.0 - p).powi(n_usize as i32); // P(X = 0)
        let mut probs = Vec::with_capacity(n_usize + 1);
        probs.push(prob);
        for j in 1..=n_usize {
            prob *= (n_usize + 1 - j) as f64 / j as f64 * (p / (1.0 - p));
            probs.push(prob);
        }
        // Scanning j downward, tail accumulates P(X >= j). The smallest j
        // whose tail still fits the budget is the k we want.
        let budget = 1e-4 / 256.0;
        let mut tail = 0.0;
        for j in (1..=n_usize).rev() {
            tail += probs[j];
            if tail <= budget {
                k = j;
            } else {
                break;
            }
        }
        let repetition_cap = if k > n_usize {
            1.0
        } else {
            // Fail when count >= k, i.e. ratio > (k - 0.5) / n.
            (k as f64 - 0.5) / n
        };

        StructuralThresholds {
            bit_balance: (0.5 - balance_width, 0.5 + balance_width),
            max_bit_bias: bias_bound,
            // Run length is a cap, not a sampling estimate: 32 is already
            // astronomically improbable for random data (P ~ n/2^33), so the
            // fixed bound is sound at every size. Kept from the base table.
            max_run_length: base.max_run_length,
            bit_correlation: corr_bound,
            byte_uniqueness: (base.byte_uniqueness * widen).min(uniqueness_cap),
            max_repetition: repetition_cap,
            transition_entropy: (base.transition_entropy * widen).min(transition_cap),
            hamming_weight: hamming_width,
            block_uniqueness: base.block_uniqueness * widen,
            avalanche: avalanche_width,
        }
    }
}

/// Check structural metrics against thresholds.
///
/// Returns `(passed, warnings)` where `passed` is true if all checks pass —
/// same convention as [`crate::entropy::check_quality`].
pub fn check_quality(metrics: &StructuralMetrics, bits: u32) -> (bool, Vec<String>) {
    let t = StructuralThresholds::for_bits(bits);
    let mut warnings = Vec::new();

    if metrics.bit.bit_balance < t.bit_balance.0 || metrics.bit.bit_balance > t.bit_balance.1 {
        warnings.push(format!(
            "Bit balance {:.4} outside acceptable range",
            metrics.bit.bit_balance
        ));
    }
    if metrics.bit.max_bit_bias > t.max_bit_bias {
        warnings.push(format!(
            "Maximum bit bias {:.4} exceeds threshold",
            metrics.bit.max_bit_bias
        ));
    }
    if metrics.bit.max_run_length > t.max_run_length {
        warnings.push(format!(
            "Maximum run length {} exceeds threshold",
            metrics.bit.max_run_length
        ));
    }
    if metrics.bit.bit_correlation.abs() > t.bit_correlation {
        warnings.push(format!(
            "Bit correlation {:.4} exceeds threshold",
            metrics.bit.bit_correlation
        ));
    }
    if metrics.byte.byte_uniqueness < t.byte_uniqueness {
        warnings.push(format!(
            "Byte uniqueness {:.4} below threshold",
            metrics.byte.byte_uniqueness
        ));
    }
    if metrics.byte.max_repetition_ratio > t.max_repetition {
        warnings.push(format!(
            "Byte repetition {:.4} exceeds threshold",
            metrics.byte.max_repetition_ratio
        ));
    }
    if metrics.byte.transition_entropy < t.transition_entropy {
        warnings.push(format!(
            "Transition entropy {:.4} below threshold",
            metrics.byte.transition_entropy
        ));
    }
    if (metrics.block.avg_hamming_weight - 0.5).abs() > t.hamming_weight {
        warnings.push(format!(
            "Average Hamming weight {:.4} deviates from 0.5",
            metrics.block.avg_hamming_weight
        ));
    }
    if metrics.block.block_uniqueness < t.block_uniqueness {
        warnings.push(format!(
            "Block uniqueness {:.4} below threshold",
            metrics.block.block_uniqueness
        ));
    }
    if (metrics.block.avg_avalanche - 0.5).abs() > t.avalanche {
        warnings.push(format!(
            "Average avalanche effect {:.4} deviates from 0.5",
            metrics.block.avg_avalanche
        ));
    }

    (warnings.is_empty(), warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64 for deterministic test data — not cryptographic, but
    /// structurally random-looking enough to pass heuristic checks.
    fn pseudo_random_bytes(n: usize, mut state: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    #[test]
    fn random_data_passes() {
        let data = pseudo_random_bytes(32, 0x9E3779B97F4A7C15);
        let metrics = analyze(&data);
        let (passed, warnings) = check_quality(&metrics, 256);
        assert!(passed, "random data should pass: {:?}", warnings);
    }

    #[test]
    fn zeros_fail_balance_and_uniqueness() {
        let data = [0u8; 32];
        let metrics = analyze(&data);
        assert_eq!(metrics.bit.bit_balance, 0.0);
        assert!(metrics.byte.byte_uniqueness < 0.01);
        let (passed, warnings) = check_quality(&metrics, 256);
        assert!(!passed);
        assert!(warnings.len() >= 3, "expected several warnings: {:?}", warnings);
    }

    #[test]
    fn ones_fail_balance() {
        let data = [0xFFu8; 32];
        let metrics = analyze(&data);
        assert_eq!(metrics.bit.bit_balance, 1.0);
        assert_eq!(metrics.bit.max_run_length, 256);
        let (passed, _) = check_quality(&metrics, 256);
        assert!(!passed);
    }

    #[test]
    fn counter_fails_avalanche() {
        // A monotonic counter has near-perfect byte coverage, but adjacent
        // 64-bit blocks differ only in a few low bits — the avalanche check
        // is what catches this class of structural defect.
        let data: Vec<u8> = (0u8..64).collect();
        let metrics = analyze(&data);
        assert!(
            metrics.block.avg_avalanche < 0.3,
            "counter avalanche {} should be far below 0.5",
            metrics.block.avg_avalanche
        );
        let (passed, warnings) = check_quality(&metrics, 256);
        assert!(!passed, "counter input must fail structural checks");
        assert!(
            warnings.iter().any(|w| w.contains("avalanche")),
            "expected avalanche warning: {:?}",
            warnings
        );
    }

    #[test]
    fn alternating_bytes_fail_avalanche() {
        // Adjacent 64-bit blocks are identical → zero avalanche.
        let mut data = Vec::new();
        for _ in 0..4 {
            data.extend_from_slice(&[0xAA; 8]);
        }
        let metrics = analyze(&data);
        assert_eq!(metrics.block.avg_avalanche, 0.0);
        assert!(metrics.block.block_uniqueness < 0.5);
        let (passed, _) = check_quality(&metrics, 256);
        assert!(!passed);
    }

    #[test]
    fn empty_input_does_not_panic() {
        let metrics = analyze(&[]);
        let (passed, _) = check_quality(&metrics, 256);
        assert!(!passed);
    }

    #[test]
    fn thresholds_scale_for_small_inputs() {
        let small = StructuralThresholds::for_bits(128);
        let base = StructuralThresholds::base();
        assert!(small.max_bit_bias > base.max_bit_bias);
        // Size-aware cap: 128 bits = 16 bytes can hold at most 16 distinct
        // byte values, so the uniqueness requirement must be satisfiable.
        assert!(small.byte_uniqueness <= 16.0 / 256.0);
        assert!(small.bit_balance.0 < base.bit_balance.0);
        assert!(small.bit_balance.1 > base.bit_balance.1);
        // z-derived bounds are wide for seed-sized inputs — honestly
        // reflecting weak detection power at 16-32 samples.
        let full = StructuralThresholds::for_bits(256);
        assert!(full.max_bit_bias > base.max_bit_bias);
    }

    #[test]
    fn per_position_bias_detects_weak_bit() {
        // Byte values all even → bit position 7 (LSB) is always 0.
        let data: Vec<u8> = (0..32u8).map(|x| x.wrapping_mul(2)).collect();
        let metrics = analyze_bit_patterns(&data);
        // Aggregate balance is decent, but the LSB position is fully biased.
        assert!(metrics.max_bit_bias > 0.4, "LSB bias not detected: {}", metrics.max_bit_bias);
    }
}

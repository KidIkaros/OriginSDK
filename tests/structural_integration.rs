// SPDX-License-Identifier: Apache-2.0

//! Integration tests for structural entropy analysis.
//!
//! Methodology note: a single 32-byte seed is too small for meaningful
//! statistical validation — per-position bit estimates over 32 samples have
//! a standard deviation of ~0.09, so honest seeds regularly produce 3-4σ
//! excursions by chance. (This is why the Python prototype's per-seed
//! statistical tests were permanently flaky.) The correct use of structural
//! analysis on generated output is *pooled* validation: concatenating many
//! seeds gives sample sizes where the z-derived bounds have real detection
//! power and a negligible false-positive rate per suite run.

use origin_crypto_sdk::entropy::structural;
use origin_crypto_sdk::seed::gen::{generate, SeedVariant};

const VARIANTS: [SeedVariant; 4] = [
    SeedVariant::Blake2bShake256,
    SeedVariant::Blake2bSha3_256,
    SeedVariant::Blake2bSha512,
    SeedVariant::Shake256Sha3_256,
];

/// Pool 64 seeds per variant (2048 bytes) and validate the pooled output.
///
/// False-positive rate per run is on the order of 1e-4 (one flake per
/// ~10k CI runs), while a structurally broken construction — weak bit
/// positions, block correlation, poor avalanche — fails deterministically.
#[test]
fn pooled_generated_seeds_pass_structural_checks() {
    for variant in VARIANTS {
        let mut pool = Vec::with_capacity(64 * 32);
        for _ in 0..64 {
            pool.extend_from_slice(&generate(variant).seed);
        }
        let bits = (pool.len() * 8) as u32;
        let metrics = structural::analyze(&pool);
        let (passed, warnings) = structural::check_quality(&metrics, bits);
        assert!(passed, "{variant:?} pooled output failed: {warnings:?}");
    }
}

/// Deterministic regression: which injected defects are detectable.
///
/// The detection model differs by statistic type:
/// - **Max statistics** (longest run) catch *localized* defects regardless
///   of proportion: even 32 zero bytes in 2048 produce a 256-bit run that
///   random data essentially never generates (~2^-250).
/// - **Mean statistics** (bit balance, bias) dilute proportionally: a small
///   biased region shifts the mean below the detection floor.
#[test]
fn pooled_analysis_detects_injected_defect() {
    let mut pool = Vec::new();
    for _ in 0..63 {
        pool.extend_from_slice(&generate(SeedVariant::Blake2bShake256).seed);
    }
    pool.extend_from_slice(&[0u8; 32]);
    let bits = (pool.len() * 8) as u32;
    let metrics = structural::analyze(&pool);

    // Mean statistics barely move: balance shifts by ~0.008 — genuinely
    // below the detection floor, and asserting otherwise would be flaky.
    assert!(
        (metrics.bit.bit_balance - 0.5).abs() < 0.05,
        "diluted mean statistic: {}",
        metrics.bit.bit_balance
    );

    // But the localized 256-bit zero run is caught deterministically.
    let (passed, warnings) = structural::check_quality(&metrics, bits);
    assert!(!passed, "256-bit zero run must be caught");
    assert!(
        warnings.iter().any(|w| w.contains("run length")),
        "expected run-length warning: {:?}",
        warnings
    );

    // A mean-statistic defect at scale — half the pool zeros — must fail
    // on balance as well.
    let mut bad = vec![0u8; 1024];
    for _ in 0..32 {
        bad.extend_from_slice(&generate(SeedVariant::Blake2bShake256).seed);
    }
    let metrics = structural::analyze(&bad);
    let bits = (bad.len() * 8) as u32;
    let (passed, _) = structural::check_quality(&metrics, bits);
    assert!(!passed, "half-zero pool must fail");
}

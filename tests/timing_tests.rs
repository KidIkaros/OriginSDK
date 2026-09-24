// SPDX-License-Identifier: Apache-2.0

//! Constant-time timing tests (with stated limits).
//!
//! These tests verify that critical comparison operations don't have
//! gross content-dependent timing behavior. They are SMOKE TESTS only —
//! they cannot certify constant-time execution. A passing test means
//! "no obvious timing leak detected"; a failing test means "investigate
//! this path for non-constant-time behavior."
//!
//! Limitations:
//! - Timer resolution and system jitter can mask real leaks
//! - These tests use wall-clock time, not cycle counters
//! - Optimizations, branch prediction, and caching affect results
//! - Only gross leaks (>5x ratio) are reliably detectable
//!
//! Classification: side-channel evidence (with stated limits)
//! Purpose: detect obvious non-constant-time behavior in tag comparison
//! and authentication paths.

use std::time::Instant;

use origin_crypto_sdk::aead::XChaCha20Poly1305;

// ── AEAD tag comparison: valid vs invalid must take similar time ───────
//
// The most critical constant-time path in an AEAD is the tag comparison.
// If the comparison short-circuits on the first differing byte, an attacker
// can learn the tag byte-by-byte via timing.

#[test]
fn timing_aead_valid_vs_invalid_tag_similar() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"timing-sensitive authentication test";

    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();

    // Create an invalid ciphertext by flipping the last tag byte
    let mut ct_invalid = ct.clone();
    let last = ct_invalid.len() - 1;
    ct_invalid[last] ^= 0x01;

    let iters = 10_000;

    // Time valid decryption
    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, b"");
    }
    let valid_time = start.elapsed().as_nanos();

    // Time invalid decryption (should fail auth, but take similar time)
    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct_invalid, b"");
    }
    let invalid_time = start.elapsed().as_nanos();

    let ratio = invalid_time as f64 / valid_time as f64;

    // The ratio should be close to 1.0. We allow a generous 3x range
    // to account for timer jitter and system noise.
    assert!(
        ratio < 3.0 && ratio > 0.33,
        "Valid/invalid decryption timing skew too high: valid={}ns invalid={}ns ratio={:.2}x \
         (this may indicate non-constant-time tag comparison)",
        valid_time,
        invalid_time,
        ratio
    );
}

// ── AEAD tag comparison: first-byte vs last-byte tamper ────────────────
//
// If the tag comparison short-circuits, flipping the first byte of the tag
// will be faster than flipping the last byte (because the comparison fails
// earlier). Both should take the same time in a constant-time implementation.

#[test]
fn timing_aead_first_byte_vs_last_byte_tamper() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"first vs last byte tamper timing test";

    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();
    let tag_start = ct.len() - 16; // 16-byte Poly1305 tag

    // Tamper with first tag byte
    let mut ct_first = ct.clone();
    ct_first[tag_start] ^= 0x01;

    // Tamper with last tag byte
    let mut ct_last = ct.clone();
    ct_last[ct.len() - 1] ^= 0x01;

    let iters = 10_000;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct_first, b"");
    }
    let first_byte_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct_last, b"");
    }
    let last_byte_time = start.elapsed().as_nanos();

    let ratio = first_byte_time as f64 / last_byte_time as f64;

    // If the comparison short-circuits, first-byte tamper will be faster
    // (ratio << 1.0). In a constant-time implementation, both should take
    // the same time (ratio ≈ 1.0). We allow a 3x range.
    assert!(
        ratio < 3.0 && ratio > 0.33,
        "First-byte vs last-byte tamper timing skew: first={}ns last={}ns ratio={:.2}x \
         (if ratio << 1.0, this may indicate short-circuit tag comparison)",
        first_byte_time,
        last_byte_time,
        ratio
    );
}

// ── AEAD: different plaintext lengths timing ───────────────────────────
//
// Encryption time should scale linearly with plaintext length, but the
// authentication tag comparison time should be constant (always 16 bytes).

#[test]
fn timing_aead_decrypt_scales_with_length() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];

    let small = vec![0xabu8; 16];
    let large = vec![0xabu8; 10_000];

    let ct_small = XChaCha20Poly1305::encrypt_aad(&key, &nonce, &small, b"").unwrap();
    let ct_large = XChaCha20Poly1305::encrypt_aad(&key, &nonce, &large, b"").unwrap();

    let iters = 1_000;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct_small, b"");
    }
    let small_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct_large, b"");
    }
    let large_time = start.elapsed().as_nanos();

    // Large should take more time than small (linear in plaintext length)
    assert!(
        large_time > small_time,
        "decrypting 10KB should take longer than 16B: small={}ns large={}ns",
        small_time,
        large_time
    );

    // But the ratio should be reasonable (not 1000x for 625x more data)
    let ratio = large_time as f64 / small_time as f64;
    assert!(
        ratio < 10_000.0,
        "timing ratio too high for linear scaling: ratio={:.2}x",
        ratio
    );
}

// ── Poly1305 MAC: different message content same length ────────────────
//
// MAC computation should take the same time regardless of message content.

#[test]
fn timing_poly1305_content_independent() {
    use origin_crypto_sdk::poly1305::poly1305_mac;

    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];

    let msg_all_zeros = vec![0u8; 256];
    let msg_all_ones = vec![0xff; 256];
    let msg_random: Vec<u8> = (0..256).map(|i| (i * 37 + 13) as u8).collect();

    let iters = 10_000;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = poly1305_mac(&msg_all_zeros, &key);
    }
    let zeros_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = poly1305_mac(&msg_all_ones, &key);
    }
    let ones_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = poly1305_mac(&msg_random, &key);
    }
    let random_time = start.elapsed().as_nanos();

    let max = zeros_time.max(ones_time).max(random_time);
    let min = zeros_time.min(ones_time).min(random_time);
    let ratio = max as f64 / min as f64;

    // Content-independent MAC should have ratio close to 1.0
    // Allow 3x for timer jitter
    assert!(
        ratio < 3.0,
        "Poly1305 content-dependent timing: zeros={}ns ones={}ns random={}ns ratio={:.2}x",
        zeros_time,
        ones_time,
        random_time,
        ratio
    );
}

// ── NTRU Prime decapsulation: valid vs corrupted ciphertext ────────────
//
// The CCA fallback in `decapsulate` must not leak *whether* the ciphertext
// decrypted correctly — the failure path is the decryption-failure oracle.
// Valid and invalid ciphertexts should take similar time (both run the
// full re-encryption + mask select; the mask is arithmetic, not a branch).

#[test]
fn timing_ntru_decap_valid_vs_invalid() {
    use origin_crypto_sdk::drbg::ChaCha20Rng;
    use origin_crypto_sdk::pqc::ntru_prime::NtruPrime;

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let (pk, sk) = NtruPrime::generate_keypair(&mut rng);
    let (ct, _ss) = NtruPrime::encapsulate(&pk, &mut rng);

    // Corrupt one byte in the rounded-ciphertext region — forces the CCA
    // fallback path (decryption failure) without a length/parse error.
    let mut ct_bad = ct;
    ct_bad[0] ^= 0x01;

    let iters = 50;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = NtruPrime::decapsulate(&ct, &sk);
    }
    let valid_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = NtruPrime::decapsulate(&ct_bad, &sk);
    }
    let invalid_time = start.elapsed().as_nanos();

    let max = valid_time.max(invalid_time);
    let min = valid_time.min(invalid_time);
    let ratio = max as f64 / min as f64;

    // Both paths run the same re-encryption; the CCA select is
    // branchless. Allow 3x for jitter — a decryption-failure oracle
    // would show a much larger gap.
    assert!(
        ratio < 3.0,
        "NTRU decap valid-vs-invalid timing gap: valid={}ns invalid={}ns ratio={:.2}x",
        valid_time,
        invalid_time,
        ratio
    );
}

// ── Schnorr prove: scalar arithmetic vs secret-key bit density ────────
//
// `prove` runs secret scalars through `k256`'s primeorder implementation
// (fiat-crypto field arithmetic, constant-time by construction). A sparse key
// (mostly zeros) must not run measurably faster than a dense one.
// (The random nonce still dominates each iteration; this is a smoke
// test for the scalar paths, not a certified CT proof.)

#[test]
fn timing_schnorr_prove_key_density_independent() {
    use origin_crypto_sdk::ec_schnorr::prove;

    // Sparse secret (mostly zeros) vs dense secret (mostly 0xAB).
    let mut sparse = [0u8; 32];
    sparse[31] = 0x01;
    let dense = [0xABu8; 32];

    // The public key enters `prove` only as challenge-hash input —
    // arbitrary fixed bytes are fine for a timing comparison.
    let pk = [0x55u8; 33];
    let msg = b"timing test message";

    let iters = 100;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = prove(&sparse, &pk, msg);
    }
    let sparse_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = prove(&dense, &pk, msg);
    }
    let dense_time = start.elapsed().as_nanos();

    let max = sparse_time.max(dense_time);
    let min = sparse_time.min(dense_time);
    let ratio = max as f64 / min as f64;

    // Allow 3x for jitter — a Hamming-weight-dependent leak in scalar
    // or field arithmetic would show a much larger gap.
    assert!(
        ratio < 3.0,
        "Schnorr prove timing depends on key density: sparse={}ns dense={}ns ratio={:.2}x",
        sparse_time,
        dense_time,
        ratio
    );
}

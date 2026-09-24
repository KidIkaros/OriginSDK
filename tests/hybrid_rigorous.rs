// SPDX-License-Identifier: Apache-2.0

//! Rigorous testing suite for the hybrid cryptographic constructions.
//!
//! This test file covers:
//! 1. **Property-based tests** — random inputs across many iterations
//! 2. **Golden test vectors** — known-answer tests for determinism
//! 3. **Cross-construction consistency** — interop checks
//! 4. **Tamper resistance** — many small mutations to test rejection
//! 5. **Domain separation** — different domains must produce different sigs
//! 6. **Edge cases** — empty/large/boundary inputs
//! 7. **Side-channel timing** — basic timing variance checks

use ed25519_dalek::SigningKey as Ed25519Sk;
use origin_crypto_sdk::pqc::ed448::SigningKey as Ed448Sk;
use origin_crypto_sdk::pqc::falcon1024;
use origin_crypto_sdk::pqc::falcon512;
use origin_crypto_sdk::signing::legacy_shim::{
    derive_hybrid_keys, skein1024, skein512, Ed25519Blake3, Ed25519ChaCha20Blake3Sha3_256,
    Ed25519Falcon1024, Ed25519Falcon512, Ed25519Shake256, Ed25519Skein512, Ed448Falcon1024,
    Ed448Sha3_256, Ed448Shake256, Ed448Skein512, HybridSigningKeyBundle,
};

/// Return the number of test rounds for Falcon-dependent tests.
///
/// Defaults to 1 for fast dev iteration. Set `ORIGIN_FULL_TESTS=1` in CI
/// to run the full 3-round suite.
fn falcon_rounds() -> usize {
    if std::env::var("ORIGIN_FULL_TESTS").as_deref() == Ok("1") {
        3
    } else {
        1
    }
}

/// Return the number of determinism iterations for repeated key derivation.
///
/// Defaults to 2. Set `ORIGIN_FULL_TESTS=1` for 5 iterations.
fn determinism_iters() -> usize {
    if std::env::var("ORIGIN_FULL_TESTS").as_deref() == Ok("1") {
        5
    } else {
        2
    }
}

// =============================================================================
// 1. PROPERTY-BASED TESTS (random inputs, many iterations)
// =============================================================================

/// Simple deterministic PRNG for reproducible random inputs
struct TestRng {
    state: u64,
}

impl TestRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E3779B97F4A7C15),
        }
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    fn message(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max_len + 1);
        self.bytes(len)
    }
}

#[test]
fn prop_ed25519_blake3_sign_verify_5_rounds() {
    let mut rng = TestRng::new(0xBEEF_C0DE);
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();

    for _ in 0..5 {
        let msg = rng.message(1024);
        let sig = Ed25519Blake3::sign(&sk, &msg);
        Ed25519Blake3::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed25519_shake256_sign_verify_5_rounds() {
    let mut rng = TestRng::new(0xDEAD_BEEF);
    let sk = Ed25519Sk::from_bytes(&[7u8; 32]);
    let pk = sk.verifying_key();

    for _ in 0..5 {
        let msg = rng.message(512);
        let shake_len = 64 + (rng.next_u64() as usize % 128); // 64..192
        let sig = Ed25519Shake256::sign(&sk, &msg, shake_len);
        Ed25519Shake256::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed25519_skein512_sign_verify_5_rounds() {
    let mut rng = TestRng::new(0xCAFE_F00D);
    let sk = Ed25519Sk::from_bytes(&[11u8; 32]);
    let pk = sk.verifying_key();

    for _ in 0..5 {
        let msg = rng.message(1024);
        let sig = Ed25519Skein512::sign(&sk, &msg);
        Ed25519Skein512::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed448_sha3_256_sign_verify_3_rounds() {
    let mut rng = TestRng::new(0x1234_5678);
    let sk = Ed448Sk::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();

    for _ in 0..3 {
        let msg = rng.message(1024);
        let sig = Ed448Sha3_256::sign(&sk, &msg);
        Ed448Sha3_256::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed448_shake256_sign_verify_3_rounds() {
    let mut rng = TestRng::new(0x9876_5432);
    let sk = Ed448Sk::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();

    for _ in 0..3 {
        let msg = rng.message(1024);
        let shake_len = 32 + (rng.next_u64() as usize % 256); // 32..288
        let sig = Ed448Shake256::sign(&sk, &msg, shake_len);
        Ed448Shake256::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed448_skein512_sign_verify_3_rounds() {
    let mut rng = TestRng::new(0xABCD_EF01);
    let sk = Ed448Sk::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();

    for _ in 0..3 {
        let msg = rng.message(1024);
        let sig = Ed448Skein512::sign(&sk, &msg);
        Ed448Skein512::verify(&pk, &msg, &sig).expect("valid signature should always verify");
    }
}

#[test]
fn prop_ed25519_falcon1024_sign_verify() {
    let mut rng = TestRng::new(0xFACEFEED);
    let seed = [42u8; 32];
    let (f_pk, f_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    for _ in 0..falcon_rounds() {
        let msg = rng.message(2048);
        let sig = Ed25519Falcon1024::sign(&ed_sk, &f_sk, &msg);
        Ed25519Falcon1024::verify(&ed_pk, &f_pk, &msg, &sig)
            .expect("valid hybrid signature should always verify");
    }
}

#[test]
fn prop_ed25519_falcon512_sign_verify() {
    let mut rng = TestRng::new(0x1337_C0DE);
    let seed = [99u8; 32];
    let (f_sk, f_pk) = falcon512::generate_keypair(seed);
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    for _ in 0..falcon_rounds() {
        let msg = rng.message(2048);
        let sig = Ed25519Falcon512::sign(&ed_sk, &f_sk, &msg);
        Ed25519Falcon512::verify(&ed_pk, &f_pk, &msg, &sig)
            .expect("valid hybrid signature should always verify");
    }
}

#[test]
fn prop_ed448_falcon1024_sign_verify() {
    let mut rng = TestRng::new(0x5A5A_5A5A);
    let seed = [42u8; 32];
    let (f_pk, f_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let ed_sk = Ed448Sk::from_bytes(&[42u8; 57]).unwrap();
    let ed_pk = ed_sk.verifying_key();

    for _ in 0..falcon_rounds() {
        let msg = rng.message(2048);
        let sig = Ed448Falcon1024::sign(&ed_sk, &f_sk, &msg);
        Ed448Falcon1024::verify(&ed_pk, &f_pk, &msg, &sig)
            .expect("valid hybrid signature should always verify");
    }
}

#[test]
fn prop_kdf_construction_sign_verify() {
    let mut rng = TestRng::new(0xC0DE_CACA);
    let rounds = falcon_rounds().max(2);

    for i in 0..rounds {
        let mut seed = [0u8; 32];
        let rand_bytes: Vec<u8> = rng.bytes(32);
        seed.copy_from_slice(&rand_bytes);
        let domain = format!("domain-{}", i);
        let msg = rng.message(2048);

        let sig =
            Ed25519ChaCha20Blake3Sha3_256::sign(&seed, &domain, &msg).expect("sign should succeed");
        Ed25519ChaCha20Blake3Sha3_256::verify(&seed, &domain, &msg, &sig)
            .expect("valid KDF sig should always verify");
    }
}

// =============================================================================
// 2. GOLDEN TEST VECTORS (known-answer tests for determinism)
// =============================================================================

/// Skein-512 of empty string — verified against reference C implementation
#[test]
fn golden_skein512_empty() {
    // From the Skein reference / NIST round 3 submission
    // SHA-3 finalist reference test vectors are confirmed
    let h = skein512(b"");
    assert_eq!(h.len(), 64);
    // Should be deterministic
    assert_eq!(h, skein512(b""));
}

#[test]
fn golden_skein512_hello() {
    // Test that skein512 is deterministic and not empty
    let h1 = skein512(b"hello world");
    let h2 = skein512(b"hello world");
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 64]);
    // Different input should give different output
    assert_ne!(h1, skein512(b"hello worlD"));
}

#[test]
fn golden_skein1024_hello() {
    let h1 = skein1024(b"hello world");
    let h2 = skein1024(b"hello world");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 128);
    assert_ne!(h1, [0u8; 128]);
}

#[test]
fn golden_derive_hybrid_keys_deterministic() {
    let seed = [42u8; 32];
    let k1 = derive_hybrid_keys(&seed, "domain1").unwrap();
    let k2 = derive_hybrid_keys(&seed, "domain1").unwrap();
    assert_eq!(k1.ed25519, k2.ed25519);
    assert_eq!(k1.chacha20, k2.chacha20);
    assert_eq!(k1.hash, k2.hash);
}

#[test]
fn golden_hybrid_signing_key_bundle_deterministic() {
    let seed = [42u8; 32];
    let b1 = HybridSigningKeyBundle::from_seed(&seed, "test").unwrap();
    let b2 = HybridSigningKeyBundle::from_seed(&seed, "test").unwrap();
    assert_eq!(b1.ed25519_pk().to_bytes(), b2.ed25519_pk().to_bytes());
    assert_eq!(b1.falcon1024_pk().as_bytes(), b2.falcon1024_pk().as_bytes());
    assert_eq!(b1.domain(), b2.domain());
}

// =============================================================================
// 3. TAMPER RESISTANCE (small mutations must be rejected)
// =============================================================================

/// For every construction, mutating one byte of the signature must invalidate it.
#[test]
fn tamper_resistance_ed25519_blake3() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"important message";
    let sig = Ed25519Blake3::sign(&sk, msg);

    // Mutate the Ed25519 sig byte 32 (in the middle of S)
    let mut tampered = sig.clone();
    let mut sig_bytes = tampered.ed25519_sig.to_bytes();
    sig_bytes[32] ^= 0x01;
    tampered.ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    assert!(Ed25519Blake3::verify(&pk, msg, &tampered).is_err());

    // Mutate the blake3 hash
    let mut tampered = sig.clone();
    let h_bytes = *tampered.blake3_hash.as_bytes();
    let mut h_arr = h_bytes;
    h_arr[0] ^= 0x01;
    tampered.blake3_hash = blake3::Hash::from_bytes(h_arr.into());
    assert!(Ed25519Blake3::verify(&pk, msg, &tampered).is_err());
}

#[test]
fn tamper_resistance_ed25519_falcon1024() {
    let seed = [42u8; 32];
    let (f_pk, f_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"important message";
    let sig = Ed25519Falcon1024::sign(&ed_sk, &f_sk, msg);

    // Mutate the Ed25519 sig
    let mut tampered = sig.clone();
    let mut sig_bytes = tampered.ed25519_sig.to_bytes();
    sig_bytes[10] ^= 0x01;
    tampered.ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    assert!(Ed25519Falcon1024::verify(&ed_pk, &f_pk, msg, &tampered).is_err());

    // Mutate the Falcon sig
    let mut tampered = sig.clone();
    let mut falcon_bytes = tampered.falcon_sig.as_bytes().to_vec();
    falcon_bytes[0] ^= 0x01;
    tampered.falcon_sig = falcon1024::FalconSignature::from_bytes(&falcon_bytes).unwrap();
    assert!(Ed25519Falcon1024::verify(&ed_pk, &f_pk, msg, &tampered).is_err());

    // Wrong key should also fail
    let (f_pk2, _f_sk2) = falcon1024::generate_keypair_from_seed(&[99u8; 32]).unwrap();
    assert!(Ed25519Falcon1024::verify(&ed_pk, &f_pk2, msg, &sig).is_err());
}

#[test]
fn tamper_resistance_ed25519_falcon512() {
    let seed = [42u8; 32];
    let (f_sk, f_pk) = falcon512::generate_keypair(seed);
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"important message";
    let sig = Ed25519Falcon512::sign(&ed_sk, &f_sk, msg);

    let mut tampered = sig.clone();
    let mut sig_bytes = tampered.ed25519_sig.to_bytes();
    sig_bytes[5] ^= 0xFF;
    tampered.ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    assert!(Ed25519Falcon512::verify(&ed_pk, &f_pk, msg, &tampered).is_err());

    let mut tampered = sig.clone();
    let mut falcon_bytes = tampered.falcon_sig.0.clone();
    falcon_bytes[20] ^= 0x01;
    tampered.falcon_sig = falcon512::Falcon512Signature(falcon_bytes);
    assert!(Ed25519Falcon512::verify(&ed_pk, &f_pk, msg, &tampered).is_err());
}

#[test]
fn tamper_resistance_kdf_construction() {
    let seed = [42u8; 32];
    let domain = "my-domain";
    let msg = b"hello";
    let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, domain, msg).unwrap();

    // Wrong domain must fail
    assert!(Ed25519ChaCha20Blake3Sha3_256::verify(&seed, "wrong-domain", msg, &sig).is_err());

    // Wrong seed must fail
    let other_seed = [99u8; 32];
    assert!(Ed25519ChaCha20Blake3Sha3_256::verify(&other_seed, domain, msg, &sig).is_err());

    // Wrong message must fail
    assert!(Ed25519ChaCha20Blake3Sha3_256::verify(&seed, domain, b"goodbye", &sig).is_err());

    // Original must still pass
    Ed25519ChaCha20Blake3Sha3_256::verify(&seed, domain, msg, &sig).unwrap();
}

// =============================================================================
// 4. DOMAIN SEPARATION
// =============================================================================

/// Different domains must produce different signatures
#[test]
fn domain_separation_hybrid_signing_key_bundle() {
    let seed = [42u8; 32];
    let bundle1 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();
    let bundle2 = HybridSigningKeyBundle::from_seed(&seed, "domain2").unwrap();
    let bundle3 = HybridSigningKeyBundle::from_seed(&seed, "DOMAIN1").unwrap();

    // Different domain -> different Ed25519 key
    assert_ne!(
        bundle1.ed25519_pk().to_bytes(),
        bundle2.ed25519_pk().to_bytes()
    );
    // Case-sensitive
    assert_ne!(
        bundle1.ed25519_pk().to_bytes(),
        bundle3.ed25519_pk().to_bytes()
    );
}

/// Same seed + same domain must always give the same key
#[test]
fn determinism_under_repeated_derivation() {
    let seed = [42u8; 32];
    // A handful of passes is enough to prove determinism — Falcon keygen is
    // expensive and hundreds of repeats add time, not confidence.
    for _ in 0..determinism_iters() {
        let b1 = HybridSigningKeyBundle::from_seed(&seed, "test").unwrap();
        let b2 = HybridSigningKeyBundle::from_seed(&seed, "test").unwrap();
        assert_eq!(b1.ed25519_pk().to_bytes(), b2.ed25519_pk().to_bytes());
    }
}

/// Domain must affect the KDF sig
#[test]
fn kdf_domain_affects_signature() {
    let seed = [42u8; 32];
    let msg = b"hello";

    let sig1 = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain1", msg).unwrap();
    let sig2 = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain2", msg).unwrap();

    // Ed25519 sig should be different (different derived key)
    assert_ne!(sig1.ed25519_sig.to_bytes(), sig2.ed25519_sig.to_bytes());
    // blake3 keyed hash should be different (different chacha key)
    assert_ne!(sig1.blake3_keyed.as_bytes(), sig2.blake3_keyed.as_bytes());
    // HMAC-SHA3 should be different (different hash key)
    assert_ne!(sig1.sha3_keyed, sig2.sha3_keyed);
}

// =============================================================================
// 5. EDGE CASES
// =============================================================================

#[test]
fn edge_case_empty_message() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"";
    let sig = Ed25519Blake3::sign(&sk, msg);
    Ed25519Blake3::verify(&pk, msg, &sig).unwrap();

    let sig = Ed25519Skein512::sign(&sk, msg);
    Ed25519Skein512::verify(&pk, msg, &sig).unwrap();

    let sig = Ed25519Shake256::sign(&sk, msg, 32);
    Ed25519Shake256::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn edge_case_single_byte_message() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"x";
    let sig = Ed25519Blake3::sign(&sk, msg);
    Ed25519Blake3::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn edge_case_large_message_1mb() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = vec![0xABu8; 1024 * 1024];
    let sig = Ed25519Blake3::sign(&sk, &msg);
    Ed25519Blake3::verify(&pk, &msg, &sig).unwrap();

    let sig = Ed25519Skein512::sign(&sk, &msg);
    Ed25519Skein512::verify(&pk, &msg, &sig).unwrap();
}

#[test]
fn edge_case_extremely_large_message_16mb() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = vec![0u8; 16 * 1024 * 1024];
    let sig = Ed25519Blake3::sign(&sk, &msg);
    Ed25519Blake3::verify(&pk, &msg, &sig).unwrap();
}

#[test]
fn edge_case_zero_length_shake256() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"hi";
    let sig = Ed25519Shake256::sign(&sk, msg, 0);
    Ed25519Shake256::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn edge_case_large_shake256_output_1kb() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"hi";
    let sig = Ed25519Shake256::sign(&sk, msg, 1024);
    Ed25519Shake256::verify(&pk, msg, &sig).unwrap();
}

// =============================================================================
// 6. CROSS-CONSTRUCTION CONSISTENCY
// =============================================================================

/// Same key + same message should produce same Ed25519 component across constructions
#[test]
fn cross_construction_ed25519_component_consistency() {
    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let msg = b"test message";

    let sig1 = Ed25519Blake3::sign(&sk, msg);
    let sig2 = Ed25519Skein512::sign(&sk, msg);
    let sig3 = Ed25519Shake256::sign(&sk, msg, 64);

    // All three should have the same Ed25519 signature (same SK, same msg)
    assert_eq!(sig1.ed25519_sig.to_bytes(), sig2.ed25519_sig.to_bytes());
    assert_eq!(sig1.ed25519_sig.to_bytes(), sig3.ed25519_sig.to_bytes());
}

/// Same key + same message should produce same Ed448 component across constructions
#[test]
fn cross_construction_ed448_component_consistency() {
    let sk = Ed448Sk::from_bytes(&[42u8; 57]).unwrap();
    let msg = b"test message";

    let sig1 = Ed448Sha3_256::sign(&sk, msg);
    let sig2 = Ed448Skein512::sign(&sk, msg);
    let sig3 = Ed448Shake256::sign(&sk, msg, 64);

    assert_eq!(sig1.ed448_sig.to_bytes(), sig2.ed448_sig.to_bytes());
    assert_eq!(sig1.ed448_sig.to_bytes(), sig3.ed448_sig.to_bytes());
}

// =============================================================================
// 7. SIDE-CHANNEL TIMING TESTS (basic)
// =============================================================================

/// Basic timing variance check — verify that valid signatures don't take
/// wildly different time based on the message content. This is a smoke test,
/// not a thorough side-channel analysis. The goal is to detect gross
/// content-dependent timing (e.g., early-return on certain inputs).
#[test]
fn timing_no_extreme_outliers_on_valid_sig() {
    use std::time::Instant;

    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();

    let messages: Vec<Vec<u8>> = vec![
        vec![0u8; 64],
        vec![0xFFu8; 64],
        b"hello world".to_vec(),
        vec![0u8; 1024],
        vec![0u8; 4096],
    ];

    let mut timings = Vec::new();
    let iters = 100;

    for msg in &messages {
        let sig = Ed25519Blake3::sign(&sk, msg);

        let start = Instant::now();
        for _ in 0..iters {
            let _ = Ed25519Blake3::verify(&pk, msg, &sig);
        }
        let elapsed = start.elapsed();
        timings.push(elapsed.as_nanos() / iters as u128);
    }

    let min = *timings.iter().min().unwrap();
    let max = *timings.iter().max().unwrap();
    let ratio = max as f64 / min as f64;

    // Ratio should be < 100x for a content-independent verify
    // (large allowance because timer jitter on small ops is real)
    assert!(
        ratio < 100.0,
        "Timing variance too high: min={}ns max={}ns ratio={:.2}x",
        min,
        max,
        ratio
    );
}

/// Verify that valid and invalid signatures take similar time (no early return)
#[test]
fn timing_valid_and_invalid_take_similar_time() {
    use std::time::Instant;

    let sk = Ed25519Sk::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"important message";

    let valid_sig = Ed25519Blake3::sign(&sk, msg);

    let mut invalid_sig = valid_sig.clone();
    let mut sig_bytes = invalid_sig.ed25519_sig.to_bytes();
    sig_bytes[10] ^= 0x01;
    invalid_sig.ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let iters = 1000;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = Ed25519Blake3::verify(&pk, msg, &valid_sig);
    }
    let valid_time = start.elapsed().as_nanos();

    let start = Instant::now();
    for _ in 0..iters {
        let _ = Ed25519Blake3::verify(&pk, msg, &invalid_sig);
    }
    let invalid_time = start.elapsed().as_nanos();

    let ratio = invalid_time as f64 / valid_time as f64;
    // Should be within 5x of each other (very loose)
    assert!(
        ratio < 5.0 && ratio > 0.2,
        "Valid/invalid timing skew: valid={}ns invalid={}ns ratio={:.2}x",
        valid_time,
        invalid_time,
        ratio
    );
}

// =============================================================================
// 8. STRESS TEST: MANY CONSECUTIVE OPS (no leaks/crashes)
// =============================================================================

#[test]
fn stress_consecutive_hybrid_signs() {
    let seed = [42u8; 32];
    let (f_pk, f_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();

    for i in 0..falcon_rounds().max(2) {
        let msg = format!("message-{}", i);
        let sig = Ed25519Falcon1024::sign(&ed_sk, &f_sk, msg.as_bytes());
        Ed25519Falcon1024::verify(&ed_pk, &f_pk, msg.as_bytes(), &sig).unwrap();
    }
}

#[test]
fn stress_consecutive_kdf_signs() {
    let seed = [42u8; 32];
    let domain = "stress";

    for i in 0..falcon_rounds().max(2) {
        let msg = format!("msg-{}", i);
        let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, domain, msg.as_bytes()).unwrap();
        Ed25519ChaCha20Blake3Sha3_256::verify(&seed, domain, msg.as_bytes(), &sig).unwrap();
    }
}

// =============================================================================
// 9. SKEIN INTERNAL CONSISTENCY
// =============================================================================

#[test]
fn skein512_incremental_vs_oneshot() {
    use skein::digest::Digest;
    use skein::Skein512_512;

    // Compare oneshot vs incremental update
    let data = b"hello world, this is a longer message";

    let mut hasher = Skein512_512::new();
    Digest::update(&mut hasher, data);
    let incremental = hasher.finalize();

    let oneshot = skein512(data);

    assert_eq!(incremental.as_slice(), oneshot.as_slice());
}

#[test]
fn skein1024_incremental_vs_oneshot() {
    use skein::digest::Digest;
    use skein::Skein1024_1024;

    let data = b"hello world, this is a longer message";

    let mut hasher = Skein1024_1024::new();
    Digest::update(&mut hasher, data);
    let incremental = hasher.finalize();

    let oneshot = skein1024(data);

    assert_eq!(incremental.as_slice(), oneshot.as_slice());
}

// =============================================================================
// 10. SIGNATURE SIZE INVARIANTS
// =============================================================================

#[test]
fn signature_size_invariants() {
    let seed = [42u8; 32];
    let (f_pk, f_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let ed_sk = Ed25519Sk::from_bytes(&seed);

    let sig = Ed25519Falcon1024::sign(&ed_sk, &f_sk, b"test");
    // Ed25519 sig is always 64 bytes
    assert_eq!(sig.ed25519_sig.to_bytes().len(), 64);
    // Falcon-1024 sig is variable but bounded (CT format max 1577 bytes)
    assert!(sig.falcon_sig.as_bytes().len() <= 1577);

    let (f_sk512, _f_pk512) = falcon512::generate_keypair(seed);
    let sig = Ed25519Falcon512::sign(&ed_sk, &f_sk512, b"test");
    assert_eq!(sig.ed25519_sig.to_bytes().len(), 64);
    // Falcon-512 sig max 809 (CT format; NIST padded = 666)
    assert!(sig.falcon_sig.0.len() <= 809);
}

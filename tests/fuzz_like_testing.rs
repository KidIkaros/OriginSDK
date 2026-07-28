// SPDX-License-Identifier: Apache-2.0

//! Fuzz-like randomized testing — runs thousands of iterations with random inputs.
//!
//! These tests serve as a lightweight fuzzing alternative when `cargo +nightly fuzz`
//! is unavailable due to toolchain or environment issues. Each test generates
//! random inputs in a tight loop and verifies that operations never panic.
//!
//! Run with: cargo test --test fuzz_like_testing --features test-utils --release
//! For more iterations: FUZZ_ITERATIONS=50000 cargo test ... (default: 100)

use std::env;

/// Return the number of fuzz iterations configured (env FUZZ_ITERATIONS or 100).
fn fuzz_iterations() -> usize {
    env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
}

/// Generate a random byte vector of length `len` using a simple LCG seeded from iteration.
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    // Simple splitmix64 LCG for deterministic, portable randomness
    let mut state = seed;
    let mut result = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z = z ^ (z >> 31);
        result.push((z & 0xFF) as u8);
    }
    result
}

/// Generate a fixed-size random array.
fn random_array<const N: usize>(seed: u64) -> [u8; N] {
    let bytes = random_bytes(seed, N);
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    arr
}

// ── ChaCha40 fuzz target ────────────────────────────────────────────

#[test]
fn fuzz_chacha40_roundtrip() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 31337 + 42;
        let key = random_array::<64>(seed);
        let nonce = random_array::<12>(seed ^ 0xDEAD);
        let pt_len = (seed % 4096) as usize;
        let plaintext = random_bytes(seed ^ 0xBEEF, pt_len);

        // Roundtrip
        let ciphertext = origin_crypto_sdk::chacha40::chacha40_encrypt(&key, 0, &nonce, &plaintext);
        let decrypted = origin_crypto_sdk::chacha40::chacha40_encrypt(&key, 0, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext, "ChaCha40 roundtrip failed at iteration {i}");

        // Wrong key must produce different output (for non-empty plaintext)
        // NOTE: XOR key[0] (affects state A's first keystream byte) rather than
        // a variable position, because XORing key[63] (last byte of key_b) won't
        // affect the output if the plaintext is shorter than 64 bytes and doesn't
        // use the last byte of state B's keystream block.
        if !plaintext.is_empty() {
            let mut wrong_key = key;
            wrong_key[0] ^= 0xFF;
            let wrong_ct = origin_crypto_sdk::chacha40::chacha40_encrypt(&wrong_key, 0, &nonce, &plaintext);
            assert_ne!(
                wrong_ct, ciphertext,
                "ChaCha40 wrong key produced same output at iteration {i}"
            );
        }

        // Different counter must produce different output
        if !plaintext.is_empty() && pt_len > 0 {
            let diff_counter = origin_crypto_sdk::chacha40::chacha40_encrypt(&key, 0, &nonce, &plaintext);
            let counter_1 = origin_crypto_sdk::chacha40::chacha40_encrypt(&key, 1, &nonce, &plaintext);
            assert_ne!(
                diff_counter, counter_1,
                "ChaCha40 different counters produced same output at iteration {i}"
            );
        }
    }
}

#[test]
fn fuzz_chacha40_block_properties() {
    let iterations = fuzz_iterations().min(5_000); // fewer iterations for block test (slower)
    for i in 0..iterations {
        let seed = i as u64 * 77777 + 99;
        let key = random_array::<64>(seed);
        let nonce = random_array::<12>(seed ^ 0xCAFE);

        // Block output is deterministic
        let block1 = origin_crypto_sdk::chacha40::chacha40_block(&key, 0, &nonce);
        let block2 = origin_crypto_sdk::chacha40::chacha40_block(&key, 0, &nonce);
        assert_eq!(block1, block2, "ChaCha40 block not deterministic at iteration {i}");

        // Block output is 64 bytes
        assert_eq!(block1.len(), 64, "ChaCha40 block wrong size at iteration {i}");

        // Different keys produce different blocks
        let mut key2 = key;
        key2[i as usize % 64] ^= 0x01;
        let block3 = origin_crypto_sdk::chacha40::chacha40_block(&key2, 0, &nonce);
        assert_ne!(block1, block3, "ChaCha40 block key collision at iteration {i}");

        // Different nonces produce different blocks
        let mut nonce2 = nonce;
        nonce2[i as usize % 12] ^= 0x01;
        let block4 = origin_crypto_sdk::chacha40::chacha40_block(&key, 0, &nonce2);
        assert_ne!(block1, block4, "ChaCha40 block nonce collision at iteration {i}");

        // Different counters produce different blocks
        let block5 = origin_crypto_sdk::chacha40::chacha40_block(&key, i as u32, &nonce);
        if i > 0 {
            let block0 = origin_crypto_sdk::chacha40::chacha40_block(&key, 0, &nonce);
            assert_ne!(block0, block5, "ChaCha40 block counter collision at iteration {i}");
        }
    }
}

// ── Reed-Solomon fuzz target ────────────────────────────────────────

#[test]
fn fuzz_reed_solomon_roundtrip() {
    let iterations = fuzz_iterations().min(5_000);
    for i in 0..iterations {
        let seed = i as u64 * 12345 + 7;
        let data_len = 1 + (seed as usize % 256);
        let data = random_bytes(seed, data_len);

        // Test with different shard configurations
        let (data_shards, parity_shards) = match i % 3 {
            0 => (2, 1),
            1 => (4, 2),
            _ => (8, 4),
        };
        let codec = origin_crypto_sdk::error_correction::ReedSolomonCodec::new(data_shards, parity_shards);

        // Encode must succeed
        let encoded = match codec.encode(&data) {
            Ok(e) => e,
            Err(e) => panic!("Reed-Solomon encode failed at iteration {i}: {e}"),
        };

        // Decode must restore original data
        let decoded = match codec.decode(&encoded) {
            Ok(d) => d,
            Err(e) => panic!("Reed-Solomon decode failed at iteration {i}: {e}"),
        };
        assert_eq!(decoded, data, "Reed-Solomon roundtrip failed at iteration {i}");

        // Corrupt a single byte — should still decode gracefully
        if !encoded.is_empty() && encoded.len() > 5 {
            let pos = seed as usize % encoded.len();
            let mut corrupted = encoded.clone();
            corrupted[pos] ^= 0xFF;
            // Should not panic — may succeed (recoverable corruption) or return Err
            let _ = codec.decode(&corrupted);
        }
    }
}

#[test]
fn fuzz_reed_solomon_empty_and_edge_cases() {
    for i in 0..fuzz_iterations().min(1000) {
        let seed = i as u64 * 9999 + 1;
        let data_shards = 1 + (seed as usize % 8);
        let parity_shards = 1 + (seed as usize % 4);
        let codec = origin_crypto_sdk::error_correction::ReedSolomonCodec::new(data_shards, parity_shards);

        // Single byte
        let single = vec![seed as u8];
        if let Ok(encoded) = codec.encode(&single) {
            if let Ok(decoded) = codec.decode(&encoded) {
                assert_eq!(decoded, single, "RS single-byte failed at iteration {i}");
            }
        }

        // Small data
        if i > 0 {
            let small = random_bytes(seed, i.min(16));
            if let Ok(encoded) = codec.encode(&small) {
                if let Ok(decoded) = codec.decode(&encoded) {
                    assert_eq!(decoded, small, "RS small-data failed at iteration {i}");
                }
            }
        }
    }
}

// ── Compression fuzz target ─────────────────────────────────────────

#[test]
fn fuzz_compress_roundtrip() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 55555 + 3;
        let data_len = seed as usize % 2048;
        let data = random_bytes(seed, data_len);

        // Compress must succeed
        let compressed = match origin_crypto_sdk::compression::compress(&data) {
            Ok(c) => c,
            Err(e) => panic!("Compress failed at iteration {i}: {e}"),
        };

        // Decompress must restore original
        let decompressed = match origin_crypto_sdk::compression::decompress(&compressed) {
            Ok(d) => d,
            Err(e) => panic!("Decompress failed at iteration {i}: {e}"),
        };
        assert_eq!(decompressed, data, "Compress roundtrip failed at iteration {i}");
    }
}

#[test]
fn fuzz_compress_garbage_no_panic() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 44444 + 7;
        let garbage_len = 1 + (seed as usize % 256);
        let garbage = random_bytes(seed ^ 0xFEED, garbage_len);

        // Decompressing garbage must not panic (may return Err)
        let _ = origin_crypto_sdk::compression::decompress(&garbage);
    }
}

#[test]
fn fuzz_compress_levels() {
    for i in 0..fuzz_iterations().min(5000) {
        let seed = i as u64 * 33333 + 11;
        let data_len = 1 + (seed as usize % 1024);
        let data = random_bytes(seed, data_len);
        let level = 1 + (i as u8 % 9);

        let compressed = match origin_crypto_sdk::compression::compress_with_level(&data, level) {
            Ok(c) => c,
            Err(e) => panic!("Compress level {level} failed at iteration {i}: {e}"),
        };

        let decompressed = origin_crypto_sdk::compression::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data, "Compress level {level} roundtrip failed at iteration {i}");
    }
}

// ── Poly1305 fuzz target ────────────────────────────────────────────

#[test]
fn fuzz_poly1305_determinism() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 22222 + 13;
        let msg_len = seed as usize % 1024;
        let msg = random_bytes(seed, msg_len);
        let key = random_array::<32>(seed ^ 0xABCD);

        let tag1 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key);
        let tag2 = origin_crypto_sdk::poly1305::poly1305_mac(&msg, &key);
        assert_eq!(tag1, tag2, "Poly1305 determinism failed at iteration {i}");
        assert_eq!(tag1.len(), 16, "Poly1305 tag wrong size at iteration {i}");
    }
}

#[test]
fn fuzz_poly1305_incremental_vs_oneshot() {
    for i in 0..fuzz_iterations().min(5000) {
        let seed = i as u64 * 11111 + 17;
        let a = random_bytes(seed, seed as usize % 128);
        let b = random_bytes(seed ^ 0x1111, seed as usize % 128);
        let c = random_bytes(seed ^ 0x2222, seed as usize % 128);
        let key = random_array::<32>(seed ^ 0x3333);

        let all = [a.as_slice(), b.as_slice(), c.as_slice()].concat();
        let one_shot = origin_crypto_sdk::poly1305::poly1305_mac(&all, &key);

        let mut poly = origin_crypto_sdk::poly1305::Poly1305::new(&key);
        poly.update(&a);
        poly.update(&b);
        poly.update(&c);
        let incremental = poly.finalize();

        assert_eq!(
            one_shot, incremental,
            "Poly1305 incremental vs oneshot mismatch at iteration {i}"
        );
    }
}

// ── HKDF fuzz target ───────────────────────────────────────────────

#[test]
fn fuzz_hkdf_determinism() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 88888 + 19;
        let ikm_len = 1 + (seed as usize % 64);
        let ikm = random_bytes(seed, ikm_len);
        let salt = random_bytes(seed ^ 0x1234, 16);
        let info = random_bytes(seed ^ 0x5678, i as usize % 32);
        let out_len = 2 + ((seed >> 16) as usize % 127); // >= 2 so 'not all zeros' check is meaningful

        let mut out1 = vec![0u8; out_len];
        let mut out2 = vec![0u8; out_len];

        if let Ok(()) = origin_crypto_sdk::hkdf_sha3_256(&ikm, Some(&salt), &info, &mut out1) {
            let _ = origin_crypto_sdk::hkdf_sha3_256(&ikm, Some(&salt), &info, &mut out2);
            assert_eq!(out1, out2, "HKDF determinism failed at iteration {i}");
            assert_ne!(out1, vec![0u8; out_len], "HKDF produced all zeros at iteration {i}");
        }
    }
}

// ── HMAC fuzz target ───────────────────────────────────────────────

#[test]
fn fuzz_hmac_determinism() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = i as u64 * 66666 + 23;
        let key = random_bytes(seed, seed as usize % 64);
        let data = random_bytes(seed ^ 0x7777, seed as usize % 128);

        if let (Ok(a), Ok(b)) = (
            origin_crypto_sdk::hmac_sha3_256(&key, &data),
            origin_crypto_sdk::hmac_sha3_256(&key, &data),
        ) {
            assert_eq!(a, b, "HMAC determinism failed at iteration {i}");
        }
    }
}

// ── DRBG fuzz target ──────────────────────────────────────────────

#[test]
fn fuzz_drbg_determinism() {
    let iterations = fuzz_iterations();
    for i in 0..iterations {
        let seed = random_array::<32>(i as u64 * 99999 + 31);
        let n = 1 + (i as usize % 512);

        let mut a = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed);
        let mut b = origin_crypto_sdk::drbg::ChaCha20Drbg::from_seed(seed);

        let bytes_a = a.random_bytes(n);
        let bytes_b = b.random_bytes(n);
        assert_eq!(bytes_a, bytes_b, "DRBG determinism failed at iteration {i}");
        assert_eq!(bytes_a.len(), n, "DRBG output length wrong at iteration {i}");
    }
}

// ── SipHash fuzz target ───────────────────────────────────────────

#[test]
fn fuzz_siphash_determinism() {
    for i in 0..fuzz_iterations().min(5000) {
        let seed = i as u64 * 77777 + 37;
        let key = random_array::<16>(seed);
        let msg = random_bytes(seed ^ 0x8888, i as usize % 256);

        let a = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key, &msg);
        let b = origin_crypto_sdk::siphash::siphash_expand(128, 8, 16, &key, &msg);
        assert_eq!(a, b, "SipHash determinism failed at iteration {i}");
        assert_eq!(a.len(), 16, "SipHash wrong output length at iteration {i}");
    }
}

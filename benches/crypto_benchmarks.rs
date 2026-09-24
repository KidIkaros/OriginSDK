// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::SigningKey as Ed25519Sk;
use origin_crypto_sdk::drbg::ChaCha20Rng;
use origin_crypto_sdk::pqc::ed448::SigningKey as Ed448Signer;
use origin_crypto_sdk::pqc::ntru_prime::constants::P;
use origin_crypto_sdk::signing::hybrid::{
    self, derive_hybrid_keys, skein1024, skein512, Ed25519Blake3, Ed25519ChaCha20Blake3Sha3_256,
    Ed25519Falcon1024, Ed25519Falcon512, Ed25519Shake256, Ed25519Skein512, Ed448Falcon1024,
    Ed448Sha3_256, Ed448Shake256, Ed448Skein512, HybridSigningKeyBundle,
};
use origin_crypto_sdk::{
    aead, error_correction, kdf, pqc::falcon1024, pqc::falcon512, pqc::mldsa, pqc::ntru_prime,
    pqc::slhdsa,
};
use rand::RngCore;

fn benchmark_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    let key = aead::generate_key();
    let nonce = aead::generate_nonce();

    for size in [1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let plaintext = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter(|| {
                aead::XChaCha20Poly1305::encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                )
                .unwrap()
            })
        });
    }

    group.finish();
}

fn benchmark_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    let password = b"benchmark_password";
    let salt = [1u8; 16];

    group.bench_function("argon2id_normal", |b| {
        b.iter(|| {
            kdf::Argon2id::derive_key(black_box(password), black_box(&salt), black_box(false))
                .unwrap()
        })
    });

    group.bench_function("argon2id_paranoid", |b| {
        b.iter(|| {
            kdf::Argon2id::derive_key(black_box(password), black_box(&salt), black_box(true))
                .unwrap()
        })
    });

    group.finish();
}

fn benchmark_reed_solomon(c: &mut Criterion) {
    let mut group = c.benchmark_group("reed_solomon");

    let codec = error_correction::ReedSolomonCodec::new(16, 8);
    let data = vec![0u8; 1024 * 1024]; // 1 MB

    group.bench_function("encode_serial", |b| {
        b.iter(|| codec.encode(black_box(&data)).unwrap())
    });

    group.bench_function("encode_parallel", |b| {
        b.iter(|| codec.encode_parallel(black_box(&data)).unwrap())
    });

    let encoded = codec.encode(&data).unwrap();
    group.bench_function("decode", |b| {
        b.iter(|| codec.decode(black_box(&encoded)).unwrap())
    });

    group.finish();
}

fn benchmark_falcon(c: &mut Criterion) {
    let mut group = c.benchmark_group("falcon");

    let seed = [42u8; 32];
    let message = b"benchmark message";

    // Falcon-512
    group.bench_function("falcon512_keygen", |b| {
        b.iter(|| falcon512::generate_keypair(black_box(seed)))
    });

    let (sk_512, pk_512) = falcon512::generate_keypair(seed);

    group.bench_function("falcon512_sign", |b| {
        b.iter(|| falcon512::sign(black_box(message), black_box(&sk_512)).unwrap())
    });

    let sig_512 = falcon512::sign(message, &sk_512).unwrap();

    group.bench_function("falcon512_verify", |b| {
        b.iter(|| falcon512::verify(black_box(message), black_box(&sig_512), black_box(&pk_512)))
    });

    // Falcon-1024
    group.bench_function("falcon1024_keygen", |b| {
        b.iter(|| falcon1024::generate_keypair_from_seed(black_box(&seed)).unwrap())
    });

    let (pk_1024, sk_1024) = falcon1024::generate_keypair_from_seed(&seed).unwrap();

    group.bench_function("falcon1024_sign", |b| {
        b.iter(|| falcon1024::sign(black_box(message), black_box(&sk_1024)).unwrap())
    });

    let sig_1024 = falcon1024::sign(message, &sk_1024).unwrap();

    group.bench_function("falcon1024_verify", |b| {
        b.iter(|| {
            falcon1024::verify(
                black_box(message),
                black_box(&sig_1024),
                black_box(&pk_1024),
            )
            .is_ok()
        })
    });

    group.finish();
}

fn benchmark_slhdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh-dsa");

    let seed = [42u8; 32];
    let message = b"benchmark message";

    group.bench_function("keygen", |b| {
        b.iter(|| slhdsa::generate_keypair_from_seed(black_box(&seed)).unwrap())
    });

    let (pk, sk) = slhdsa::generate_keypair_from_seed(&seed).unwrap();

    group.bench_function("sign", |b| {
        b.iter(|| slhdsa::sign(black_box(message), black_box(&sk)).unwrap())
    });

    let sig = slhdsa::sign(message, &sk).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| slhdsa::verify(black_box(message), black_box(&sig), black_box(&pk)).is_ok())
    });

    group.finish();
}

fn benchmark_mldsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-dsa");

    let seed = [42u8; 32];
    let message = b"benchmark message";

    group.bench_function("keygen", |b| {
        b.iter(|| mldsa::generate_keypair_from_seed(black_box(&seed)).unwrap())
    });

    let (pk, sk) = mldsa::generate_keypair_from_seed(&seed).unwrap();

    group.bench_function("sign", |b| {
        b.iter(|| mldsa::sign(black_box(message), black_box(&sk)).unwrap())
    });

    let sig = mldsa::sign(message, &sk).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| mldsa::verify(black_box(message), black_box(&sig), black_box(&pk)).is_ok())
    });

    group.finish();
}

fn benchmark_poly_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_mul");

    // Generate deterministic random test data
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut f_i16 = [0i16; P];
    let mut g_i8 = [0i8; P];
    for i in 0..P {
        f_i16[i] = (rng.next_u32() % 4591) as i16 - 2295; // range ~[-2295, 2295]
        g_i8[i] = (rng.next_u32() % 3) as i8 - 1; // range [-1, 0, 1]
    }
    let g_i16: Vec<i16> = g_i8.iter().map(|&x| x as i16).collect();

    // Pre-allocate output buffer for mult_scalar
    let mut h_scalar = [0i16; P];

    // Warmup: ensure both paths are JIT-compiled/cached before measurement
    origin_crypto_sdk::pqc::ntru_prime::rq::mult_scalar(
        &mut h_scalar,
        black_box(f_i16),
        black_box(g_i8),
    );
    let karatsuba_result = origin_crypto_sdk::pqc::ntru_prime::ntt::ntru_poly_mul_karatsuba(
        black_box(&f_i16),
        black_box(&g_i16),
    );

    group.bench_function("mult_scalar_O_P2", |b| {
        b.iter(|| {
            origin_crypto_sdk::pqc::ntru_prime::rq::mult_scalar(
                black_box(&mut h_scalar),
                black_box(f_i16),
                black_box(g_i8),
            );
        })
    });

    group.bench_function("karatsuba_O_P1.585", |b| {
        b.iter(|| {
            let _ = origin_crypto_sdk::pqc::ntru_prime::ntt::ntru_poly_mul_karatsuba(
                black_box(&f_i16),
                black_box(&g_i16),
            );
        })
    });

    group.finish();

    // Verify both paths produce same result (sanity check)
    for i in 0..P {
        assert_eq!(
            h_scalar[i], karatsuba_result[i],
            "Mismatch at coefficient {}: scalar={}, karatsuba={}",
            i, h_scalar[i], karatsuba_result[i]
        );
    }
}

fn benchmark_ntru(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntru");

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    group.bench_function("keygen", |b| {
        b.iter(|| ntru_prime::NtruPrime::generate_keypair(black_box(&mut rng)))
    });

    let (pk, sk) = ntru_prime::NtruPrime::generate_keypair(&mut rng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| ntru_prime::NtruPrime::encapsulate(black_box(&pk), black_box(&mut rng)))
    });

    let (ct, _) = ntru_prime::NtruPrime::encapsulate(&pk, &mut rng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| ntru_prime::NtruPrime::decapsulate(black_box(&ct), black_box(&sk)).unwrap())
    });

    group.finish();
}

fn benchmark_round3(c: &mut Criterion) {
    let mut group = c.benchmark_group("round3");

    // Deterministic test data: h = wild coefficients in [-2295, 2295]
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut h = [0i16; P];
    for i in 0..P {
        h[i] = (rng.next_u32() % 4591) as i16 - 2295;
    }

    group.bench_function("scalar", |b| {
        let mut h_copy = h;
        b.iter(|| {
            origin_crypto_sdk::pqc::ntru_prime::rq::round3_scalar(black_box(&mut h_copy));
        })
    });

    group.bench_function("dispatch_round3", |b| {
        let mut h_copy = h;
        b.iter(|| {
            origin_crypto_sdk::pqc::ntru_prime::rq::round3(black_box(&mut h_copy));
        })
    });

    group.finish();
}

fn benchmark_serpent(c: &mut Criterion) {
    let mut group = c.benchmark_group("serpent");

    let key = [1u8; 32];
    let iv = [2u8; 16];
    let plaintext = vec![0u8; 1024 * 1024]; // 1 MB

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            aead::symmetric::SerpentCbc::encrypt(
                black_box(&key),
                black_box(&iv),
                black_box(&plaintext),
            )
            .unwrap()
        })
    });

    let encrypted = aead::symmetric::SerpentCbc::encrypt(&key, &iv, &plaintext).unwrap();

    group.bench_function("decrypt", |b| {
        b.iter(|| {
            aead::symmetric::SerpentCbc::decrypt(
                black_box(&key),
                black_box(&iv),
                black_box(&encrypted),
            )
            .unwrap()
        })
    });

    group.finish();
}

// =====================================================================
// Hybrid Construction Benchmarks
// =====================================================================

fn benchmark_hybrid_hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid-hashes");
    let messages: Vec<Vec<u8>> = vec![
        b"short".to_vec(),
        vec![0u8; 1024],
        vec![0u8; 64 * 1024],
        vec![0u8; 1024 * 1024],
    ];

    for (i, msg) in messages.iter().enumerate() {
        let id = BenchmarkId::from_parameter(match i {
            0 => "5B",
            1 => "1KB",
            2 => "64KB",
            _ => "1MB",
        });

        group.bench_with_input(id.clone(), msg, |b, m| {
            b.iter(|| {
                let _ = skein512(black_box(m));
                let _ = skein1024(black_box(m));
            })
        });
    }

    group.finish();
}

fn benchmark_hybrid_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid-signatures");

    let seed = [42u8; 32];
    let message = b"benchmark message for hybrid signatures";
    let ed_sk = Ed25519Sk::from_bytes(&seed);
    let ed_pk = ed_sk.verifying_key();
    let ed448_sk = Ed448Signer::from_bytes(&[42u8; 57]).unwrap();
    let ed448_pk = ed448_sk.verifying_key();

    // Ed25519 + Falcon-1024
    let (f1024_pk, f1024_sk) = falcon1024::generate_keypair_from_seed(&seed).unwrap();
    let h_sig = Ed25519Falcon1024::sign(&ed_sk, &f1024_sk, message);
    group.bench_function("ed25519_falcon1024_sign", |b| {
        b.iter(|| {
            Ed25519Falcon1024::sign(black_box(&ed_sk), black_box(&f1024_sk), black_box(message))
        })
    });
    group.bench_function("ed25519_falcon1024_verify", |b| {
        b.iter(|| {
            Ed25519Falcon1024::verify(
                black_box(&ed_pk),
                black_box(&f1024_pk),
                black_box(message),
                black_box(&h_sig),
            )
        })
    });

    // Ed25519 + Falcon-512
    let (f512_sk, f512_pk) = falcon512::generate_keypair(seed);
    let h512_sig = Ed25519Falcon512::sign(&ed_sk, &f512_sk, message);
    group.bench_function("ed25519_falcon512_sign", |b| {
        b.iter(|| {
            Ed25519Falcon512::sign(black_box(&ed_sk), black_box(&f512_sk), black_box(message))
        })
    });
    group.bench_function("ed25519_falcon512_verify", |b| {
        b.iter(|| {
            Ed25519Falcon512::verify(
                black_box(&ed_pk),
                black_box(&f512_pk),
                black_box(message),
                black_box(&h512_sig),
            )
        })
    });

    // Ed448 + Falcon-1024
    let h448_sig = Ed448Falcon1024::sign(&ed448_sk, &f1024_sk, message);
    group.bench_function("ed448_falcon1024_sign", |b| {
        b.iter(|| {
            Ed448Falcon1024::sign(
                black_box(&ed448_sk),
                black_box(&f1024_sk),
                black_box(message),
            )
        })
    });
    group.bench_function("ed448_falcon1024_verify", |b| {
        b.iter(|| {
            Ed448Falcon1024::verify(
                black_box(&ed448_pk),
                black_box(&f1024_pk),
                black_box(message),
                black_box(&h448_sig),
            )
        })
    });

    // Non-KDF hash combiners (lightweight, smaller sigs)
    let b3_sig = Ed25519Blake3::sign(&ed_sk, message);
    group.bench_function("ed25519_blake3_sign", |b| {
        b.iter(|| Ed25519Blake3::sign(black_box(&ed_sk), black_box(message)))
    });
    group.bench_function("ed25519_blake3_verify", |b| {
        b.iter(|| Ed25519Blake3::verify(black_box(&ed_pk), black_box(message), black_box(&b3_sig)))
    });

    let sk512_sig = Ed25519Skein512::sign(&ed_sk, message);
    group.bench_function("ed25519_skein512_sign", |b| {
        b.iter(|| Ed25519Skein512::sign(black_box(&ed_sk), black_box(message)))
    });
    group.bench_function("ed25519_skein512_verify", |b| {
        b.iter(|| {
            Ed25519Skein512::verify(black_box(&ed_pk), black_box(message), black_box(&sk512_sig))
        })
    });

    let sh256_sig = Ed25519Shake256::sign(&ed_sk, message, 64);
    group.bench_function("ed25519_shake256_sign", |b| {
        b.iter(|| Ed25519Shake256::sign(black_box(&ed_sk), black_box(message), 64))
    });
    group.bench_function("ed25519_shake256_verify", |b| {
        b.iter(|| {
            Ed25519Shake256::verify(black_box(&ed_pk), black_box(message), black_box(&sh256_sig))
        })
    });

    // Ed448 variants
    let ed448_s3 = Ed448Sha3_256::sign(&ed448_sk, message);
    group.bench_function("ed448_sha3_256_sign", |b| {
        b.iter(|| Ed448Sha3_256::sign(black_box(&ed448_sk), black_box(message)))
    });
    group.bench_function("ed448_sha3_256_verify", |b| {
        b.iter(|| {
            Ed448Sha3_256::verify(
                black_box(&ed448_pk),
                black_box(message),
                black_box(&ed448_s3),
            )
        })
    });

    let ed448_sk512 = Ed448Skein512::sign(&ed448_sk, message);
    group.bench_function("ed448_skein512_sign", |b| {
        b.iter(|| Ed448Skein512::sign(black_box(&ed448_sk), black_box(message)))
    });
    group.bench_function("ed448_skein512_verify", |b| {
        b.iter(|| {
            Ed448Skein512::verify(
                black_box(&ed448_pk),
                black_box(message),
                black_box(&ed448_sk512),
            )
        })
    });

    let ed448_sh = Ed448Shake256::sign(&ed448_sk, message, 64);
    group.bench_function("ed448_shake256_sign", |b| {
        b.iter(|| Ed448Shake256::sign(black_box(&ed448_sk), black_box(message), 64))
    });
    group.bench_function("ed448_shake256_verify", |b| {
        b.iter(|| {
            Ed448Shake256::verify(
                black_box(&ed448_pk),
                black_box(message),
                black_box(&ed448_sh),
            )
        })
    });

    group.finish();
}

fn benchmark_hybrid_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("hybrid-kdf");

    let master_seed = [42u8; 32];
    let domain = "bench.v1";
    let message = b"benchmark message for KDF hybrid";

    // HKDF subkey derivation
    group.bench_function("derive_hybrid_keys", |b| {
        b.iter(|| {
            derive_hybrid_keys(black_box(&master_seed), black_box(domain), 32, 32, 32).unwrap()
        })
    });

    // Bundle from_seed
    group.bench_function("bundle_from_seed", |b| {
        b.iter(|| {
            HybridSigningKeyBundle::from_seed(black_box(&master_seed), black_box(domain)).unwrap()
        })
    });

    // Bundle single-call sign
    let bundle = HybridSigningKeyBundle::from_seed(&master_seed, domain).unwrap();
    group.bench_function("bundle_sign_hybrid", |b| {
        b.iter(|| bundle.sign_hybrid(black_box(message)))
    });

    // Cached path: amortized cost should be near-zero after first call
    let _ = HybridSigningKeyBundle::from_seed_cached(&master_seed, domain).unwrap();
    group.bench_function("bundle_from_seed_cached", |b| {
        b.iter(|| {
            HybridSigningKeyBundle::from_seed_cached(black_box(&master_seed), black_box(domain))
                .unwrap()
        })
    });

    // Non-cached path: should be slow (Falcon keygen dominates)
    hybrid::bundle_cache_clear();
    group.bench_function("bundle_from_seed_uncached", |b| {
        b.iter(|| {
            hybrid::bundle_cache_clear();
            HybridSigningKeyBundle::from_seed_cached(black_box(&master_seed), black_box(domain))
                .unwrap()
        })
    });

    // Full KDF construction
    group.bench_function("ed25519_chacha20blake3_sha3_256_sign", |b| {
        b.iter(|| {
            Ed25519ChaCha20Blake3Sha3_256::sign(
                black_box(&master_seed),
                black_box(domain),
                black_box(message),
            )
            .unwrap()
        })
    });

    let kdf_sig = Ed25519ChaCha20Blake3Sha3_256::sign(&master_seed, domain, message).unwrap();
    group.bench_function("ed25519_chacha20blake3_sha3_256_verify", |b| {
        b.iter(|| {
            Ed25519ChaCha20Blake3Sha3_256::verify(
                black_box(&master_seed),
                black_box(domain),
                black_box(message),
                black_box(&kdf_sig),
            )
        })
    });

    group.finish();
}

/// Benchmark the 4 SHAKE KEM hashing variants:
/// 1. NIST reference (SHA-2-512 with domain separation)
/// 2. SHAKE128 (experimental, behind feature flag)
/// 3. SHAKE256 two-call (experimental, behind feature flag)
/// 4. SHAKE256 single-absorb (experimental, behind feature flag)
fn benchmark_ntru_kem_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntru_kem_hash");

    // Test data: realistic r_enc (191 bytes) and cache (32 bytes)
    let r_enc = [0xABu8; 191];
    let cache = [0xCDu8; 32];

    // 1. NIST reference: HashConfirm (3 SHA-512 calls)
    group.bench_function("confirm_nist_sha2_512", |b| {
        b.iter(|| {
            origin_crypto_sdk::pqc::ntru_prime::kem_hashing::hash_confirm(
                black_box(&r_enc),
                black_box(&cache),
            )
        })
    });

    // 2. NIST reference: HashSession (2 SHA-512 calls)
    let confirm = origin_crypto_sdk::pqc::ntru_prime::kem_hashing::hash_confirm(&r_enc, &cache);
    group.bench_function("session_nist_sha2_512", |b| {
        b.iter(|| {
            origin_crypto_sdk::pqc::ntru_prime::kem_hashing::hash_session(
                black_box(1),
                black_box(&r_enc),
                black_box(&confirm),
            )
        })
    });

    // 3. NIST reference: Hash4 (1 SHA-512 call over 1158-byte pk)
    let pk = [0x42u8; 1158];
    group.bench_function("hash4_nist_sha2_512", |b| {
        b.iter(|| origin_crypto_sdk::pqc::ntru_prime::kem_hashing::hash4(black_box(&pk)))
    });

    // SHAKE variants (only compiled when features are enabled)
    #[cfg(feature = "ntru-shake128")]
    {
        group.bench_function("confirm_shake128", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake128_kem::hash_confirm(
                    black_box(&r_enc),
                    black_box(&cache),
                )
            })
        });

        group.bench_function("session_shake128", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake128_kem::hash_session(
                    black_box(1),
                    black_box(&r_enc),
                    black_box(&confirm),
                )
            })
        });

        group.bench_function("hash4_shake128", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake128_kem::hash4(black_box(&pk))
            })
        });
    }

    #[cfg(feature = "ntru-shake256")]
    {
        group.bench_function("confirm_shake256", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake256_kem::hash_confirm(
                    black_box(&r_enc),
                    black_box(&cache),
                )
            })
        });

        group.bench_function("session_shake256", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake256_kem::hash_session(
                    black_box(1),
                    black_box(&r_enc),
                    black_box(&confirm),
                )
            })
        });

        group.bench_function("hash4_shake256", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake256_kem::hash4(black_box(&pk))
            })
        });

        // Single-absorb mode: produces both confirm and session in one call
        group.bench_function("confirm_and_session_shake256_single", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::shake256_kem::hash_confirm_and_session(
                    black_box(&r_enc),
                    black_box(&cache),
                )
            })
        });
    }

    #[cfg(feature = "ntru-blake3")]
    {
        group.bench_function("confirm_blake3", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::blake3_kem::hash_confirm(
                    black_box(&r_enc),
                    black_box(&cache),
                )
            })
        });

        group.bench_function("session_blake3", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::blake3_kem::hash_session(
                    black_box(1),
                    black_box(&r_enc),
                    black_box(&confirm),
                )
            })
        });

        group.bench_function("hash4_blake3", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::blake3_kem::hash4(black_box(&pk))
            })
        });

        // Single-absorb mode: produces both confirm and session in one BLAKE3 call
        group.bench_function("confirm_and_session_blake3_single", |b| {
            b.iter(|| {
                origin_crypto_sdk::pqc::ntru_prime::kem_hashing::blake3_kem::hash_confirm_and_session(
                    black_box(&r_enc),
                    black_box(&cache),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_aead,
    benchmark_kdf,
    benchmark_reed_solomon,
    benchmark_falcon,
    benchmark_slhdsa,
    benchmark_mldsa,
    benchmark_ntru,
    benchmark_ntru_kem_hash,
    benchmark_poly_mul,
    benchmark_round3,
    benchmark_serpent,
    benchmark_hybrid_hashes,
    benchmark_hybrid_signatures,
    benchmark_hybrid_kdf
);
criterion_main!(benches);

// SPDX-License-Identifier: OPL-1.1

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use origin_crypto_sdk::{
    aead, kdf, error_correction, symmetric,
    pqc::falcon512, pqc::falcon1024, pqc::ntru_prime,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn benchmark_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    
    let key = aead::generate_key();
    let nonce = aead::generate_nonce();
    
    for size in [1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let plaintext = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("encrypt", size),
            size,
            |b, _| b.iter(|| {
                aead::XChaCha20Poly1305::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext)).unwrap()
            }),
        );
    }
    
    group.finish();
}

fn benchmark_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");
    
    let password = b"benchmark_password";
    let salt = [1u8; 16];
    
    group.bench_function("argon2id_normal", |b| {
        b.iter(|| {
            kdf::Argon2id::derive_key(black_box(password), black_box(&salt), black_box(false)).unwrap()
        })
    });
    
    group.bench_function("argon2id_paranoid", |b| {
        b.iter(|| {
            kdf::Argon2id::derive_key(black_box(password), black_box(&salt), black_box(true)).unwrap()
        })
    });
    
    group.finish();
}

fn benchmark_reed_solomon(c: &mut Criterion) {
    let mut group = c.benchmark_group("reed_solomon");
    
    let codec = error_correction::ReedSolomonCodec::new(16, 8);
    let data = vec![0u8; 1024 * 1024]; // 1 MB
    
    group.bench_function("encode_serial", |b| {
        b.iter(|| {
            codec.encode(black_box(&data)).unwrap()
        })
    });
    
    group.bench_function("encode_parallel", |b| {
        b.iter(|| {
            codec.encode_parallel(black_box(&data)).unwrap()
        })
    });
    
    let encoded = codec.encode(&data).unwrap();
    group.bench_function("decode", |b| {
        b.iter(|| {
            codec.decode(black_box(&encoded)).unwrap()
        })
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
        b.iter(|| falcon1024::verify(black_box(message), black_box(&sig_1024), black_box(&pk_1024)).is_ok())
    });
    
    group.finish();
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

fn benchmark_serpent(c: &mut Criterion) {
    let mut group = c.benchmark_group("serpent");
    
    let key = [1u8; 32];
    let iv = [2u8; 16];
    let plaintext = vec![0u8; 1024 * 1024]; // 1 MB
    
    group.bench_function("encrypt", |b| {
        b.iter(|| symmetric::SerpentCbc::encrypt(black_box(&key), black_box(&iv), black_box(&plaintext)).unwrap())
    });
    
    let encrypted = symmetric::SerpentCbc::encrypt(&key, &iv, &plaintext).unwrap();
    
    group.bench_function("decrypt", |b| {
        b.iter(|| symmetric::SerpentCbc::decrypt(black_box(&key), black_box(&iv), black_box(&encrypted)).unwrap())
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_aead,
    benchmark_kdf,
    benchmark_reed_solomon,
    benchmark_falcon,
    benchmark_ntru,
    benchmark_serpent
);
criterion_main!(benches);

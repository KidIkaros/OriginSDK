# Performance baseline — v0.7.1-rc.9

Recorded `cargo bench --bench crypto_benchmarks --features slh-dsa,ml-dsa,pqc-simd,test-utils`
with `--measurement-time 3 --warm-up-time 1 --sample-size 30` (61 benchmarks).

**Reference machine:** Intel Core i7-10750H @ 2.60 GHz (12 threads), x86_64,
Linux, rustc 1.97.1, criterion 0.5.1. Absolute times are machine-specific —
use the ratios and orders of magnitude, not the raw numbers, on other
hardware. Numbers below are Criterion's median estimate.

## Headline operations

| Benchmark | Median | Notes |
|-----------|--------|-------|
| `ntru/keygen` | 12.6 ms | scalar; `pqc-simd` is a placeholder feature |
| `ntru/encapsulate` | 401 µs | |
| `ntru/decapsulate` | 3.79 ms | includes R3/Rq ops + CCA re-encryption check |
| `falcon/falcon512_keygen` | 7.59 ms | external `falcon-rs` |
| `falcon/falcon512_sign` | 810 µs | |
| `falcon/falcon512_verify` | 144 µs | |
| `falcon/falcon1024_keygen` | 47.5 ms | |
| `falcon/falcon1024_sign` | 1.07 ms | |
| `falcon/falcon1024_verify` | 147 µs | |
| `ml-dsa/keygen` | 212 µs | external `ml-dsa` crate |
| `ml-dsa/sign` | 683 µs | |
| `ml-dsa/verify` | 136 µs | |
| `slh-dsa/keygen` | 5.33 ms | external `slh-dsa` crate |
| `slh-dsa/sign` | 126 ms | SPHINCS+ is signing-bound by design |
| `slh-dsa/verify` | 7.63 ms | |

## Symmetric & KDF

| Benchmark | Median | Notes |
|-----------|--------|-------|
| `aead/encrypt/1024` | 5.08 µs | ChaCha20-Poly1305, 1 KiB |
| `aead/encrypt/1048576` | 6.42 ms | 1 MiB → ~163 MiB/s |
| `aead/encrypt/10485760` | 65.0 ms | 10 MiB → ~161 MiB/s |
| `kdf/argon2id_normal` | 223 ms | 64 MiB memory-hard by design |
| `kdf/argon2id_paranoid` | 420 ms | |
| `serpent/encrypt` | 367 ms | CBC over test payload — slow, known |
| `serpent/decrypt` | 357 ms | |

## Reed–Solomon & NTRU internals

| Benchmark | Median | Notes |
|-----------|--------|-------|
| `reed_solomon/encode_serial` | 60.0 ms | |
| `reed_solomon/encode_parallel` | 14.1 ms | ~4.3× on 12 threads |
| `reed_solomon/decode` | 63.1 ms | |
| `poly_mul/mult_scalar_O_P2` | 3.38 ms | naive O(P²) reference |
| `poly_mul/karatsuba_O_P1.585` | 341 µs | ~10× over scalar |
| `round3/scalar` | 215 ns | |
| `round3/dispatch_round3` | 254 ns | runtime SIMD dispatch cost |
| `ntru_kem_hash/confirm_nist_sha2_512` | 1.17 µs | |
| `ntru_kem_hash/session_nist_sha2_512` | 4.07 µs | full-ct input (post-12.3 fix) |
| `ntru_kem_hash/hash4_nist_sha2_512` | 3.68 µs | |

## Hybrid signing

| Benchmark | Median |
|-----------|--------|
| `hybrid-signatures/ed25519_falcon1024_sign` | 1.11 ms |
| `hybrid-signatures/ed25519_falcon1024_verify` | 189 µs |
| `hybrid-signatures/ed25519_falcon512_sign` | 545 µs |
| `hybrid-signatures/ed25519_falcon512_verify` | 117 µs |
| `hybrid-signatures/ed448_falcon1024_sign` | 1.80 ms |
| `hybrid-signatures/ed448_falcon1024_verify` | 1.55 ms |
| `hybrid-signatures/ed25519_{blake3,skein512,shake256}_sign` | ~24 µs |
| `hybrid-signatures/ed25519_{blake3,skein512,shake256}_verify` | ~44–49 µs |
| `hybrid-signatures/ed448_{sha3_256,skein512,shake256}_sign` | ~640 µs |
| `hybrid-signatures/ed448_{sha3_256,skein512,shake256}_verify` | ~1.42–1.49 ms |
| `hybrid-hashes/5B` | 5.69 µs |
| `hybrid-hashes/1KB` | 24.3 µs |
| `hybrid-hashes/64KB` | 1.12 ms |
| `hybrid-hashes/1MB` | 18.5 ms |
| `hybrid-kdf/derive_hybrid_keys` | 17.4 µs |
| `hybrid-kdf/bundle_from_seed` | 24.3 ms |
| `hybrid-kdf/bundle_from_seed_cached` | 254 ns |
| `hybrid-kdf/bundle_from_seed_uncached` | 24.1 ms |
| `hybrid-kdf/bundle_sign_hybrid` | 1.07 ms |
| `hybrid-kdf/ed25519_chacha20blake3_sha3_256_sign` | 72.7 µs |
| `hybrid-kdf/ed25519_chacha20blake3_sha3_256_verify` | 87.2 µs |

## Comparing against this baseline

Criterion baselines are stored under `target/criterion/<id>/` — they are
**not** committed (they're machine- and build-specific). To do a real
before/after comparison on the same machine:

```bash
# before your change
cargo bench --bench crypto_benchmarks --features slh-dsa,ml-dsa,pqc-simd,test-utils \
  -- --save-baseline v0.7.1-rc9
# after your change
cargo bench --bench crypto_benchmarks --features slh-dsa,ml-dsa,pqc-simd,test-utils \
  -- --baseline v0.7.1-rc9
```

Criterion prints per-benchmark change statistics; treat p < 0.05
worsenings beyond ~10% as worth investigating. Do **not** compare
baselines recorded on different machines.

## CI behavior

The `benchmark` CI job runs the suite cleanly (no `|| true`) and uploads
`target/criterion/` as a `benchmark-results` artifact. It verifies the
bench code compiles and executes — it does **not** gate on numeric
regressions, because GitHub-hosted runners vary enough that cross-run
absolute-time thresholds produce false positives. Regression gating
requires same-machine before/after comparison (e.g. a dedicated
self-hosted runner or criterion-compare on the same checkout), which is
deferred until such infrastructure exists.

# Benchmarks

This crate ships with [Criterion](https://github.com/bheisler/criterion.rs)
benchmarks in `benches/crypto_benchmarks.rs`. They measure throughput
and latency for the security-critical operations.

## Running

```bash
# All benchmarks (requires slh-dsa and ml-dsa features)
cargo bench --features slh-dsa,ml-dsa

# Just AEAD + KDF (no PQC required)
cargo bench --bench crypto_benchmarks -- "aead" "kdf"
```

Criterion generates an HTML report at `target/criterion/report/index.html`
with per-benchmark charts and statistical analysis.

## Benchmark Groups

| Group | Coverage |
|-------|----------|
| `aead` | XChaCha20-Poly1305 encrypt at 1KB / 1MB / 10MB |
| `kdf` | Argon2id normal (4 iter) and paranoid (8 iter) |
| `reed_solomon` | RS encode (serial + parallel) and decode |
| `falcon` | Falcon-512 and Falcon-1024 keygen / sign / verify |
| `slhdsa` | SLH-DSA (FIPS 205) keygen / sign / verify |
| `mldsa` | ML-DSA (FIPS 204) keygen / sign / verify |
| `ntru` | NTRU Prime KEM keygen / encaps / decaps |

## Expected Performance (workstation reference)

These are approximate numbers on a recent x86_64 CPU, single-threaded.
Your numbers will vary; use these only for relative comparisons.

| Operation | Time | Notes |
|-----------|------|-------|
| XChaCha20-Poly1305 encrypt (1 KB) | ~0.5 µs | Memory-bound |
| XChaCha20-Poly1305 encrypt (1 MB) | ~3 ms | ~330 MB/s |
| Argon2id normal (4 iter, 64 MiB) | ~80 ms | Memory-hard |
| Argon2id paranoid (8 iter, 64 MiB) | ~160 ms | Memory-hard |
| Falcon-512 sign | ~0.5 ms | |
| Falcon-512 verify | ~0.1 ms | |
| Falcon-1024 sign | ~1.5 ms | |
| Falcon-1024 verify | ~0.3 ms | |
| SLH-DSA-128s sign | ~50 ms | Hash-based, slow |
| ML-DSA-44 sign | ~0.1 ms | Lattice, fast |
| NTRU Prime sntrup761 encaps | ~0.1 ms | |
| Ed25519 hybrid (Ed25519 + Falcon-1024) sign | ~1.6 ms | Sum of components |
| Ed25519 hybrid verify | ~0.4 ms | |

## Performance Notes

- **Falcon-1024 keygen is expensive** (~100ms on first call, ~10ms cached).
  Use `HybridSigningKeyBundle::from_seed_cached` if you sign many
  messages with the same seed.
- **SLH-DSA is intentionally slow** — that's the security margin.
  Prefer Falcon or ML-DSA unless you specifically need hash-based.
- **AEAD throughput** is ~330 MB/s for XChaCha20-Poly1305 on a single
  core. Use the `streaming` module for files >10 MB to avoid loading
  ciphertext into memory.
- **Hybrid signing overhead** is negligible — Ed25519 (~50µs) dominates
  total time, Falcon-1024 is the bottleneck.

## CI Integration

Add a benchmark run to your PR pipeline to catch performance regressions:

```yaml
- name: Bench
  run: cargo bench --features slh-dsa,ml-dsa -- --output-format bencher | tee bench.txt
```

Compare `bench.txt` against a baseline stored in your repo.
Criterion's `--save-baseline` flag makes this easy.

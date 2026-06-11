# origin-crypto-sdk fuzz targets

Fuzz targets built with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz).

## Setup

```bash
cargo install cargo-fuzz
```

## Running

```bash
# Run a target for 60 seconds
cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=60

# Run all targets in parallel
cargo +nightly fuzz run fuzz_hybrid_verify -- -max_total_time=60
cargo +nightly fuzz run fuzz_kdf -- -max_total_time=60
```

## Targets

| Target | What it fuzzes | Properties verified |
|--------|----------------|---------------------|
| `fuzz_encrypt_decrypt` | ChaCha20-BLAKE3 AEAD | Roundtrip, no panic, wrong-nonce rejection |
| `fuzz_hybrid_verify` | Ed25519 + Falcon-1024 verify | No panic on arbitrary inputs |
| `fuzz_kdf` | HKDF-SHA3-256 | Determinism, no panic |

## Notes

- Fuzzing requires the nightly toolchain (`cargo +nightly`)
- Crashes and corpus are stored in `fuzz/corpus/<target_name>/`
- The fuzzer should run for at least 10 minutes per target to be useful
- CI integration: see `.github/workflows/ci.yml` (nightly fuzz smoke test)

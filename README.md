# Origin Crypto SDK

Standalone Rust cryptographic SDK with classical and post-quantum primitives. Hybrid signing by default.

[![License: OPL-1.1](https://img.shields.io/badge/license-OPL--1.1-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)
[![crates.io](https://img.shields.io/crates/v/origin-crypto-sdk.svg)](https://crates.io/crates/origin-crypto-sdk)

## Quick Start

```rust
use origin_crypto_sdk::prelude::*;

// Hybrid Ed25519 + Falcon-1024 signature (recommended default)
let master_seed = [0x42u8; 32];
let bundle = HybridSigningKeyBundle::from_seed(&master_seed, "my-app")
    .expect("valid seed");

let sig = bundle.sign_hybrid(b"sign this");
// sig is an Ed25519 + Falcon-1024 hybrid signature — both must verify
```

## What's Inside

| Category | Primitives | Recommended |
|----------|-----------|-------------|
| **Signatures** | Ed25519, Falcon-512/1024, SLH-DSA, ML-DSA, Ed448, Ed41417 | Hybrid (Ed25519 + Falcon-1024) |
| **Encryption** | XChaCha20-Poly1305, ChaCha20-BLAKE3, Serpent CBC | ChaCha20-BLAKE3 (committing AEAD) |
| **KDF** | Argon2id, HKDF-SHA3-256 | Argon2id for passwords, HKDF for derivation |
| **Hashing** | BLAKE3, SHA3-256, SHAKE128/256, Skein-512/1024 | BLAKE3 or SHA3-256 |
| **PQC KEM** | NTRU Prime (sntrup761), hybrid X25519+NTRU+Ed41417 | Hybrid KEM |
| **Utilities** | ChaCha20-DRBG, seed hierarchy, Reed-Solomon, OTP/TOTP, compression, entropy analysis | -- |

## Features

| Feature | Enables | Default |
|---------|---------|---------|
| `parallel` | Rayon-based parallel ops | **yes** |
| `slh-dsa` | SLH-DSA / SPHINCS+ (FIPS 205, hash-based signatures) | no |
| `ml-dsa` | ML-DSA / Dilithium (FIPS 204, lattice signatures) | no |
| `pqc-simd` | SIMD acceleration for NTRU Prime (placeholder) | no |

```toml
# Minimal (no parallel, no optional PQC)
origin-crypto-sdk = { version = "0.4", default-features = false }

# With FIPS 204 + FIPS 205 signatures
origin-crypto-sdk = { version = "0.4", features = ["slh-dsa", "ml-dsa"] }
```

## Security Posture

- **Hybrid-first**: signatures remain secure if *either* classical or PQ primitive breaks
- **Committing AEAD by default**: ChaCha20-BLAKE3 prevents partitioning oracle attacks
- **External + custom implementations**: see [SECURITY.md](SECURITY.md) for a full source table
- Custom PQC implementations (NTRU Prime, Ed41417) are **not independently audited**
- Constant-time verification on Ed25519, Falcon, Ed448 paths
- Memory zeroing via `zeroize` where applicable

**Do not use custom implementations in production without independent audit.**

## Module Map

```
origin_crypto_sdk::
  signing::             -- Ed25519, Falcon, SLH-DSA, ML-DSA, hybrid
    hybrid::            -- HybridSigningKeyBundle (recommended)
    classical::         -- Ed25519 alone
    postquantum::       -- Falcon-512/1024 alone
  aead::                -- XChaCha20-Poly1305
  chacha20_blake3::     -- ChaCha20-BLAKE3 (committing AEAD)
  kdf::                 -- Argon2id, HKDF-SHA3-256
  pqc::                 -- Raw PQC primitives (advanced)
    falcon512::         -- Falcon-512
    falcon1024::        -- Falcon-1024
    ed448::             -- Ed448 (Goldilocks, RFC 8032)
    curve41417::        -- Curve41417 / Ed41417
    ntru_prime::        -- NTRU Prime sntrup761
    slhdsa::            -- SLH-DSA (feature-gated)
    mldsa::             -- ML-DSA (feature-gated)
  drbg::                -- ChaCha20 DRBG (auto-reseed at 16 MB)
  entropy::             -- Entropy quality analysis
  seed::                -- Hierarchical seed derivation
  blob::                -- Encrypted seed at rest
  mmr::                 -- Merkle Mountain Range
  ec_schnorr::          -- secp256k1 Schnorr (native, zero deps)
  prelude::             -- Common re-exports
```

## Examples

```bash
cargo run --example hybrid_sign
cargo run --example encrypt_file
cargo run --example kdf_derive
cargo run --example seed_tree
```

## Requirements

- **MSRV**: Rust 1.85
- **Platform**: Linux, macOS, Windows (requires `getrandom`)

## License

OPL-1.1 — see [LICENSE](LICENSE).

## Links

- [Documentation](https://docs.rs/origin-crypto-sdk)
- [Security Notes](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Migration Guide](MIGRATION.md) — for 0.3 → 0.4 and earlier transitions
- [Maintenance Policy](docs/MAINTENANCE_POLICY.md)
- [Repository](https://github.com/KidIkaros/OriginSDK)

## API Stability

**Pre-1.0 notice**: This crate is at version 0.4.0. Per [Cargo's SemVer
guidance](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#pre-1.0),
anything below 1.0 may contain breaking changes in minor releases.

**Stable** (breaking changes will require a major version bump):
- `CryptoError` variants and their `Display` output
- `HybridSigningKeyBundle` API
- `ChaCha20Blake3::encrypt` / `decrypt` signatures
- `Argon2id::derive_key` signature

**Unstable** (may change in minor releases):
- The exact set of items in `prelude::*`
- Low-level PQC module APIs (`pqc::falcon1024`, `pqc::ed448`, etc.)
- `signing_legacy` — kept for one release cycle, will be removed
- `test_utils` API — stabilizing in 0.5

**Frozen** (will not change):
- Wire formats of `HybridSignatureOutput` byte representations
- AEAD ciphertext format (32-byte auth tag appended to ciphertext)
- Domain separation labels for `HybridSigningKeyBundle::from_seed`

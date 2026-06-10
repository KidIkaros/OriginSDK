# Origin Crypto SDK

Production-grade post-quantum and classical cryptographic primitives
for the Origin ecosystem. Hybrid signing by default.

Pure Rust. Native implementations where possible. All PQ constructions
hybrid-paired with classical fallbacks for defense in depth.

## Version 0.4.0 — what changed

- **New module structure**: `signing::{classical, postquantum, hybrid}` —
  direct access to each algorithm family instead of one monolithic
  `hybrid` module
- **Prelude module**: `use origin_crypto_sdk::prelude::*;` for one-line
  access to the common types
- **Ed448 alias**: `origin_crypto_sdk::ed448` exposes Curve41417 under
  the standard Ed448 name
- **Removed**: broken `HybridKem` stub, deprecated `signature.rs` shim,
  W3C `validation.rs` leftovers
- **Hidden**: `internal/` is now `#[doc(hidden)]`

## Installation

```toml
[dependencies]
origin-crypto-sdk = "0.4"
```

## Quick Start

```rust
use origin_crypto_sdk::prelude::*;

// Recommended: hybrid Ed25519 + Falcon-1024 signing
let master_seed = [0x42u8; 32];
let bundle = HybridSigningKeyBundle::from_seed(&master_seed, "my-app")
    .expect("valid seed");
let msg = b"important document";
let sig = bundle.sign_hybrid(msg);
assert!(bundle.verify_hybrid(msg, &sig));
```

### Just Ed25519 (no PQ)

```rust
use origin_crypto_sdk::signing::classical::Ed25519Signer;

let signer = Ed25519Signer::from_seed(&[0x42u8; 32]);
let sig = signer.sign(b"hello");
assert!(signer.verify(b"hello", &sig));
```

### Just Falcon-1024 (PQ only)

```rust
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;

let signer = Falcon1024Signer::from_seed(&[0x42u8; 32])
    .expect("valid seed");
let sig = signer.sign(b"hello").expect("Falcon sign");
assert!(signer.verify(b"hello", &sig));
```

### Committing AEAD encryption

```rust
use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;
use origin_crypto_sdk::kdf::Argon2id;

let password = b"correct horse battery staple";
let salt = [0u8; 16];
let key = Argon2id::derive_key(password, &salt, false).unwrap();
let nonce = ChaCha20Blake3::generate_nonce();
let ct = ChaCha20Blake3::encrypt(&key, &nonce, b"secret message", b"my-app").unwrap();
let pt = ChaCha20Blake3::decrypt(&key, &nonce, &ct, b"my-app").unwrap();
assert_eq!(pt, b"secret message");
```

## Module Organization

| Need | Module |
|------|--------|
| Hybrid signing (recommended) | `signing::hybrid` |
| Pure Ed25519 | `signing::classical` |
| Pure Falcon-512/1024, SLH-DSA, ML-DSA | `signing::postquantum` |
| secp256k1 Schnorr | `ec_schnorr` |
| Committing AEAD | `chacha20_blake3` |
| Standard AEAD | `aead` |
| Key derivation (Argon2id, HKDF) | `kdf` |
| MAC | `mac` |
| DRBG | `drbg` |
| SipHash | `siphash` |
| Compress | `compression` |
| Elliptic-curve primitives | `pqc::curve41417` (Ed448) |
| One-stop import | `prelude` |

## Hybrid Constructions

Every signature scheme in `signing::hybrid` pairs a classical curve with
a post-quantum primitive. A break in any single primitive does not
compromise the signature.

| Construction | Classical | Post-quantum | Hash combiner |
|---|---|---|---|
| `Ed25519Falcon1024` | Ed25519 | Falcon-1024 | (sig) |
| `Ed25519Falcon512` | Ed25519 | Falcon-512 | (sig) |
| `Ed448Falcon1024` | Ed448 | Falcon-1024 | (sig) |
| `Ed25519Blake3` | Ed25519 | — | BLAKE3 |
| `Ed25519Shake256` | Ed25519 | — | SHAKE-256 |
| `Ed25519Skein512` | Ed25519 | — | Skein-512 |
| `Ed448Blake3` | Ed448 | — | BLAKE3 |
| `Ed448Shake256` | Ed448 | — | SHAKE-256 |
| `Ed448Skein512` | Ed448 | — | Skein-512 |
| `Ed448Sha3_256` | Ed448 | — | SHA3-256 |
| `Ed25519ChaCha20Blake3Sha3_256` | Ed25519 | ChaCha20-BLAKE3 KDF | SHA3-256 |

## Security Defaults

- **For signatures**: use the hybrid (Ed25519 + PQ) — see `signing::hybrid`.
  Both must verify, so a vulnerability in one primitive does not break security.
- **For encryption**: prefer `chacha20_blake3` (committing AEAD).
  Avoid `XChaCha20-Poly1305` unless you specifically need the smaller tag
  and accept the partitioning-oracle risk.
- **For key derivation**: use Argon2id (memory-hard) for password-based KDF,
  HKDF-SHA3-256 for HKDF-style derivation.

## Features

| Feature | Description |
|---------|-------------|
| `parallel` (default) | Rayon-based parallel processing |
| `slh-dsa` | SLH-DSA (FIPS 205) hash-based signatures |
| `ml-dsa` | ML-DSA (FIPS 204) lattice-based signatures |
| `pqc-simd` | SIMD-accelerated PQC (placeholder) |

## License

OPL-1.1

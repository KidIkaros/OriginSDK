# Origin Crypto SDK

A standalone cryptographic SDK providing post-quantum and classical cryptographic primitives for the Origin ecosystem.

## Installation

Add as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
origin-crypto-sdk = { git = "https://github.com/KidIkaros/OriginSDK.git", branch = "main" }
```

## Features

### Encryption & Authentication
- **AEAD**: XChaCha20-Poly1305 (256-bit keys, 192-bit nonces)
- **Native AEAD**: Zero-dep ChaCha20-Poly1305 & XChaCha20-Poly1305 (RFC 8439)
- **Symmetric**: Serpent CBC for paranoid mode
- **Streaming**: Chunked encryption/decryption for large files

### Key Derivation & Management
- **KDF**: Argon2id with configurable tiers (Nano / Standard / Sovereign)
- **HKDF**: HKDF-SHA3-256 subkey derivation
- **HMAC**: HMAC-SHA3-256 message authentication
- **Seed Blob**: Encrypted master seed at rest (Argon2id + XChaCha20-Poly1305)
- **DRBG**: ChaCha20-based deterministic CSPRNG with auto-reseed

### Post-Quantum Cryptography
- **NTRU Prime**: sntrup761 KEM (custom native, ~256-bit quantum security)
- **Falcon-512/1024**: Post-quantum lattice signatures
- **Ed41417**: Curve41417 Edwards curve operations
- **Hybrid KEM**: X25519 + Ed41417 + NTRU Prime (defense in depth)
- **Hybrid Signatures**: Ed25519 + Falcon-1024

### Utilities
- **Error Correction**: Reed-Solomon with parallel encoding
- **Compression**: zlib via flate2
- **SipHash-c-d**: Compute hardener for entropy pipelines
- **Memory Tiers**: Nano (8 MB) / Standard (64 MB) / Sovereign (256 MB)

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `parallel` | ✓ | Parallel Reed-Solomon encoding via rayon |
| `pqc-simd` | | SIMD-accelerated NTRU Prime on x86_64 |

## Quick Start

```rust
use origin_crypto_sdk::{XChaCha20Poly1305, Argon2id};

// Derive key from password
let password = b"secure_password";
let salt = [1u8; 16];
let key = Argon2id::derive_key(password, &salt, false)?;

// Encrypt data
let nonce = origin_crypto_sdk::aead::generate_nonce();
let plaintext = b"Hello, World!";
let ciphertext = XChaCha20Poly1305::encrypt(&key, &nonce, plaintext)?;

// Decrypt
let decrypted = XChaCha20Poly1305::decrypt(&key, &nonce, &ciphertext)?;
assert_eq!(plaintext.to_vec(), decrypted);
```

## MSRV

Minimum Supported Rust Version: **1.70**

## Upstream Credits

This SDK builds upon the following open-source crates:

| Crate | License | Usage |
|-------|---------|-------|
| `chacha20poly1305` | MIT / Apache-2.0 | AEAD encryption |
| `argon2` | MIT / Apache-2.0 | Key derivation |
| `falcon-rust` | MIT | Post-quantum signatures |
| `sha3` / `sha2` | MIT / Apache-2.0 | Hash functions |
| `ed25519-dalek` / `x25519-dalek` | BSD-3-Clause | Classical key exchange |
| `serpent` | MIT / Apache-2.0 | Symmetric encryption |
| `hmac` / `hkdf` | MIT / Apache-2.0 | MAC / Key derivation |
| `subtle` | BSD-3-Clause | Constant-time operations |
| `zeroize` | MIT / Apache-2.0 | Memory safety |
| `rayon` | MIT / Apache-2.0 | Parallelism |

## License

OPL-1.1 OR PolyForm-Shield-1.0.0

See [LICENSE](LICENSE) for full text.

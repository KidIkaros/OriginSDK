# Origin Crypto SDK

Post-quantum and classical cryptographic primitives for the Origin ecosystem.

Pure Rust. Zero external crypto dependencies where possible. All PQ constructions
hybrid-paired with classical fallbacks.

## Installation

```toml
[dependencies]
origin-crypto-sdk = { git = "https://github.com/KidIkaros/OriginSDK.git", branch = "main" }
```

## What's Inside

### Hybrid Signing (DSA-resistant constructions)

Every signature scheme pairs a classical curve with a post-quantum lattice
signature, chained through independent hash functions. A break in any single
primitive does not compromise the signature.

| Construction | Classical | PQ | Hash |
|---|---|---|---|
| Ed25519-ChaCha20-BLAKE3-SHA3-256 | Ed25519 | ChaCha20-BLAKE3 KDF | SHA3-256 |
| Ed25519-ChaCha20-BLAKE3-Skein512 | Ed25519 | ChaCha20-BLAKE3 KDF | Skein-512 |
| Ed25519-Blake3 | Ed25519 | BLAKE3 keyed | Blake3 |
| Ed25519-Skein512 | Ed25519 | Skein-512 | Skein |
| Ed25519-Shake256 | Ed25519 | SHAKE-256 | SHAKE |
| Ed448-Skein512 | Ed448 | Skein-512 | Skein |
| Ed448-Shake256 | Ed448 | SHAKE-256 | SHAKE |
| Ed448-SHA3-256 | Ed448 | SHA3-256 | SHA3 |
| Ed25519-Falcon-512 | Ed25519 | Falcon-512 | HKDF-SHA3-256 |
| Ed25519-Falcon-1024 | Ed25519 | Falcon-1024 | HKDF-SHA3-256 |
| Ed448-Falcon-1024 | Ed448 | Falcon-1024 | HKDF-SHA3-256 |

All hybrid keys derive from a single master seed via HKDF-SHA3-256 with
domain-separated labels (`zti:key:ed25519`, `zti:key:falcon1024`, etc.).
Epoch-based rotation: same identity, new keys.

### Post-Quantum Primitives

| Primitive | Type | Security Level |
|---|---|---|
| Falcon-512 | Lattice signature | NIST Level 1 |
| Falcon-1024 | Lattice signature | NIST Level 5 |
| SLH-DSA (SPHINCS+) | Hash-based signature | FIPS 205 |
| ML-DSA (Dilithium) | Lattice signature | FIPS 204 |
| NTRU Prime (sntrup761) | KEM | ~256-bit quantum |

### Classical Primitives

| Primitive | Notes |
|---|---|
| Ed25519 | Ed25519-dalek |
| Ed448 | Edwards curve via Curve41417 (p = 2^414 - 17) |
| X25519 | Classical DH |
| Curve41417 | 414-bit Edwards, native Montgomery ladder |
| secp256k1 | Native implementation (EC-Schnorr) |

### Encryption & AEAD

- **XChaCha20-Poly1305**: 256-bit keys, 192-bit nonces (RFC 8439)
- **ChaCha20-BLAKE3**: Committing AEAD (encrypt-then-MAC with BLAKE3)
- **Serpent-CBC**: Paranoid-mode symmetric encryption

### Key Derivation & Seed Management

- **Argon2id**: Configurable tiers (Nano 8MB / Standard 64MB / Sovereign 256MB)
- **HKDF-SHA3-256**: Subkey derivation with domain-separated labels
- **Seed Blob**: Encrypted master seed at rest (Argon2id + XChaCha20-Poly1305)
- **Seed Handle**: mlock + zeroize, TTL-based expiry, child seed derivation
- **DRBG**: ChaCha20-based deterministic CSPRNG with auto-reseed
- **Multi-hash seed generation**: BLAKE2b-SHAKE256, BLAKE2b-SHA3, BLAKE2b-SHA512, SHAKE256-SHA3 chains

### Hybrid KEM

X25519 + Curve41417 + NTRU Prime in parallel. Shared secret via HKDF combining
all three DH outputs. Break any one KEM, the others hold.

### OTP (RFC 4226 / RFC 6238)

- **HOTP**: Counter-based one-time passwords (SHA-1, SHA-256, SHA-512)
- **TOTP**: Time-based one-time passwords with configurable period and digits
- **otpauth:// URI generation**: Google Authenticator compatible provisioning

### Entropy Analysis

Shannon entropy, min-entropy, collision entropy, chi-squared test,
serial correlation, longest bit run, bit bias analysis. Quality thresholds
for 128/192/256-bit seeds.

### Data Structures & Utilities

- **MMR**: Merkle Mountain Range with membership proofs
- **Stealth PoW**: Proof-of-work with configurable difficulty
- **Stealth KDF**: Index-derived stealth address keys
- **Reed-Solomon**: Parallel error correction (rayon)
- **Compression**: zlib via flate2
- **SipHash-c-d**: Compute-hard entropy pipeline
- **BIP-39**: Seed encoding (word list not included)

## Architecture

```
master seed (256 bits)
    |
    +-- HKDF-SHA3-256("zti:key:ed25519")      --> Ed25519 signing key
    +-- HKDF-SHA3-256("zti:key:falcon1024")    --> Falcon-1024 signing key
    +-- HKDF-SHA3-256("zti:key:ml-kem-768")    --> ML-KEM-768 encapsulation key
    +-- HKDF-SHA3-256("zti:key:ed41417")       --> Curve41417 DH key
    +-- HKDF-SHA3-256("zti:identity:poseidon") --> Poseidon commitment (identity)
    |
    +-- Epoch rotation: ":e1", ":e2", ... same seed, new keys
```

## Feature Flags

| Flag | Default | Description |
|---|---|---|
| `parallel` | yes | Parallel Reed-Solomon via rayon |
| `pqc-simd` | no | SIMD NTRU Prime on x86_64 |

## Quick Start

```rust
use origin_crypto_sdk::hybrid::{HybridSigningKeyBundle, SignatureCombine};

// Derive hybrid keys from a seed
let seed = [0x42u8; 32];
let bundle = HybridSigningKeyBundle::from_seed(&seed);

// Sign with both Ed25519 + Falcon-1024
let message = b"post-quantum resistant signature";
let sig = bundle.sign(message);

// Verify (both must pass)
assert!(bundle.verify(message, &sig).is_ok());
```

## Test Suite

280 tests across 4 tiers:

- **216 unit tests**: Every primitive, edge case, and error path
- **16 integration tests**: Cross-module workflows
- **15 golden vector tests**: Known-answer tests against standards
- **33 rigorous tests**: Property-based and adversarial testing

```bash
cargo test --lib           # unit tests (~2 min, Falcon keygen is slow)
cargo test --test integration_tests
cargo test --test hybrid_golden_vectors
cargo test --test hybrid_rigorous       # ~5 min
```

## Design Principles

1. **Hybrid by default**: Every PQ construction paired with classical fallback
2. **Seed-derived everything**: One master seed, all keys derived via HKDF with domain labels
3. **Zero external C deps**: Pure Rust where possible, auditable supply chain
4. **Defense in depth**: Multiple hash families, multiple signature schemes, multiple KEMs
5. **Memory safety**: mlock sensitive data, zeroize on drop, no key material on disk

## Upstream Credits

| Crate | License | Usage |
|---|---|---|
| `chacha20poly1305` | MIT / Apache-2.0 | AEAD encryption |
| `argon2` | MIT / Apache-2.0 | Key derivation |
| `sha3` / `sha2` | MIT / Apache-2.0 | Hash functions |
| `ed25519-dalek` | BSD-3-Clause | Ed25519 signatures |
| `x25519-dalek` | BSD-3-Clause | X25519 DH |
| `hmac` | MIT / Apache-2.0 | HMAC constructions |
| `subtle` | BSD-3-Clause | Constant-time ops |
| `zeroize` | MIT / Apache-2.0 | Secure memory wiping |
| `rayon` | MIT / Apache-2.0 | Parallelism |
| `blake3` | CC0-1.0 / Apache-2.0 | BLAKE3 hash |
| `skein` | MIT / Apache-2.0 | Skein-512/1024 |

## License

OPL-1.1 OR PolyForm-Shield-1.0.0

See [LICENSE](LICENSE) for full text.

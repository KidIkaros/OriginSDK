# Origin Crypto SDK

> ⚠️ **EXPERIMENTAL — NOT FOR PRODUCTION USE** ⚠️
>
> This SDK is under active development and **has not undergone independent
> security audit or formal review**. Cryptographic code is notoriously subtle;
> an implementation that passes its own tests is not the same as one that is
> safe to trust with real secrets.
>
> - **Do not** use this in production systems.
> - **Do not** use it to protect real funds, real identities, or real data.
> - Treat every release (including patch releases) as experimental.
> - The API, wire formats, and on-disk formats **may change without notice**,
>   and may do so in ways that break compatibility with previously written data.
>
> Use for research, evaluation, and experimentation only. A rigorous external
> audit is a prerequisite for any production deployment.

Standalone Rust cryptographic SDK with classical and post-quantum primitives. Hybrid signing by default.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-orange.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)
[![crates.io](https://img.shields.io/crates/v/origin-crypto-sdk.svg)](https://crates.io/crates/origin-crypto-sdk)

> **🌐 Live browser demo:** [kidikaros.github.io/origin-web](https://kidikaros.github.io/origin-web)
> — signing, encryption, sharding, and entropy analysis compiled to WASM. Zero servers, zero network requests.

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
| **Encryption** | XChaCha20-Poly1305, ChaCha20-BLAKE3, Serpent CBC, **ChaCha40** (512-bit key stream cipher) | ChaCha20-BLAKE3 (committing AEAD) |
| **KDF** | Argon2id, HKDF-SHA3-256, HMAC-SHA3-256 | Argon2id for passwords, HKDF for derivation |
| **Hashing** | BLAKE3, SHA3-256, SHAKE128/256, Skein-512/1024 | BLAKE3 or SHA3-256 |
| **PQC KEM** | NTRU Prime (sntrup761), hybrid X25519+NTRU+Ed41417 | Hybrid KEM |
| **Ciphers** | ChaCha20 stream cipher, **ChaCha40** (PQ-hardened, 512-bit key, 40 rounds) | ChaCha40 for PQ-sensitive streams |
| **Utilities** | ChaCha20-DRBG, seed hierarchy, Reed-Solomon, OTP/TOTP, compression, entropy analysis | -- |
| **Recovery** | Unicode-codepoint recovery phrases (12 / 24-word, SHA-3-256 checksum) | Unicode cipher — NOT BIP-39 compatible |

## Recovery Phrases

The `recovery::unicode_cipher` module provides a BIP-39-shaped recovery phrase codec using Unicode codepoints instead of an English wordlist.

- **NOT BIP-39 compatible**: uses a curated Unicode codepoint wordlist and SHA-3-256 (not SHA-256). Phrases generated here cannot be recovered by other BIP-39 wallets — recovery requires this module.
- **Strict NFKC safety**: the decoder rejects ZWJ, Variation Selectors, Combining Marks, BIDI marks, default-ignorable characters, and multi-codepoint NFKC decompositions. No silent canonicalization.
- **12 or 24 words**: 12-word = 128-bit entropy + 4-bit SHA-3-256 checksum; 24-word = 256-bit entropy + 8-bit checksum.
- **Custom alphabets**: power-of-2 sized (16, 32, ..., 4096), with a 128-bit safety floor.

```rust
use origin_crypto_sdk::recovery::unicode_cipher::{
    encode_phrase, decode_phrase, PhraseLength, UnicodeWordlist,
};

let entropy = [0x42u8; 32]; // 256-bit for 24-word phrase
let phrase = encode_phrase(&entropy, &UnicodeWordlist::default(), PhraseLength::Words24)
    .expect("valid entropy");
let recovered = decode_phrase(&phrase, &UnicodeWordlist::default())
    .expect("valid phrase");
assert_eq!(recovered, entropy);
```

See the [module docs](https://docs.rs/origin-crypto-sdk/latest/origin_crypto_sdk/recovery/unicode_cipher/index.html) for the full API surface.

## Features

| Feature | Enables | Default |
|---------|---------|---------|
| `parallel` | Rayon-based parallel ops | **yes** |
| `slh-dsa` | SLH-DSA / SPHINCS+ (FIPS 205, hash-based signatures) | no |
| `ml-dsa` | ML-DSA / Dilithium (FIPS 204, lattice signatures) | no |
| `pqc-simd` | SIMD acceleration for NTRU Prime (placeholder) | no |

```toml
# Minimal (no parallel, no optional PQC)
origin-crypto-sdk = { version = "0.6", default-features = false }

# With FIPS 204 + FIPS 205 signatures
origin-crypto-sdk = { version = "0.6", features = ["slh-dsa", "ml-dsa"] }
```

## Security Posture

- **Hybrid-first**: signatures remain secure if *either* classical or PQ primitive breaks
- **Committing AEAD by default**: ChaCha20-BLAKE3 prevents partitioning oracle attacks
- **External + custom implementations**: see [SECURITY.md](SECURITY.md) for a full source table
- Custom PQC implementations (NTRU Prime, Ed41417) are **not independently audited**
- Constant-time verification on Ed25519, Falcon, Ed448 paths
- Memory zeroing via `zeroize` where applicable

**Do not use custom implementations in production without independent audit.**

## Threat Modeling & Duress Patterns

If your application serves users facing legal compulsion or physical coercion
(journalists, activists, dissidents), the SDK ships **no duress or self-destruct
primitive** by deliberate design. Active-wipe / self-destruct features have
been prosecuted under 18 U.S.C. §2232 ("destruction of property to prevent
seizure"); see the Tunick matter (TechCrunch 2026-07-24).

For application-level guidance on:

- **Pattern P1**: Operational deniability — keep sensitive state off the device the user carries (EFF SSD clean-traveler pattern)
- **Pattern P2**: Distinguishable decoy vault — three vaults, duress passphrase silently routes to decoy (no destruction occurs; §2232 risk avoided)
- **Pattern P3**: Indistinguishable plausible deniability — VeraCrypt-style hidden volume; operationally fragile
- **Jurisdictional matrix**: US, UK (Investigatory Powers Act 2016), EU (member-state variance), authoritarian regimes

…see [`docs/duress-pattern.md`](docs/duress-pattern.md).

## Module Map

```
origin_crypto_sdk::
  signing::             -- Ed25519, Falcon, SLH-DSA, ML-DSA, hybrid
    hybrid::            -- HybridSigningKeyBundle (recommended)
    classical::         -- Ed25519 alone
    postquantum::       -- Falcon-512/1024 alone (OOP signers)
    legacy_shim::       -- Deprecated: old `hybrid::*` re-exports
  aead::                -- XChaCha20-Poly1305
    symmetric::         -- Serpent CBC (non-AEAD)
    streaming::         -- Streaming encryption
  chacha20_blake3::     -- ChaCha20-BLAKE3 (committing AEAD)
  chacha40::            -- ChaCha40 (PQ-hardened stream cipher, 512-bit key)
  chacha20::            -- ChaCha20 stream cipher (RFC 8439)
  kdf::                 -- Argon2id, HKDF-SHA3-256
    mac::               -- HMAC-SHA3-256 (keyed hash)
  pqc::                 -- Raw PQC primitives (advanced)
    falcon512::         -- Falcon-512
    falcon1024::        -- Falcon-1024
    ed448::             -- Ed448 (Goldilocks, RFC 8032)
    curve41417::        -- Curve41417 / Ed41417
    ntru_prime::        -- NTRU Prime sntrup761
    slhdsa::            -- SLH-DSA (feature-gated)
    mldsa::             -- ML-DSA (feature-gated)
  drbg::                -- ChaCha20 DRBG (auto-reseed at 16 MB)
    otp::               -- One-time pad (HOTP/TOTP, RFC 4226/6238)
  ocra::                -- OCRA challenge-response (RFC 6287 core)
  entropy::             -- Entropy quality analysis
  seed::                -- Hierarchical seed derivation
    gen::               -- Multi-hash seed generation
  blob::                -- Seed-blob storage format (v1/v2, tier-aware)
  error_correction::    -- Reed-Solomon over GF(2^8) (experimental utility)
  compression::         -- DEFLATE helpers used by `compressed` (experimental utility)
  compressed::          -- Atomic compress-then-encrypt container
  siphash::             -- SipHash-c-d compute-hardener (experimental utility)
  stealth::             -- Stealth address primitives
    kdf::               -- Stealth master/child key derivation
    pow::               -- Hashcash PoW for enumeration rate-limiting
  recovery::            -- Unicode recovery phrase codec (NOT BIP-39 compatible)
    unicode_cipher::    -- Encode/decode Unicode-phrase backups
  ec_schnorr::          -- secp256k1 Schnorr (native, zero deps)
  prelude::             -- Common re-exports
  test_utils::          -- Deterministic test helpers (feature = "test-utils")
  types::               -- Zeroizing byte array newtypes (XNonce, CNonce, Seed, etc.)
  error::               -- CryptoError, Result alias
```

> **Note**: Utility modules marked `(experimental utility)` are public API but their wire formats and surface are not yet frozen — see each module's docs. The `internal` and `primitives` implementation layers are crate-private and unreachable from outside the crate; see `docs/ARCHITECTURE.md` for the layer rules.

## Usage: Two Layers for Signing

```rust
// Layer 1: OOP signers (easy, recommended for single-primitive use)
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;
let signer = Falcon1024Signer::from_seed(&[0x42u8; 32]).expect("valid seed");
signer.sign(b"hello").expect("sign failed");

// Layer 2: Raw primitives (advanced, for custom composition)
use origin_crypto_sdk::pqc::falcon1024::{FalconPrivateKey, FalconPublicKey, sign, verify};
let (pk, sk) = falcon1024::generate_keypair_from_seed(&seed).expect("keygen");
let sig = sign(b"hello", &sk).expect("sign failed");
verify(b"hello", &sig, &pk).expect("verify failed");
```

The `signing::postquantum` OOP types are thin wrappers over `pqc::` — no duplicate implementations.

## Examples

```bash
cargo run --example hybrid_sign
cargo run --example encrypt_file
cargo run --example chacha40_encrypt
cargo run --example kdf_derive
cargo run --example seed_tree
```

## Requirements

- **MSRV**: Rust 1.85
- **Platform**: Linux, macOS, Windows (requires `getrandom`)

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Links

- [Documentation](https://docs.rs/origin-crypto-sdk)
- [Security Notes](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Migration Guide](MIGRATION.md) — for 0.3 → 0.4 and earlier transitions
- [Maintenance Policy](docs/MAINTENANCE_POLICY.md)
- [Repository](https://github.com/KidIkaros/OriginSDK)

## API Stability

**Pre-1.0 notice**: This crate is at version 0.7.1-rc.9. Per [Cargo's SemVer guidance](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#pre-1-0), anything below 1.0 may contain breaking changes in minor releases.

**Stable** (breaking changes will require a major version bump):
- `CryptoError` variants and their `Display` output
- `HybridSigningKeyBundle` API (`from_seed`, `from_seed_cached`, `sign_hybrid`, `verify`)
- `XChaCha20Poly1305::encrypt_aad` / `decrypt_aad` signatures
- `ChaCha20Blake3::encrypt` / `decrypt` signatures
- `Argon2id::derive_key` signature
- `fill_random` (public RNG boundary)
- `algorithm_id::AlgorithmId` enum variants and numeric values
- `algorithm_id::DowngradePolicy` API

**Unstable** (may change in minor releases):
- The exact set of items in `prelude::*`
- Low-level PQC module APIs (`pqc::falcon1024`, `pqc::ed448`, `pqc::ntru_prime`, `pqc::curve41417`)
- `test_utils` API
- `blob` module internal format (v2 format is frozen, but API may change)
- `drbg` module API
- `ec_schnorr` module API
- `stealth` module API
- `ocra` module API

**Experimental** (custom implementations, not for production use):
- `pqc::ntru_prime` — custom NTRU Prime KEM
- `pqc::curve41417` — custom Ed41417
- `primitives::chacha20` — native ChaCha20 (use `aead` module for production)
- `primitives::poly1305` — native Poly1305 (use `aead` module for production)
- `drbg` — custom ChaCha20-DRBG
- `signing::hybrid` — hybrid compositions (novel, needs formal analysis)
- `blob` — custom persistence format
- `ec_schnorr` — custom secp256k1 arithmetic
- `error_correction` — custom Reed-Solomon (bounded-distance decoder; see module docs)
- `siphash`, `compression` — internal utilities exposed for testing

**Frozen** (will not change):
- Wire formats of `HybridSignatureOutput` byte representations
- AEAD ciphertext format (16-byte Poly1305 tag appended to ciphertext)
- Domain separation labels for `HybridSigningKeyBundle::from_seed`
- Seed Blob v2 format (`ORGB` magic, 94 bytes)
- `AlgorithmId` numeric assignments (stable, will not be reused)
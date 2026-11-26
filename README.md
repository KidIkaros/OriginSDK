# Origin Crypto SDK

**Hybrid post-quantum cryptography for Rust — secure if *either* the classical or the lattice assumption survives, and honest about exactly what evidence backs every component.**

[![CI](https://github.com/KidIkaros/OriginSDK/actions/workflows/ci.yml/badge.svg)](https://github.com/KidIkaros/OriginSDK/actions)
[![crates.io](https://img.shields.io/crates/v/origin-crypto-sdk.svg)](https://crates.io/crates/origin-crypto-sdk)
[![docs.rs](https://img.shields.io/docsrs/origin-crypto-sdk)](https://docs.rs/origin-crypto-sdk)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![MSRV: 1.95](https://img.shields.io/badge/MSRV-1.95-orange.svg)](https://blog.rust-lang.org/)

> **Live browser demo:** [kidikaros.github.io/origin-web](https://kidikaros.github.io/origin-web) — signing, encryption, sharding, and entropy analysis compiled to WASM. Zero servers, zero network requests.

```rust
use origin_crypto_sdk::prelude::*;

// Hybrid Ed25519 + Falcon-1024 signature — both must verify
let bundle = HybridSigningKeyBundle::from_seed(&[0x42u8; 32], "my-app")?;
let sig = bundle.sign_hybrid(b"sign this");
```

## Why hybrid-first

Post-quantum security estimates keep moving *downward* — and the 2026 literature now includes subexponential classical attacks across the lattice design family (asymptotic, not yet practical — see [`docs/RESEARCH-NOTE-cryptanalysis-evidence.md`](docs/RESEARCH-NOTE-cryptanalysis-evidence.md)). Betting any system on a single assumption family is the monoculture risk. Origin's answer is structural, not selective:

- **Signatures**: Ed25519 + Falcon AND-composed — a break of either alone breaks nothing
- **KEMs**: X25519 + NTRU Prime (+ optional ML-KEM-768) hybrid encapsulation
- **Domain-separated composition**: hybrid component signatures are cryptographically non-extractable — they cannot be replayed as standalone signatures (H-1 class, test-guarded)
- **Deterministic where it matters**: EdDSA-style deterministic Schnorr nonces eliminate the RNG-failure key-recovery attack class

## What's inside

| Category | Primitives | Recommended |
|----------|-----------|-------------|
| **Signatures** | Ed25519, Falcon-512/1024, SLH-DSA, ML-DSA, Ed448, Ed41417 | Hybrid (Ed25519 + Falcon-1024) |
| **Encryption** | XChaCha20-Poly1305, ChaCha20-BLAKE3, Serpent CBC, **ChaCha40** (512-bit key) | ChaCha20-BLAKE3 (committing AEAD) |
| **KDF** | Argon2id, HKDF-SHA3-256/512, HMAC-SHA3-256 | Argon2id for passwords, HKDF for derivation |
| **Hashing** | BLAKE3, SHA3-256/512, SHAKE128/256, Skein-512/1024 | BLAKE3 or SHA3-256 |
| **PQC KEM** | NTRU Prime (sntrup761), ML-KEM-768, hybrid X25519+sntrup761 | Hybrid KEM (`kem::hybrid`) |
| **Utilities** | ChaCha20-DRBG, seed hierarchy, Reed-Solomon, OTP/TOTP, entropy analysis | — |
| **Recovery** | Unicode-codepoint recovery phrases (NOT BIP-39 compatible) | 12/24-word, SHA-3-256 checksum |

## Radical transparency: evidence tiers, not vibes

Most crypto libraries say "don't use in production" or nothing at all. Origin publishes exactly what evidence backs each component — the first PQC SDK we know of to ship a machine-readable cryptographic inventory (CycloneDX CBOM: `cargo run --bin cbom`).

| Tier | Meaning | Components |
|------|---------|-----------|
| **A** | Externally validated implementations | AEAD crates, Argon2id, Ed25519/X25519, SHA-2/3, Falcon (`falcon-rs`), `k256` |
| **B** | Custom implementations, reference-vector proven | NTRU Prime (100/100 design-team KAT byte-exact), native ChaCha20/Poly1305 (RFC 8439) — internal constant-time review complete |
| **C** | Custom constructions, internal evidence only | hybrid composition, Ed41417, EC-Schnorr, DRBG, formats, sharding |

**What this means for you**: Tier A deployment carries mainstream-equivalent risk. Tier C is the design core — novel, internally reviewed, and **not yet independently audited** (the audit package in [`AUDIT_PACKAGE.md`](AUDIT_PACKAGE.md) is prepared for exactly that engagement). If you deploy Tier C against real secrets today, you are the reviewer of last resort.

Evidence is ranked by independence, not authority — standards-body endorsement is explicitly *not* treated as evidence (the Dual_EC lesson). The design deviations here (NTRU Prime over Kyber, Curve41417, hybrid composition) are deliberate, expert-guided positions documented in [`SECURITY.md`](SECURITY.md) and the research note.

Full per-component matrix: **[STABILITY.md](STABILITY.md)** · Wire formats are golden-vector pinned and semver-versioned.

## Quick start

```toml
[dependencies]
origin-crypto-sdk = "0.7"

# minimal: no parallel, no optional PQC
# origin-crypto-sdk = { version = "0.7", default-features = false }

# with hash-based + lattice signature alternatives
# origin-crypto-sdk = { version = "0.7", features = ["slh-dsa", "ml-dsa"] }
```

Two layers for signing:

```rust
// Layer 1: OOP signers (easy)
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;
let signer = Falcon1024Signer::from_seed(&[0x42u8; 32])?;
signer.sign(b"hello")?;

// Layer 2: raw primitives (custom composition)
use origin_crypto_sdk::pqc::falcon1024::{self, sign, verify};
let (pk, sk) = falcon1024::generate_keypair_from_seed(&seed)?;
let sig = sign(b"hello", &sk)?;
verify(b"hello", &sig, &pk)?;
```

```bash
cargo run --example hybrid_sign
cargo run --example encrypt_file
cargo run --example seed_tree
```

## Highlights

- **Constant-time discipline**: internal CT review sweep complete; timing tests in CI; verification hygiene on Ed25519/Falcon/Ed448 paths
- **Test-evidence depth**: 500+ lib tests, property tests, differential tests, NTRU Prime + Falcon KATs, malformed-input and adversarial suites, ASan/TSan, fuzz smoke — 20+ CI jobs on every push
- **Correct statistics**: entropy analysis uses size-aware thresholds and pooled validation (small samples *cannot* meet large-sample bounds — the math is in the test docs)
- **Memory hygiene**: zeroizing types, `mlock` support, secure cleanup paths
- **WASM**: the entire SDK compiles to `wasm32-unknown-unknown` — the demo is proof

## Recovery phrases

BIP-39-shaped Unicode-codepoint phrases — **not BIP-39 compatible** (curated codepoint list, SHA-3-256 checksum). Strict NFKC safety: rejects ZWJ, variation selectors, combining marks, BIDI marks. 12-word (128-bit) or 24-word (256-bit); custom alphabets with a 128-bit floor.

```rust
use origin_crypto_sdk::recovery::unicode_cipher::{
    encode_phrase, decode_phrase, PhraseLength, UnicodeWordlist,
};
let phrase = encode_phrase(&entropy, &UnicodeWordlist::default(), PhraseLength::Words24)?;
assert_eq!(decode_phrase(&phrase, &UnicodeWordlist::default())?, entropy);
```

## Threat modeling & duress

For users facing legal compulsion or physical coercion: **no duress/self-destruct primitive, by deliberate design** (18 U.S.C. §2232 risk). Application-level patterns — operational deniability, distinguishable decoy vaults, jurisdictional matrix — in [`docs/duress-pattern.md`](docs/duress-pattern.md).

## Module map

```
signing::    Ed25519, Falcon, SLH-DSA, ML-DSA + hybrid composition
kem::        X25519, NTRU Prime, ML-KEM + hybrid KEM combiner
aead::       XChaCha20-Poly1305, Serpent CBC, streaming
pqc::        raw primitives: falcon512/1024, ed448, curve41417, ntru_prime, slhdsa, mldsa
seed::       hierarchical seed derivation          recovery::  Unicode phrase codec
drbg::       ChaCha20-DRBG (auto-reseed)           stealth::   stealth addresses + PoW
entropy::    structural entropy analysis           blob::      seed-blob storage (v1/v2)
ec_schnorr:: secp256k1 Schnorr (deterministic)     ocra::      OCRA challenge-response
```

Full annotated map in the rendered docs. The `internal`/`primitives` layers are crate-private — see `docs/ARCHITECTURE.md` for layer rules.

## Requirements

- **MSRV**: Rust 1.95 · **Platform**: Linux, macOS, Windows (`getrandom`)
- **License**: Apache-2.0

## Links

- [Documentation](https://docs.rs/origin-crypto-sdk) · [Security Notes](SECURITY.md) · [Stability Matrix](STABILITY.md) · [Changelog](CHANGELOG.md)
- [Research Note: cryptanalysis evidence](docs/RESEARCH-NOTE-cryptanalysis-evidence.md) · [Audit package](AUDIT_PACKAGE.md) · [Duress patterns](docs/duress-pattern.md)
- [Migration Guide](MIGRATION.md) · [Maintenance Policy](docs/MAINTENANCE_POLICY.md)

# Migration Guide

This document helps you move between major versions of `origin-crypto-sdk`.

## 0.3 → 0.4

The 0.4 release focused on API clarity, error handling, and security hardening.
Most code will compile and run unchanged, but the following patterns are now
preferred.

### 1. Use the prelude for common operations

**Before** (0.3):
```rust
use origin_crypto_sdk::signing::{
    Ed25519Blake3, Ed25519Falcon1024, HybridSigningKeyBundle,
};
use origin_crypto_sdk::chacha20_blake3;
```

**After** (0.4):
```rust
use origin_crypto_sdk::prelude::*;
```

The prelude now exposes ~15 curated items: `HybridSigningKeyBundle`,
`ChaCha20Blake3`, `Argon2id`, `Argon2idBuilder`, `hkdf_sha3_256`,
`derive_subkeys`, `hmac_sha3_256`, `blake3`, `sha3`, `ChaCha20Drbg`,
`SeedHandle`, `Seed`, `XNonce`, `CNonce`, `CryptoError`, `Result`.

Low-level PQC types (`FalconPrivateKey`, `MldsaPublicKey`, `ed448::SigningKey`)
are no longer in the prelude. Access them via their module:
```rust
use origin_crypto_sdk::pqc::falcon1024::FalconPrivateKey;
use origin_crypto_sdk::pqc::ed448::SigningKey;
```

### 2. Use newtype wrappers for keys and nonces

**Before** (0.3):
```rust
let seed: &[u8; 32] = &[0x42; 32];
let nonce: &[u8; 24] = &[0xAB; 24];
let ciphertext = ChaCha20Blake3::encrypt(seed, nonce, plaintext, aad)?;
```

**After** (0.4):
```rust
let seed = Seed::from([0x42u8; 32]);
let nonce = XNonce::from([0xABu8; 24]);
let ciphertext = ChaCha20Blake3::encrypt(seed.as_bytes(), nonce.as_bytes(), plaintext, aad)?;
```

The newtypes catch length mismatches at construction time:
```rust
let bad = Seed::from_slice(&[0u8; 16]); // Err(InvalidKeyLength { expected: 32, got: 16 })
```

The `&[u8]` API still works for backward compatibility.

### 3. Match on structured error variants

**Before** (0.3):
```rust
match err {
    CryptoError::InvalidKey(msg) => {
        if msg.contains("32 bytes") { /* ... */ }
    }
    _ => {}
}
```

**After** (0.4):
```rust
match err {
    CryptoError::InvalidKeyLength { algorithm, expected, got } => {
        eprintln!("{algorithm} needs {expected} bytes, got {got}");
    }
    _ => {}
}
```

The new structured variants let you write real logic, not string parsing.

### 4. Use the builder for custom Argon2id parameters

**Before** (0.3):
```rust
let key = Argon2id::derive_key(password, &salt, false)?; // 64 MiB, 4 iter
let key = Argon2id::derive_key(password, &salt, true)?;  // 64 MiB, 8 iter
```

**After** (0.4):
```rust
let key = Argon2idBuilder::new()                  // defaults
    .memory_kib(32768)                             // 32 MiB
    .iterations(3)
    .parallelism(4)
    .derive(password, &salt)?;
```

The preset `Argon2id::derive_key()` still works for the common case.

### 5. Hybrid verify is now constant-time

**Behavior change**: Hybrid verification paths now use
`ConstantTimeEq` for hash comparisons. This is a security improvement
that should be invisible to callers. Verify signatures that used to
return `Err` will still return `Err`; valid signatures will still pass.

### 6. Test utilities (new)

If you write tests against the SDK, enable the `test-utils` feature:

```toml
[dev-dependencies]
origin-crypto-sdk = { version = "0.4", features = ["test-utils"] }
```

```rust
use origin_crypto_sdk::test_utils::{deterministic_seed, deterministic_key};

let seed = deterministic_seed(42);
let key = deterministic_key(7);
```

### 7. Removed: `signing::HybridKem`

The 0.3 `HybridKem` stub that returned zeros is **removed in 0.4**.
Use the `signing::hybrid::Ed25519Falcon1024` or the KEM API in
`pqc::ntru_prime` instead.

## 0.4 → 0.5.1

This transition rolls up the 0.4.1 module reorganization with the 0.5.1 adoption of the new `recovery::unicode_cipher` module. Most code that imports via the prelude continues to compile unchanged; the following patterns matter for upgraders.

### 1. Internal utilities hidden from docs

Modules that lived at the crate root in 0.4.0 are now `#[doc(hidden)]` in 0.5.1 — they still compile and are accessible, but no longer appear in the public docs.rs surface:

- `entropy` — entropy quality analysis
- `mmr` — Merkle Mountain Range
- `error_correction` — Reed-Solomon
- `siphash` — SipHash keyed hash
- `compression` — zlib wrapper
- `blob` — encrypted blob storage
- `primitives` — low-level hashes/ciphers
- `internal` — internal utilities

If you depend on any of these directly, the import path is unchanged; they simply do not show up in `cargo doc`.

### 2. PQC types moved out of crate root

Low-level PQC types that were re-exported at the crate root in 0.4.0 are no longer there in 0.5.1. Access them via their module:

**Before** (0.4):
```rust
use origin_crypto_sdk::Falcon1024PrivateKey;
use origin_crypto_sdk::Falcon512PrivateKey;
use origin_crypto_sdk::FalconSignature;
```

**After** (0.5.1):
```rust
use origin_crypto_sdk::pqc::falcon1024::FalconPrivateKey;
use origin_crypto_sdk::pqc::falcon512::FalconPrivateKey;
use origin_crypto_sdk::pqc::falcon1024::FalconSignature;
```

The signing OOP API (`signing::postquantum::*`) and `signing::hybrid::HybridSigningKeyBundle` are unchanged.

### 3. signing_legacy removal deferred to 0.6

The `signing_legacy` module and the three crate-root re-exports (`HybridSignatureOutput`, `HybridSigningKey`, `HybridVerifyingKey`) were originally deprecated in 0.4.0 with a promise of removal in 0.5. That removal is now deferred to 0.6 — they remain available in 0.5.1, and `#[deprecated(since = "0.5.1")]` is now attached. New code should keep using `signing::hybrid::HybridSigningKeyBundle`.

## Non-breaking additions

- **`recovery::unicode_cipher` (new module)** — a BIP-39-shaped recovery phrase codec using Unicode codepoints instead of an English wordlist. See the [module docs](https://docs.rs/origin-crypto-sdk/latest/origin_crypto_sdk/recovery/unicode_cipher/index.html) for the full quick-start. Phrases are **deliberately NOT BIP-39 compatible** — the wordlist is curated Unicode and the checksum is SHA-3-256 (not SHA-256).
- **`origin-crypto` CLI binary fix**: the standalone CLI no longer fails to compile during `cargo publish` — fixed an unresolved `crate::internal::getrandom` import (bin target has its own `crate::` root) and a borrow-after-move in `cmd_decrypt`.
- **`unicode-normalization = "=0.1.25"`** newly required dependency for the recovery module's NFKC canonical-form validation.

## 0.5.1 → 0.5.2

This is a doc-only patch release. **No API changes.** No code changes are required for upgraders.

If you were seeing red `?` doc-test indicators in the 0.5.1 docs.rs output for any of the modules below, they are resolved in 0.5.2:

- `drbg::otp` — module-level Quick-start example was using the pre-0.4.1 path `origin_crypto_sdk::otp::{hotp, totp}` (and missing the `HashAlgorithm` import).
- `seed::gen` — module-level Quick-start example was using the pre-0.4.1 path `origin_crypto_sdk::seed_gen::{self, SeedVariant}`.
- `signing::hybrid` — both Quick-Start examples (the Falcon+Ed25519 hybrid and the KDF construction `Ed25519ChaCha20Blake3Sha3_256`) were using the pre-0.4.1 path `origin_crypto_sdk::hybrid::...`.
- (lib root) the "single primitive" example was failing because both `Ed25519Signer::from_seed(...)` and `Falcon1024Signer::from_seed(...)` return `Result<Self>`; the example treated `Result` as `Signer` and tried to call `.sign(...)` on it.

## 0.2 → 0.3

### 1. Signing module restructured

**Before** (0.2):
```rust
use origin_crypto_sdk::signing::{
    Ed25519Signer, Falcon1024Signer, HybridSigningKey,
};
```

**After** (0.3+):
```rust
use origin_crypto_sdk::signing::classical::Ed25519Signer;
use origin_crypto_sdk::signing::postquantum::Falcon1024Signer;
use origin_crypto_sdk::signing::hybrid::HybridSigningKey;
```

The flat `signing::*` re-exports are still available via
`signing_legacy` for one release cycle, but new code should use the
nested paths.

### 2. Falcon-512 keygen return order

Note: `pqc::falcon512::generate_keypair()` returns `(sk, pk)` (the
original Falcon-512 native API order), while `pqc::falcon1024`,
`pqc::mldsa`, and `pqc::slhdsa` return `(pk, sk)`.

This inconsistency is a known issue (see #TODO). To avoid it, use the
high-level `signing::postquantum::Falcon512Signer::from_seed` which
handles the order internally.

## Pre-0.2

If you're upgrading from pre-0.2, see the git history. Major changes
include the introduction of `HybridSigningKey` (replacing the
inline `(ed_sk, falcon_sk)` pair) and the addition of `pqc::ed448`
(distinct from the existing `pqc::curve41417::ed41417`).

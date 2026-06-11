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

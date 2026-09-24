# Contributing to origin-crypto-sdk

Thank you for your interest in improving the Origin Cryptographic SDK.
This document covers everything you need to get started.

## Quick Start

```bash
# Build
cargo build

# Run all tests (unit + integration + golden vectors)
cargo test --lib
cargo test --test integration_tests
cargo test --test hybrid_golden_vectors
cargo test --test proptest_crypto

# Run with all optional features enabled
cargo test --all-features

# Run examples
cargo run --example hybrid_sign
cargo run --example encrypt_file
cargo run --example kdf_derive
cargo run --example seed_tree
```

## Development Setup

- **MSRV**: Rust 1.85 (see `Cargo.toml` `rust-version`)
- **Edition**: 2021
- **Recommended**: latest stable Rust toolchain

## Running Specific Test Suites

| Suite | Command | What it covers |
|-------|---------|----------------|
| Unit tests | `cargo test --lib` | 226 module-level tests |
| Integration | `cargo test --test integration_tests` | Cross-module workflows |
| Golden vectors | `cargo test --test hybrid_golden_vectors` | Known-answer determinism |
| Property tests | `cargo test --test proptest_crypto` | Randomized invariants (proptest) |
| Rigorous hybrid | `cargo test --test hybrid_rigorous` | Edge cases, timing, tamper resistance |
| Benchmarks | `cargo bench` | Performance (requires `slh-dsa`, `ml-dsa` features) |

## Code Style

```bash
# Format check
cargo fmt --check

# Lint
cargo clippy --all-features -- -D warnings
```

All PRs must pass `cargo fmt` and `cargo clippy` with no warnings.

> **Note on `deprecated` warnings**: The `signing::hybrid` module keeps a
> deprecated `hkdf_combine` compatibility shim (audit CC-3) — use
> `kdf::hkdf::hkdf_sha3_256(ikm, salt, info, out)` in new code.
> The `legacy_shim` wildcard re-export also emits deprecation warnings
> by design during the pre-1.0 window.

## Project Structure

```
src/
  lib.rs              -- crate root, feature-gated module re-exports
  error.rs            -- CryptoError enum (thiserror)
  types.rs            -- Seed, XNonce, CNonce newtypes
  prelude.rs          -- curated re-exports (~15 items)
  chacha20_blake3.rs  -- ChaCha20-BLAKE3 committing AEAD
  aead/               -- XChaCha20-Poly1305 AEAD (+ symmetric, streaming)
  kdf/                -- HKDF-SHA3-256, Argon2id, MAC vocabulary
  signing/            -- classical, postquantum, hybrid constructions
    hybrid/           -- combinators, constructions, kdf, bundle, cache
  pqc/                -- Falcon-1024, Falcon-512, ML-DSA, SLH-DSA, Ed448, Ed41417, NTRU Prime
  seed/               -- SeedHandle + hierarchical derivation (gen.rs)
  entropy.rs          -- Entropy quality analysis
  blob.rs             -- Seed-blob storage format (v1/v2)
  error_correction.rs -- Reed-Solomon over GF(2^8)
  compression.rs      -- DEFLATE helpers (used by compressed.rs)
  compressed.rs       -- compress-then-encrypt container
  siphash.rs          -- SipHash compute-hardener (entropy pipeline)
  stealth/            -- Stealth address utilities
  internal/           -- subtle (CT eq), hmac, hkdf, secp256k1, mlock, getrandom
examples/             -- runnable examples
tests/                -- integration, golden vectors, proptest, rigorous hybrid
benches/              -- criterion benchmarks
docs/                 -- ARCHITECTURE.md (layer rules), DESIGN_AUDIT.md
```

### Architectural layer rules (enforced)

`internal/` and `primitives/` are `pub(crate)` — **not** `#[doc(hidden)]
pub`. The dependency direction is one-way:

```
public façade (lib.rs, prelude) → composition (aead, compressed, signing)
  → schemes (pqc, ec_schnorr, x25519) → primitives → internal (vendored/unsafe)
```

- Never add `use crate::internal::…` outside `src/` internals — reach
  deterministic RNG through `drbg::ChaCha20Rng` and OS entropy through
  `fill_random`. The binary (`src/bin/`) follows the same rule.
- Full rules: `docs/ARCHITECTURE.md`. Design-smell checklist used in
  review: `docs/DESIGN_AUDIT.md`.

## Making Changes

### Adding a New Algorithm

1. Create a module under `src/pqc/` or `src/signing/`
2. Feature-gate it in `Cargo.toml` if it adds dependencies
3. Add `pub mod` in `src/lib.rs` behind the feature gate
4. Add module-level docs following the pattern:
   - Summary
   - "When to use"
   - Code example
   - Security notes
   - "See also" links
5. Add at least one test in the module (`#[cfg(test)] mod tests`)
6. Add a golden vector if the algorithm is deterministic

### Error Handling

Use structured error variants from `CryptoError`:

```rust
// For length mismatches:
return Err(CryptoError::InvalidKeyLength {
    algorithm: "Algorithm-Name",
    expected: 32,
    got: bytes.len(),
});

// For generic failures:
return Err(CryptoError::InvalidKey("descriptive message".into()));
```

### Constant-Time Requirements

All hash/signature comparisons in `verify()` functions MUST use
`ConstantTimeEq` from `crate::internal::subtle`:

```rust
use crate::internal::subtle::ConstantTimeEq;
if !bool::from(sig.hash.ct_eq(&expected)) {
    return Err(CryptoError::AuthenticationFailed);
}
```

Never use `==` or `!=` for comparing secret-derived values.

Sites whose constant-time behavior needs verification before 1.0 are
marked `// CT-REVIEW(12.1)` — do not remove the marks; Phase 12.1 of
`ROADMAP_1_0_0.md` resolves them. If you add a site with secret-dependent
control flow, either use constant-time primitives or add the mark.

### Panic + `try_*` pairs

Functions that can fail on OS entropy or allocation expose a fallible
`try_*` variant; the infallible form delegates to it and documents a
`# Panics` contract. New fallible APIs follow the same pattern:

```rust
pub fn generate_key() -> [u8; 32] {
    Self::try_generate_key().expect("OS entropy failure")
}
/// # Panics — see `generate_key`.
pub fn try_generate_key() -> Result<[u8; 32]> { /* ... */ }
```

### State discipline

Mutable state lives inside named types (`SeedHandle`, `ChaCha20Drbg`,
`BundleCache`) — no bare `static`/`Mutex` at module scope without a
documented reason. Process-global convenience state is allowed only as
a thin layer over an ownable value type.

### Zeroize

All private key types MUST implement `Drop` with zeroize:

```rust
impl Drop for MyPrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

## Commit Conventions

- Use present tense: "add X" not "added X"
- Prefix with scope when clear: "error: add InvalidKeyLength variant"
- One logical change per commit

## Pull Request Process

1. Ensure all tests pass: `cargo test --all-features`
2. Ensure clippy is clean: `cargo clippy --all-features -- -D warnings`
3. Ensure docs build: `cargo doc --all-features`
4. Update CHANGELOG.md with your change under `[Unreleased]`
5. If adding a public API, add a doc-comment with example code

## Security Reporting

**Do NOT report security vulnerabilities via GitHub issues.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

By contributing, you agree that your contributions will be licensed under
the same license as the project (see LICENSE file).

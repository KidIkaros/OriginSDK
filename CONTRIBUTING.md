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

> **Note on `deprecated` warnings**: The `signing_legacy` module is
> marked `#[deprecated]` and will be removed in 0.5. Internal tests
> in `src/signing_legacy.rs` exercise the deprecated API and will
> emit `deprecated` lint warnings during `cargo test`. These are
> intentional — the tests verify the deprecated path still works
> during the deprecation window. They do not indicate a problem.

## Project Structure

```
src/
  lib.rs              -- crate root, feature-gated module re-exports
  error.rs            -- CryptoError enum (thiserror)
  types.rs            -- Seed, XNonce, CNonce newtypes
  prelude.rs          -- curated re-exports (~15 items)
  chacha20_blake3.rs  -- ChaCha20-BLAKE3 committing AEAD
  aead.rs             -- XChaCha20-Poly1305 AEAD
  kdf/                -- HKDF-SHA3-256, Argon2id
  signing/            -- classical, postquantum, hybrid constructions
  pqc/                -- Falcon-1024, Falcon-512, ML-DSA, SLH-DSA, Ed448, Ed41417, NTRU Prime
  seed.rs             -- Hierarchical seed derivation
  entropy.rs          -- DRBG (ChaCha20-based)
  blob.rs             -- Binary large object compression
  stealth_*.rs        -- Stealth address utilities
  internal/           -- subtle (CT eq), hmac, secp256k1
examples/             -- 4 runnable examples
tests/                -- integration, golden vectors, proptest, rigorous hybrid
benches/              -- criterion benchmarks
```

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

# Independent Review Package

> **Status**: Prepared for external review. No independent audit has been
> commissioned yet. This document defines the scope, inventory, and
> residual risks for a reviewer to evaluate.

## 1. Audit Scope

### 1.1 Custom cryptographic implementations (highest priority)

| Component | Source | Files | Risk |
|-----------|--------|-------|------|
| NTRU Prime (sntrup761) | Custom, NIST-compatible encoding (Phase 11) | `src/pqc/ntru_prime/` | Medium — NIST wire-compatible, needs expert review |
| Ed41417 (Curve41417) | Custom, based on Bernstein et al. CHES 2014 | `src/pqc/curve41417/` | High — custom ECC |
| Native ChaCha20-Poly1305 | Custom, RFC 8439 reference | `src/primitives/chacha20.rs`, `src/primitives/chacha20poly1305.rs` | Medium — standard algorithm, custom impl |
| Native Poly1305 | Custom, RFC 8439 §2.5 | `src/primitives/poly1305.rs` | Medium — standard algorithm, custom impl |
| ChaCha20-DRBG | Custom | `src/drbg/` | Medium — custom DRBG |
| SipHash-c-d | Custom | `src/siphash.rs` | Low — compute hardener, not security boundary |
| secp256k1 arithmetic | Custom | `src/ec_schnorr.rs` | High — custom ECC arithmetic |
| Hybrid KEM | Custom composition | `src/pqc/` | High — novel composition |
| Hybrid signing | Custom composition | `src/signing/hybrid.rs` | High — novel composition |
| Seed blob format | Custom | `src/blob.rs` | Medium — persistence format |
| Memory handling | Custom (mlock, zeroize) | `src/internal/zeroize.rs`, `src/seed/mod.rs` | Medium — unsafe code |

### 1.2 External dependencies (review integration, not implementation)

| Component | Crate | Version | Notes |
|-----------|-------|---------|-------|
| XChaCha20-Poly1305 (AEAD) | `chacha20poly1305` | `=0.10.1` | Pinned, battle-tested |
| Argon2id (KDF) | `argon2` | `=0.5.3` | Pinned, battle-tested |
| SHA-2/SHA-3 | `sha2`, `sha3` | `=0.10.8`, `0.11` | Battle-tested |
| Falcon-512/1024 | `falcon-rs` | `0.2.5` | FIPS 206, PQC signature |
| Ed25519 | `ed25519-dalek` | `2` | Battle-tested |
| Ed448 | `ed448-goldilocks` | `0.14.0-pre.13` | Pre-release |
| BLAKE3 | `blake3` | `1.8` | Battle-tested |
| Reed-Solomon | Custom | `src/error_correction.rs` | Custom impl |

### 1.3 Unsafe code review targets

- `src/internal/zeroize.rs` — memory zeroization
- `src/seed/mod.rs` — mlock/munlock syscalls
- `src/internal/getrandom.rs` — OS entropy syscall wrappers
- Any SIMD/AVX2 code paths (if `pqc-simd` feature is enabled)

## 2. Threat Model

### 2.1 Attacker capabilities assumed

- Can observe ciphertexts, signatures, and public keys
- Can submit chosen plaintexts for encryption
- Can submit chosen ciphertexts for decryption
- Can observe timing of operations
- Cannot access private keys or seeds directly
- Cannot modify the SDK source code at rest
- May be a legitimate user with limited access (insider threat)

### 2.2 Security properties verified

| Property | Evidence |
|----------|---------|
| AEAD confidentiality + integrity | RFC 8439 KAT, differential vs RustCrypto, 14 adversarial tests |
| Hybrid signature unforgeability | 11 hybrid security tests, 14 adversarial tests |
| Domain separation | Cross-domain splicing tests fail |
| Key derivation determinism | Cache/non-cached consistency test |
| Nonce sensitivity | Different nonces produce different ciphertext |
| Key sensitivity | Different keys produce different ciphertext |
| AAD binding | AAD stripping/modification tests fail |
| Truncation resistance | Truncated ciphertext/tag rejected |
| No panic on malformed input | 20 malformed-input tests, 0 panics |
| No gross timing leaks | 4 timing tests (smoke, with stated limits) |

### 2.3 Properties NOT verified (require external review)

- Constant-time execution (timing tests are smoke tests only)
- Side-channel resistance (power, EM, cache timing)
- Formal security proof of hybrid composition
- Resistance to fault injection
- Memory safety of unsafe code (Miri not yet run)
- Long-duration fuzzing (only 60s smoke runs in CI)

## 3. Test Coverage Summary

| Test Suite | Tests | Category |
|-----------|-------|----------|
| `known_answer_vectors.rs` | 20 | KAT vectors (RFC 8439, draft-irtf-xchacha, SipHash) |
| `differential_tests.rs` | 8 | Differential vs RustCrypto chacha20poly1305 |
| `hybrid_security.rs` | 11 | Hybrid signature security properties |
| `malformed_input.rs` | 20 | Parser robustness, no panics |
| `rng_and_cache.rs` | 20 | RNG failure injection, cache lifecycle/concurrency |
| `timing_tests.rs` | 4 | Constant-time smoke tests (with stated limits) |
| `adversarial.rs` | 14 | Self-adversarial review (forge, splice, downgrade) |
| `hybrid_rigorous.rs` | existing | Rigorous hybrid tests |
| `proptest_crypto.rs` | existing | Property-based tests |
| `integration_tests.rs` | existing | Integration tests |
| Unit tests (in-crate) | existing | Per-module unit tests |
| **Total new tests** | **97** | Phase 6-8 |

## 4. Residual Risks (Accepted)

| Risk | Severity | Mitigation | Status |
|------|----------|------------|--------|
| No independent audit | Critical | This package prepared for review | Pending |
| Custom NTRU Prime impl | Medium | NIST-compatible encoding (Phase 11), needs expert review | Pending |
| Custom Ed41417 impl | High | Based on published paper, needs expert review | Pending |
| Custom secp256k1 arithmetic | High | Previous defects fixed, needs expert review | Pending |
| No Miri analysis | Medium | Unsafe code is minimal and scoped | Deferred |
| Timing tests are smoke-only | Medium | Stated limits documented | Accepted |
| Long-duration fuzzing not run | Medium | 60s smoke in CI, sustained deferred | Deferred |
| `rand 0.8.5` unsound advisory | Low | Requires custom global logger (not used) | Accepted |
| `crypto-bigint 0.7.3` yanked | Low | Transitive via pre-release ed448-goldilocks | Accepted |
| No Falcon/NTRU KAT vectors | Resolved | NIST-compatible encoding integrated (Phase 11) | Done |

## 5. Reviewer Instructions

1. **Read** `SECURITY.md` for the implementation inventory and known properties.
2. **Read** `VIABILITY_ASSESSMENT.md` for the full assessment context.
3. **Review** custom implementations listed in §1.1, focusing on:
   - Correctness of arithmetic (NTRU Prime, Ed41417, secp256k1)
   - Constant-time behavior of comparison and conditional operations
   - Key generation, signing, and verification paths
   - Hybrid composition binding (message, key, domain, algorithm)
4. **Review** unsafe code listed in §1.3 for memory safety.
5. **Run** the full test suite: `cargo test --all-targets`
6. **Run** sanitizers: `cargo +nightly test --lib --target-sanitizer=address`
7. **Attempt** to break the threat model beyond the self-adversarial tests.
8. **Document** each finding with: severity, exploitability, affected data,
   evidence, mitigation, and recommended release target.

## 6. Reproduction

```bash
# Full test suite
cargo test --all-targets

# Phase 6-8 test suites
cargo test --test known_answer_vectors
cargo test --test differential_tests
cargo test --test hybrid_security
cargo test --test malformed_input
cargo test --test rng_and_cache -- --test-threads=2
cargo test --test timing_tests
cargo test --test adversarial -- --test-threads=1

# Supply-chain checks
cargo audit
cargo deny check

# Sanitizers (nightly)
cargo +nightly test --lib -- -Z sanitizer=address
cargo +nightly test --lib -- -Z sanitizer=undefined
```

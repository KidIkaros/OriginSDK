# Independent Review Package

> **Status**: Prepared for external review. No independent audit has been
> commissioned yet. This document defines the scope, inventory, and
> residual risks for a reviewer to evaluate.

## 1. Audit Scope

### 1.1 Custom cryptographic implementations (highest priority)

| Component | Source | Files | Risk |
|-----------|--------|-------|------|
| NTRU Prime (sntrup761) | Custom, NIST wire format + KEM hashing | `src/pqc/ntru_prime/` | Medium — 100/100 official KAT vectors byte-exact (pk/sk/ct/ss); needs expert review |
| NTRU Prime migration codec | Custom, ported 0.6.x Rq decoder | `src/pqc/ntru_prime/migrate.rs` | Low — decode/re-encode only, test-verified |
| Ed41417 (Curve41417) | Custom, based on Bernstein et al. CHES 2014 | `src/pqc/curve41417/` | High — custom ECC |
| secp256k1 arithmetic | Custom | `src/internal/secp256k1/` (+ `src/ec_schnorr.rs`) | High — custom ECC arithmetic; branchless rewrite in Phase 12.1, needs codegen verification |
| Native ChaCha20-Poly1305 | Custom, RFC 8439 reference | `src/primitives/chacha20.rs`, `src/primitives/chacha20poly1305.rs` | Medium — standard algorithm, custom impl |
| Native Poly1305 | Custom, RFC 8439 §2.5 | `src/primitives/poly1305.rs` | Medium — standard algorithm, custom impl |
| ChaCha20-DRBG | Custom | `src/drbg/` | Medium — custom DRBG |
| Reed-Solomon (GF(2⁸)) | Custom | `src/error_correction.rs` | Medium — custom impl, branchless GF mul |
| SipHash-c-d | Custom | `src/siphash.rs` | Low — compute hardener, not security boundary |
| Hybrid signing | Custom composition | `src/signing/hybrid/` | High — novel composition (binding, domain separation) |
| Seed blob format | Custom | `src/blob.rs` | Medium — persistence format (v2 `ORGB`) |
| Compressed container | Custom | `src/compressed.rs` | Medium — chunked AEAD container |
| Memory handling | Custom (mlock, zeroize) | `src/internal/mlock.rs`, `src/internal/zeroize.rs`, `src/seed/` | Medium — unsafe code |
| Galois-field helpers | Custom | `src/error_correction.rs` | Low — branchless since Phase 12.1 |

> There is **no hybrid KEM construction** in this crate — the only
> compositions are hybrid *signing* and the compressed container. Earlier
> drafts of this document listed a "Hybrid KEM" row in error.
>
> **Standards posture:** non-NIST constructions in this crate are
> *deliberate* — see `SECURITY.md` §"Standards Posture" for the per-item
> rationale (e.g. committing AEAD, hybrid dual-algorithm robustness,
> alternate NTRU hash backends). Reviewers should evaluate deviations as
> design intent, not assume NIST-compatibility was the goal — while noting
> that custom implementations are unreviewed, not claimed superior.

### 1.2 External dependencies (review integration, not implementation)

| Component | Crate | Version | Notes |
|-----------|-------|---------|-------|
| XChaCha20-Poly1305 (AEAD) | `chacha20poly1305` | `=0.10.1` | Pinned, battle-tested |
| ChaCha20-BLAKE3 AEAD | `chacha20-blake3` | `=0.10.0` | Pinned; 0.10 fixed aarch64 NEON path |
| Argon2id (KDF) | `argon2` | `=0.5.3` | Pinned, battle-tested |
| SHA-2/SHA-3/SHAKE | `sha2`, `sha3` | `=0.10.8`, `0.11` | Battle-tested |
| Falcon-512/1024 | `falcon-rs` | `=0.2.5` | FIPS 206, upstream KATs pass |
| Ed25519 | `ed25519-dalek` | `2` | Battle-tested |
| X25519 | `x25519-dalek` | `=2.0.1` | Battle-tested |
| Ed448 | `ed448-goldilocks`, `ed448` | `=0.14.0-pre.15`, `0.5` | Pre-release |
| ML-KEM-768 | `ml-kem` | `=0.3.2` | FIPS 203, RustCrypto, optional |
| ML-DSA | `ml-dsa` | `0.1.0` | FIPS 204, optional |
| SLH-DSA | `slh-dsa` | `0.2.0-rc.5` | FIPS 205, optional, rc |
| BLAKE3 | `blake3` | `1.8` | Battle-tested |
| Skein | `skein` | `0.2` | |
| Serpent | `serpent` | `0.5` | |
| RNG | `rand`, `getrandom` | `=0.8.7`, `0.2` | rand pinned |
| Constant-time utils | `subtle` | `2.6.1` | |
| Compression | `flate2`, `zstd` | `1.0`, `0.13` | |
| NFKC validation | `unicode-normalization` | `=0.1.25` | Pinned |
| Parallelism | `rayon` | `1.11` | optional |
| KAT test DRBG (dev) | `aes` | dev-dep only | NIST AES-256-CTR replay |
| Property tests (dev) | `proptest` | `1.5` | dev-dep only |
| Benchmarks (dev) | `criterion` | `0.5` | dev-dep only |

### 1.3 Unsafe code review targets

- `src/internal/zeroize.rs` — memory zeroization (volatile writes)
- `src/internal/mlock.rs` — mlock/munlock syscall wrappers
- `src/internal/getrandom.rs` — OS entropy syscall wrappers
- `src/pqc/ntru_prime/rq.rs` — `round3_avx2` SIMD path + dispatch
- `src/x25519.rs` (test-only `drop_in_place`/`&*ptr` in zeroization tests)

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
| sntrup761 wire compatibility | **All 100 official NIST KAT vectors** — pk, sk, ct, and ss byte-exact via seeded DRBG replay (`tests/ntru_prime_kat.rs::kat_execution`) |
| sntrup761 decapsulation | 100/100 official vectors produce expected ss; cross-roundtrip on foreign keys |
| X25519 correctness | RFC 7748 §5.2/§6.1 vectors + Python-cryptography reference |
| Hybrid signature unforgeability | 11 hybrid security tests, 37 rigorous tests, 15 golden vectors, 14 adversarial tests |
| Domain separation | Cross-domain splicing tests fail |
| Key derivation determinism | Cache/non-cached consistency test |
| Nonce sensitivity | Different nonces produce different ciphertext |
| Key sensitivity | Different keys produce different ciphertext |
| AAD binding | AAD stripping/modification tests fail |
| Truncation resistance | Truncated ciphertext/tag rejected |
| No panic on malformed input | 20 malformed-input tests + 8 libFuzzer targets (60s CI smoke, no crashes) |
| No gross timing leaks | 6 timing tests incl. NTRU decap CCA boundary + Schnorr key-density (smoke, with stated limits) |
| 0.6.x key migration | Ported decoder roundtrips; migrated keypair decapsulates end-to-end |

### 2.3 Properties NOT verified (require external review)

- Constant-time execution (timing tests are smoke tests; the Phase 12.1
  branchless rewrite removed known secret-dependent branches but codegen
  was not verified — see `docs/CONSTANT_TIME.md`)
- Side-channel resistance (power, EM, cache timing)
- Formal security proof of hybrid signing composition
- Resistance to fault injection
- Memory safety of unsafe code (Miri not yet run)
- Sustained fuzzing (CI runs 60s/target smoke; 24h+ deferred to hosted
  infrastructure such as OSS-Fuzz — see `ROADMAP_1_0_0.md` 12.2)
- Falcon external KAT vectors (NIST FIPS 206 ACVP vectors not yet
  published; `falcon-rs` passes NIST KATs upstream; our internal
  `falcon_kat.rs` covers FIPS 206 structural cases)

## 3. Test Coverage Summary

455 lib unit tests + 269 integration tests across 15 binaries:

| Test Suite | Tests | Category |
|-----------|-------|----------|
| `ntru_prime_kat.rs` | 17 | **Official NIST sntrup761 KAT execution** — all 100 vectors, pk/sk/ct/ss byte-exact (default SHA-2 backend only) |
| `falcon_kat.rs` | 20 | FIPS 206 structural KAT cases |
| `known_answer_vectors.rs` | 20 | RFC 8439, draft-irtf-xchacha, SipHash |
| `differential_tests.rs` | 8 | Differential vs RustCrypto chacha20poly1305 |
| `x25519_key_agreement.rs` | 5 | RFC 7748 vectors, low-order rejection |
| `hybrid_security.rs` | 11 | Hybrid signature security properties |
| `hybrid_rigorous.rs` | 37 | Rigorous hybrid tests |
| `hybrid_golden_vectors.rs` | 15 | Golden wire vectors |
| `malformed_input.rs` | 20 | Parser robustness, no panics |
| `rng_and_cache.rs` | 20 | RNG failure injection, cache lifecycle/concurrency |
| `timing_tests.rs` | 6 | Constant-time smoke tests (with stated limits) |
| `adversarial.rs` | 14 | Self-adversarial review (forge, splice, downgrade) |
| `fuzz_like_testing.rs` | 13 | Deterministic fuzz-shaped inputs |
| `proptest_crypto.rs` | 30 | Property-based tests |
| `integration_tests.rs` | 33 | Integration tests |
| Unit tests (in-crate) | 455 | Per-module unit tests |

**Fuzz targets (libFuzzer, `fuzz/`):** `fuzz_chacha40`,
`fuzz_encrypt_decrypt`, `fuzz_hybrid_verify`, `fuzz_kdf`,
`fuzz_reed_solomon`, `fuzz_ntru_prime`, `fuzz_falcon`, `fuzz_blob` —
all run in CI as a 60s/target smoke; fixed key material is hoisted out of
the fuzz loop (`fuzz_falcon` ≈52k runs/smoke).

## 4. Residual Risks (Accepted)

| Risk | Severity | Mitigation | Status |
|------|----------|------------|--------|
| No independent audit | Critical | This package prepared for review | Pending |
| Custom NTRU Prime impl | Medium | 100/100 official KAT vectors byte-exact (Phase 12.3/4); two spec deviations found & fixed | KAT-verified; still needs expert review |
| Custom Ed41417 impl | High | Based on published paper | Pending — needs expert review |
| Custom secp256k1 arithmetic | High | Secret-dependent branches eliminated (Phase 12.1 branchless rewrite); previous defects fixed | Pending — needs codegen verification or `k256` substitution review |
| No Miri analysis | Medium | Unsafe code is minimal and scoped | Deferred |
| Timing tests are smoke-only | Medium | 6 tests incl. CCA boundary; limits in `docs/CONSTANT_TIME.md` | Accepted |
| Long-duration fuzzing not run | Medium | 60s/target smoke in CI; sustained deferred to hosted infra (OSS-Fuzz) | Deferred |
| `rand` unsound advisory | Low | Requires custom global logger (not used) | Accepted |
| `crypto-bigint` yanked | Low | Transitive via pre-release ed448-goldilocks | Accepted |
| Pre-0.7 persisted keys stranded | Medium | `pqc::ntru_prime::migrate` + `origin-crypto migrate` CLI; Falcon regenerate+re-sign (`docs/MIGRATION_0_6_TO_0_7.md`) | Done |
| No NTRU KAT vectors | Resolved | Official 100-vector execution in-tree | Done |
| No Falcon external KAT | Medium | FIPS 206 ACVP vectors unpublished; `falcon-rs` passes upstream KATs | Deferred (external blocker) |

## 5. Reviewer Instructions

1. **Read** `SECURITY.md` for the implementation inventory and known properties.
2. **Read** `VIABILITY_ASSESSMENT.md` for the full assessment context.
3. **Read** `docs/ARCHITECTURE.md` (layer rules), `docs/CONSTANT_TIME.md`
   (CT posture + residual risks), `docs/DESIGN_AUDIT.md` (internal audit
   dispositions), `docs/MIGRATION_0_6_TO_0_7.md` (format migration),
   `docs/BENCHMARKS.md` (perf baseline), `FORMAT_REGISTRY.md` (wire formats).
4. **Review** custom implementations listed in §1.1, focusing on:
   - Correctness of arithmetic (NTRU Prime, Ed41417, secp256k1)
   - Constant-time behavior — especially the Phase 12.1 branchless
     secp256k1 rewrite (verify codegen, no residual secret-dependent
     control flow)
   - Key generation, signing, and verification paths
   - Hybrid composition binding (message, key, domain, algorithm)
   - NTRU CCA fallback path and `rho`-keyed failure derivation
5. **Review** unsafe code listed in §1.3 for memory safety.
6. **Run** the full test suite: `cargo test --all-targets`
7. **Run** sanitizers: `cargo +nightly test --lib --target-sanitizer=address`
8. **Attempt** to break the threat model beyond the self-adversarial tests.
9. **Document** each finding with: severity, exploitability, affected data,
   evidence, mitigation, and recommended release target.

## 6. Reproduction

```bash
# Full test suite (455 lib + 269 integration)
cargo test --all-targets

# Official NIST sntrup761 KAT execution (default backend only)
cargo test --test ntru_prime_kat

# Phase 6-8 test suites
cargo test --test known_answer_vectors
cargo test --test differential_tests
cargo test --test hybrid_security
cargo test --test malformed_input
cargo test --test rng_and_cache -- --test-threads=2
cargo test --test timing_tests
cargo test --test adversarial -- --test-threads=1

# Fuzz smoke (nightly + cargo-fuzz)
for t in fuzz_chacha40 fuzz_encrypt_decrypt fuzz_hybrid_verify fuzz_kdf \
         fuzz_reed_solomon fuzz_ntru_prime fuzz_falcon fuzz_blob; do
  timeout 120s cargo +nightly fuzz run "$t" -- -max_len=4096 -max_total_time=60
done

# Benchmarks
cargo bench --bench crypto_benchmarks --features slh-dsa,ml-dsa,pqc-simd,test-utils

# Key migration (0.6.x → 0.7.x)
origin-crypto migrate ntru-pk --key <1218-byte-hex|@file>
origin-crypto migrate ntru-sk --key <1600-byte-hex|@file>

# Supply-chain checks
cargo audit
cargo deny check

# Sanitizers (nightly)
cargo +nightly test --lib -- -Z sanitizer=address
cargo +nightly test --lib -- -Z sanitizer=undefined
```

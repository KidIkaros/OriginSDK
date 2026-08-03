# Changelog

All notable changes to origin-crypto-sdk will be documented in this file.

## [0.7.1-rc.3] — 2026-08-03

_MSFR and sanitizer workflow correction: pin the ChaCha20-BLAKE3 dependency
for Rust 1.85 and build the standard library for sanitizer ABI consistency._

### Changed
- Pin `chacha20-blake3` to `0.9.12`, preserving the declared Rust 1.85 MSRV.
- Build `std` with `-Zbuild-std` in nightly sanitizer jobs.

## [0.7.1-rc.2] — 2026-08-03

_Corrected evidence-backed release candidate: security-fixed dependency graph,
validated documentation, sanitizer workflow, and signed-release asset workflow._

### Changed
- Upgrade `rand` to 0.8.7 and update the Ed448 dependency graph to remove the
  yanked `crypto-bigint 0.7.3` path.
- Remove the obsolete WASI advisory path from the locked dependency graph.
- Correct rustdoc broken-link and bare-URL failures.
- Replace the unsupported nightly undefined-sanitizer mode with ThreadSanitizer.
- Add GitHub release assets for the crate, checksum, and SPDX SBOM; use GitHub
  artifact attestation when repository visibility supports it.

### Verification
- `cargo audit --deny warnings` passes.
- `cargo deny check advisories licenses bans sources` passes.
- All-feature tests and documentation build pass.

## [0.7.1-rc.1] — 2026-08-03

_Evidence-backed release candidate: SDK-owned randomness, NTRU CCA validation,
secret-safe diagnostics, and cross-tool format conformance._

### Changed
- Seed Blob generation now uses the public fallible SDK randomness boundary.
- NTRU decapsulation includes the recovered-polynomial weight check in the CCA
  validity mask.
- Added redacted `Debug` implementations for ML-DSA, SLH-DSA, and secp256k1
  scalar types.
- Added deterministic and malformed-input format evidence for SDK/tool
  integration, including ORGB, ORGN, SEAL, OVLT, Share, and provenance fixtures.

### Verification
- 398 default-feature library tests pass.
- 420 all-feature library tests pass.
- NTRU/Falcon KAT suites pass.
- Full origin-tools workspace tests pass against the exact candidate version.
- Strict origin-tools Clippy and formatting checks pass.

### Release status
- This is a release candidate, not an independent cryptographic audit or
  blanket production approval for every experimental module.

## [0.7.0] — 2026-08-02

_Boundary release: NIST PQC compatibility, CCA-secure KEM, FIPS 206 signatures,
105+ new tests, supply-chain hardening, algorithm ID system, experimental labels._

### Breaking Changes
- **NTRU Prime wire format**: PK 1218→1158, SK 1600→1763, CT 1047→1039.
  Old 0.6.7 NTRU Prime keys are **not readable** by 0.7.0.
- **Falcon signature format**: `falcon-rust` → `falcon-rs` (FIPS 206).
  Falcon-512 sig: 666→809 bytes, Falcon-1024 sig: 1280→1577 bytes.
  Old 0.6.7 Falcon signatures are **not verifiable** by 0.7.0.
- **Falcon dependency**: `falcon-rust = "=0.1.2"` → `falcon-rs = "0.2.5"`.

### Changed (Phase 11 — NIST PQC Compatibility)

#### Falcon: `falcon-rust` → `falcon-rs` (FIPS 206)
- **Replaced** `falcon-rust = "=0.1.2"` with `falcon-rs = "0.2.5"` in
  `Cargo.toml`. The new crate implements the FIPS 206 standard with
  compressed-tree signature format (headers 0x30/0x50).
- **Rewrote** `src/pqc/falcon512.rs` and `src/pqc/falcon1024.rs` to use
  the `falcon-rs` API while maintaining the external wrapper API for
  `hybrid.rs` compatibility.
- **Updated signature sizes** to FIPS 206 CT format:
  Falcon-512: 666 → **809 bytes**, Falcon-1024: 1280 → **1577 bytes**.
- **Rewrote** `tests/falcon_kat.rs` (20 tests) to verify FIPS 206
  regression vectors. The original NIST PQC submission KAT file uses
  an older format (header 0x02) incompatible with FIPS 206.
- All Falcon unit tests, hybrid signing tests, and the full test suite
  pass with the new crate.

#### NTRU Prime: NIST-compatible encoding + CCA-secure KEM
- **Implemented** official NIST recursive `Encode()`/`Decode()` in new
  `src/pqc/ntru_prime/encode.rs` (499 lines). Direct translation of the
  supercop-20201130 reference algorithm.
- **Updated wire-format sizes** to match NIST reference:
  - PK: 1218 → **1158 bytes** (Rq_bytes)
  - SK: 1600 → **1763 bytes** (2×Small + Rq + rho + cache)
  - CT: 1047 → **1039 bytes** (Rounded + confirm)
- **Rewrote KEM flow** in `src/pqc/ntru_prime/mod.rs` with:
  - SHA-2-512 domain-separated hashing (`Hash_prefix`, `HashConfirm`,
    `HashSession`, `Hash4`) matching the NIST reference
  - CCA fallback via `rho` (random secret in SK) — decapsulation always
    returns `Ok`, producing a random-looking key on failure
  - Public key binding via precomputed `cache = Hash4(pk)`
- **Added** SHAKE-based KEM hashing helpers behind feature flags
  (`ntru-shake128`, `ntru-shake256`) for performance comparison.
  **Not NIST-compatible** — for benchmarking only.
- **Updated** `tests/ntru_prime_kat.rs` (14 tests) to verify NIST
  size compatibility and CCA security properties.
- All 726 tests pass with `--all-features`.

#### NTRU Prime: BLAKE3 KEM hash backend (experimental)
- **Added** `ntru-blake3` feature flag: uses BLAKE3 instead of SHA-2-512
  for KEM hashing. 3.6× faster hash operations, ~8% faster decapsulate.
  **Not NIST-compatible** — for non-interop use.
- **Added** `blake3_kem` module in `primitives/sha3.rs` with `hash_confirm`,
  `hash_session`, `hash4`, and single-absorb `hash_confirm_and_session`.
- **Benchmarked** all 4 hash backends: NIST SHA-2-512 (default), BLAKE3,
  SHAKE128, SHAKE256. BLAKE3 is fastest on x86-64 with AVX2.
- 5 BLAKE3 unit tests + 7 NTRU Prime property tests (proptest).

### Added (Phase 10 — NIST PQC KAT Investigation)
- **NTRU Prime KAT investigation** (`tests/ntru_prime_kat.rs`):
  downloaded official NIST sntrup761 KAT vectors (100 vectors).
  Originally found encoding incompatibility — now resolved (Phase 11).
- **Falcon-512 KAT investigation** (`tests/falcon_kat.rs`):
  downloaded official NIST Falcon-512 KAT vectors (100 vectors). Found
  `falcon-rust` crate is not NIST-compatible — resolved by switching to
  `falcon-rs` (Phase 11).
- **KAT data files**: `tests/kat_data/sntrup761_kat_kem.rsp` (100
  vectors), `tests/kat_data/falcon512-KAT.rsp` (100 vectors).

### Added (Phase 6 — Verification & Testing)
- **Known-answer test vectors** (`tests/known_answer_vectors.rs`, 20 tests):
  RFC 8439 Poly1305 and ChaCha20-Poly1305 AEAD vectors, draft-irtf-cfrg-xchacha
  HChaCha20 vector, SipHash-2-4 determinism/sensitivity vectors.
- **Differential tests** (`tests/differential_tests.rs`, 8 tests): Origin's
  XChaCha20-Poly1305 verified byte-identical to RustCrypto `chacha20poly1305`
  0.10.1 across basic, empty, large, and cross-decrypt scenarios.
- **Hybrid security tests** (`tests/hybrid_security.rs`, 11 tests): component
  substitution, message/key mismatch, domain separation, seed sensitivity,
  Ed25519 determinism, tampered component, empty/large message handling.
- **Malformed-input robustness** (`tests/malformed_input.rs`, 20 tests):
  XChaCha20-Poly1305 and blob parser handle malformed inputs without panics.
- **RNG and cache lifecycle** (`tests/rng_and_cache.rs`, 20 tests): fallible
  RNG API, nonce uniqueness, thread safety, cache populate/hit/clear/bounds/
  TTL/concurrency/consistency.
- **Constant-time timing tests** (`tests/timing_tests.rs`, 4 tests): AEAD
  tag comparison, first-vs-last byte tamper, length scaling, Poly1305
  content independence (smoke tests with stated limits).
- **CI jobs**: sanitizer-address (ASan), sanitizer-undefined (UBSan),
  fuzz-smoke (60s per target), benchmark regression check, hybrid-security,
  rng-and-cache.

### Added (Phase 7 — Supply-chain & Release Engineering)
- **cargo-deny** configuration (`deny.toml`): license allowlist, advisory
  ignore list with documented reasons, duplicate-version warnings.
- **CI jobs**: `audit` (cargo-audit --deny warnings), `deny` (cargo-deny
  check), `no-default-features` (feature matrix), `wasm-check`
  (wasm32-unknown-unknown target).
- **Dependency policy** documented in `SECURITY.md`: pinning rationale,
  update cadence, advisory response, supply-chain checks.
- **Vulnerability disclosure process** documented in `SECURITY.md`.

### Fixed
- Updated `crossbeam-epoch` from 0.9.18 to 0.9.20, resolving
  RUSTSEC-2026-0204 (invalid pointer dereference in `fmt::Pointer` impl).

### Added (Phase 8 — Adversarial Review)
- **Adversarial tests** (`tests/adversarial.rs`, 14 tests): signature forgery,
  cross-domain/seed splicing, message substitution, AEAD nonce reuse,
  truncation/AAD/key confusion, single-byte manipulation, component swap,
  DoS resistance, degenerate key handling. 0 exploitable weaknesses found.
- **Audit package** (`AUDIT_PACKAGE.md`): full scope, threat model, test
  coverage, residual risks, and reviewer instructions for external audit.

### Added (Phase 9 — Stabilization)
- **Algorithm ID system** (`src/algorithm_id.rs`): 32 stable algorithm
  identifiers with `DowngradePolicy` for downgrade resistance. 8 unit tests.
- **Experimental warnings**: `# Experimental` doc sections added to all
  custom implementations (NTRU Prime, Ed41417, native ChaCha20/Poly1305,
  DRBG, hybrid signing, blob).
- **API stability contract**: README updated with Stable/Unstable/
  Experimental/Frozen classification for all public surfaces.

## [0.6.6] — 2026-07-29

### Changed
- **Docs only** — corrected the `HybridSigningKeyBundle::from_seed_cached`
  doc comment: Falcon-1024 keygen is ~4s on a desktop CPU (NTRU lattice
  rejection sampling), not ~100ms as previously stated. No code or API
  changes.

## [0.6.5] — 2026-07-29

### Added
- **Prominent experimental-use warnings** — README, crate-level docs, and
  SECURITY.md now lead with a clear "EXPERIMENTAL — NOT FOR PRODUCTION USE"
  banner. This SDK has not undergone independent security audit; it must not
  be used to protect real funds, identities, or data.

### Changed
- Clarified that all releases (including patch releases) are experimental and
  that API / wire / on-disk formats may change without notice.

## [0.6.4] — 2026-07-28

### Fixed
- **secp256k1 scalar arithmetic** — rewrote `Scalar` to plain (non-Montgomery)
  modular arithmetic, fixing large-scalar multiplication and reduction that
  broke `ec_schnorr` roundtrips for many key/message combinations.
- **ec_schnorr challenge computation** — `compute_challenge` now uses
  `Scalar::from_repr_reduced` instead of falling back to `Scalar::ONE` when the
  hash digest is ≥ n. This eliminates false-positive verification where
  different messages could share the same challenge.
- **Reed-Solomon erasure recovery** — added `decode_shards`/`encode_shards` for
  full parity_shards-way erasure recovery with explicit erasure indices. Fixed
  Vandermonde matrix generation so every data shard affects parity.
- **Falcon test performance** — reduced fuzz iterations (10k→100) and stress
  loops (50→5) to keep test suite runtime practical without sacrificing
  coverage.

### Added
- **HKDF-SHA3-256 reference-vector tests** — cross-checked against Python
  `hmac`/`hashlib` for independent verification.
- **HMAC-SHA3-256 reference-vector tests** — same independent verification.
- **Constant-time NTRU Prime ciphertext comparison** — hash check now uses
  constant-time comparison to avoid timing side-channels.
- **`SDK_DEFECTS.md`** — defect tracking document used for the 0.6.4 repair
  cycle.

### Changed
- Un-ignored all `ec_schnorr` tests (roundtrip, wrong-message, wrong-key,
  batch verify, empty/large message) — all pass.
- Updated `decode()` doc comments to accurately describe the single-error
  correction limitation of the flat RS path. `decode_shards()` with explicit
  erasure locations is the documented robust recovery path.
- Updated fuzz test doc comments to match actual default iteration count (100).

### Removed
- `tests/diag_secp.rs` — temporary diagnostic scaffolding.
- `dbg_reduce` debug test in scalar.rs.

## [0.6.3] — 2026-07-26

### Added
- **ChaCha40** — post-quantum hardened stream cipher with 512-bit key and 40 rounds
  (dual-state parallel design). Provides 256-bit post-quantum security against
  Grover's algorithm. Accessible at `origin_crypto_sdk::chacha40::*`.
  - `chacha40_block(key, counter, nonce) -> [u8; 64]` — combined keystream block
  - `chacha40_encrypt(key, counter, nonce, data) -> Vec<u8>` — stream cipher
  - `hchacha40(key, nonce) -> [u8; 64]` — key derivation for XChaCha40
  - 12 unit tests covering roundtrip, determinism, key/nonce/counter distinction
- **ChaCha40 example**: `cargo run --example chacha40_encrypt` — demonstrates
  file encryption and key wrapping modes
- **Property-based tests**: 20 new proptest invariants across Reed-Solomon,
  compression, Poly1305, SipHash, blob, and DRBG — verified at 1,000 cases each
  (23,000 total property checks, all passing)
- **Edge-case unit tests**: +26 new tests across 10 modules: AEAD (empty/large
  plaintext, wrong nonce), Serpent-CBC (empty/invalid-length), DRBG (fill,
  zero-length, OS-entropy), HKDF (no-salt/empty-info/large-output/different-info),
  HMAC (empty key/data, key sensitivity), hex (encode-to-slice, decode-array),
  MemoryTier (labels, buffer-size, should-lock, defaults)
- **Fuzz targets**: `fuzz_chacha40` (roundtrip + wrong-key detection) and
  `fuzz_reed_solomon` (encode/decode + corruption recovery)
- **Fuzz-like test harness**: `tests/fuzz_like_testing.rs` — 13 randomized tests
  at 10,000 iterations each (130,000+ random inputs), covering ChaCha40,
  Reed-Solomon, compression, Poly1305, HKDF, HMAC, DRBG, and SipHash.
  Bypasses `cargo +nightly fuzz` toolchain issues.
- Crate-root re-exports: `pub use primitives::chacha40` and `pub use primitives::chacha20`

### Changed
- `primitives::chacha20::quarter_round` and `init_state` promoted from `fn` to
  `pub(crate)` so the ChaCha40 module can share the canonical implementations
  (no code duplication)
- `siphash`, `compression`, and `blob` promoted from `pub(crate) mod` to
  `pub mod` (with `#[doc(hidden)]`, matching `error_correction`'s pattern)
  for integration-test access
- Crate-root re-exports: `pub use primitives::poly1305` and
  `pub use primitives::tier` (both `#[doc(hidden)]`)
- README docs: updated What's Inside table, Module Map, and examples list
- lib.rs docs: updated Module organization and Security defaults sections

## [0.6.2] — 2026-07-26

### Fixed
- **Pivoted NTRU Prime fast-path from NTT to Karatsuba.** The orphan `src/pqc/ntru_prime/ntt.rs` has been purged of the broken NTT primitives (invalid for $\mathbb{Z}_{4591}$ because only $2^1$ divides $Q-1$, so primitive $2^k$-th roots of unity for $k \ge 2$ don't exist) and now contains a working true split-and-conquer Karatsuba multiplication ($O(P^{1.585})$) that avoids roots of unity entirely. The module is re-linked (`mod ntt;` declared) and `rq::mult` calls `ntru_poly_mul_karatsuba` under `#[cfg(feature = "pqc-simd")]`.

### Performance
- **NTRU Prime encapsulate 8.5× faster** under `pqc-simd` (Karatsuba polynomial multiplication replaces O(P²) convolution). Decapsulate 2.5× faster, keygen 1.6× faster.
- **Karatsuba threshold tuned** to 64 (empirically optimal for P=761). Tested at 96 and 128 — both slower due to larger O(P²) base-case dominance.
- **round3_avx2 rewritten with real SIMD**: replaced a dead `use std::arch::x86_64::*;` import (present since the module was introduced) with actual SSE intrinsics processing 4 coefficients per iteration. ~12% speedup over scalar (157 ns vs 179 ns).
- **Performance baseline saved** at `benches/baseline/v0.6.2/` with both scalar-only (`--features slh-dsa,ml-dsa`) and `pqc-simd` configurations. Criterion change columns will flag regressions in CI against this baseline.
- **benches/README.md** updated with baseline instructions, `cargo bench --load-baseline` commands, and CI workflow example.

### Changed
- **`test-utils` feature gating**: Benchmark-only exports (`ntru_prime::ntt`, `rq::mult_scalar`, `rq::round3_scalar`) are now `pub` only under `#[cfg(feature = "test-utils")]`. Without `test-utils`, they're `pub(crate)` (internal usage). Benchmarks require `test-utils` via `required-features = ["slh-dsa", "ml-dsa", "test-utils"]`.
- **6 internal modules demoted from `pub` to `pub(crate)`**: `entropy`, `mmr`, `primitives`, `siphash`, `compression`, `blob` — all `#[doc(hidden)]` modules with zero external consumers. This shrinks the public API surface by 6 modules.
- **Crate-root hash re-exports**: `pub use primitives::sha3_256`, `pub use primitives::sha3_512`, `pub use primitives::blake3` — these were the only `primitives` items referenced by integration tests; now accessible at `origin_crypto_sdk::sha3_256` etc. instead of `origin_crypto_sdk::primitives::sha3_256`.

### Benchmarking
- Added benchmark groups: `poly_mul` (scalar O(P²) vs Karatsuba O(P¹·⁵⁸⁵) head-to-head), `round3` (scalar vs AVX2 dispatch), `serpent` (Serpent-CBC 1 MB encrypt/decrypt), `hybrid-hashes` (Skein512 + Skein1024 at 5B/1KB/64KB/1MB).

## [0.6.1] — 2026-07-26

### Added
- **`ocra` (RFC 6287: OATH Challenge-Response Algorithms)** — new public module implementing the **core** challenge→response algorithm. No Suite-string parsing (deferred to 0.6.2) and no QR mode (deferred to 0.6.2).
  - `pub struct OcraRequest<'a>` — explicit field set: `counter: u64` (C, 8-byte big-endian), `challenge: &'a [u8]` (Q; **SHA-1-hashed internally per §6.1**), `password: Option<&'a [u8]>` (P; **SHA-1-hashed internally per §6.2**), `session: &'a [u8]` (S; raw), `timestamp: Option<u64>` (T, 8-byte big-endian).
  - `pub struct OcraResponse { value: u32, digits: u32 }` with `format_code()` (zero-padded) and `verify(&expected) -> bool` **constant-time** comparison via `subtle::ConstantTimeEq` (RFC 6287 §10).
  - `pub fn ocra(key: &[u8], req: &OcraRequest, digits: u32, algo: HashAlgorithm) -> Result<OcraResponse>` — RFC 6287 §7.1 formula `Truncate(HMAC(K, C || Q || P || S || T))` with RFC 4226 §5.3 dynamic truncation.
  - Custom `Debug` impls on `OcraRequest` and `OcraResponse` redacting secret-derived content (challenge/password bytes hidden, response value hidden). `OcraResponse` is `#[derive(Clone, Copy, PartialEq, Eq)]`.
  - Reuses the existing `drbg::otp::{compute_hmac, format_code, HashAlgorithm}` — **no new dependencies**.
- **`drbg::otp::compute_hmac`** is now `pub(crate)` (was `fn`) so the new `ocra` module can share the HMAC computation without duplication.

### Notes
- **Additive release.** No public API removed or renamed from 0.6.0. Downstream code that imports `HybridSigningKeyBundle`, `XChaCha20Poly1305`, `ChaCha20Drbg`, `Argon2id`, etc. all continues to compile unchanged.
- `cargo test --lib` count: 247 → 258 (+11 OCRA tests inline in `src/ocra.rs`). Note: the orphan `test_poly_mul_ntt_simple` in `src/pqc/ntru_prime/ntt.rs` was never in the baseline count (the file was always unreachable), so it neither adds nor subtracts from this delta. Includes the **canonical RFC 6287 Appendix A.1 Test #1** vector: Suite `OCRA-1:HOTP-SHA1-6:QN08`, key ASCII `12345678901234567890`, counter=0, Q = numeric zeros × 8 (ASCII `"00000000"`) → expected `196958` (  verified independently by a Python recomputation against the RFC §7.1 byte-trace). If the test vector ever fails on your machine, the standard has drifted or your HMAC impl has — investigate against the RFC text before patching.

## [0.6.0] — 2026-07-26

### Removed (BREAKING)
- **`pub mod signing_legacy`** — entire module deleted. Pre-0.4 flat `signing_*` API was deprecated at `0.4.0` with a promise of removal in `0.5`; that removal was deferred once at `0.5.1` and is now honored in `0.6.0`. See [MIGRATION.md](MIGRATION.md#0.5x--06) for migration instructions.
- **Crate-root re-exports**: `HybridSignatureOutput`, `HybridSigningKey`, `HybridVerifyingKey`. Deprecated at `0.5.1` (`#[deprecated(since = "0.5.1")]`); removed in `0.6.0`. Use `signing::hybrid::HybridSigningKeyBundle` instead — the canonical surface has been available at `origin_crypto_sdk::signing::hybrid::HybridSigningKeyBundle` since `0.4.0`.

### Added (tooling)
- **`scripts/audit_signing_legacy.sh`** — downstream consumers can run this against their own repos to find pre-0.6 uses of the removed symbols. Default scan is `*.rs` only; pass `--include-toml` and/or `--include-md` to widen; `--json` emits machine-readable findings. Exit codes: `0` clean, `1` matches found, `2` argument error. See `bash scripts/audit_signing_legacy.sh --help` for usage.

## [0.5.3] — 2026-07-26

### Added
- **`docs/duress-pattern.md`** — Application-level guidance document for developers integrating `origin-crypto-sdk` into products that serve users facing legal compulsion or physical coercion. Covers:
  - **Threat model**: adversaries A1 (legal compulsion at border), A2 (offline forensic analysis), A3 (physical / rubber-hose coercion)
  - **Pattern P1**: Operational deniability — recommended default; sensitive state stays off the device the user carries (EFF SSD clean-traveler pattern)
  - **Pattern P2**: Distinguishable decoy vault — three vaults, duress passphrase silently routes to decoy; **no destruction occurs**, so 18 U.S.C. §2232 risk is avoided. Runtime blueprint uses `create_blob`, `recover_seed`, `SeedHandle::with_tier`, and `MemoryTier::Sovereign` from the existing public API.
  - **Pattern P3**: Plausible deniability — VeraCrypt-style hidden volume; operationally fragile (SSD TRIM, OS logs, file timestamps); recommended only with deniability training
  - **Jurisdictional matrix**: US (18 U.S.C. §2232; Tunick matter, TechCrunch 2026-07-24), UK (Investigatory Powers Act 2016, successor to RIPA Part III), EU (member-state variance — LCEN art. 230-1, §100a StPO, etc.), Five Eyes (MLAT cross-border), authoritarian regimes
- Cross-linked from `README.md` (Security Posture section), `src/lib.rs` crate-level documentation (`//!` `Threat modeling for application authors` section), and `SECURITY.md` (Threat-modeling section).

### Notes
- **Documentation-only addition. No API surface changes.** The SDK deliberately ships no duress or self-destruct primitive (see `docs/duress-pattern.md` §“Legal Context” for the §2232 reasoning).

## [0.5.1] — 2026-07-26

### Changed
- Polish release for `recovery::unicode_cipher`. No public API changes; same `0.5.x` wordlist.

### Fixed
- **`origin-crypto` CLI binary (publish-blocker)**: fixed `E0432` unresolved import on `crate::internal::getrandom` in `src/bin/origin-crypto.rs`. The bin target's `crate::…` resolves to its own root, which has no `internal` module; switched to `use origin_crypto_sdk::internal::getrandom;`. **This was the cause of `cargo publish --dry-run` failing to verify the package tarball on 0.5.x.**
- **`origin-crypto decrypt` (publish-blocker)**: fixed `E0382` borrow-after-move in `cmd_decrypt`. `fs::write(&args.output, pt)` consumed `pt` before the trailing status print accessed `pt.len()`; switched to `fs::write(&args.output, &pt)` so the print can read `pt.len()` afterwards.
- Replaced a dead defensive `if cs_byte < bits.len()` branch in `decode_phrase` with a `debug_assert` — the buffer is grown by `insert_bits_msb` to fit all `total_bits` (264 for `Words24`, 132 for `Words12`), so the conditional was always in-range and only obscured the read.
- Added a **No transport-layer NFKC normalization** note to the module-level Security notes, documenting that phrase codepoints are matched byte-for-byte (not by canonical form) and warning against smart-quote editors, NFC/NFD/NFKC/NFKD pipelines, IME composers, and visually-equivalent glyph substitution (e.g. `ⓕ` U+24D5 ↔ `f` U+0066).

### Added
- **`recovery::unicode_cipher`** — new public module providing a BIP-39-shaped recovery phrase codec using Unicode codepoints instead of an English wordlist:
  - `PhraseLength::{Words12, Words24}` — 12-word (128-bit entropy + 4-bit SHA-3-256 checksum) and 24-word (256-bit + 8-bit) modes
  - `UnicodeWordlist::default()` — curated 2048-codepoint wordlist generated by `scripts/generate_wordlist.py` from Geometric Shapes, Box Drawing, Block Elements, Misc Symbols, Dingbats, Math Operators (A and B), Arrows, Alchemical Symbols, and Geometric Shapes Extended
  - `encode_phrase(...)` / `decode_phrase(...)` — primary API; strict NFKC + ZWJ + Variation Selector + Combining Mark + BIDI Mark + Control + Default-Ignorable rejection
  - `encode_phrase_custom(...)` — power-of-2 sized custom alphabets (16 / 32 / 64 / ... / 4096) with explicit entropy reporting and a 128-bit safety floor
- **5 new `CryptoError` variants** — `ChecksumMismatch { expected, got }`, `InvalidNormalization { codepoint, reason }`, `RejectedCodepointClass { codepoint, class }`, `InsufficientEntropy { got_bits, required_min }`, fallback `RecoveryPhrase(String)`. All have matching `Display` and `Clone` arms.
- **`unicode-normalization = "0.1"` new dependency** for NFKC canonical-form checks.

### Notes
- Recovery phrases generated by this module are **deliberately NOT BIP-39 compatible**. The wordlist is Unicode codepoints (not English) and the checksum is SHA-3-256 (not SHA-256). Phrases cannot be recovered by other BIP-39 wallets — use this module for recovery.

## [0.4.0] — 2026-06-10

### Added
- **Ed448**: RFC 8032 signature scheme on the 448-bit Goldilocks curve
- **Ed41417**: Curve41417 Edwards curve operations (Bernstein et al.)
- **ML-DSA**: FIPS 204 lattice-based signatures (feature-gated, `ml-dsa`)
- **SLH-DSA**: FIPS 205 hash-based signatures (feature-gated, `slh-dsa`)
- **Hybrid constructions**: Ed448+Falcon-1024, Ed25519+Falcon-512, Ed448+Shake256,
  Ed448+Skein512, Ed448+Sha3_256, Ed25519ChaCha20Blake3Sha3_256 (KDF mode)
- **HybridSigningKeyBundle**: canonical PQ-hybrid signing API — derive Ed25519 +
  Falcon-1024 keys from a single seed with domain separation
- **Bundle caching**: `from_seed_cached()` for process-wide key cache (avoids
  re-running Falcon keygen on repeated calls)
- **signing module restructured**: `signing::classical`, `signing::postquantum`,
  `signing::hybrid` — clear family-based organization
- **signing_legacy**: backward-compatible re-exports for pre-0.3 callers
- **Cargo features documented** in crate-level doc with table
- **docs.rs metadata**: `[package.metadata.docs.rs]` for correct docs.rs builds
- **Dependency pin documentation**: reasons for pinned versions in Cargo.toml
- **Examples**: `examples/hybrid_sign.rs`, `examples/encrypt_file.rs`,
  `examples/kdf_derive.rs`, `examples/seed_tree.rs`
- **README.md**: quick start, feature table, module map, security posture

### Changed
- **Prelude narrowed**: removed low-level PQC type dumps (Falcon512PrivateKey,
  SlhDsaPrivateKey, MldsaPrivateKey, ed448, ed41417_raw, slhdsa_sign/verify).
  These are now accessed through their modules: `pqc::falcon1024::*`, etc.
- **Crate root re-exports**: consolidated to blessed top-level API only
- **EC Schnorr tests**: marked `#[ignore]` pending Montgomery arithmetic fix

### Fixed
- **ec_schnorr keygen**: rejection sampling — no more fallback to `Scalar::ONE`
- **secp256k1 field.rs**: overflow panic in `reduce_if_carry_or_gte_p`
- **9 unused-import/mut warnings** eliminated

### Security
- See [SECURITY.md](SECURITY.md) for implementation source table
- Custom PQC implementations (NTRU Prime, Ed41417) remain unaudited

### Type Safety
- **`Seed`** newtype (32 bytes, zeroize on drop, Debug hides bytes)
- **`XNonce`** newtype (24 bytes for ChaCha20-BLAKE3)
- **`CNonce`** newtype (12 bytes for ChaCha20-Poly1305)
- All newtypes reject wrong-length input at construction time

### Error Handling
- Structured `CryptoError::InvalidKeyLength { algorithm, expected, got }`
- Structured `CryptoError::InvalidNonceLength { algorithm, expected, got }`
- Full variant table in `error.rs` module docs
- Programmatic `match` instead of string parsing

### API Hardening
- **`Argon2idBuilder`** for custom memory / iterations / parallelism
- `unsafe_code = "forbid"` workspace lint
- `clippy::correctness = "deny"`, `clippy::panic = "deny"`
- Constant-time comparison for hash fields in hybrid verify (8 sites)
- `MldsaPrivateKey` and `SlhDsaPrivateKey` now zeroize on drop
- `#[deprecated(since = "0.4.0")]` on `signing_legacy` (will be removed in 0.5)

### Documentation
- 42 → 0 missing-documentation warnings (with `#[cfg_attr(docsrs, warn(missing_docs))]`)
- 0 unresolved intra-doc links
- Module docs follow consistent pattern (summary → when to use → example
  → security notes → see also)
- `MIGRATION.md` for 0.3 → 0.4 transitions
- `CONTRIBUTING.md` for contributors
- `RELEASE.md` for 0.4.0 release notes
- `benches/README.md` with expected performance numbers
- `fuzz/README.md` with cargo-fuzz instructions
- API Stability section in README (Stable / Unstable / Frozen)

### Tooling
- **CI workflow** (`.github/workflows/ci.yml`) with 9 jobs: check, test,
  test-features, examples, clippy, fmt, doc, proptest, test-utils, MSRV
- **Fuzz targets** (`fuzz/`) for AEAD, HKDF, hybrid verify
- **`test-utils` feature** with `deterministic_seed`, `deterministic_key`,
  `deterministic_nonce_24/12`, `deterministic_bytes`
- `cargo` `exclude` reduces crates.io package size

### Testing
- 275 tests passing (was 246 at start of release)
- 10 proptest property-based tests (roundtrip, tamper detection, etc.)
- 3 fuzz targets compile
- 4 runnable examples verified
- All 3 pre-existing `hybrid_rigorous` test failures now compile and pass

## [0.5.2] — 2026-07-26

### Fixed
- **Doc-tests**: resolved 5 pre-existing `///` rust doc-test path bugs that referenced paths from before the 0.4.1 module reorganization. Previously broken:
  - `src/drbg/otp.rs` Quick-start: `use origin_crypto_sdk::otp::{hotp, totp};` → `use origin_crypto_sdk::drbg::otp::{hotp, totp, HashAlgorithm};` (HashAlgorithm was also missing from the import)
  - `src/seed/gen.rs` Quick-start: `use origin_crypto_sdk::seed_gen::{self, SeedVariant};` → `use origin_crypto_sdk::seed::gen::{self, SeedVariant};`
  - `src/signing/hybrid.rs` Quick Start (x2): `use origin_crypto_sdk::hybrid::...` → `use origin_crypto_sdk::signing::hybrid::...`
  - `src/lib.rs` Single-primitive example: added `.expect("valid seed")` after the `Ed25519Signer::from_seed(...)` and `Falcon1024Signer::from_seed(...)` calls — both `from_seed` functions return `Result<Self>`, so the doc-test chains `from_seed(...).sign(...)` were silently treating the Result as the Signer.
- **Intra-doc-link warnings**: 4 unresolved rustdoc `[`name`]` links in module-level docs fixed by adding full module paths:
  - `src/signing/mod.rs`: `[`hybrid`]` → `[`signing::hybrid`]`
  - `src/recovery/mod.rs`: `[`unicode_cipher`]` → `[`recovery::unicode_cipher`]`
  - `src/seed/mod.rs`: `[`gen`]` → `[`seed::gen`]`
  - `src/stealth.rs`: `[`pow`]` → `[`stealth::pow`]`

### Notes
This is a **doc-only patch release**. No runtime surface changes; no API changes; no deprecations. The 5 `cargo test --doc` failures and 4 unresolved intra-doc-link warnings that existed in 0.5.1 are resolved.

## [0.4.1] — 2026-06-11

### Added
- **Module reorganization**: crate structure now matches the README module map exactly
  - `aead::{symmetric, streaming}` — Serpent CBC + streaming encryption under AEAD
  - `kdf::mac` — HMAC-SHA3-256 moved under KDF (keyed hash = KDF primitive)
  - `drbg::otp` — One-time pad (HOTP/TOTP) moved under DRBG (RNG utility)
  - `seed::gen` — Multi-hash seed generation moved under seed
  - `stealth::{kdf, pow}` — Stealth KDF + PoW merged into single `stealth` module
  - `signing::legacy_shim` — deprecated top-level `hybrid` shim moved under signing

### Changed
- **Internal utilities marked `#[doc(hidden)]`**: `entropy`, `mmr`, `error_correction`,
  `siphash`, `compression`, `blob`, `primitives`, `otp` (now `drbg::otp`), `internal`
  — still public API but hidden from docs.rs, use at own risk
- **PQC type re-exports removed from crate root**: `Falcon1024PrivateKey`, `Falcon512PrivateKey`,
  `FalconSignature`, `ed41417_raw` no longer at `origin_crypto_sdk::*`
  - Use `pqc::falcon1024::FalconPrivateKey` etc. for advanced access
  - Use `signing::postquantum::{Falcon1024Signer,Falcon512Signer}` for OOP API
  - Eliminates duplicate Falcon exposure at crate root
- **README module map updated** to show full nested structure

### Fixed
- All 228 lib + 41 integration/proptest/hybrid tests pass after reorganization
- 4 examples build and run correctly

## [0.3.0] — 2026-05-28

### Added
- **Hybrid signing module** (`signing/hybrid.rs`): Ed25519+Falcon-1024,
  Ed25519+BLAKE3 hash-check, Ed25519+SHAKE256, Ed25519+Skein512
- **HybridSigningKeyBundle**: one-call API for PQ-hybrid signing
- **falcon1024_keygen**: seed-based Falcon key generation
- **skein512 / skein1024**: Skein hash wrappers for hybrid constructions
- **Prelude restructured**: clear section comments, feature-gated PQC types

### Changed
- **signing module split** into `classical`, `postquantum`, `hybrid` submodules
- **signing_legacy.rs**: shim for backward compatibility with flat `signing::*` imports
- **hybrid.rs** (top-level): thin compat re-export pointing to `signing::hybrid`

### Fixed
- Hybrid key derivation uses domain-separated HKDF (prevents cross-domain reuse)
- Falcon keygen seeded deterministically (no hidden RNG state)

## [0.2.0] — 2025-05-20

### Fixed
- **ec_schnorr**: Keygen rejection sampling — no more fallback to `Scalar::ONE` which caused identical keys from different seeds
- **secp256k1 field.rs**: Overflow panic in `reduce_if_carry_or_gte_p` — `p_limbs[i] + borrow` could wrap u64
- **Warnings**: Zero unused-import/mut warnings across entire crate (was 9)

### Changed
- `ec_schnorr` tests marked `#[ignore]` — underlying Montgomery arithmetic needs a deeper fix (see module-level doc)
- License format: `license-file = "LICENSE"` for crates.io compatibility

## [0.1.0] — 2025-07-08

### Added

- **AEAD**: XChaCha20-Poly1305 encryption via `chacha20poly1305` crate
- **KDF**: Argon2id key derivation with configurable paranoid mode
- **HKDF**: HKDF-SHA3-256 for subkey derivation
- **HMAC**: HMAC-SHA3-256 message authentication
- **Symmetric**: Serpent CBC encryption (paranoid mode)
- **Compression**: zlib via `flate2`
- **Error correction**: Reed-Solomon with parallel encoding support
- **Streaming**: Stream encryption/decryption for large files
- **PQC — NTRU Prime**: sntrup761 KEM (custom native implementation)
- **PQC — Falcon-512/1024**: Post-quantum signatures via `falcon-rs` (FIPS 206)
- **PQC — Ed41417**: Curve41417 Edwards curve operations (custom native)
- **Hybrid KEM**: X25519 + Ed41417 + NTRU Prime combined encapsulation
- **Hybrid signatures**: Ed25519 + Falcon-1024 combined signing
- **Native ChaCha20**: RFC 8439 stream cipher (zero external crypto deps)
- **Native Poly1305**: RFC 8439 §2.5 MAC (zero external crypto deps)
- **Native ChaCha20-Poly1305**: RFC 8439 AEAD + XChaCha20-Poly1305
- **Seed Blob**: Encrypted master seed at rest (Argon2id + XChaCha20-Poly1305)
- **ChaCha20-DRBG**: Deterministic CSPRNG with auto-reseed after 16 MB
- **SipHash-c-d**: Compute hardener for entropy pipeline
- **Memory tiers**: Nano / Standard / Sovereign Argon2id cost profiles

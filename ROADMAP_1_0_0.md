# Roadmap to v1.0.0

**Current version:** 0.7.0 (2026-08-02)
**Target:** 1.0.0 — evidence-backed production release

## Where We Are (0.7.0)

### Completed
- NIST PQC compatibility: NTRU Prime (NIST encoding + CCA KEM), Falcon (FIPS 206)
- 726 tests passing with `--all-features` (0 failures)
- **Design audit + structural remediation** (pre-Phase-12, commits
  `326a2ff`…`e7afb48`, see `docs/DESIGN_AUDIT.md`):
  - Layer sealing: `internal`/`primitives` are `pub(crate)`; layer rules
    documented in `docs/ARCHITECTURE.md`
  - `signing/hybrid.rs` (1541 lines) split into a `hybrid/` module dir
    with shared combinators; ~400 lines of copy-paste constructions gone
  - `BundleCache` is an ownable value type (process-global kept as
    convenience)
  - Error/boundary hygiene: every RNG-panic site has a `try_*` variant;
    error variants remapped (`Pqc`/`Serialization`/`AuthenticationFailed`)
  - Long functions decomposed; `// CT-REVIEW(12.1)` marks placed at
    every timing-sensitive site for Phase 12.1 to verify
  - Public surface rationalized: doc-hidden utilities promoted to
    documented experimental modules; `html_root_url`/README drift fixed
- CCA-secure decapsulation (always returns Ok, pseudorandom on failure)
- 7 property tests (proptest) for NTRU Prime
- BLAKE3/SHAKE128/SHAKE256 KEM hash backends behind feature flags
- Supply-chain hardening: cargo-audit clean, cargo-deny clean
- Algorithm ID system with downgrade policy
- Bounded hybrid cache (max_entries + TTL)
- Fallible RNG API, malformed-input tests, timing tests
- Format registry, golden vectors, audit package
- 22 CI jobs covering formatting, linting, docs, MSRV, sanitizers, fuzz

### 1.0.0 Acceptance Criteria Status

| Category | Satisfied | Pending |
|----------|-----------|---------|
| Security & cryptography | 5/6 | 1 (external review) |
| Key management & runtime | 5/5 | 0 |
| Compatibility & downstream | 4/4 | 0 |
| Verification & operations | 4/5 | 1 (independent audit) |
| **Total** | **18/20** | **2** |

Only 2 items remain, both requiring external engagement:
1. Independent cryptographic review of custom primitives
2. Independent audit report with findings disposition

---

## Roadmap: 0.7.0 → 1.0.0

### Phase 12 — Evidence & Protocol Stability (v0.8.0)

**Goal:** Strengthen internal evidence to the point where external review
is the only remaining gate.

#### 12.1 Constant-time review
- [x] Audit all NTRU Prime operations for timing side channels
      (coefficient comparison, weight check, rounding) — CCA mask select
      made arithmetic, `crypto_sort` min_max made branchless, poly ops
      verified fixed-bound
- [x] Audit Falcon wrapper for timing leakage in verify path — thin
      wrapper over `falcon-rs` FIPS 206 `FnDsaSignature::verify`; no
      local secret-dependent branches (upstream boundary documented)
- [x] Audit hybrid signing combiner for timing leakage — all digest
      comparisons via `subtle::ConstantTimeEq`
- [x] Document which operations are constant-time and which are not —
      `docs/CONSTANT_TIME.md`
- [x] Add timing tests for NTRU Prime encapsulate/decapsulate —
      `timing_ntru_decap_valid_vs_invalid` (+ Schnorr key-density test)
- [x] Sweep every `// CT-REVIEW(12.1)` mark placed by the design-remediation
      pass: fixed — `x25519` `==`→`ct_eq` (2 sites), `GaloisField::mul`
      branchless, NTRU CCA mask arithmetic, `internal::secp256k1` made
      branchless (scalar mul, point add/double, `is_gte_*`/`is_lt_n`
      borrow chains, masked `conditional_add_*`, fixed-trip REDC,
      4-fold `reduce_512`, mask-select `reduce_257`); documented as
      public-data-only — `GaloisField::exp`, syndrome early-continue,
      `pow` public exponents, decode/parse early returns. Residual:
      external codegen verification of hand-rolled secp256k1 (Phase 13)

#### 12.2 Fuzzing expansion
- [x] Add libFuzzer targets for NTRU Prime decode/decapsulate
      (`fuzz_ntru_prime`: malformed + mutated ciphertexts into decapsulate,
      valid encapsulate/decapsulate round-trip)
- [x] Add libFuzzer targets for Falcon signature parsing
      (`fuzz_falcon`: arbitrary bytes into `Falcon512Signature`/`PublicKey`/
      `PrivateKey::from_bytes`, parse + verify, sign round-trip)
- [x] Add libFuzzer targets for blob deserialization
      (`fuzz_blob`: `detect_blob_version`, `blob_tier`, `recover_seed`,
      `rotate_blob` on arbitrary input)
- [x] Add libFuzzer targets for hybrid signature verification
      (pre-existing `fuzz_hybrid_verify`)
- [x] Fix fuzz infrastructure: `libfuzzer-sys` was built with
      `default-features = false`, which disables `link_libfuzzer` — no target
      ever linked a `main`, and the CI job's `|| true` masked the failure.
      Manifest fixed; CI smoke job now fails on crashes/hangs/build errors
      instead of ignoring them
- [ ] Sustained fuzzing and document results — rescoped: requires
      dedicated infrastructure the project doesn't have. CI runs a
      60s/target smoke on every build (8 targets, all clean locally:
      ntru_prime 619 execs/30s, falcon 52,386, blob 1,477 incl.
      "ORGB" magic discovery). Intended path is an OSS-Fuzz submission
      (or equivalent hosted fuzzing) rather than local 24h runs;
      corpus directories under fuzz/corpus/ accumulate seeds for
      whichever infra picks this up

#### 12.3 Differential testing
- [x] NTRU Prime: differential test against the reference implementation —
      stronger than liboqs: the NIST AES-256-CTR DRBG is replayed through
      our `RngCore`-generic keygen/encapsulate, reproducing pk, sk, ct AND
      ss byte-for-byte on all 100 official submission vectors
      (`tests/ntru_prime_kat.rs::kat_execution`). This caught two real
      spec-deviation bugs: `hash_session` committed to the 32-byte confirm
      instead of the full ciphertext, and `random_tsmall` sorted signed
      i32 where the reference uses `crypto_sort_uint32`
- [x] Falcon: N/A as scoped — our Falcon path delegates to the external,
      audited `falcon-rs` crate (FIPS 206 format), which passes all NIST
      KATs upstream. pqclean/falcon implements the incompatible
      PQC-submission format (header 0x02 vs FIPS 206 0x30/0x50), so a
      byte-level differential is impossible by construction. Our wrapper
      layer is covered by `tests/falcon_kat.rs` regression vectors
- [x] Hybrid KEM: N/A — the crate has no hybrid KEM construction
      (hybrid signing only). Rescope when a hybrid KEM is actually designed

#### 12.4 NTRU Prime full KAT integration
- [x] Port AES-256-CTR DRBG to match NIST KAT seed expansion
      (`NistDrbg` in `tests/ntru_prime_kat.rs`; `aes` dev-dep)
- [x] Verify 100/100 NIST sntrup761 KAT vectors — full pipeline:
      seeded keygen → pk + sk byte-exact; encapsulate → ct + ss byte-exact;
      decapsulate(ct, sk) → ss on all vectors; plus cross-roundtrip with
      reference keys under our encapsulate
- [x] This requires implementing the NIST DRBG or using a crate
      (implemented `NistDrbg` test-only, `aes = "=0.8.4"` dev-dep)
- [x] Alternative: verify against liboqs-rs if it exposes sntrup761
      (superseded — official submission KATs are the stronger oracle)

#### 12.5 Falcon full KAT integration
- [ ] Port AES-256-CTR DRBG to match FIPS 206 KAT seed expansion
      (blocked: NIST has not published FIPS 206 ACVP vectors; the old
      submission `falcon512-KAT.rsp` uses an incompatible signature format —
      see `tests/falcon_kat.rs` header)
- [ ] Verify 100/100 Falcon-512/1024 FIPS 206 KAT vectors
      (blocked pending ACVP vectors; falcon-rs already passes NIST KATs
      internally via its own `nist_kat.rs`)
- [ ] Or: verify against pqclean if falcon-rs exposes deterministic keygen
      (deferred — see 12.3 note: submission format ≠ FIPS 206)

#### 12.6 Persistence format migration
- [x] Add 0.6.7 → 0.7.0 migration tool for NTRU Prime keys —
      `pqc::ntru_prime::migrate` (lib) + `origin-crypto migrate ntru-pk|ntru-sk`
      (CLI). f/gr carry over verbatim; h is re-encoded; rho/cache regenerated
- [x] Falcon keys: **not migratable** — `falcon-rs` only accepts FIPS 206 wire
      keys and exposes no polynomial-level key builder, so submission-format
      keys cannot be re-encoded. Path is regenerate + re-sign (documented)
- [x] Document migration limitations — `docs/MIGRATION_0_6_TO_0_7.md`:
      ciphertexts ephemeral, shared secrets not preserved (session derivation
      changed), Falcon signatures must be re-signed

#### 12.7 Performance regression baseline
- [x] Establish benchmark baseline — 61 Criterion benchmarks recorded on the
      reference machine in `docs/BENCHMARKS.md` (v0.7.1-rc.9)
- [x] Benchmark CI job fixed — removed `|| true` masking and the phantom
      `v0.6.2-scalar` baseline reference; job now fails on broken bench code
      and uploads `target/criterion/` as a `benchmark-results` artifact
- [x] Document expected performance characteristics per platform —
      `docs/BENCHMARKS.md` records reference hardware, per-group medians,
      and same-machine comparison procedure
- [ ] Numeric regression gating in CI — **deferred**: hosted runners vary too
      much for absolute-time thresholds; requires a self-hosted runner or
      same-machine before/after comparison (see `docs/BENCHMARKS.md`)

---

### Phase 13 — External Review Preparation (v0.9.0)

**Goal:** Prepare and deliver the audit package, commission external review.

#### 13.1 Audit package finalization
- [x] Update AUDIT_PACKAGE.md with v0.7.1-rc.9 state
- [x] Include all test evidence (455 lib + 269 integration, 100/100 NIST
      KAT vectors, 8 fuzz targets, 6 timing tests)
- [x] Include threat model, security claims, and known limitations
- [x] Include dependency inventory and advisory dispositions
- [x] Include format registry (FORMAT_REGISTRY.md) and migration tooling
      (`docs/MIGRATION_0_6_TO_0_7.md` + `origin-crypto migrate`)

#### 13.2 Commission independent cryptographic review
- [ ] Engage external reviewer for NTRU Prime custom implementation
      (encoding, KEM flow, CCA security, constant-time)
- [ ] Engage external reviewer for hybrid composition
      (binding, domain separation, downgrade resistance)
- [ ] Engage external reviewer for Ed41417/Curve41417
- [ ] Engage Rust/unsafe reviewer for SIMD, mlock, RNG, zeroization

#### 13.3 Findings disposition
- [ ] Triage all findings by severity (critical/high/medium/low)
- [ ] Fix or narrow all critical/high findings
- [ ] Document disposition for each finding
- [ ] Re-test after fixes

#### 13.4 Release candidate
- [ ] Freeze API and wire formats
- [ ] Produce reproducible build artifacts
- [ ] Generate SBOM and locked dependency manifest
- [ ] Sign release artifacts
- [ ] Tag v0.9.0-rc1

---

### Phase 14 — Production Release (v1.0.0)

**Goal:** Evidence-backed production release.

#### 14.1 Final verification
- [ ] All critical/high findings resolved or narrowed
- [ ] Full test suite passes on all supported targets
- [ ] Fuzzing runs clean for 24h+ per target
- [ ] KAT vectors pass for all standard algorithms
- [ ] Differential tests pass against all reference implementations
- [ ] No open cargo-audit advisories in supported surfaces

#### 14.2 Documentation
- [ ] Update README for 1.0.0 (remove experimental labels from supported)
- [ ] Update VIABILITY_ASSESSMENT with final review results
- [ ] Publish audit report and findings disposition
- [ | Update SECURITY.md with final threat model
- [ ] Publish migration guide (0.6.x → 1.0.0)

#### 14.3 Release
- [ ] Tag v1.0.0
- [ ] Publish to crates.io
- [ ] Announce with release notes
- [ ] Establish vulnerability response process
- [ ] Establish LTS/support policy

---

## Things We Are NOT Doing for 1.0.0

- **Replacing Origin algorithms with standards**: Origin constructions
  remain the primary design. Standards are comparison points, not
  replacements.
- **Constant-time guarantees on all paths**: Only reviewed operations
  will have constant-time claims. Others will be explicitly labeled.
- **Supporting all platforms**: 1.0.0 targets x86-64, ARM64, WASM.
  Other platforms remain best-effort.
- **Backward compatibility with 0.6.x wire formats**: 0.7.0 is a
  breaking release. Migration tooling will be provided but old formats
  are not supported at the wire level.

---

## Estimated Effort

| Phase | Effort | Dependency |
|-------|--------|------------|
| 12 (Evidence) | 2-4 weeks | Internal, no blockers |
| 13 (External review) | 4-8 weeks | Requires external engagement |
| 14 (Release) | 1-2 weeks | Requires Phase 13 completion |

**Critical path**: Phase 13 (external review) is the long pole. Phase 12
can proceed in parallel with audit package preparation.

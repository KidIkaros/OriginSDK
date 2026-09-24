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
- [ ] Audit all NTRU Prime operations for timing side channels
      (coefficient comparison, weight check, rounding)
- [ ] Audit Falcon wrapper for timing leakage in verify path
- [ ] Audit hybrid signing combiner for timing leakage
- [ ] Document which operations are constant-time and which are not
- [ ] Add timing tests for NTRU Prime encapsulate/decapsulate
- [ ] Sweep every `// CT-REVIEW(12.1)` mark placed by the design-remediation
      pass (grep for `CT-REVIEW`): `GaloisField::{mul,exp}`,
      `correct_single_shard_errors`, `ntru_prime::decapsulate` +
      `count_weight`, `x25519::{from_secret_key,from_seed}` `==` on scalars,
      `ec_schnorr::prove`, and all of `internal::secp256k1`

#### 12.2 Fuzzing expansion
- [ ] Add libFuzzer targets for NTRU Prime decode/decapsulate
- [ ] Add libFuzzer targets for Falcon signature parsing
- [ ] Add libFuzzer targets for blob deserialization
- [ ] Add libFuzzer targets for hybrid signature verification
- [ ] Run sustained fuzzing (24h+ per target) and document results

#### 12.3 Differential testing
- [ ] NTRU Prime: differential test against liboqs/sntrup761
      (encode/decode, encapsulate/decapsulate with same seed)
- [ ] Falcon: differential test against pqclean/falcon
      (sign/verify with same key, same message)
- [ ] Hybrid KEM: differential test against X25519 + Ed41417 references

#### 12.4 NTRU Prime full KAT integration
- [ ] Port AES-256-CTR DRBG to match NIST KAT seed expansion
- [ ] Verify 100/100 NIST sntrup761 KAT vectors (encapsulate + decapsulate)
- [ ] This requires implementing the NIST DRBG or using a crate
- [ ] Alternative: verify against liboqs-rs if it exposes sntrup761

#### 12.5 Falcon full KAT integration
- [ ] Port AES-256-CTR DRBG to match FIPS 206 KAT seed expansion
- [ ] Verify 100/100 Falcon-512/1024 FIPS 206 KAT vectors
- [ ] Or: verify against pqclean if falcon-rs exposes deterministic keygen

#### 12.6 Persistence format migration
- [ ] Add 0.6.7 → 0.7.0 migration tool for NTRU Prime keys
      (re-encode old format to new NIST encoding)
- [ ] Add 0.6.7 → 0.7.0 migration tool for Falcon keys
      (re-sign with new falcon-rs format)
- [ ] Document migration limitations (Falcon: old signatures can't be
      re-verified, must re-sign)

#### 12.7 Performance regression baseline
- [ ] Establish v0.7.0 benchmark baseline
- [ ] Add benchmark regression CI job with thresholds
- [ ] Document expected performance characteristics per platform

---

### Phase 13 — External Review Preparation (v0.9.0)

**Goal:** Prepare and deliver the audit package, commission external review.

#### 13.1 Audit package finalization
- [ ] Update AUDIT_PACKAGE.md with v0.7.0 state
- [ ] Include all test evidence (726 tests, KAT vectors, fuzz results)
- [ ] Include threat model, security claims, and known limitations
- [ ] Include dependency inventory and advisory dispositions
- [ ] Include format registry and migration tooling

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

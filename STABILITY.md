# Stability & Evidence Tiers

**Version:** 0.7.3 · **Status of independent audit:** not yet commissioned —
see `AUDIT_PACKAGE.md` for the prepared review package.

Production use of cryptographic software is a risk decision. This document
exists so that decision can be made with accurate information rather than a
blanket warning.

## Evidentiary posture

This SDK does not treat standardization-body endorsement — NIST or otherwise —
as evidence of security. The historical record (Dual_EC_DRBG most sharply)
shows endorsement can be neutral or negative signal, and the post-quantum
literature shows security estimates for standardized lattice schemes being
revised *downward* repeatedly after selection (see
`docs/RESEARCH-NOTE-cryptanalysis-evidence.md`). Evidence is ranked here by
independence, not authority:

1. **Public cryptanalysis** — published attempts to break the construction
2. **Independent implementations and differential testing**
3. **Academic security analysis with scrutinized assumptions**
4. **Reference test vectors** — correctness evidence only, whatever the source
5. **Standards endorsement** — not treated as evidence

The custom constructions in this crate are not deviations-from-a-baseline;
they are deliberate expert-guided design decisions (independent cryptographic
consultant; rationale documented per-component in `SECURITY.md` §"Standards
Posture"). NTRU Prime over Kyber, Curve41417 over NIST curves, and hybrid
AND-composition are positions *against* the monoculture, taken on published
cryptanalytic reasoning — the same reasoning the 2026 subexponential lattice
results later corroborated structurally. The honest residual gap is breadth
of scrutiny: one expert's design review, however strong, is not independent
public review. That is what the external audit gate is for.

Each component is assigned an evidence tier:

- **Tier A** — externally validated implementation (audited or battle-tested
  upstream). Risk profile equivalent to mainstream deployments of the same
  primitives.
- **Tier B** — custom implementation, verified byte-exact against
  independent reference test vectors (design-team KAT / RFC vectors — correctness evidence, not endorsement), internally constant-time
  reviewed with timing tests. Residual risk: implementation flaws that
  vectors do not reach (edge cases, composition, side channels internal
  review missed).
- **Tier C** — custom construction or composition, internal evidence only
  (property tests, golden vectors, adversarial tests, fuzz smoke). Residual
  risk: design-level and implementation-level flaws no internal process can
  exclude. **These components are what the external review is for.**

## Component matrix

| Component | Tier | Evidence | Residual risk notes |
|---|---|---|---|
| XChaCha20-Poly1305 AEAD | A | `chacha20poly1305` crate (pinned) | — |
| ChaCha20-BLAKE3 AEAD | A | `chacha20-blake3` crate (pinned) | committing-AEAD variant, non-standard but upstream |
| Argon2id KDF | A | `argon2` crate (pinned) | — |
| Ed25519 / X25519 | A | `ed25519-dalek` / `x25519-dalek` | — |
| SHA-2 / SHA-3 / SHAKE | A | `sha2` / `sha3` crates | — |
| Falcon-512/1024 | A | `falcon-rs` — widely reviewed implementation of the published Falcon design, upstream KATs pass | in-crate KAT verification blocked on unpublished ACVP vectors |
| secp256k1 arithmetic | A | `k256` — fiat-crypto, CT by construction | — |
| NTRU Prime (sntrup761) | B | 100/100 design-team reference KAT byte-exact (`tests/ntru_prime_kat.rs`), CT review, timing tests, fuzz targets | custom implementation; expert review pending |
| Native ChaCha20 / Poly1305 | B | RFC 8439 test vectors in-crate | custom implementation of a standard algorithm |
| Hybrid signing | C | golden vectors, rigorous/adversarial/security test files, proptest | novel composition — internal separability audit in `docs/AUDIT-NOTE-hybrid-combiner.md` (finding H-1 open); external review pending |
| Ed41417 (Curve41417) ECC | C | internal test vectors | custom ECC — highest-risk component in the crate |
| EC-Schnorr composition | C | Fiat-Shamir over audited `k256` arithmetic | composition itself unreviewed |
| ChaCha20-DRBG | C | statistical validation, entropy tests | custom DRBG construction |
| Seed blob / compressed container | C | golden vectors, format registry, fuzz targets for deserialization | persistence format (`ORGB` v2) |
| Reed-Solomon sharding | C | property tests, branchless GF arithmetic | custom implementation |
| Memory handling (mlock/zeroize) | C | documented unsafe sites, zeroize-on-drop | `unsafe` code — Rust/unsafe reviewer item |
| Entropy analysis (statistical + structural) | C | size-aware derived thresholds, pooled validation methodology | statistical tooling, not a security boundary |
| Seed generation chains | C | deterministic-under-injected-entropy tests, structural validation of pooled output | custom two-round hash chains |

## Process evidence

- 518 library tests + integration/proptest/fuzz-like/adversarial/timing
  suites, all green
- 22 CI jobs: fmt, clippy, docs, MSRV, sanitizers, fuzz smoke (60s/target)
- Constant-time review (Phase 12.1) complete: all `CT-REVIEW` marks swept,
  timing tests for NTRU Prime encapsulate/decapsulate
- Wire formats pinned by golden-vector tests; algorithm IDs versioned
  explicitly (`src/algorithm_id.rs`) — formats follow semver
- Supply chain: `cargo audit` + `cargo deny` clean, dependencies pinned

## What is NOT yet done

1. **Independent cryptographic review** of Tier C constructions (audit
   package prepared; reviewer not yet commissioned)
2. **Published audit findings and disposition**
3. Sustained fuzzing beyond CI smoke (infrastructure-dependent)

Until items 1–2 are complete, Tier C components should be treated as
unreviewed cryptographic research — which is a statement about evidence,
not about the quality of the engineering.

## Cryptographic inventory (CBOM)

A CycloneDX 1.6 Cryptographic Bill of Materials is generated from the
`AlgorithmId` inventory — the single source of truth in `src/algorithm_id.rs`:

```
cargo run --bin cbom > cbom.json
```

All 34 algorithm assets are classified by primitive, implementation platform,
execution environment, and provenance (custom vs external). A unit test pins
the inventory count so new variants cannot ship without CBOM coverage. (For
context: none of the seven PQC libraries audited in arXiv:2605.17061 shipped
cryptographic discovery/inventory tooling.)

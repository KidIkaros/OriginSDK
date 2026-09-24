# SPDX-License-Identifier: Apache-2.0

# Origin Crypto SDK — Security Notes

> ⚠️ **EXPERIMENTAL — NOT FOR PRODUCTION USE**
>
> This SDK has not undergone independent security audit or formal review.
> Do not use it to protect real funds, identities, or data. See the README
> for the full warning.

## Overview

The Origin Crypto SDK contains both external (battle-tested) and custom implementations of cryptographic primitives. Custom implementations have **not been independently audited** as of this writing.

## Implementations

| Component | Source | Notes |
|-----------|--------|-------|
| XChaCha20-Poly1305 (AEAD) | External | `chacha20poly1305` crate (battle-tested) |
| Argon2id (KDF) | External | `argon2` crate (battle-tested) |
| SHA3/SHA2 | External | `sha3`, `sha2` crates |
| HMAC-SHA3 | External | `hmac` crate |
| HKDF-SHA3 | External | `hkdf` crate |
| Serpent CBC | External | `serpent` crate |
| Falcon-512/1024 | External | `falcon-rs` crate (FIPS 206) |
| Reed-Solomon | Custom | Parallel encoding support |
| NTRU Prime (sntrup761) | Custom | NIST-compatible encoding (supercop-20201130), CCA-secure KEM |
| Ed41417 (Curve41417) | Custom | Based on Bernstein et al. CHES 2014 paper |
| Native ChaCha20-Poly1305 | Custom | RFC 8439 reference, native Rust (zero-dep) |
| Native Poly1305 | Custom | RFC 8439 §2.5, native Rust |
| Hybrid signing | Custom | Combines Ed25519 + Falcon |
| Seed Blob | Custom | XChaCha20-Poly1305 + Argon2id |
| ChaCha20-DRBG | Custom | Auto-reseed after 16 MB |
| SipHash-c-d | Custom | Compute hardener (not a security boundary) |

## Standards Posture

The SDK deliberately mixes NIST-wire-compatible and non-NIST constructions.
Non-NIST choices are **design intent**, not oversight — but they divide into
two honest categories.

### NIST / standard-wire-compatible (interop is the goal)

| Component | Standard |
|-----------|----------|
| sntrup761 (default backend) | NIST PQC submission wire format (supercop-20201130); 100/100 official KAT vectors byte-exact |
| Falcon-512/1024 | FIPS 206 via `falcon-rs` |
| ML-KEM-768 | FIPS 203 via `ml-kem` (optional) |
| ML-DSA | FIPS 204 via `ml-dsa` (optional) |
| SLH-DSA | FIPS 205 via `slh-dsa` (optional) |
| Ed25519 | FIPS 186-5 EdDSA via `ed25519-dalek` |
| Ed448 | FIPS 186-5 EdDSA via `ed448`/`ed448-goldilocks` (impl is pre-release) |
| X25519 | RFC 7748 via `x25519-dalek` |
| ChaCha20-Poly1305 | RFC 8439 (native + `chacha20poly1305` crate) |
| SHA-2/SHA-3/HMAC/HKDF | FIPS 180/202, RFC 2104/5869 |
| Argon2id | RFC 9106 |

### Deliberately non-NIST (added properties or different goals)

| Component | Rationale |
|-----------|-----------|
| ChaCha20-BLAKE3 AEAD | Committing AEAD (key+nonce committed in tag) — a property standard AEADs lack; BLAKE3 throughput |
| Hybrid signing (Ed25519+Falcon, etc.) | Dual-algorithm robustness: stays secure if *either* half holds — exceeds any single NIST algorithm's assurance in PQ-transition threat models |
| sntrup761 `ntru-blake3`/`ntru-shake*` backends | Non-wire-compatible by design (perf/experimentation); default remains NIST-compatible |
| Argon2id Sovereign tier (256 MiB) | Exceeds RFC 9106 minimums for high-value seeds |
| `unicode_cipher` recovery phrases | Deliberately **not** BIP-39: Unicode codepoint wordlist + SHA-3-256 checksum |
| Skein-512/1024 | SHA-3 finalist, tree-hashing, non-NIST |
| Serpent | AES finalist, non-NIST |
| Ed41417 / Curve41417 | Published (CHES 2014) but nonstandard curve — *different, not proven stronger* |
| SipHash-c-d | Custom parameter choice — compute hardener, not a security boundary |
| ChaCha20-DRBG, secp256k1 internals | Custom implementations — *unreviewed, not claimed stronger* |

**Honest caveat:** "stronger than NIST" holds for *compositions and
parameters* (hybrid robustness, committing AEAD, larger memory-hard bounds)
where the added property is definable. For individual custom
implementations (Ed41417, secp256k1 internals, DRBG, NTRU Prime itself),
non-NIST means *unreviewed* — superiority is not claimed without external
analysis (Phase 13).

## Known Properties

### Constant-time

- **NTRU Prime**: Uses constant-time comparisons where applicable
- **Falcon**: Relies on `falcon-rs` (FIPS 206) implementation
- **Ed41417**: Scalar multiplication uses Montgomery ladder
- **Poly1305**: Field arithmetic avoids secret-dependent branches
- **ChaCha20**: Standard ARX construction, no secret-dependent branches

### Side channels

- No timing-based side channels are explicitly mitigated in all paths
- Memory is zeroed where applicable (via `zeroize` crate)
- Key material should be locked in memory (requires `mlock` support)

## Recommendations

1. **Do not use custom implementations in production without independent audit**
2. The SDK provides both external (battle-tested) and native implementations — use the external versions via the `aead` module for production workloads
3. Native implementations are provided for environments requiring zero external crypto dependencies
4. For post-quantum components (NTRU Prime, Falcon, Ed41417), there are no battle-tested alternatives

## Threat Modeling for Application Authors

If your application serves users facing legal compulsion or physical coercion,
the SDK ships **no duress or self-destruct primitive** by deliberate design.

Active-wipe features have been charged under 18 U.S.C. §2232 ("destruction of
property to prevent seizure") following border incidents where users entered
a duress PIN that triggered a device wipe (see the Tunick matter, TechCrunch
2026-07-24). The SDK cannot expose a general "destroy" API without inviting
application developers to wire it to UI affordances that expose end users
to potential destruction-of-evidence prosecution.

See [`docs/duress-pattern.md`](docs/duress-pattern.md) for app-level guidance
on:

- Pattern P1: Operational deniability (clean-traveler device)
- Pattern P2: Distinguishable decoy-vault routing (i.e., no destruction occurs)
- Pattern P3: Plausible deniability (VeraCrypt-style; operationally fragile)
- Jurisdictional risk matrix (US, UK, EU, Five Eyes, authoritarian regimes)
- Working pseudocode using only the SDK's existing public API

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately to the repository maintainers. Do not open a public issue.

### Disclosure process

1. Report the vulnerability privately via the repository's security advisories
   page (GitHub Security Advisories) or direct contact with maintainers.
2. Maintainiers will acknowledge receipt within 72 hours and provide an
   initial assessment within 7 days.
3. A fix or mitigation will be developed and coordinated disclosure scheduled.
4. The reporter will be credited unless they prefer to remain anonymous.

## Dependency Policy

### Pinning

Critical cryptographic dependencies are pinned to exact versions (`=x.y.z`)
to prevent unexpected breaking changes or subtle behavioral differences in
cryptographic primitives:

| Dependency | Version | Pin Reason |
|-----------|---------|------------|
| `falcon-rs` | `0.2.5` | FIPS 206, NIST KAT verified |
| `chacha20poly1305` | `=0.10.1` | Stable API; 0.11 has breaking changes |
| `argon2` | `=0.5.3` | Matches password-hash traits used internally |
| `sha2` | `=0.10.8` | Compatible with Digest trait usage |
| `rand` | `=0.8.5` | Intentionally pinned to avoid getrandom 0.3 migration |
| `unicode-normalization` | `=0.1.25` | NFKC canonical-form checks; input-validation dep |

### Update cadence

- Non-critical dependencies: update quarterly or when a security advisory
  requires it.
- Pinned cryptographic dependencies: update only after testing all affected
  code paths with the full test suite (including KAT vectors, differential
  tests, and property tests).
- New dependencies: must be reviewed for license compatibility (via
  `cargo-deny`), security advisories (via `cargo-audit`), and maintenance
  status before being added.

### Advisory response

- `cargo audit` and `cargo deny check` run on every PR and push.
- Vulnerabilities in production dependencies: fix immediately or pin to a
  non-vulnerable version.
- Vulnerabilities in dev-only dependencies: fix in the next release cycle
  unless the vulnerability affects the build or test integrity.
- All accepted advisories are documented in `deny.toml` with a reason.

### Supply-chain checks

- **cargo-audit**: checks Cargo.lock against the RustSec advisory database
- **cargo-deny**: checks licenses, duplicate versions, yanked crates, and
  banned sources
- Both run in CI on every push and PR

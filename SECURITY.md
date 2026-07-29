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
| Falcon-512/1024 | External | `falcon-rust` crate |
| Reed-Solomon | Custom | Parallel encoding support |
| NTRU Prime (sntrup761) | Custom | Based on NIST Round 3 reference implementation |
| Ed41417 (Curve41417) | Custom | Based on Bernstein et al. CHES 2014 paper |
| Native ChaCha20-Poly1305 | Custom | RFC 8439 reference, native Rust (zero-dep) |
| Native Poly1305 | Custom | RFC 8439 §2.5, native Rust |
| Hybrid KEM | Custom | Combines X25519 + NTRU + Ed41417 |
| Hybrid signing | Custom | Combines Ed25519 + Falcon |
| Seed Blob | Custom | XChaCha20-Poly1305 + Argon2id |
| ChaCha20-DRBG | Custom | Auto-reseed after 16 MB |
| SipHash-c-d | Custom | Compute hardener (not a security boundary) |

## Known Properties

### Constant-time

- **NTRU Prime**: Uses constant-time comparisons where applicable
- **Falcon**: Relies on `falcon-rust` implementation
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

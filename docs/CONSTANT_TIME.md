# Constant-Time Posture

Status of constant-time (CT) discipline after the Phase 12.1 sweep.
This document records *which* operations are designed to be CT, which
deliberately are not, and where residual risk lives. "Designed CT" means
the source contains no secret-dependent branch or loop bound — it is
not a certified guarantee; compiler codegen is verified by Phase 13's
external review.

## Designed constant-time

| Operation | Mechanism |
|-----------|-----------|
| Signature/MAC/tag comparisons | `subtle::ConstantTimeEq` everywhere (`verify_sig_and_digest`, `ct_eq_or_failed`, AEAD tag check, OCRA compare, NTRU confirm hash) |
| NTRU Prime decapsulation | CCA failure select is arithmetic (`mask = all_match - 1`, `r ^ (mask & (r ^ rho))`); `count_weight` is `abs().sum()` (branchless) |
| NTRU Prime keygen sort | `zx::random::min_max` is a branchless i64-sign-mask swap (crypto_sort_int32 style) |
| secp256k1 scalar multiplication | Fixed 256-iteration double-and-add with `conditional_select` — no per-bit branch |
| secp256k1 point add/double | General formula always evaluated; identity/doubling/inverse cases resolved by limb-mask select |
| secp256k1 field/scalar reduce | Borrow-chain `is_gte_*`, masked `conditional_add_*`, fixed-trip REDC carry propagation, 4-fold `reduce_512` (R256 < 2^129), mask-select `reduce_257` |
| x25519 all-zero scalar check | `subtle::ConstantTimeEq` (no short-circuit) |
| Hash functions (SHA-3, BLAKE3, SHAKE, SHA-512) | Data-oblivious by construction (upstream or vendored fixed rounds) |

## Deliberately not constant-time (public data only)

| Site | Why it's acceptable |
|------|---------------------|
| `secp256k1` `pow` square-and-multiply | Branches on the *exponent*, always a public constant (p-2, n-2, (p+1)/4) |
| `secp256k1` point decoding / `verify` parsing | Early returns on malformed *public* input — standard rejection path |
| `error_correction` syndrome early-continue | Leaks corruption *positions* — adversary-observable metadata in every transport/backup scenario; `GaloisField::mul` itself is branchless so contents don't leak |
| `GaloisField::exp` | Branches on public exponents/matrix entries only (documented at the site) |
| `compressed`/`blob` header parsing | Branches on untrusted container metadata — structure is public |
| `drbg::otp` base32 decode | Public input |

## Residual risks for external review

- `internal/secp256k1` is hand-rolled — codegen verification pending
  (Phase 13). Consider replacing with `k256` at 1.0 if the reviewer
  prefers a maintained implementation.
- `to_affine`'s identity early-return and `ProjectivePoint::IDENTITY`
  encoding are public-observable states; scalar-mul results are identity
  only for invalid (≡0 mod n) scalars rejected upstream.
- `ml_kem::encapsulate`/`decapsulate` delegate to the upstream `ml-kem`
  crate — that crate's CT posture is upstream's contract.
- `falcon-rs` verify/sign likewise delegate to the upstream FIPS 206
  implementation.

## Verification

`tests/timing_tests.rs` holds wall-clock smoke tests (gross-leak
detection, ±3x jitter tolerance): AEAD tag paths, Poly1305 content
independence, NTRU decap valid-vs-invalid, Schnorr key-density
independence. These detect obvious leaks only — they cannot prove
constant-time behavior.

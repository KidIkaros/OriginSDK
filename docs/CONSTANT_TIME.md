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
| secp256k1 scalar/point/field ops | Delegated to `k256 0.14` (RustCrypto): fiat-crypto field arithmetic and complete-formula point ops are constant-time by construction |
| x25519 all-zero scalar check | `subtle::ConstantTimeEq` (no short-circuit) |
| Hash functions (SHA-3, BLAKE3, SHAKE, SHA-512) | Data-oblivious by construction (upstream or vendored fixed rounds) |

## Deliberately not constant-time (public data only)

| Site | Why it's acceptable |
|------|---------------------|
| `ec_schnorr` point decoding / `verify` parsing | Early returns on malformed *public* input — standard rejection path (k256 `from_sec1_bytes`) |
| `error_correction` syndrome early-continue | Leaks corruption *positions* — adversary-observable metadata in every transport/backup scenario; `GaloisField::mul` itself is branchless so contents don't leak |
| `GaloisField::exp` | Branches on public exponents/matrix entries only (documented at the site) |
| `compressed`/`blob` header parsing | Branches on untrusted container metadata — structure is public |
| `drbg::otp` base32 decode | Public input |

## Residual risks for external review

- ~~`internal/secp256k1` is hand-rolled~~ — **resolved**: the vendored
  arithmetic was replaced by `k256 0.14` (RustCrypto, fiat-crypto codegen,
  externally maintained). Byte-equivalence with the vendored impl was
  verified before removal (scalar repr/reduce parity, generator-mul SEC1
  encoding, cross-decoding). The EC-Schnorr Fiat-Shamir composition in
  `src/ec_schnorr.rs` remains in review scope.
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

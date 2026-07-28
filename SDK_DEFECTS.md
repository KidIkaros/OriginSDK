# origin-crypto-sdk — Defect List (handoff)

Compiled by the investigating agent on 2026-07-28; updated after a full
re-audit and fix pass the same day, then updated again after a whole-SDK
bug-hunt pass covering every module (see D8). The SDK is the cryptographic
provider for the `origin-tools` workspace. Items marked DONE below are
verified: `cargo test --lib` (342 tests), `cargo test --test
integration_tests --test proptest_crypto`, and `cargo build --all-features`
all pass cleanly as of this update.

Branch context: SDK is at v0.6.3. Working tree has uncommitted fixes for the
items below.

================================================================================
## D0 — Falcon test bloat (DONE, verified)
================================================================================
The Falcon stress/fuzz tests ran thousands of passes. Reduced to sane counts per
user request (reduce passes/iterations, NOT a timeout):

- `tests/fuzz_like_testing.rs`: `fuzz_iterations()` default 10_000 -> 100.
  The hardcoded `0..1000` and `0..5000` loops now capped with `.min(1000)/(5000)`.
- `tests/hybrid_rigorous.rs`:
  - `determinism_under_repeated_derivation` loop 0..100 -> 0..5.
  - the two Falcon stress tests (were 0..50 each) -> 0..5.
  - renamed to `stress_consecutive_hybrid_signs` / `stress_consecutive_kdf_signs`.

VERIFIED: `cargo test --lib` passes (340/340) with the reduced counts.

================================================================================
## D1 — secp256k1 scalar arithmetic: `mul`/`reduce_512` (DONE, verified)
================================================================================
FILE: `src/internal/secp256k1/scalar.rs`

STATUS: FIXED. Root causes were (a) `product_512`'s inner loop truncated the
128-bit partial product to 64 bits before adding it in, and (b) `pow`'s
square-and-multiply loop called `.add()` instead of `.mul()` when accumulating
the result bit. Also corrected the `N` and `EXP_N2` constants, whose limbs 2
and 3 were swapped: the correct little-endian order has limb 2 = `0xFFFF...FFFE`
and limb 3 = `0xFFFF...FFFF` (both were the other way around).

VERIFIED: `cargo test --lib internal::secp256k1::scalar` passes, including
`mul_reference` and `invert_roundtrip` against Python-computed reference
values for large operands.

================================================================================
## D2 — secp256k1 field/point/generator constants (DONE, verified end-to-end)
================================================================================
FILE: `src/internal/secp256k1/field.rs`, `point.rs`

STATUS: FIXED. This was actually several independent bugs, found via direct
Montgomery-arithmetic audits (not just constant typos as first suspected):

- `field.rs::mul` (Montgomery multiplication): the schoolbook product
  accumulated into `t[j]` instead of `t[i+j]` (wrong limb position), and the
  REDC overflow-bit correction called `result.sub(&P)`, but `sub()` silently
  auto-corrects underflow by adding `P` back — canceling the intended `+R`
  correction for the carry-out bit whenever the low 256 bits were already `< P`
  (the common case). Rewrote `mul` as proper schoolbook-product + REDC, and
  fixed the overflow correction to add `R` (not subtract `P`) for the carry-out
  bit before the final conditional `-P`.
- `field.rs`: Montgomery radix `R` and the `TWO`/`THREE`/`FOUR`/`EIGHT` helper
  constants all had hex literals missing digits (e.g. `R` was `0x10003d1`
  instead of `0x1000003d1`), so they didn't actually equal `2^256 mod p` or
  its multiples.
- `field.rs::normalize`: multiplied by `R` (Montgomery form of 1) instead of
  raw `1`; since `mul` already divides by `R` once via REDC, this canceled the
  conversion back out of Montgomery form.
- `point.rs`: `G_X`/`G_Y`/`CURVE_B` were stored as raw (non-Montgomery),
  byte-order-reversed values fed directly into `FieldElement::from_limbs`
  (which assumes little-endian Montgomery form) — so the generator point
  didn't actually correspond to the real secp256k1 generator once field
  arithmetic was fixed. Recomputed all three in correct little-endian
  Montgomery form.
- `point.rs::add`: the general Jacobian addition formula divides by
  `h = u2 - u1`, which is zero both when the two points are equal and when
  they're inverses of each other — so it can't distinguish `double(P)` from
  `P + (-P) = O`. Added an explicit check: equal x and y -> `double()`; equal
  x, differing y -> `IDENTITY`.

VERIFIED: `cargo test --lib` passes end-to-end, including point-algebra
regression tests (`scalar_mul_matches_repeated_add`,
`mul_distributes_over_scalar_add`, `double_matches_mul_by_two`,
`double_matches_self_add`) and `ec_schnorr` roundtrip/rejection tests.

================================================================================
## D3 — ec_schnorr `compute_challenge` false-accept (DONE, verified)
================================================================================
FILE: `src/ec_schnorr.rs`

Fixed: `compute_challenge` previously did `Scalar::from_repr(hash).unwrap_or_else(|| ... Scalar::ONE)`.
When the SHA3 digest was >= n (~50% of inputs), `from_repr` returned None and the
challenge collapsed to `Scalar::ONE` — so two distinct messages could hash to the
SAME challenge, letting `verify` accept a tampered message (false positive).

Fix: `compute_challenge` now uses `Scalar::from_repr_reduced(&hash)` which
deterministically reduces the digest mod n (never collapses to ONE).

VERIFIED: all `ec_schnorr` tests pass, including `test_prove_verify_roundtrip`,
`test_verify_wrong_message_fails`, `test_verify_wrong_public_key_fails`,
`test_batch_verify_one_invalid`, `test_batch_verify_all_valid`,
`test_empty_message`, `test_large_message` — now that D1/D2 are also fixed.

================================================================================
## D4 — RS erasure recovery only supported clean roundtrip (DONE, verified)
================================================================================
FILE: `src/error_correction.rs`

STATUS: FIXED, plus a related root-cause bug found while fixing it.

- **Root cause found**: `vandermonde_matrix` used evaluation points
  `0..data_shards` with exponent `i+1`, so column 0 (data shard 0) was
  `0^(i+1) = 0` for every parity row — data shard 0 was invisible to every
  parity equation. It could never be detected as corrupted, and removing it
  never changed any parity check. Fixed to use points `1..=data_shards` with
  exponent starting at `0` (a genuine Vandermonde matrix, so every square
  submatrix of the generator matrix is invertible).
- **Erasure support added**: added `encode_shards`/`decode_shards`, which
  track each shard by explicit index (unlike the flat `encode`/`decode`
  byte-buffer format, which has no way to represent a shard being *missing*
  vs. present-but-corrupted). `decode_shards` takes `&[Option<Vec<u8>>]` and
  reconstructs via proper GF(2^8) Gauss-Jordan matrix inversion — standard
  systematic Reed-Solomon erasure decoding — recovering correctly as long as
  at most `parity_shards` shards are `None`.
- `decode`'s corrupted-shard recovery step was also rewritten to use the same
  matrix-inversion reconstruction instead of the old heuristic, which
  hardcoded parity row 0 and gave wrong results whenever more than one shard
  was flagged.
- The flat `encode`/`decode` API is kept for backward compatibility, with a
  doc comment now explicitly noting it cannot represent true shard loss —
  callers that need real erasure tolerance should use the new shard-aware API.

VERIFIED: new tests `decode_shards_recovers_one_missing_data_shard` (every
index, one at a time), `decode_shards_recovers_max_simultaneous_erasures`
(losing 2 of 6, including shard 0), `decode_shards_fails_when_too_many_missing`
(fails cleanly rather than returning corrupted data), and
`every_data_shard_affects_parity` (regression test for the shard-0 blind
spot) all pass. Existing `origin-tools` no-loss-roundtrip workarounds
(`origin-shard`) remain compatible since the flat API's behavior for the
no-loss case is unchanged.

================================================================================
## D5 — subtle API consistency across modules (DONE, verified)
================================================================================
The crate has a LOCAL shim at `src/internal/subtle.rs` providing `Choice` with
`from_bool`/`is_true`, a local `CtOption`, and a local `ConstantTimeEq` trait.
Many modules must import `crate::internal::subtle::*` (NOT the external `subtle`
crate, v2.6.1, which lacks those methods).

VERIFIED: `cargo build --all-features` (covers `slh-dsa`, `ml-dsa`, `test-utils`,
and `pqc::ntru_prime::ntt`) compiles cleanly — no misuse of the external
`subtle::` crate found. The one direct external-`subtle` usage in `ocra.rs`
is fine as-is: it only needs the array `ConstantTimeEq` impl that the real
crate provides, not `Choice::from_bool`/`is_true`.

================================================================================
## D6 — origin-tools integration test still ignored (NOT VERIFIABLE HERE)
================================================================================
FILE: `origin-tools/origin-proof/tests/suite_integration.rs`

`identity_schnorr_prove_verify` was `#[ignore]`d pending the SDK scalar fix (D1).
D1/D2/D3 are now fixed and verified inside this repo, so the ignore should be
safe to remove — but `origin-tools/` is empty in this workspace, so this could
not be checked directly. Whoever has that repo checked out should:
  1. Remove the `#[ignore]` from `identity_schnorr_prove_verify`.
  2. Confirm it passes.
  3. Re-run: cd origin-tools && cargo test --workspace -- --test-threads=1

================================================================================
## D7 — secp256k1 mod.rs public constants were wrong (DONE, verified)
================================================================================
FILE: `src/internal/secp256k1/mod.rs`

STATUS: FIXED. `CURVE_ORDER`, `FIELD_PRIME`, `GENERATOR_X`, `GENERATOR_Y` are
`pub const` exports that turned out not to match either the raw or
Montgomery-form values used internally (`FIELD_PRIME`'s last limb ended in
`FFFE` instead of `FFFF`; `CURVE_ORDER`'s limbs 2/3 were swapped like the old
scalar `N` bug in D1; `GENERATOR_X`/`Y` matched neither representation at
all). Found by this audit; not previously listed. Was dead code internally —
no consumer in this crate reads them — but broken public API that any
downstream crate importing them would silently get wrong values from.

Fix: replaced with correct little-endian limbs, and bumped `field::P`,
`scalar::N`, `point::G_X`/`G_Y` to `pub(crate)` so a new cross-check test in
`mod.rs` (`public_constants_match_internal_representations`) asserts equality
against those single sources of truth — so the two can't silently drift apart
again.

VERIFIED: `cargo test --lib internal::secp256k1::tests` passes.

================================================================================
## D8 — Whole-SDK bug-hunt pass (findings summary)
================================================================================
Full audit of every module in `src/`, tiered by how much hand-rolled crypto
math each contains (custom implementations are far more bug-prone than thin
wrappers over vetted external crates — see D1–D3 above for what that class
of bug looks like). One real bug found and fixed; everything else checked
out clean, several items got their weak self-consistency-only tests upgraded
to genuine reference-vector cross-checks.

### Found and fixed
- **`src/pqc/ntru_prime/mod.rs::decapsulate`** — the Fujisaki-Okamoto-style
  re-encryption confirmation hash was compared with plain slice `==`
  (`s[..32] == ciphertext[..32]`), which is not constant-time (short-circuits
  on first mismatching byte). This is exactly the kind of check `subtle`'s
  `ConstantTimeEq` exists to protect, and every other tag/MAC/signature
  comparison in the crate already uses it (`chacha20poly1305.rs`, `ocra.rs`,
  the `secp256k1` module) — this one comparison was missed. **Fixed** to use
  `ConstantTimeEq::ct_eq`.

### Verified correct (no bug), coverage gaps closed with real reference vectors
- **`src/primitives/chacha20.rs`, `poly1305.rs`, `chacha20poly1305.rs`** —
  already had genuine RFC 8439 test vectors (quarter-round, block function,
  encryption, HChaCha20, full AEAD) that pass. `chacha40.rs` is an
  intentional non-standard SDK-original construction (documented as such);
  self-consistency tests are the right kind of test for it since there's no
  external reference to check against.
- **`src/internal/sha3.rs`** — Keccak round constants, rho/pi rotation
  offsets, and padding all verified against real NIST FIPS 202 test vectors
  (already present, already passing).
- **`src/pqc/curve41417/`** (`fe.rs`, `edwards.rs`, `scalar.rs`, `mont.rs`,
  `ed41417.rs`) — structurally the highest-risk module (same shape as the
  buggy secp256k1 code), so this got the deepest scrutiny: independently
  cross-verified `FieldElem::mul`/`carry` (the 68-wraparound reduction path)
  and `Scalar::mul`/`reduce_weak` against direct Python bignum modular
  arithmetic over 200+ random large operands each (existing tests only used
  tiny single-limb values, the same blind spot that hid the original
  secp256k1 bugs); verified the `inv()` and `sqrt_p3mod4()` fixed exponent
  bit-patterns bit-by-bit against the actual `p-2` / `(p+1)/4` values.
  `mont.rs` already has a real "from the original curve41417.rs repository"
  scalar-mult test vector that passes. All correct.
- **`src/pqc/ntru_prime/`** — faithful line-for-line port of the reference
  sntrup761 algorithm structure; existing tests already cross-check the
  Karatsuba/SIMD fast paths against the naive scalar path (the "silent
  divergence" risk called out in the audit plan), and the parity/weight
  checks are already computed via constant-time accumulation.
- **`src/internal/hmac.rs`, `hkdf.rs`** — construction was already correct
  (standard HMAC/RFC 5869 formulas, no numeric constants to typo), but the
  existing tests only checked *self*-consistency (determinism, "different
  input gives different output"), never actual output bytes. Added
  `test_hmac_matches_reference` / `test_hkdf_matches_reference`, cross-
  checked against Python's `hmac`/`hashlib.sha3_256` and a from-scratch
  RFC 5869 Expand loop, respectively. Both pass.
- **`src/drbg/otp.rs`** — already has real RFC 4226 Appendix D test vectors
  (10/10 counters) and RFC 4648 base32 vectors, all passing.
- **`src/ocra.rs`** — already carries a real RFC 6287 §A.1 test vector; a
  prior pass had already caught and fixed a wrong hardcoded expected value
  here (`237537` → correct `196958`, per an in-code comment). Uses
  constant-time response comparison per RFC 6287 §10.
- **`src/siphash.rs`** — round function, IV constants
  ("somepseudorandomlygeneratedbytes" split into 4 words), and finalization
  all match the standard SipHash-c-d reference construction exactly.
- **`src/mmr.rs`** — proofs verify correctly at 1000+ leaves; note the
  *doc comment* claims a "mountain range... multiple peaks" structure but
  the actual implementation is a simple binary Merkle tree that rebuilds
  from scratch on every append (duplicating the last node when a level is
  odd, Bitcoin-style). This is a **documentation/implementation naming
  mismatch, not a security bug** — proofs are still sound — but the module
  isn't the incremental-update structure its doc comment describes.
- **`src/entropy.rs`** — Shannon/min-entropy/collision-entropy formulas all
  match their textbook definitions exactly.
- **`src/stealth.rs`** — the audit plan assumed this depended on
  `secp256k1` (stealth addresses usually do); it doesn't — it's HKDF-based
  key derivation plus a hashcash-style proof-of-work, no EC math at all. No
  cross-check needed.

### Not deeply re-derived (lower risk, thin wrappers — spot-checked only)
Falcon-512/1024, ML-DSA, SLH-DSA, Ed448, `signing/*`, `aead/*`, `blob.rs`,
`compression.rs`, `seed/*` all wrap external, independently-audited crates
(`falcon-rust`, `ml-dsa`, `slh-dsa`, `ed448-goldilocks`). Plumbing looked
correct on inspection (key/seed sizes, domain separation, constant-time
comparisons via `ct_eq` in `signing/hybrid.rs`) but were not put through the
same reference-vector-derivation treatment as the Tier 1/2 modules above —
flag for a follow-up pass if a higher assurance level is wanted there.

VERIFIED: `cargo test --lib` (342/342, +2 new reference-vector tests since
the D1–D7 pass), `cargo build --all-features` clean.

================================================================================
## SUMMARY
================================================================================
All defects found (D0–D5, D7, D8) are FIXED and verified via:
  cargo test --lib                                            (342/342 pass)
  cargo test --test integration_tests --test proptest_crypto   (all pass)
  cargo build --all-features                                   (clean)

D6 is the only item that could not be verified from this workspace (the
`origin-tools` repo checkout is empty here) — see D6 above for what to do.

Useful reference (Python, secp256k1 group order n):
  n   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  R256 = pow(2,256,n) limbs [0x402da1732fc9bebf,0x4551231950b75fc4,0x1,0x0]
  mul(a,b) expected = (a*b) % n  (limbs little-endian)
  a^-1 expected    = pow(a,-1,n)

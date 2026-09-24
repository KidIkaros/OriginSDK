# Design Audit — origin-crypto-sdk 0.7.1-rc.9

**Scope:** full crate (`src/`, ~25k lines; `tests/`, ~5.5k lines).
**Disciplines applied:** Clean Code, Clean Architecture (dependency rule /
SOLID / component principles), GoF design patterns, Functional Design.
**Method:** each finding is `smell → location → concrete fix`. Findings are
triaged by severity and assigned to a remediation step in the design-quality
plan that lands before ROADMAP_1_0_0 Phase 12.

Severity legend: **High** = structural, multiplies maintenance/error risk;
**Med** = real smell with a bounded fix; **Low** = polish.

---

## Findings summary

| ID | Discipline | Finding | Severity | Remediation step |
|----|-----------|---------|----------|------------------|
| CA-1 | clean-arch | `internal` is `pub` + `#[doc(hidden)]`; the bin target imports `origin_crypto_sdk::internal::getrandom` directly — the "internal" boundary leaks and is load-bearing for a shipped artifact | **High** | Step 1 |
| CA-2 | clean-arch | Three overlapping primitive tiers (`internal/` vendored impls, `primitives/` crate-internal blocks, `kdf/`+`aead/` public wrappers) with no documented dependency rules | Med | Step 1 |
| CA-3 | clean-arch | `x25519.rs` imports `crate::hkdf_blake3` / `crate::hkdf_sha3_256` via the crate-root facade instead of `crate::kdf::hkdf::*` — upward dependency through the facade | Med | Step 1 |
| CA-4 | clean-arch | `ocra.rs` couples to `drbg::otp::HashAlgorithm` — OTP hash enum lives in the DRBG module; OCRA (RFC 6287) and OTP (RFC 4226/6238) are different use cases | Med | Step 1 |
| CA-5 | clean-arch | `seed::SeedHandle::with_tier` declares `extern "C" { fn mlock }` inline inside a function — FFI detail inside domain code | Med | Step 1 |
| CA-6 | clean-arch | `#[doc(hidden)] pub` forms an undocumented second public surface: `mmr`, `error_correction`, `siphash`, `compression`, `blob`, `internal`, `poly1305`, `tier` — inconsistent with `pub(crate)` used for `primitives` | Med | Step 7 |
| CA-7 | clean-arch | `mmr.rs` (393 lines) is dead code — zero callers outside the module | Low | Step 7 |
| CA-8 | clean-arch | `prelude` re-exports `compression::{compress, decompress}` — the facade leaks a `#[doc(hidden)]` module's API | Med | Step 7 |
| CC-1 | clean-code | Six non-KDF hybrid constructions are copy-paste (identical `sign+hash` / `verify+ct_eq`, ~400 lines); three signature hybrids duplicate `sign`/`try_sign`/`verify` (~150 lines each) | **High** | Step 2 |
| CC-2 | clean-code | `impl std::fmt::Debug for HybridSigningKeyBundle` declared *inside* `from_seed_cached` behind `#[allow(non_local_definitions)]` | Med | Step 2 |
| CC-3 | clean-code | `hkdf_combine(salt, ikm, info, out)` forwards to `hkdf_sha3_256(ikm, salt, info, out)` — salt/ikm order swaps across the boundary | Med | Step 4 |
| CC-4 | clean-code | `once_cell::sync::Lazy` used in `pqc/ntru_prime/tables.rs` but `once_cell` is only a *transitive* dependency; `std::sync::LazyLock` (MSRV 1.80+, ours is 1.85) is used in `unicode_cipher.rs` — two mechanisms, one undeclared | Med | Step 1 |
| CC-5 | clean-code | Functions >100 lines: `error_correction::decode` (145), `compressed::decompress_decrypt` (142), `seed::gen::generate_with_entropy` (110), `ocra::ocra` (107), `entropy::analyze` (106) | Med | Step 5 |
| CC-6 | clean-code | `CryptoError::InvalidParameter(String)` is a catch-all used 64×; 9 `String`-payload variants mix with structured variants — callers can't match on the common cases | Med | Step 4 |
| CC-7 | clean-code | Panic-on-RNG-failure without fallible variant: `seed::gen` ×3 (`generate_with_entropy`), `drbg::ChaCha20Drbg::from_os_entropy`/`random_bytes`, `internal::rng::ChaCha20Rng::from_entropy` — inconsistent with the `fill_random`/`try_*` fallible-boundary policy used elsewhere | Med | Step 4 |
| CC-8 | clean-code | `derive_hybrid_keys(master_seed, domain, 32, 32, 32)` — three length params always called with the same constants; magic numbers as args | Low | Step 2 |
| CC-9 | clean-code | Stale docs: `lib.rs` `html_root_url` still says `0.4.0`; module-map comment lists `chacha40`/`chacha20` as modules though they are re-exports | Low | Step 7 |
| GOF-1 | gof | Hybrid constructions miss the Strategy/combinator abstraction: `verify = all components must verify` is a fold over component verifiers; `sign+hash` is `combine(sig_fn, hash_fn)`. Rust idiom: generics/free functions — not trait objects, preserving the crate's documented no-`dyn` stance | **High** | Step 2 |
| GOF-2 | gof | `BUNDLE_CACHE` is a Singleton with no injection seam — `from_seed_cached` reaches into a hidden global, untestable without the `CACHE_TEST_GUARD` mutex | Med | Step 3 |
| GOF-3 | gof | `AlgorithmId` + `DowngradePolicy` use exhaustive `match` — idiomatic Rust dispatch; a Registry pattern exists via the enum + FORMAT_REGISTRY. **Disposition: no pattern needed** | — | none |
| GOF-4 | gof | `legacy_shim` is a correct Adapter/Façade; `Argon2idBuilder` is a correct Builder; `SeedHandle::new`/`with_tier` arity is small enough that a Builder is not warranted. **Disposition: as designed** | — | none |
| FD-1 | functional | `static BUNDLE_CACHE: OnceLock<BundleCache>` + three `Mutex` fields — wrapped mutable state hidden at module scope; `from_seed_cached` looks pure but mutates process-global state | **High** | Step 3 |
| FD-2 | functional | Lazy tables (`SMALL_PRODUCT_TABLE`, `MOD_Q_TABLE`, `TWIDDLE_TABLE`, `DEFAULT_WORDLIST`) are memoized pure values — the correct FP pattern. **Disposition: keep; unify on `LazyLock`** | — | Step 1 |
| FD-3 | functional | Entropy effects sit at the `internal::getrandom` boundary correctly, but five call sites panic on failure instead of propagating (see CC-7) — the boundary exists; the error policy doesn't | Med | Step 4 |
| FD-4 | functional | `xor_combine` uses index loop + `Vec` alloc; `a.iter().zip(b).map(\|(x,y)\| x^y).collect()` is equivalent (verify no constant-time requirement before changing) | Low | Step 6 |
| FD-5 | functional | `SeedHandle`/`ChaCha20Drbg`/`ChaCha20Rng` hold mutable secret state wrapped in value types with `Drop` zeroization — correct wrapped-state discipline. **Disposition: as designed** | — | none |

---

## Discipline sections

### Clean Architecture — module circles and violations

Observed layering (from `crate::` import graph):

```
Main/drivers:   bin/origin-crypto.rs, examples/, prelude (facade)
Composition:    signing/{hybrid,wire}, aead, compressed, seed, blob,
                stealth, recovery, drbg, ocra, entropy, kdf
Schemes:        pqc/*, x25519, ec_schnorr, signing/{classical,postquantum}
Primitives:     primitives/* (pub(crate)), internal/* (vendored impls)
Vocabulary:     error, types, algorithm_id
```

Direction rule: dependencies may only point inward (down the list).
Confirmed violations: CA-1 (bin → internal), CA-3 (scheme → facade),
CA-4 (composition → sibling composition's enum), CA-5 (FFI detail inside
composition layer), CA-8 (facade → hidden module).

`blob.rs` fans out across `aead` + `kdf` + `primitives` + `seed` — a
composition-layer aggregator, acceptable, but it also reaches into
`internal` (`internal::hmac`); fine after sealing since same-crate.

`error_correction` is `#[doc(hidden)] pub` but consumed only by the
crate's own integration tests — an internal utility wearing a public
wrapper. Either move its tests in-crate and seal it, or document it.

### Clean Code — notable non-findings (audited, clean)

- Function bodies in the NTRU Prime kernels (`ntt`, `rq`, `encode`,
  `simd_poly`) are long but are crypto kernels where loop-level clarity
  and constant-time layout matter more than line count — excluded from
  the size rule by domain convention, pending Phase 12.1 CT review.
- `CryptoError`'s manual `Clone` (69 lines) is required because
  `std::io::Error` is not `Clone`; the impl is mechanical. Keep.
- Banner comments (`// =====`) are used consistently as section markers
  in large modules — house style; after Step 2 splits hybrid.rs they
  become unnecessary there, retained elsewhere.

### GoF — pattern disposition table

| Site | Verdict |
|------|---------|
| Hybrid constructions | **Strategy/combinator missing** → generic `verify_all` fold + type-level pairings (Step 2) |
| `BUNDLE_CACHE` | Singleton — keep global convenience, add ownable value type (Step 3) |
| `AlgorithmId`/`DowngradePolicy`/`FORMAT_REGISTRY` | Registry + exhaustive match — correct as-is |
| `legacy_shim` | Adapter — correct; removal at 1.0 |
| `wire.rs` encode/decode | Codec pair — correct |
| `Argon2idBuilder` | Builder — correct |
| `SeedHandle::new`/`with_tier` | Two-arg family — Builder rejected (overkill) |
| `Compressor::from_byte` | Byte→enum codec — correct |

### Functional Design — state inventory

| State | Classification | Disposition |
|-------|---------------|-------------|
| `BUNDLE_CACHE` + 3 Mutexes | wrapped mutable, hidden | isolate → Step 3 |
| `CACHE_TEST_GUARD` | test-only mutex | keep |
| `Lazy`/`LazyLock` tables & wordlist | memoized pure values | keep; unify mechanism (Step 1) |
| `SeedHandle` (seed, created, ttl, tier) | wrapped resource w/ Drop | as designed |
| `ChaCha20Drbg`/`ChaCha20Rng` buffers | wrapped state w/ Drop | as designed |
| `Instant` in `CacheEntry`/`SeedHandle` | effect at edge | as designed |
| `getrandom` call sites | effect boundary | keep boundary; fix panic policy (Step 4) |

No bare mutation found outside wrapped types. The crypto kernels'
in-place array mutation is local to pure functions — acceptable.

---

## Remediation map

Phase B executes eight ordered steps (see plan). Findings without a step
are dispositioned above as "as designed" / "no pattern needed" — none are
silently dropped.

**Wire-format guarantee:** every step is structure-only. `hybrid_golden_vectors`,
`known_answer_vectors`, `ntru_prime_kat`, `falcon_kat` are the tripwires.

---

## Disposition log

### Step 1 — layer sealing (commit `fbc215f`)

Resolved: CA-1 (`internal` → `pub(crate)`, bin migrated to `fill_random`),
CA-2 (`docs/ARCHITECTURE.md` records the layer rules), CA-3 (`x25519` imports
`crate::kdf::hkdf::*` directly), CA-4 (`HashAlgorithm`/`compute_hmac` moved to
`kdf::mac`; `drbg::otp` re-exports for compat), CA-5 (`internal/mlock.rs`),
CC-4 (`once_cell::Lazy` → `std::sync::LazyLock` in `ntru_prime/tables.rs`),
FD-2 (`LazyLock` unified). Bonus dead-code removal surfaced by sealing:
`internal::hex` (+10 dead tests), `internal::secp256k1` mirror constants
(+1 dead test), `internal::zeroize::Zeroizing` shim.

### Step 2 — `signing/hybrid.rs` decomposition

Resolved: CC-1 (six non-KDF constructions now share
`verify_sig_and_digest`; three signature hybrids share `both_must_verify`;
KDF construction shares `ct_eq_or_failed` — ~400 lines of copy-paste gone),
CC-2 (`impl Debug for HybridSigningKeyBundle` hoisted to top level in
`hybrid/bundle.rs`; `#[allow(non_local_definitions)]` deleted), CC-8
(`derive_hybrid_keys` now returns `HybridSubkeys` — named `[u8; 32]` fields
`ed25519`/`chacha20`/`hash`, magic-length params and the `(Vec, Vec, Vec)`
triple gone; call sites migrated), GOF-1 (combinator functions chosen over
trait objects — no `dyn`, preserving the crate's no-`dyn` stance).

New structure: `src/signing/hybrid/{mod,combinators,constructions,kdf,
bundle,cache,tests}.rs`. `mod.rs` keeps every previously public name at
`signing::hybrid::*` via `pub use` (verified by `legacy_shim`'s wildcard
re-export and all external test suites passing unchanged except the
`derive_hybrid_keys` call sites, which used the migrated API).

Verification: 457 lib tests, `hybrid_golden_vectors` (15),
`hybrid_rigorous` (37), `hybrid_security` (11), `falcon_kat` (20),
`integration_tests` (33), `rng_and_cache` (20) — all green; derived bytes
byte-identical (golden vectors), wire format untouched.

Not done here (deferred per plan): `BundleCache` remains the process-global
`BUNDLE_CACHE` behind the same public functions — its ownable-type redesign
is Step 3 (GOF-2/FD-1).

### Step 3 — `BundleCache` as an ownable value type

Resolved: GOF-2, FD-1. `BundleCache` is now `pub` with `new`/`Default`,
`get_or_insert(seed, domain, derive)`, `configure`, `clear`, `len`,
`is_empty`, and a redacted `Debug`. Callers that want explicit ownership
(per-tenant caches, test isolation) construct their own instance; the
process-global `BUNDLE_CACHE` remains as a documented convenience behind
the unchanged `bundle_cache_*` functions and `from_seed_cached`.
`get_or_insert` keeps the original behavior — `derive` runs while the
entry lock is held, so misses serialize. New test
`test_ownable_bundle_cache_is_independent_of_global` proves local and
global instances do not share entries.

### Step 4 — error and boundary hygiene

Resolved: CC-3, CC-6 (partial, by design), CC-7, FD-3.

- **CC-3** `hkdf_combine` is now `#[deprecated]` — it was a pure
  pass-through whose only effect was permuting `(salt, ikm)` vs the public
  `kdf::hkdf::hkdf_sha3_256(ikm, salt)` convention. All in-crate callers
  migrated; the shim remains exported for downstream callers.
- **CC-7/FD-3** every OS-entropy call site now has a fallible variant:
  `ChaCha20Rng::try_from_entropy`, `ChaCha20Drbg::try_from_os_entropy` /
  `try_random_bytes`, `seed::gen::try_generate` / `try_generate_with_entropy`,
  `ChaCha20Blake3::try_generate_nonce` / `try_generate_key`. Infallible
  forms delegate to the `try_*` form with a documented `# Panics`
  contract (previously `aead`/`types` duplicated the RNG call instead of
  delegating). Failures map to `CryptoError::Io`, matching `fill_random`.
- **CC-6** miscategorized uses remapped to existing structured variants:
  Falcon `SizeError`/`InternalError` → `Pqc`; `SchnorrError::From` now maps
  `InvalidPublicKey` → `InvalidKey`, `VerificationFailed` →
  `AuthenticationFailed`, `RngFailed` → `Io`; `compressed`/`blob`
  container parse failures (13 sites) → `Serialization`. The remaining
  `InvalidParameter` uses are genuine parameter validation (empty seeds,
  expired handles, digit ranges, wordlist checks) — the catch-all is the
  correct category there per the error vocabulary docs.
- **Bug fixed in passing:** `seed::gen` compressed caller-supplied entropy
  through `try_into::<[u8;32]>().unwrap_or([0;32])`, silently producing an
  all-zero keyed-BLAKE2b key for any entropy ≠ 32 bytes. The key pool is
  now `sha3_256(entropy ‖ "seed-gen-key")` — domain-separated from the msg
  and salt pools. This changes deterministic outputs for the
  `Some(entropy)` path only (a testing seam with no pinned vectors);
  the OS-RNG path is unchanged. Intermediate key/msg material is now
  zeroized instead of plain-dropped.

### Step 5 — long-function decomposition

Resolved: CC-5. All five functions decomposed into named helpers with
single responsibilities; every public signature, error condition, and
error message preserved. No wire-format or cryptographic changes.

- `error_correction::decode` (145→4 lines of orchestration): split into
  `parse_encoded` (length/shard validation + split),
  `correct_single_shard_errors` (per-byte syndrome decode, in place),
  and `reassemble` (concat + truncate). The bounded-distance warning and
  the `GaloisField::inv` pivot invariant are documented on the helper.
- `compressed::decompress_decrypt` (142→20): split into
  `ParsedHeader::parse` (fixed-header decode → `ParsedHeader` struct)
  and `decrypt_chunks` (per-chunk authenticate-then-decrypt loop).
  Verify-before-decompress ordering preserved.
- `seed::gen::generate_with_entropy` (~110→~60): the four `SeedVariant`
  match arms extracted to `chain_blake2b_shake256`,
  `chain_blake2b_sha3_256`, `chain_blake2b_sha512`,
  `chain_shake256_sha3_256` — the construction table is now readable as
  a table.
- `ocra::ocra` (107→~45): split into `build_ocra_message`
  (`M = C‖Q‖P‖S‖T` assembly) and `dynamic_truncate` (RFC 4226 §5.4
  truncation + decimal reduction).
- `entropy::analyze` (106→~20): split into `byte_frequencies`,
  `entropy_stats` (Shannon/min/collision), `chi_squared_stat`,
  `bit_bias`, and `EntropyMetrics::zero` for the empty-input early
  return.

Verification: 458 lib tests + all integration suites
(`malformed_input` 20, `proptest_crypto` 30, `hybrid_golden_vectors` 15,
`hybrid_rigorous` 37, `integration_tests` 33, `rng_and_cache` 20, and
all remaining binaries) pass; 13 doc tests pass; `cargo fmt --check`
clean; docs build shows only pre-existing `-W unsafe-code` warnings.

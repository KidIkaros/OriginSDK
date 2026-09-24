# Architecture — module layers and dependency rules

This document defines the crate's internal layering (established during the
0.7.x design-quality pass; see `docs/DESIGN_AUDIT.md`). The compiler enforces
the bottom two boundaries (`internal` and `primitives` are `pub(crate)`);
the rest is enforced by review.

## Layers

Dependencies may only point **inward** (down this list). A module may not
name anything from a layer above it.

```
┌─────────────────────────────────────────────────────────────┐
│ Main / drivers                                               │
│   src/bin/origin-crypto.rs, examples/, prelude (facade)        │
├─────────────────────────────────────────────────────────────┤
│ Composition / use cases                                      │
│   signing::{hybrid, wire}, aead, compressed, seed, blob,       │
│   stealth, recovery, drbg, otp (drbg::otp), ocra, entropy, kdf │
├─────────────────────────────────────────────────────────────┤
│ Schemes (algorithm adapters)                                 │
│   pqc::*, x25519, ec_schnorr, signing::{classical,postquantum} │
├─────────────────────────────────────────────────────────────┤
│ Primitives (crate-private)                                   │
│   primitives::* — crate-internal building blocks             │
│   internal::*   — vendored implementations (sha3, hmac, hkdf,  │
│                   rng, subtle, zeroize, getrandom, mlock)    │
├─────────────────────────────────────────────────────────────┤
│ Domain vocabulary (innermost — no inward deps)               │
│   error, types, algorithm_id                                 │
└─────────────────────────────────────────────────────────────┘
```

## Rules

1. **`internal` is `pub(crate)`.** Nothing outside the crate may name it.
   Public consumers reach OS entropy via [`crate::fill_random`] and the
   deterministic CSPRNG via [`crate::drbg::ChaCha20Rng`].

2. **`primitives` is `pub(crate)`.** Selected items are re-exported at the
   crate root (`blake3`, `chacha20`, `chacha40`, `sha3_256`, `sha3_512`);
   that re-export list *is* the public primitives surface.

3. **Composition modules do not declare FFI.** `extern "C"` lives in
   `internal/` only (currently `internal::mlock`, `internal::getrandom`).

4. **Composition modules do not depend on sibling composition modules'
   internals.** Shared vocabulary moves inward — e.g. `HashAlgorithm` and
   `compute_hmac` live in `kdf::mac` (the MAC layer) and are used by both
   `drbg::otp` and `ocra`, which re-export/`use` rather than duplicate.

5. **Effects at the edges.** OS entropy (`internal::getrandom`), memory
   locking (`internal::mlock`), time (`Instant`), and I/O happen at
   boundary points, never buried inside pure transformations. Fallible
   effect calls get `try_*`/`Result` variants; panic-on-failure needs a
   documented `# Panics` contract (see CONTRIBUTING.md).

6. **Wrapped state only.** Mutable state lives inside named wrappers
   (`SeedHandle`, `ChaCha20Drbg`, `BundleCache`); the only process-global
   mutable state is `BUNDLE_CACHE` (see `signing::hybrid::cache`), which is
   documented and bounded. `BundleCache` is an ownable value type — the
   global is a convenience wrapper over one instance, not a requirement.

7. **Wire formats are frozen by golden vectors.** `signing::wire`,
   `blob` (Seed Blob v2), `compressed`, and the NTRU/Falcon codecs must
   not change byte output without a FORMAT_REGISTRY bump. Refactors are
   structure-only; `tests/hybrid_golden_vectors.rs` is the tripwire.

## Where new code lives

| Adding... | Put it in |
|-----------|-----------|
| A new signature/KEM scheme | `pqc/<scheme>.rs`, adapter in `signing::postquantum` |
| A hash/MAC/KDF helper | `kdf::` (public) or `internal::` (vendored impl) |
| A hybrid construction | `signing::hybrid::` submodules |
| A serialization format | `signing::wire` or the owning module + FORMAT_REGISTRY entry |
| A utility with no crypto deps | `types.rs` / `error.rs` (vocabulary) or its own leaf module |
| Anything with `unsafe`/FFI | `internal/` |

## Known deliberate exceptions

- `prelude` is a flat facade over every layer — by design (convenience
  adapter, the "composition root" for downstream imports).
- `blob.rs` fans out to `aead` + `kdf` + `primitives` + `seed` — it is a
  composition aggregator by design.
- `error_correction`, `siphash`, `compression`, `blob`, `mmr` remain
  `#[doc(hidden)] pub` pending the Step-7 surface decision (seal vs.
  document). `error_correction` is consumed only by the crate's own
  integration tests.

# Release 0.4.0

**Release date:** 2026-06-10

This is a major API quality and security hardening release. It introduces
typed wrappers for keys and nonces, structured error variants, constant-time
verification on hybrid paths, a builder for Argon2id, feature-gated test
utilities, fuzz targets, CI on every push, and complete documentation.

## Highlights

### Type Safety
- **`Seed`**, **`XNonce`**, **`CNonce`** newtypes (in `types` module) — catch
  length mismatches at construction time instead of in verify
- Updated examples to demonstrate the new wrappers

### Error Handling
- Structured `CryptoError` variants with typed payloads:
  - `InvalidKeyLength { algorithm, expected, got }`
  - `InvalidNonceLength { algorithm, expected, got }`
- New `error.rs` module documentation with a full variant table
- Programmatic `match` instead of string parsing

### Security
- **Constant-time comparison** for hash fields in hybrid verify paths
  (8 sites in `signing/hybrid.rs` upgraded from `==` to
  `ConstantTimeEq`)
- Zeroize audit: `MldsaPrivateKey` and `SlhDsaPrivateKey` now have `Drop`
  implementations that zeroize their secret bytes
- Workspace lints: `unsafe_code = "forbid"`, `clippy::correctness = "deny"`,
  `clippy::panic = "deny"`

### API
- **`Argon2idBuilder`** for custom memory/iteration/parallelism parameters
- **`#[deprecated(since = "0.4.0")]`** on `signing_legacy` module — will be
  removed in 0.5
- MIGRATION.md with concrete before/after examples for all breaking changes
- API Stability section in README classifying each public surface as
  Stable, Unstable, or Frozen

### Tooling
- **CI workflow** (`.github/workflows/ci.yml`) with 8 jobs: check, test,
  test-features, examples, clippy, fmt, doc, proptest, test-utils, MSRV
- **Fuzz targets** (`fuzz/`) for AEAD, HKDF, and hybrid verify
- **`test-utils` feature** with `deterministic_seed`, `deterministic_key`,
  `deterministic_nonce_24/12`, `deterministic_bytes` for downstream tests

### Documentation
- 42 → 0 missing-doc warnings (with `#[cfg_attr(docsrs, warn(missing_docs))]`)
- 0 unresolved intra-doc links
- 0 missing-documentation items
- Module docs follow consistent pattern: summary → when to use → example →
  security notes → see also

### Testing
- **275 tests passing** (was 246 at start of release cycle)
- 10 proptest property-based tests (roundtrip, tamper detection, etc.)
- 3 fuzz targets compile and run on nightly
- 4 runnable examples
- All 3 pre-existing `hybrid_rigorous` test failures now compile and pass

## Files Changed

- 20 files modified
- 10 new files: README.md, examples/{4}, MIGRATION.md, CONTRIBUTING.md,
  src/types.rs, src/test_utils.rs, tests/proptest_crypto.rs,
  fuzz/{Cargo.toml + 3 targets + README}
- 819 lines added, 225 removed (net +594)

## Breaking Changes from 0.3

1. **Prelude narrowed** — Low-level PQC types removed from prelude.
   Access via `pqc::falcon1024::*` etc.
2. **Signing module restructured** — Already in 0.3 but the `signing_legacy`
   re-export is now `#[deprecated]`.
3. **Constant-time verify** — Existing valid signatures still pass;
   existing invalid signatures still fail. No API change.
4. **`signing_legacy` deprecated** — `HybridSigningKey`, `HybridVerifyingKey`,
   `HybridSignatureOutput` re-exports at crate root all produce deprecation
   warnings. Use `signing::hybrid::HybridSigningKeyBundle` instead.

## Non-Breaking Improvements

- New `types` module (additive)
- New `test_utils` feature (opt-in)
- New `Argon2idBuilder` (alternative API)
- New fuzz targets (in separate `fuzz/` workspace)
- Structured error variants (additive — old String variants still work)
- Documentation improvements (additive)
- CI workflow (additive)

# Release 0.5.1

**Release date:** 2026-07-26

This release stabilizes the crate topology changes that originated in 0.4.1 and introduces the new `recovery::unicode_cipher` module.

## Highlights

- **Unicode recovery phrases**: new `recovery::unicode_cipher` module for BIP-39-shaped phrase codecs using Unicode codepoints and SHA-3-256. Phrases are deliberately **NOT BIP-39-compatible** — see the [module docs](https://docs.rs/origin-crypto-sdk/latest/origin_crypto_sdk/recovery/unicode_cipher/index.html).
- **Crate root cleanup (0.4.1 carryover)**: low-level PQC types (`Falcon1024PrivateKey`, `Falcon512PrivateKey`, `FalconSignature`, `ed41417_raw`) are no longer re-exported at the crate root. Access via `pqc::falcon1024::*` etc.
- **`origin-crypto` CLI binary fix**: the standalone CLI was failing to compile with `E0432` (unresolved `crate::internal` import in the bin target) and `E0382` (borrow-after-move in `cmd_decrypt`) errors that blocked `cargo publish`. Both fixes land in 0.5.1.
- **`signing_legacy` removal deferred to 0.6**: it remains in 0.5.1, with `#[deprecated(since = "0.5.1")]`. Originally promised in 0.4 to be removed by 0.5.

## Breaking changes

None. See [MIGRATION.md](MIGRATION.md) for the 0.4 → 0.5.1 transition notes.

## Dependencies

- New pinned dependency: `unicode-normalization = "=0.1.25"` (NFKC canonical-form validation for the recovery module).

See [CHANGELOG.md](CHANGELOG.md) for detailed patch notes.

# Release 0.5.2

**Release date:** 2026-07-26

This is a doc-only patch release. It resolves all 5 `cargo test --doc` failures and 4 unresolved intra-doc-link warnings that existed in 0.5.1.

## Highlights

- **Doc-tests**: 5 pre-existing doc-test imports of paths that were relocated during the 0.4.1 module reorg fixed: `otp` → `drbg::otp`, `seed_gen` → `seed::gen`, `hybrid::*` → `signing::hybrid::*`. Plus a `.expect("valid seed")` chain fix in the lib-root single-primitive example (both `*Signer::from_seed(...)` return `Result<Self>`).
- **Intra-doc-links**: 4 bare `[`name`]` rustdoc links converted to full-path forms.
- **No runtime changes**: identical binary behaviour to 0.5.1.

See [CHANGELOG.md](CHANGELOG.md) for the exact patch list.


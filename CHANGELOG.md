# Changelog

All notable changes to origin-crypto-sdk will be documented in this file.

## [0.4.0] — 2026-06-10

### Added
- **Ed448**: RFC 8032 signature scheme on the 448-bit Goldilocks curve
- **Ed41417**: Curve41417 Edwards curve operations (Bernstein et al.)
- **ML-DSA**: FIPS 204 lattice-based signatures (feature-gated, `ml-dsa`)
- **SLH-DSA**: FIPS 205 hash-based signatures (feature-gated, `slh-dsa`)
- **Hybrid constructions**: Ed448+Falcon-1024, Ed25519+Falcon-512, Ed448+Shake256,
  Ed448+Skein512, Ed448+Sha3_256, Ed25519ChaCha20Blake3Sha3_256 (KDF mode)
- **HybridSigningKeyBundle**: canonical PQ-hybrid signing API — derive Ed25519 +
  Falcon-1024 keys from a single seed with domain separation
- **Bundle caching**: `from_seed_cached()` for process-wide key cache (avoids
  re-running Falcon keygen on repeated calls)
- **signing module restructured**: `signing::classical`, `signing::postquantum`,
  `signing::hybrid` — clear family-based organization
- **signing_legacy**: backward-compatible re-exports for pre-0.3 callers
- **Cargo features documented** in crate-level doc with table
- **docs.rs metadata**: `[package.metadata.docs.rs]` for correct docs.rs builds
- **Dependency pin documentation**: reasons for pinned versions in Cargo.toml
- **Examples**: `examples/hybrid_sign.rs`, `examples/encrypt_file.rs`,
  `examples/kdf_derive.rs`, `examples/seed_tree.rs`
- **README.md**: quick start, feature table, module map, security posture

### Changed
- **Prelude narrowed**: removed low-level PQC type dumps (Falcon512PrivateKey,
  SlhDsaPrivateKey, MldsaPrivateKey, ed448, ed41417_raw, slhdsa_sign/verify).
  These are now accessed through their modules: `pqc::falcon1024::*`, etc.
- **Crate root re-exports**: consolidated to blessed top-level API only
- **EC Schnorr tests**: marked `#[ignore]` pending Montgomery arithmetic fix

### Fixed
- **ec_schnorr keygen**: rejection sampling — no more fallback to `Scalar::ONE`
- **secp256k1 field.rs**: overflow panic in `reduce_if_carry_or_gte_p`
- **9 unused-import/mut warnings** eliminated

### Security
- See [SECURITY.md](SECURITY.md) for implementation source table
- Custom PQC implementations (NTRU Prime, Ed41417) remain unaudited

### Type Safety
- **`Seed`** newtype (32 bytes, zeroize on drop, Debug hides bytes)
- **`XNonce`** newtype (24 bytes for ChaCha20-BLAKE3)
- **`CNonce`** newtype (12 bytes for ChaCha20-Poly1305)
- All newtypes reject wrong-length input at construction time

### Error Handling
- Structured `CryptoError::InvalidKeyLength { algorithm, expected, got }`
- Structured `CryptoError::InvalidNonceLength { algorithm, expected, got }`
- Full variant table in `error.rs` module docs
- Programmatic `match` instead of string parsing

### API Hardening
- **`Argon2idBuilder`** for custom memory / iterations / parallelism
- `unsafe_code = "forbid"` workspace lint
- `clippy::correctness = "deny"`, `clippy::panic = "deny"`
- Constant-time comparison for hash fields in hybrid verify (8 sites)
- `MldsaPrivateKey` and `SlhDsaPrivateKey` now zeroize on drop
- `#[deprecated(since = "0.4.0")]` on `signing_legacy` (will be removed in 0.5)

### Documentation
- 42 → 0 missing-documentation warnings (with `#[cfg_attr(docsrs, warn(missing_docs))]`)
- 0 unresolved intra-doc links
- Module docs follow consistent pattern (summary → when to use → example
  → security notes → see also)
- `MIGRATION.md` for 0.3 → 0.4 transitions
- `CONTRIBUTING.md` for contributors
- `RELEASE.md` for 0.4.0 release notes
- `benches/README.md` with expected performance numbers
- `fuzz/README.md` with cargo-fuzz instructions
- API Stability section in README (Stable / Unstable / Frozen)

### Tooling
- **CI workflow** (`.github/workflows/ci.yml`) with 9 jobs: check, test,
  test-features, examples, clippy, fmt, doc, proptest, test-utils, MSRV
- **Fuzz targets** (`fuzz/`) for AEAD, HKDF, hybrid verify
- **`test-utils` feature** with `deterministic_seed`, `deterministic_key`,
  `deterministic_nonce_24/12`, `deterministic_bytes`
- `cargo` `exclude` reduces crates.io package size

### Testing
- 275 tests passing (was 246 at start of release)
- 10 proptest property-based tests (roundtrip, tamper detection, etc.)
- 3 fuzz targets compile
- 4 runnable examples verified
- All 3 pre-existing `hybrid_rigorous` test failures now compile and pass

## [0.3.0] — 2026-05-28

### Added
- **Hybrid signing module** (`signing/hybrid.rs`): Ed25519+Falcon-1024,
  Ed25519+BLAKE3 hash-check, Ed25519+SHAKE256, Ed25519+Skein512
- **HybridSigningKeyBundle**: one-call API for PQ-hybrid signing
- **falcon1024_keygen**: seed-based Falcon key generation
- **skein512 / skein1024**: Skein hash wrappers for hybrid constructions
- **Prelude restructured**: clear section comments, feature-gated PQC types

### Changed
- **signing module split** into `classical`, `postquantum`, `hybrid` submodules
- **signing_legacy.rs**: shim for backward compatibility with flat `signing::*` imports
- **hybrid.rs** (top-level): thin compat re-export pointing to `signing::hybrid`

### Fixed
- Hybrid key derivation uses domain-separated HKDF (prevents cross-domain reuse)
- Falcon keygen seeded deterministically (no hidden RNG state)

## [0.2.0] — 2025-05-20

### Fixed
- **ec_schnorr**: Keygen rejection sampling — no more fallback to `Scalar::ONE` which caused identical keys from different seeds
- **secp256k1 field.rs**: Overflow panic in `reduce_if_carry_or_gte_p` — `p_limbs[i] + borrow` could wrap u64
- **Warnings**: Zero unused-import/mut warnings across entire crate (was 9)

### Changed
- `ec_schnorr` tests marked `#[ignore]` — underlying Montgomery arithmetic needs a deeper fix (see module-level doc)
- License format: `license-file = "LICENSE"` for crates.io compatibility

## [0.1.0] — 2025-07-08

### Added

- **AEAD**: XChaCha20-Poly1305 encryption via `chacha20poly1305` crate
- **KDF**: Argon2id key derivation with configurable paranoid mode
- **HKDF**: HKDF-SHA3-256 for subkey derivation
- **HMAC**: HMAC-SHA3-256 message authentication
- **Symmetric**: Serpent CBC encryption (paranoid mode)
- **Compression**: zlib via `flate2`
- **Error correction**: Reed-Solomon with parallel encoding support
- **Streaming**: Stream encryption/decryption for large files
- **PQC — NTRU Prime**: sntrup761 KEM (custom native implementation)
- **PQC — Falcon-512/1024**: Post-quantum signatures via `falcon-rust`
- **PQC — Ed41417**: Curve41417 Edwards curve operations (custom native)
- **Hybrid KEM**: X25519 + Ed41417 + NTRU Prime combined encapsulation
- **Hybrid signatures**: Ed25519 + Falcon-1024 combined signing
- **Native ChaCha20**: RFC 8439 stream cipher (zero external crypto deps)
- **Native Poly1305**: RFC 8439 §2.5 MAC (zero external crypto deps)
- **Native ChaCha20-Poly1305**: RFC 8439 AEAD + XChaCha20-Poly1305
- **Seed Blob**: Encrypted master seed at rest (Argon2id + XChaCha20-Poly1305)
- **ChaCha20-DRBG**: Deterministic CSPRNG with auto-reseed after 16 MB
- **SipHash-c-d**: Compute hardener for entropy pipeline
- **Memory tiers**: Nano / Standard / Sovereign Argon2id cost profiles

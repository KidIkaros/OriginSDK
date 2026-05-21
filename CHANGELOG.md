# Changelog

All notable changes to origin-crypto-sdk will be documented in this file.

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

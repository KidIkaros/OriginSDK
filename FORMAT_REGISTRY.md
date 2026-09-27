# Origin Crypto SDK — Format Registry

This document catalogues every persistent binary format defined or consumed by
`origin-crypto-sdk` and `origin-tools`. It assigns format ownership, documents
versioning policy, and tracks validation coverage.

## Format Ownership Policy

- **SDK-owned:** The SDK defines the format and guarantees backward-compatible
  readers within a major version. Downstream consumers must not redefine or
  re-implement parsing for these formats.
- **Tools-owned:** `origin-tools` defines the format. The SDK provides
  primitives (AEAD, KDF, signatures) but does not own the container.
- **Jointly-versioned:** Both SDK and tools participate in format evolution.
  Changes require coordinated releases.

## Versioning Policy

1. Every binary format MUST have a magic byte sequence and a version field.
2. Readers MUST reject unknown versions with a typed error (not panic).
3. Readers MUST reject truncated input before accessing fixed-size fields.
4. Readers MUST enforce a maximum total size to prevent memory exhaustion.
5. Writers MUST emit the current version. No auto-upgrade on write.
6. Golden vectors MUST be maintained for each supported version.

## SDK-Owned Formats

### 1. Seed Blob (`blob.rs`)

**v2 (current — written by `create_blob`):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| magic | 0 | 4 | `"ORGB"` (0x4F 0x52 0x47 0x42) |
| version | 4 | 1 | 0x02 |
| tier | 5 | 1 | MemoryTier byte (Nano=0, Standard=1, Sovereign=2) |
| salt | 6 | 16 | Argon2id salt |
| nonce | 22 | 24 | XChaCha20-Poly1305 nonce |
| ct+tag | 46 | 48 | Ciphertext + 16-byte Poly1305 tag |

- **Total v2 size:** 94 bytes (constant `BLOB_V2_LEN`)
- **KDF:** Argon2id (tier read from blob header, not caller-supplied)
- **AEAD:** XChaCha20-Poly1305, AAD = magic + version + tier + salt
- **Validation:** Magic check, version check, tier validation, minimum length
- **Self-describing:** Tier is embedded; `recover_seed` reads it automatically
- **Ownership:** SDK-owned

**v1 (legacy — still readable, no longer written):**

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| salt | 0 | 16 | Argon2id salt |
| nonce | 16 | 24 | XChaCha20-Poly1305 nonce |
| ct+tag | 40 | 48 | Ciphertext + 16-byte Poly1305 tag |

- **Total v1 size:** 88 bytes (constant `BLOB_LEN`)
- **KDF:** Argon2id (caller must supply correct tier)
- **AEAD:** XChaCha20-Poly1305, AAD = salt
- **Validation:** Minimum length check only
- **Migration:** `rotate_blob` reads v1, writes v2. `detect_blob_version` and
  `blob_tier` helper functions available for migration tooling.

### 2. Recovery Phrase (`recovery/unicode_cipher.rs`)

- **Format:** BIP-39-like, 12 or 24 words from a 2048-entry wordlist
- **Entropy:** 16 bytes (12-word) or 32 bytes (24-word)
- **Checksum:** Truncated SHA-3-256 (4 bits / 8 bits)
- **Validation:** Extensive — word count, entropy length, wordlist size,
  codepoint classes, NFKC normalization
- **Version:** Implicit (phrase length determines format). **Frozen** — v1
  decoding is permanent because phrases are seed backups; new phrases use v2.
- **Ownership:** SDK-owned

### 2b. Recovery Phrase v2 (`recovery/{alphabet,format,phrase}.rs`)

- **Format:** `entropy ‖ checksum` written as a fixed number of symbols over a
  caller-supplied alphabet
- **Alphabet:** any size 2..=4096, validated for uniqueness and codepoint
  policy; not restricted to powers of two
- **Entropy:** 16, 24, or 32 bytes
- **Checksum:** truncated SHA-3-256 over `"origin-recovery-phrase-v2" ‖ entropy`,
  one bit per byte of entropy (16/24/32 bits), versus v1's entropy/32
- **Symbol encoding:** `log2(n)`-bit groups for a power-of-two alphabet, base-`n`
  digits otherwise. Both are canonical: a symbol string whose value exceeds the
  message range is rejected, so one seed has exactly one phrase.
- **Version:** explicit — bound into the checksum domain and described by a
  caller-supplied `RecoveryFormat`; not inferred from symbol count
- **Text form:** canonical space-separated output; parsing accepts concatenated,
  whitespace-separated, multiline, and BOM-prefixed input
- **Validation:** symbol count, alphabet membership, canonical form, codepoint
  policy; wrong-alphabet phrases fail the checksum with probability
  `1 - 2^-checksum_bits`
- **Alphabet analysis (authoring surface):**
  `RecoveryAlphabet::is_safe_codepoint` / `first_unsafe_symbol` classify a
  candidate symbol against the policy, and `RecoveryFormat::symbol_count_for`
  reports the phrase length an alphabet would need at a supported width without
  enforcing the 64-symbol limit that `new` keeps enforcing.
  `SUPPORTED_ENTROPY_BYTES` lists the accepted widths. A sibling layout tool
  (UNICODE) has its own offline check for authoring without this crate; it is
  independent and not kept in lockstep, and this policy is authoritative.
- **Ownership:** SDK-owned

### 3. NTRU Prime Key/Ciphertext (`pqc/ntru_prime/`)

| Type | Size (bytes) | Constant |
|------|-------------|----------|
| Public key | 1158 | `PK_SIZE` |
| Private key | 1763 | `SK_SIZE` |
| Ciphertext | 1039 | `CT_SIZE` |
| Shared secret | 32 | `K_SIZE` |

- **Encoding:** NIST recursive `Encode()`/`Decode()` (supercop-20201130)
- **SK layout:** `Small(f)[191] || Small(gr)[191] || Rq(h)[1158] || rho[191] || cache[32]`
- **CT layout:** `Rounded(c)[1007] || confirm[32]`
- **KEM hashing:** SHA-2-512 with domain-separation prefixes (NIST reference)
- **CCA security:** Decapsulation always returns `Ok`; on failure, session
  key is derived from `rho` (random secret in SK) instead of recovered `r`
- **Validation:** Type-system enforced (fixed-size arrays)
- **Internal decode bounds checks:** encode.rs decode functions return
  zero-filled arrays on short input (defensive, no panic)
- **Ownership:** SDK-owned (NIST sntrup761 wire-compatible)

### 4. Falcon-1024 Key/Signature (`pqc/falcon1024.rs`)

| Type | Size (bytes) | Constant |
|------|-------------|----------|
| Public key | 1793 | `sizes::PUBLIC_KEY` |
| Private key | 2305 | `sizes::PRIVATE_KEY` |
| Signature | ≤1577 | `sizes::SIGNATURE` |

- **Encoding:** FIPS 206 compressed-tree format (header 0x50)
- **Validation:** `from_bytes` constructors validate exact length
- **Ownership:** SDK-owned (FIPS 206 wire-compatible via `falcon-rs`)

### 5. Falcon-512 Key/Signature (`pqc/falcon512.rs`)

| Type | Size (bytes) | Constant |
|------|-------------|----------|
| Public key | 897 | `PK_LEN` |
| Private key | 1281 | `SK_LEN` |
| Signature | ≤809 | `MAX_SIGNATURE_LEN` |

- **Encoding:** FIPS 206 compressed-tree format (header 0x30)
- **Validation:** `from_bytes` constructors validate exact/max length
- **Ownership:** SDK-owned (FIPS 206 wire-compatible via `falcon-rs`)

### 6. Ed448 Key/Signature (`pqc/ed448.rs`)

| Type | Size (bytes) |
|------|-------------|
| Secret key | 57 |
| Public key | 57 |
| Signature | 114 |

- **Validation:** `from_bytes` constructors validate exact length
- **Ownership:** SDK-owned (RFC 8032 standard)

### 7. Ed41417 Key/Signature (`pqc/curve41417/ed41417.rs`)

| Type | Size (bytes) |
|------|-------------|
| Private key | 52 |
| Public key | 52 |
| Signature | 104 |

- **Validation:** `from_bytes` constructors validate exact length
- **Domain separation:** `"DGP-ED41417-NONCE-V1"`, `"DGP-ED41417-CHALLENGE-V1"`
- **Ownership:** SDK-owned

### 8. Reed-Solomon Shards (`error_correction.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| original_len | 0 | 4 | LE u32 — original data length |
| shards | 4 | variable | data_shards + parity_shards concatenated |

- **Validation:** Minimum length (4 bytes), shard count, shard size consistency
- **Warning:** Bounded-distance decoder can silently miscorrect if >1 shard
  corrupted at the same byte offset
- **Ownership:** SDK-owned

## Tools-Owned Formats

### 9. ORGN Envelope (`origin-common/src/envelope.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| magic | 0 | 4 | `"ORGN"` (0x4F 0x52 0x47 0x4E) |
| version | 4 | 1 | 0x01 |
| payload_type | 5 | 1 | 0x01=vault, 0x02=file, 0x03=signed, 0x04=seed, 0x05=shard, 0x06=proof |
| flags | 6 | 1 | bit0=compressed, bit1=streamed, bit2=dual_signed |
| tier | 7 | 1 | MemoryTier byte |
| salt | 8 | 16 | KDF salt |
| nonce | 24 | 24 | XChaCha20-Poly1305 nonce |
| payload | 48 | variable | Ciphertext + tag |

- **Header length:** 48 bytes
- **Validation:** Magic check, version check, minimum length, payload type
  validation, tier validation
- **Parsing safety:** `try_into` for salt/nonce uses `map_err` (no unwrap)
- **Ownership:** Tools-owned
- **Validation status:** Maximum payload size enforced; golden vectors remain pending

### 10. Identity Blob (`origin-common/src/identity.rs`)

`origin-common::IdentityStore` writes and reads the SDK-owned Seed Blob v2
format. Legacy origin-common identity blobs remain read-compatible through a
narrow fallback reader but are never written.

- **Current format:** SDK Seed Blob v2 (`ORGB`, 94 bytes)
- **Legacy format:** `salt(16) || nonce(24) || tier(1) || ciphertext+tag(48)`;
  read-only compatibility path
- **Validation:** SDK magic/version/tier/length/authentication validation;
  legacy minimum length, tier validation, and authentication validation
- **Maximum size:** 1 MiB at the origin-tools file boundary
- **Ownership:** SDK-owned for current writes and v2 parsing; origin-tools owns
  only the legacy compatibility reader
- **Vectors/tests:** SDK Seed Blob vectors plus origin-common and cross-tool
  ORGB v2 round-trip/malformed-input coverage

### 11. SEAL Envelope (`origin-seal/src/commands.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| magic | 0 | 4 | `"SEAL"` |
| version | 4 | 1 | 0x01 |
| flags | 5 | 1 | bit0=compressed, bit1=streamed |
| tier | 6 | 1 | MemoryTier byte |
| reserved | 7 | 1 | 0x00 |
| salt | 8 | 16 | KDF salt |
| nonce | 24 | 24 | XChaCha20-Poly1305 nonce |
| ciphertext | 48 | variable | Ciphertext + tag (or streamed chunks) |

- **Streaming mode:** Length-prefixed chunks (4-byte BE + ciphertext),
  zero-length sentinel marks end. Chunk bounds: 1 KiB – 1 GiB.
- **Validation:** Magic, version, supported flags, reserved-byte zero, minimum
  length, chunk size bounds, and maximum total size
- **Ownership:** Tools-owned

### 12. OVLT Vault (`origin-pass/src/vault.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| magic | 0 | 4 | `"OVLT"` |
| version | 4 | 1 | 0x01 |
| cipher_suite | 5 | 1 | 0x00 = ChaCha20-BLAKE3 |
| tier | 6 | 1 | MemoryTier byte |
| reserved | 7 | 1 | 0x00 |
| kdf_salt | 8 | 16 | Argon2id salt |
| header_nonce | 24 | 24 | XChaCha20-Poly1305 nonce |
| header_ct_len | 48 | 2 | BE u16 — header ciphertext length |
| header_ct | 50 | variable | Encrypted entry index |

- **Entry index:** 76 bytes per entry (name_hash 32 + nonce 24 + ct_len 4 + reserved 16)
- **Validation:** Magic, version, minimum header length, supported cipher suite,
  tier, reserved-byte zero, authentication-tag-sized header ciphertext, and
  maximum total vault size
- **Ownership:** Tools-owned

### 13. Channel Message (`origin-channel/src/message.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| msg_type | 0 | 1 | 0x01-0x03=handshake, 0x10=data, 0x20=close, 0x30=ping, 0x31=pong |
| sequence | 1 | 8 | BE u64 |
| nonce | 9 | 24 | XChaCha20-Poly1305 nonce |
| ciphertext | 33 | variable | Ciphertext + tag |

- **Framing:** 4-byte BE length prefix, max 16 MiB per frame
- **Validation:** Minimum length (49 bytes), max frame size
- **Ownership:** Tools-owned

### 14. CombinedSignature (`origin-identity/src/commands.rs`)

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| falcon_len | 0 | 4 | BE u32 — Falcon signature length |
| ed25519_sig | 4 | 64 | Ed25519 signature |
| falcon_sig | 68 | variable | Falcon-1024 signature |

- **Validation:** Minimum length (68), length consistency check
- **Ownership:** Tools-owned

## JSON/Text Formats (Not Binary)

These formats use JSON or text encoding and are not covered by the binary
format registry. They are listed for completeness:

- `origin-secrets` vault/share (JSON)
- `origin-proof` MMR state/proof (JSON)
- `origin-provenance` stamp/manifest (JSON)
- `origin-provenance` watermark (text markers + JSON)
- `origin-schnorr` proof (JSON)
- `origin-stealth` PoW proof (JSON)
- `origin-attest` capability claims (JSON)

## Validation Coverage Summary

| Format | Magic | Version | Min len | Max len | Exact fields | No unwrap | Golden vectors |
|--------|-------|---------|---------|---------|-------------|-----------|---------------|
| Seed Blob v2 | ✅ | ✅ | ✅ | ✅ (fixed) | ✅ | ✅ | ✅ |
| Seed Blob v1 | ❌ | ❌ | ✅ | ✅ (fixed) | ✅ | ✅ | ✅ |
| Recovery Phrase | N/A | implicit | ✅ | ✅ | ✅ | ✅ | ✅ (format_golden_vectors) |
| NTRU Prime | N/A | N/A | ✅ | ✅ (types) | ✅ | ✅ | ✅ (official NIST KATs, 100/100) |
| Falcon-1024 | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ (format_golden_vectors) |
| Falcon-512 | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ (format_golden_vectors) |
| Ed448 | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ (format_golden_vectors) |
| Ed41417 | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ (format_golden_vectors) |
| Reed-Solomon | N/A | N/A | ✅ | ❌ | ✅ | ✅ | ✅ (format_golden_vectors) |
| ORGN Envelope | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Identity Blob | ✅ (ORGB) | ✅ (ORGB) | ✅ | ✅ (1 MiB boundary) | ✅ | ✅ | ✅ (SDK v2) |
| SEAL Envelope | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (origin-seal api.rs) |
| OVLT Vault | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (header/index) |
| Channel Message | N/A | N/A | ✅ | ✅ | ✅ | ✅ | ✅ (origin-channel message.rs) |
| CombinedSignature | N/A | N/A | ✅ | ✅ (falcon_len ≤ SIGNATURE_MAX) | ✅ | ✅ | ✅ (origin-identity commands.rs) |

## Priorities

1. ~~Add magic + version to Seed Blob~~ ✅ Done (v2 format with `ORGB` magic)
2. ~~Generate golden vectors for Seed Blob~~ ✅ Done (5 structural + round-trip + tamper tests)
3. ~~Add maximum size limits~~ ✅ Already enforced everywhere — ORGN max
   payload, identity blob 1 MiB boundary, SEAL `MAX_ENVELOPE_LEN`, OVLT max
   vault size, CombinedSignature `falcon_len ≤ SIGNATURE_MAX`
   (`origin-identity/src/commands.rs`). The ❌ in the table was stale.
4. ~~Add magic + version to Identity Blob~~ ✅ Superseded — current writes
   are Seed Blob v2 (`ORGB` magic + version byte). The legacy no-magic
   format is read-only compatibility; retrofitting a magic into a frozen
   read path would break existing files, not fix them.
5. ~~Generate golden vectors for SDK-owned formats~~ ✅ Done — recovery phrase, Falcon-512/1024, Ed448, Ed41417, Reed-Solomon in `tests/format_golden_vectors.rs`; NTRU Prime covered by the official NIST KATs (100/100 byte-exact)
6. ~~Add cross-version read/write fixtures for downstream formats~~ ✅ v1
   golden vectors added in origin-tools: SEAL envelope
   (`origin-seal/src/api.rs::seal_envelope_golden_vector_v1`), channel
   message (`origin-channel/src/message.rs::channel_message_golden_vector_v1`),
   CombinedSignature (`origin-identity/src/commands.rs::combined_signature_golden_vector_v1`).
   All downstream formats are v1-only today, so "cross-version" coverage
   is the pinned-v1 fixture plus the unknown-version rejection paths
   (dedicated test for ORGN; parse-time rejection for SEAL); when a v2
   ships, the v1 fixture becomes the backward-compat oracle.
7. ~~Make the recovery phrase alphabet-agnostic~~ ✅ Done — format v2
   (entry 2b). v1's "implicit version" was workable only while there was one
   blessed 2048-codepoint list: the moment an alphabet is user-supplied,
   symbol count implies nothing, so the format descriptor became explicit and
   the version was bound into the checksum. v1 stays decodable, and
   `tests/recovery_phrase_v2.rs` pins both. The golden vectors were reproduced
   by an independent Python implementation of the format.

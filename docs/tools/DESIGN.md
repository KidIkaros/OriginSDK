# Origin-Tools Design Specification

> **Status**: Draft  
> **SDK dependency**: `origin-crypto-sdk ^0.6.3`  
> **Last updated**: 2026-07-26

---

## 1. Overview

Origin-Tools is a suite of per-domain CLI tools built on `origin-crypto-sdk`. Each tool is a separate crate in a shared workspace, sharing nothing but the SDK dependency.

### Tool inventory

| Tool | Crate | Purpose |
|------|-------|---------|
| `origin-identity` | `origin-identity/` | Identity key generation, hybrid signing/verification, stealth address derivation, seed export/import |
| `origin-vault` | `origin-vault/` | Encrypted password/secret store with file encryption |
| `origin-auth` | `origin-auth/` | 2FA authenticator (TOTP/HOTP/OCRA) |
| `origin-kdf` | `origin-kdf/` | Key derivation utility (Argon2id, HKDF, HMAC) |
| `origin-backup` | `origin-backup/` | Recovery phrases + encrypted vault backup |

### Cross-cutting decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Key model | Single master seed | HD derivation via HKDF-SHA3-256 with domain labels (BIP-32-like) |
| Vault AEAD | ChaCha20-BLAKE3 (committing) | Prevents partitioning-oracle attacks; SDK-recommended |
| Identity at rest | Encrypted blob, `~/.origin/identities/*.id` | Reuses SDK `blob` pattern with metadata wrapper |
| Vault format | Header + independently encrypted entries | Per-entry nonces; tamper-evident via AEAD |
| Duress vault | Separate vault file | No destruction pattern (legally safe per SDK duress docs) |
| Repo | Separate private repo (`origin-tools`) | Independent versioning from SDK |

---

## 2. Directory Layout

All tools share a common data directory.

### `~/.origin/` hierarchy

```
~/.origin/
├── config.toml              # Global preferences (default tier, etc.)
├── identities/
│   ├── personal.id           # Encrypted identity blob
│   ├── work.id               # Another identity
│   └── devices.id            # Device-specific key
├── vaults/
│   ├── personal.vault        # Main vault
│   ├── work.vault            # Work vault (separate passphrase)
│   └── duress.vault          # Decoy vault (plausible-deniability duct tape)
├── tokens/
│   └── github.otpauth        # Exported otpauth:// URI (optional)
├── backups/
│   └── 2026-07-26.phrase     # Recovery phrase (encrypted)
├── cache/
│   └── identity.cache        # Hot key cache (mlocked, TTL-bound)
└── identity.lock             # Coarse file lock for concurrent access
```

### `config.toml`

```toml
# Default Argon2id tier for blob encryption
default_tier = "standard"        # "nano" | "standard" | "sovereign"

# Default vault identity (for tools that need a signing identity)
default_identity = "personal"

# Auth tool defaults
auth_digits = 6
auth_auto_clear_secs = 30

# Vault file encryption (applies to vault header)
vault_cipher = "chacha20-blake3" # "chacha20-blake3" | "xchacha20-poly1305"
```

---

## 3. Identity Blob Format

### File extension: `.id`

The identity blob stores an encrypted master seed plus metadata. It wraps the SDK's basic `blob` format with a structured header.

### Wire format

```
Offset  Size  Field           Description
──────────────────────────────────────────────
 0       4    magic           "ORID" (0x4F524944)
 4       1    version         0x01
 5       1    tier            Argon2id tier: 0=Nano, 1=Standard, 2=Sovereign
 6       2    reserved        Zeroed; reserved for future flags
 8       2    payload_len     Encrypted payload length (big-endian u16)
10      16    salt            Argon2id salt (from SDK blob)
26      24    vault_nonce     XChaCha20-Poly1305 nonce (from SDK blob)
50       ?    ciphertext      Encrypted payload (payload_len bytes)
50+?    16    tag             Poly1305 authentication tag
──────────────────────────────────────────────
Total (minimum): 50 + 4 + 16 = 70 bytes (empty payload)
Total (typical):  50 + 76 + 16 = 142 bytes
```

### Encrypted payload (plaintext structure)

Decrypted ciphertext contains:

```
Offset  Size  Field           Description
──────────────────────────────────────────────
 0      32    seed            Master seed (256 bits)
32      40    domain          Domain label, space-padded to 40 bytes
72       8    created_at      Unix timestamp (big-endian i64)
80       4    key_flags       Bitfield:
                                  bit 0: is_hybrid
                                  bit 1: is_stealth
                                  bit 2: is_ecdsa
                                  bits 3-31: reserved
84       4    reserved        Reserved; zeroed
──────────────────────────────────────────────
Total: 88 bytes
```

### SDK functions used

| Operation | SDK API |
|-----------|---------|
| Encrypt | `blob::create_blob(passphrase, tier, Some(&seed))` |
| Decrypt | `blob::recover_seed(&blob, passphrase, tier)` |
| Keygen | `seed::gen::generate(SeedVariant::Blake2bShake256)` |
| Recovery phrase | `recovery::unicode_cipher::encode_phrase(entropy, &UnicodeWordlist::default(), PhraseLength::Words24)` |
| Derive signing keys | `signing::hybrid::HybridSigningKeyBundle::from_seed(&seed, &domain)` |

### Lifecycle

```
keygen:
  1. Generate 32B seed via seed::gen::generate
  2. (Optional) Show recovery phrase
  3. Prompt for passphrase (confirm)
  4. Encrypt seed + metadata → blob file
  5. Write to ~/.origin/identities/<name>.id

load (for sign/verify):
  1. Read blob file
  2. Prompt for passphrase
  3. blob::recover_seed → seed
  4. SeedHandle::new(&seed, Some(TTL))
  5. derive_key("signing", domain) → session key
  6. Zeroize seed on handle drop
```

---

## 4. Vault File Format

### File extension: `.vault`

The vault stores an encrypted header plus independently-encrypted entries. Each entry has its own nonce, so tampering one entry does not affect others.

### Wire format overview

```
┌────────────────────────────────────────────┐
│ Vault Header (encrypted with master key)   │
│   - Points to entry index                  │
│   - Contains cipher suite + KDF params     │
├────────────────────────────────────────────┤
│ Entry Index (encrypted, inside header ct)  │
│   - List of (name_hash, nonce, length)     │
├────────────────────────────────────────────┤
│ Entry 0 payload (name + secret + tag)      │
│ Entry 1 payload (name + secret + tag)      │
│ ...                                         │
└────────────────────────────────────────────┘
```

### Vault header

```
Offset  Size  Field             Description
────────────────────────────────────────────────
 0       4    magic             "OVLT" (0x4F564C54)
 4       1    version           0x01
 5       1    cipher_suite      0 = ChaCha20-BLAKE3, 1 = XChaCha20-Poly1305
 6       1    kdf_tier          0 = Nano, 1 = Standard, 2 = Sovereign
 7       1    reserved          Zeroed
 8      16    kdf_salt          Argon2id salt
24      16    header_nonce      AEAD nonce for header (24B for XChaCha20, 12B for ChaCha20)
40       ?    header_ct         Encrypted entry index (see below)
40+?     ?    header_tag        AEAD authentication tag (32B for BLAKE3, 16B for Poly1305)
────────────────────────────────────────────────
```

### Entry index (plaintext within encrypted header)

```
Offset  Size  Field             Description
────────────────────────────────────────────────
 0       4    entry_count       Number of entries (big-endian u32)
 4       4    version           Index format version (0x01)
 8       ?    entries[]         Array of EntryMetadata
────────────────────────────────────────────────

Each EntryMetadata:
  Offset  Size  Field             Description
  ──────────────────────────────────────────────
   0      32    name_hash         SHA3-256 of entry name (for lookup)
  32      24    entry_nonce       AEAD nonce for this entry
  56       4    entry_ct_len      Encrypted payload length (big-endian u32)
  60      16    entry_reserved    Zeroed
  ──────────────────────────────────────────────
  Total per entry: 76 bytes
```

### Entry payload (encrypted independently)

```
Offset  Size  Field             Description
────────────────────────────────────────────────
 0       ?    name              Entry name (UTF-8, variable, plaintext AEAD)
 ?       ?    secret            Entry secret value (variable, plaintext AEAD)
 ?       ?    entry_metadata    8 bytes: created_at (i64 BE) + updated_at (i64 BE)
────────────────────────────────────────────────
```

The entire payload (name + secret + metadata) is encrypted as a single AEAD message with AAD = `name_hash || entry_nonce`.

### SDK functions used

| Operation | SDK API |
|-----------|---------|
| Vault key derivation | `kdf::hkdf::hkdf_sha3_256(master_key, Some(b"origin-vault"), b"header-key", &mut header_key)` |
| Entry key derivation | `kdf::hkdf::hkdf_sha3_256(master_key, Some(&entry_nonce), b"entry-key", &mut entry_key)` |
| Header encrypt | `ChaCha20Blake3::encrypt(&header_key, &header_nonce, &entry_index_bytes, &[])` |
| Entry encrypt | `ChaCha20Blake3::encrypt(&entry_key, &entry_nonce, &payload_bytes, &aad)` |
| AAD for entry | `SHA3-256(name_bytes) || entry_nonce` |
| Entry name hash | `primitives::sha3::sha3_256(name)` |
| KDF tier config | `primitives::tier::MemoryTier::argon2_params(32)` |

### Vault operations

```
vault init:
  1. Generate 16B KDF salt
  2. Derive master key: Argon2id(passphrase, salt, tier) → 32B
  3. Derive header key: HKDF(master_key, "origin-vault", "header-key") → 32B
  4. Encrypt empty entry index → header_ct
  5. Write header + CT to file

vault add:
  1. Decrypt header (Argon2id + HKDF + ChaCha20-BLAKE3 open)
  2. Generate fresh 24B entry_nonce
  3. Derive entry_key: HKDF(master_key, entry_nonce, "entry-key")
  4. Encrypt name + secret → entry_payload
  5. Compute name_hash = SHA3-256(name)
  6. Append entry payload to file
  7. Update entry index, re-encrypt header
  8. Write updated header

vault get:
  1. Decrypt header → entry index
  2. Find entry by name_hash (constant-time scan all hashes)
  3. Read entry payload at stored offset
  4. Derive entry_key, decrypt payload
  5. Return (name, secret)
```

### Entry lookup privacy

Entry names are stored as SHA3-256 hashes in the index. While the encrypted index is inside the encrypted header (hidden from disk), once unlocked, the index reveals which entries exist but not their original names. The entry name is stored inside the encrypted entry payload itself.

**Attack**: Someone with the passphrase and the unlocked vault can see `name_hash` values but not the original names until they decrypt each entry. This provides a weak form of plausible deniability (you know there are N entries, but not which services they correspond to).

---

## 5. Key Derivation Paths

All keys derive from a single 32-byte master seed using HKDF-SHA3-256 with domain-labeled salts.

### Derivation tree

```
Master Seed (32B)
├── "signing" ─┬── "ed25519" + domain    → Ed25519 seed (32B)
│              └── "falcon1024" + domain  → Falcon-1024 seed (32B)
├── "encryption" ─── "vault" + nonce     → Vault session key (32B)
├── "identity" ──── "blob" + tier        → Blob encryption key (32B)
├── "stealth" ─┬── "viewing"             → Stealth viewing master (32B)
│              ├── "spending"            → Stealth spending master (32B)
│              └── "ephemeral"           → Stealth ephemeral master (32B)
├── "auth" ─────── "totp" + index        → TOTP seed (variable)
└── "backup" ──── "recovery" + version   → Recovery phrase key (32B)
```

### SDK function

```rust
// Derive a domain-specific subkey
let mut subkey = [0u8; 32];
hkdf_sha3_256(&master_seed, Some(b"domain-label"), b"context-label", &mut subkey)?;
```

Domain labels use short, fixed ASCII strings (≤ 32 bytes) for deterministic derivation. The label hierarchy is:

- Tier 1: `b"signing"`, `b"encryption"`, `b"identity"`, `b"stealth"`, `b"auth"`, `b"backup"`
- Tier 2 (info): `b"ed25519"`, `b"falcon1024"`, `b"vault"`, `b"blob"`, `b"viewing"`, `b"spending"`, `b"ephemeral"`, `b"totp"`, `b"recovery"`

---

## 6. Threat Model

### Tool-level threats

#### origin-identity

| Threat | Attack | Mitigation |
|--------|--------|-----------|
| T1.1 | Device stolen; blob exfiltrated | Argon2id memory-hard KDF (Standard = 64 MB, Sovereign = 256 MB) |
| T1.2 | Passphrase keylogged | TouchID/secret-service integration (future); TOTP 2FA required for signing |
| T1.3 | Forensic memory dump of seed | `SeedHandle` with TTL (auto-zeroize); `MemoryTier::Sovereign` uses mlock |
| T1.4 | Recovery phrase intercepted | Phrase only displayed once at keygen; user must store offline |
| T1.5 | Brute-force via leaked blob | `MemoryTier::Sovereign` = 256 MB × 5 iterations × 4 lanes = ~5s per attempt |
| T1.6 | Blob rollback / downgrade | Blob format version + `created_at` timestamp in encrypted payload |

#### origin-vault

| Threat | Attack | Mitigation |
|--------|--------|-----------|
| T2.1 | Vault file stolen | Header AEAD + per-entry AEAD, both with independent nonces |
| T2.2 | Brute-force vault passphrase | Argon2id configurable up to Sovereign tier |
| T2.3 | Coerced decryption | Duress vault (separate file, no destruction, legally safe per SDK docs) |
| T2.4 | Entry tampering | Per-entry AEAD tag verification on every `get` |
| T2.5 | Entry reordering / deletion | Entry index tracks entry count; monotonic counter (future) |
| T2.6 | Ciphertext length analysis | Padding to nearest 32-byte boundary (future) |
| T2.7 | Partitioning oracle | ChaCha20-BLAKE3 (committing AEAD) — immune by construction |

#### origin-auth

| Threat | Attack | Mitigation |
|--------|--------|-----------|
| T3.1 | 2FA seeds stolen from disk | Encrypted in vault; never stored unencrypted |
| T3.2 | TOTP code phishing | OCRA challenge-response binds code to session context |
| T3.3 | Clock skew | TOTP uses 30s window with ±1 step tolerance (RFC 6238) |
| T3.4 | Screen capture malware | Codes displayed with auto-clear (default 30s); configurable |
| T3.5 | Shoulder-surfing | `origin-auth totp` hides code after display; `--quiet` suppresses echo |

### Cross-tool threats

| Threat | Attack | Mitigation |
|--------|--------|-----------|
| T4.1 | `~/.origin` directory enumeration | All sensitive files are encrypted blobs; no identifying plaintext filenames beyond `.id` / `.vault` |
| T4.2 | File metadata leakage | Touch timestamps, file sizes reveal approximation of activity; mitigated by padding (future) |
| T4.3 | Concurrent tool invocations | `identity.lock` (flock) prevents concurrent writes to identity/vault files |
| T4.4 | Insecure temp files | All decryption happens in-memory; `mkstemp` with `O_CLOEXEC` for any temp writes (future) |
| T4.5 | Swap / hibernation | Sovereign tier uses mlock; general recommendation: full-disk encryption |

---

## 7. CLI Design Principles

### Common flags across all tools

| Flag | Description |
|------|-------------|
| `--tier nano\|standard\|sovereign` | Override default Argon2id tier |
| `--identity <name>` | Which identity to use (default: `config.toml` or `personal`) |
| `--passphrase-file <file>` | Read passphrase from file instead of prompt |
| `--quiet` | Suppress status messages (machine-readable output) |
| `--json` | Structured JSON output instead of human-readable |
| `--help` | Show help |
| `--version` | Show version |

### Passphrase handling

- Passphrase is read from `/dev/tty` (not stdin) to prevent piping secrets through shell history
- No passphrase echo (POSIX `tcsetattr` with `ECHO` off)
- `--passphrase-file` reads from a file descriptor (FD) — intended for secret managers, not disk files
- Confirm prompt on `keygen` and `vault init`

### Output conventions

- Default: human-readable colored terminal output
- `--json`: structured JSON, parseable by `jq`
- Errors go to stderr
- Exit codes: 0 = success, 1 = user error (bad passphrase, wrong args), 2 = internal error

---

## 8. Data Flow Diagrams

### Identity keygen

```
User                     origin-identity                  SDK                Filesystem
────                     ───────────────                  ───                ──────────
  │                            │                            │                    │
  │  $ origin-identity        │                            │                    │
  │    keygen --name personal  │                            │                    │
  │───────────────────────────>│                            │                    │
  │                            │  generate 32B seed         │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <──── seed bytes ────────│                    │
  │                            │                            │                    │
  │  ╔══ PHRASE ════════╗     │  (optional) encode phrase  │                    │
  │  ║ ─ ─ ─ ■ ■ ■      ║     │───────────────────────────>│                    │
  │  ╚═══════════════════╝     │  <──── phrase chars ──────│                    │
  │  ────────────────────>│    │                            │                    │
  │  (press enter to continue) │                            │                    │
  │                            │                            │                    │
  │  Passphrase: ······        │  Argon2id(pw, salt)       │                    │
  │  Confirm:    ······        │───────────────────────────>│                    │
  │                            │  <──── enc_key ──────────│                    │
  │                            │                            │                    │
  │                            │  XChaCha20-Poly1305 seal  │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <──── blob ─────────────│                    │
  │                            │                            │                    │
  │                            │                            │  write personal.id │
  │                            │                            │───────────────────>│
  │  <── "Created personal" ──│                            │                    │
```

### Vault read

```
User                     origin-vault                     SDK                Filesystem
────                     ────────────                     ───                ──────────
  │                            │                            │                    │
  │  $ origin-vault get        │                            │                    │
  │    personal.vault twitter  │                            │                    │
  │───────────────────────────>│                            │                    │
  │                            │                            │  open personal.    │
  │                            │                            │  vault             │
  │                            │                            │───────────────────>│
  │                            │                            │  <── raw bytes ────│
  │                            │                            │                    │
  │  Passphrase: ······        │  Argon2id(pw, salt)       │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <──── enc_key ──────────│                    │
  │                            │                            │                    │
  │                            │  HKDF(enc_key, vault)     │                    │
  │                            │  → header_key             │                    │
  │                            │                            │                    │
  │                            │  ChaCha20-BLAKE3 open      │                    │
  │                            │  (header_key, nonce, ct)   │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <── entry_index ────────│                    │
  │                            │                            │                    │
  │                            │  scan index for           │                    │
  │                            │  SHA3-256("twitter")       │                    │
  │                            │                            │                    │
  │                            │  read entry at offset      │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <── raw entry ──────────│                    │
  │                            │                            │                    │
  │                            │  HKDF(enc_key, entry_nonce│                    │
  │                            │  → entry_key               │                    │
  │                            │                            │                    │
  │                            │  ChaCha20-BLAKE3 open      │                    │
  │                            │───────────────────────────>│                    │
  │                            │  <── (name, secret) ─────│                    │
  │                            │                            │                    │
  │  twitter: s3cr3t           │                            │                    │
  │  <────────────────────────│                            │                    │
```

---

## 9. Migration & Compatibility

### Blob format versioning

| Version | Date | Changes |
|---------|------|---------|
| `0x01` | 2026-07 | Initial format |
| future  | —    | Reserved |

### Upgrading blobs

`origin-identity upgrade *.id` re-encrypts the payload under the new format version while keeping the same seed and passphrase. Uses `blob::rotate_blob` under the hood.

### Vault format versioning

| Version | Date | Changes |
|---------|------|---------|
| `0x01` | 2026-07 | Initial format (ChaCha20-BLAKE3) |
| future  | —    | Reserved |

---

## 10. Future Considerations

### Not in v0.1 but tracked for later

- **`origin-auth qr`**: Render QR codes in terminal for easy otpauth:// scanning
- **`origin-vault` entry padding**: Pad to nearest 32/64/128-byte boundary to mask entry sizes
- **`origin-vault` sync**: Encrypted sync with WebDAV / SFTP / cloud storage (vault-level, not entry-level)
- **`origin-identity` hardware wallet**: `--hid` flag to delegate signing to a hardware security module
- **`origin-backup` with Reed-Solomon**: Sharded backup to multiple locations (N of M recovery)
- **FIDO2 / WebAuthn support**: For the auth tool
- **`origin-vault` import from Bitwarden / 1Password / KeePass**: CSV-based import

---

## 11. Hex-Pipe Wire Format

### Purpose

`origin-identity sign --output hex` produces a stream of hex-encoded bytes that
can be piped directly into `origin-identity verify --hex --signature HEXSTR …`.
This enables shell-level tooling (e.g. signing in one container, verifying in
another) without depending on filesystem paths or JSON envelopes. The format is
**stable** — any byte sequence encoded by `sign --output hex` on a given
`message + identity` is decodable by `verify --hex` on the same message+identity.

### Layout

```text
┌───────────────────────────┬──────────────────┬────────────────────────┐
│ falcon_len (4B, BE u32)   │ ed25519 (64B)    │ falcon1024 (N B)       │
└───────────────────────────┴──────────────────┴────────────────────────┘
```

| Field        | Bytes | Encoding            | Notes |
|--------------|-------|---------------------|-------|
| `falcon_len` | 4     | big-endian `u32`    | length of the Falcon portion that follows |
| `ed25519`    | 64    | raw bytes           | length is invariant (Ed25519 is universally 64 B) |
| `falcon1024` | `N`   | raw bytes           | `N = falcon_len`; in this SDK typically 1280 B, max 1330 B per `SIGNATURE_MAX` |

Total = `4 + 64 + N` bytes. Hex-encoded: `(8 + 128 + 2N)` characters.

### Why a length prefix?

Falcon-1024 signatures are **variable-length** (padding is message-dependent).
The SDK exposes `pub const SIGNATURE_MAX: usize = 1330;` (see
`origin-crypto-sdk/src/pqc/falcon1024.rs`). A fixed-byte split at offset 64 is
impossible — the decoder must be told where Falcon ends. The 4-byte big-endian
length prefix is the smallest unambiguous layout.

### Canonical source

The encoder and decoder share a single typed struct in
`origin-tools/origin-identity/src/commands.rs`:

```rust
pub struct CombinedSignature {
    pub ed: ed25519_dalek::Signature,
    pub falcon: origin_crypto_sdk::pqc::falcon1024::FalconSignature,
}

impl CombinedSignature {
    pub const ED_LEN: usize = 64;
    pub const LEN_PREFIX: usize = 4;
    pub fn to_wire_bytes(&self) -> Vec<u8>;
    pub fn from_wire(raw: &[u8]) -> Result<Self, String>;
}
```

Both `cmd_sign --output hex` and `cmd_verify --hex` exclusively route through
this struct. The struct is the only place the format is encoded — encoder /
decoder drift is impossible by construction.

### Decode invariants

`CombinedSignature::from_wire` returns `Err(String)` (not panic) on:

| Condition | Behaviour |
|-----------|-----------|
| `raw.len() < LEN_PREFIX + ED_LEN` (= 68) | err: "must be at least 68 bytes" |
| Header `falcon_len` doesn't match actual buffer layout | err: "size mismatch" |
| `Signature::from_slice(&ed25519_bytes[..64])` fails | err: "invalid ed25519 signature" |
| `FalconSignature::from_bytes(&falcon_bytes[..N])` fails | err: "invalid falcon signature" |

Importantly: an over-large `falcon_len` (e.g. claiming 100 GB) is rejected by
the first size-mismatch check BEFORE any allocation is attempted — no resource
exhaustion risk.

### Test coverage locked in by 6 tests

The format is verified at three layers — unit, integration, smoke:

| Test                                                       | Layer | Purpose |
|------------------------------------------------------------|-------|---------|
| `commands::tests::combined_signature_round_trip`            | unit (commands.rs) | synthetic ed25519 + Falcon round-trip |
| `commands::tests::combined_signature_rejects_short`        | unit | buffer-too-small rejection |
| `commands::tests::combined_signature_rejects_wrong_total_length` | unit | length-mismatch rejection |
| `commands::tests::combined_signature_rejects_size_mismatch_only_via_header` | unit | declared > actual rejection |
| `commands::tests::combined_signature_handles_max_falcon_len` | unit | `u32::MAX` declared length rejected structurally |
| `commands::tests::sign_and_verify_hex_pipe_roundtrip`      | unit | round-trips the real signer through the format |
| `tests::integration::import_then_sign_and_verify_end_to_end` | integration | full CLI sign+verify through the format |

Any change to the wire format that breaks parsing will fail at least two of
these tests simultaneously.

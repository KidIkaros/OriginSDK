# Migration: 0.6.x → 0.7.x formats

Version 0.7.0 (commit `50b4543`) replaced the pre-NIST encodings with the
official submission formats. Wire sizes changed:

| Primitive        | 0.6.x   | 0.7.x   | Migratable?            |
|------------------|---------|---------|------------------------|
| sntrup761 pk     | 1218 B  | 1158 B  | Yes — `migrate_public_key` |
| sntrup761 sk     | 1600 B  | 1763 B  | Yes — `migrate_private_key` |
| sntrup761 ct     | 1047 B  | 1039 B  | No — ephemeral, re-encapsulate |
| sntrup761 ss     | 32 B    | 32 B    | No — session derivation changed |
| Falcon-512 sig   | 666 B   | 809 B   | No — re-sign with the new key |
| Falcon-1024 sig  | 1280 B  | 1577 B  | No — re-sign with the new key |
| Falcon keys      | old fmt | FIPS 206| No — regenerate (see below) |

## NTRU Prime

The 0.6.x secret key layout was `Small(f) ‖ Small(gr) ‖ Rq_v06(h)`; `f` and
`gr` used the same 191-byte Small encoding the NIST format still uses, so they
carry over verbatim. Migration decodes `h` from the old Rq encoding,
re-encodes it in the NIST format, draws a fresh `rho`, and recomputes
`cache = H4(pk)`:

```rust
use origin_crypto_sdk::pqc::ntru_prime::migrate;

let new_pk = migrate::migrate_public_key(&old_pk)?;             // 1218 → 1158
let new_sk = migrate::migrate_private_key(&old_sk, &mut rng)?;  // 1600 → 1763
```

Or from the CLI:

```bash
origin-crypto migrate ntru-pk --key <1218-byte-hex|@file>
origin-crypto migrate ntru-sk --key <1600-byte-hex|@file>
```

**Caveats:**

- Migration re-encodes; it does not validate the keypair. Run an
  encapsulate/decapsulate roundtrip on the result before relying on it.
- Shared secrets are **not** preserved: 0.6.x and 0.7.x use different session
  derivation (0.7.x commits to the full ciphertext, 0.6.x did not — see the
  12.3/12.4 audit entry). Anything encrypted under a 0.6.x session key must be
  re-keyed; migrating the keypair only preserves its identity.
- Ciphertexts are ephemeral by design; there is nothing to migrate.
- Migration is only defined for the default SHA-2-512 KEM hash backend. Under
  `ntru-blake3`/`ntru-shake*` the cache field uses that backend's `H4`, so the
  migrated key is still self-consistent but not NIST-interoperable — same as
  any freshly generated key under those features.

## Falcon

0.6.x used `falcon-rust` 0.1.2 (NIST submission format); 0.7.x uses
`falcon-rs` 0.2.5 (FIPS 206). Key migration is not possible:

- `falcon-rs` only accepts FIPS 206 wire-format keys; it exposes no API to
  reconstruct a private key from its component polynomials, so a submission-
  format key cannot be re-encoded through the supported library.
- Old signatures are not verifiable under FIPS 206 regardless — the signature
  encoding changed (666→809 / 1280→1577 bytes).

The migration path is **regenerate + re-sign**: create a fresh `falcon-rs`
keypair, distribute the new public key, and re-sign anything whose signature
must remain verifiable. For hybrid bundles this means deriving a new bundle
with `Ed25519Falcon1024` / `HybridSigningKeyBundle` — the Ed25519 side is
unaffected by the format change, but bundle bytes embed the Falcon key and
must be re-derived wholesale.

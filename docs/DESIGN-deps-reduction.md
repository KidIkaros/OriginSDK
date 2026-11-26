# Design: Dependency Reduction & First-Party Crypto Ownership

> **Status:** Draft — architecture review before implementation.
> **Spec companion:** `docs/plans/deps-reduction-plan.md` (task list).
> **Goal:** Replace unverifiable third-party crypto code paths with first-party code the SDK owns and can audit, while preserving FIPS/NIST interop, the hybrid wire formats, and consumer-crate ABI. The plan is staged by risk rather than alphabetically.
> **Root constraint (from Obsidian forensics):** the attack is not "a dep exists" but "an unverifiable constant/code path in an audited-but-not-executed crate." See `IKEAROS/Research Papers Synthesis/cluster_e.md` (Dual EC / Juniper / EUCLEAK).

---

## 1. Threat model (what "control" actually buys)

| Attack class | Example from Obsidian | Which of OUR deps it targets | Mitigation by owning |
|---|---|---|---|
| **Vendor-chosen constant** — a backdoor key embedded in a spec'd constant | Dual EC `Q`; Juniper `prng_temporary` buffer swap | any crate that imports a hardcoded `const` and is never exercised on the CCA path (EUCLEAK proved constant-time `memcmp` survives ~80 CC evals because the *vulnerable branch* is dead code) | Owning the code path makes the constant auditable in-tree; you can read it. |
| **Dead-code-oracle** — security-critical branch is present but never executed, so testing never reaches it | Juniper `shared` flag in `prng_temporary`; EUCLEAK modular inversion | `sha3` crate's `Sha3_256` used for SLH-DSA seed derivation (a path a fuzzer rarely drives); `chacha20poly1305` used only in diff tests | Moving the primitive in-tree + a KAT/differential gate on the **actually-used** path eliminates the "audited but not executed" gap. |
| **Transitive drift** — a transitive dep gets re-resolved to a different revision with a bad constant | Dual EC propagated via BSAFE → RSA SecurID SDK → countless products | any non-pinned transitive crypto dep | Pin + `deny.toml` bans + `cargo vendor` removes drift. |
| **Algorithm-level impl bug** — the math is standardized but the *implementation* is wrong | lattice-risks cluster: Falcon discrete-Gaussian; Frodo `memcmp`; Round5 2⁻⁵⁵ failure | `falcon-rs`, `ml-dsa`, `ml-kem`, `slh-dsa` (FIPS 204/205/206) | Do NOT own these — ENISA + lattice-risks explicitly warn that lattice/FFT implementations are the failure class. Keep them external, pinned, interop-tested. |

**Verdict from the corpus:** own the symmetric + hash layer (short specs, differential-testable, where constants live); keep standardized asymmetric/lattice cores external (where implementations break).

## 2. Current dependency inventory (verified 2026-10-15)

`cargo tree`, 169 unique crates under default features. External crypto crates ranked by replaceability. Status: ✅ gone, 🧪 dev-only, 🏠 native twin exists, 🔁 redirect needed, 🔒 keep.

| Crate | Role | Status | Rationale (corpus link) |
|---|---|---|---|
| `ring` (0.17) | — | ✅ **DEAD — remove** | Zero `use ring` in src/tests/benches/examples/fuzz; `cargo tree -i ring` → root-only. Pure dead weight. → Task 1.1 |
| `chacha20poly1305` (0.10.1) | reference AEAD for diff tests | 🧪 **dev-dep only** | Only `tests/differential_tests.rs` calls it; `cargo tree -i` → root-only. SDK ships native `primitives/chacha20poly1305.rs` (219 L). → Task 1.2 |
| `sha3` (0.11) | Shake128/256 + Sha3_256/512 + `digest` traits | 🔁 **redirect → native** | 28 src sites; `cargo tree -i sha3` → root-only. Native Keccak-f[1600] (414 L) already backs SHA3-256/512; SHAKE = same state + `0x1F` suffix. → Task 1.4/1.5 |
| `subtle` (2.6.1) | CT comparisons | 🔁 **redirect → native** | `internal/subtle.rs` (82 L) exists; 3 external sites (x25519.rs, recovery/phrase.rs, ocra.rs). → Task 1.3 |
| `sha2` (0.10.8) | SHA-256/512 | 🔒 **keep** | Transitive pull of `k256`/`p256`/`ed448` (passkey/ECDSA interop). Native SHA-2 = code-ownership, not dep-removal (Phase 3 ⏸). |
| `blake3` (1.8) | BLAKE3 hash | 🔒 **keep** | Owned-BLAKE3 = ~400 L + SIMD; the `blake3` crate is the audited fast path; HMAC-BLAKE3 is *correct* usage (`hash`+`Hasher`, not `keyed_hash`). Cluster A documents BLAKE3; Cluster B treats it as the ARX successor to BLAKE2. |
| `argon2` (0.5.3) | Argon2id KDF | 🔒 **keep** | RFC 9106 / PHC memory-hard. Corpus: memory-hard KDFs are *exactly* the class not to hand-roll (timing + side-channel surface). |
| `falcon-rs` (0.2.5) | Falcon-1024 | 🔒 **keep (pinned)** | FIPS 206; your hybrid-default signer. The discrete-Gaussian sampler is the documented impl-risk class (lattice-risks). → keep gated. |
| `ml-dsa`, `ml-kem`, `slh-dsa` | FIPS 204/205/206 | 🔒 **keep (gated)** | Interop surface standards; lattice-risks cluster. Native version loses wire compat. |
| `ed25519-dalek` / `x25519-dalek` (2.x) | Ed25519 / X25519 | 🔒 **keep (Phase 3 ⏸)** | dalek v2 is the audited reference; you have curve41417 field arithmetic (1.4 kL) that *could* retarget to curve25519, but that's a multi-month audited effort — reverse-K256, only on incident trigger. |
| `k256`, `p256` (0.14) | secp256k1 / secp256r1 | 🔒 **keep** | Passkey WebAuthn (p256) + secp256k1 Schnorr (k256). The `docs/DESIGN_AUDIT.md` precedent: hand-rolled → k256 after byte-equivalence. Do not reverse this. |
| `ed448-goldilocks` | Ed448 | 🔒 **keep** | No native twin; pre-release upstream pinned. |
| `serpent`, `skein` | Non-NIST decorative | 🧪 **feature-gate** | Serpent: `aead::symmetric` paranoid mode ("to be replaced in future phase"). Skein: `signing::hybrid::combinators` — **shapes Ed25519Skein512/1024 struct layout**, so gating ≠ deletion. → Task 2.1/2.2 |
| `hmac`+`sha1` | TOTP/HOTP | 🔒 **keep** | RFC 4226/6238 interop demands SHA1. |
| `rand`+`getrandom` | entropy / DRBG | 🔒 **keep** | `internal/getrandom.rs` wraps the external crate on the syscall path. Native OS-entropy = Phase 3. |
| `clap`/`serde`/`rayon`/`flate2`/`zstd`/`unicode-normalization`/`hex` | utility | 🔒 **keep** | Non-crypto; `zstd` pulls `zstd-sys` (C) — note as a build-surface risk separately. |

### Net Phase 1 effect (before Phase 3)
- **Direct crypto deps removed from the normal graph: `ring`, `sha3`, `subtle`, `chacha20poly1305`.**
- **`chacha20poly1305` retained as dev-only** (still needed as the differential-test reference for the native AEAD).
- **Consumer ABI unchanged:** public re-export names (`Shake128`, `Shake256`, `Sha3_256`, `Sha3_512`, `sha3_256`, `sha3_512`) are identical; only the *origin* is native. Skein/serpent stay available behind opt-in features.

## 3. Phase 1 architecture — native SHAKE on the existing Keccak state

### Design
- `internal::sha3::keccakf1600`/`xor_bytes`/`extract_bytes` already exist and are KAT-verified for SHA3-256/512 (NIST vectors at `internal/sha3.rs:353-377`).
- SHAKE adds: absorb with domain suffix `0x1F` (bit pattern `11110` + zero-pad to rate), then squeeze indefinitely. Same permutation; different rate and an XOF reader (no finalize gate).
- Native `Shake128` rate = 168 B (capacity 32 → 128-bit security); `Shake256` rate = 136 B (capacity 64 → 256-bit security). FIPS 202 §3.2.

### Native XOF API surface (must match the call sites so the port is import-only)
```rust
// internal/sha3.rs
pub struct Shake128 { state: [u64;25], buffer: [u8;168], buf_len: usize, finalized: bool }
impl Shake128 {
    pub fn new() -> Self;
    pub fn default() -> Self;          // matches `Shake128::default()` call sites
    pub fn update(&mut self, data: &[u8]);          // inherent — no `digest::Update` trait
    pub fn finalize_xof(self) -> Shake128Reader;     // inherent — no `digest::ExtendableOutput`
}
pub struct Shake128Reader { state: [u64;25], buffer: [u8;168], pos: usize }
impl Shake128Reader {
    pub fn read(&mut self, out: &mut [u8]);          // inherent — no `digest::XofReader`
}
// Shake256 identical, rate=136.
```
This lets every call site keep `hasher.update(...)` and `hasher.finalize_xof().read(&mut out)` verbatim; only the `use` lines change.

### Redirect map — the exact edits (Task 1.5)
| File:line | From (external) | To (native) | Return-type note |
|---|---|---|---|
| `primitives.rs:16` | `pub use sha3::{sha3_256, sha3_512, Shake128, Shake256};` | `pub use crate::internal::sha3::{sha3_256, sha3_512, Shake128, Shake256, Sha3_256, Sha3_512};` | add `Sha3_256`/`Sha3_512` to match external re-export surface |
| `primitives/sha3.rs:22` | `pub use sha3::{Shake128, Shake256};` | `pub use crate::internal::sha3::{Shake128, Shake256};` | |
| `primitives/sha3.rs:126,187` (cfg feature test blocks) | `use sha3::{digest::{ExtendableOutput,Update,XofReader}, Shake128}` | `use crate::internal::sha3::{Shake128};` (drop trait imports) | inherent API identical |
| `recovery/format.rs:44` | `use sha3::{Digest, Sha3_256};` | `use crate::internal::sha3::Sha3_256;` | `finalize()` now `[u8;32]`; `.into()→[u8;32]` trivial ✓ |
| `recovery/unicode_cipher.rs:78` | `use sha3::{Digest, Sha3_256};` | `use crate::internal::sha3::Sha3_256;` | `.into()` identity ✓ |
| `recovery/alphabet.rs:23` | `use sha3::{Digest, Sha3_256};` | `use crate::internal::sha3::Sha3_256;` | `finalize().into()` ✓ |
| `pqc/slhdsa.rs:109` | `use sha3::{Digest, Sha3_256};` | `use crate::internal::sha3::Sha3_256;` | `&hasher.finalize()[..16]` ✓ (slices `[u8;32]`) |
| `seed/gen.rs:33` | `use sha3::digest::{ExtendableOutput, Update, XofReader};` | *(remove; line 32 already imports `crate::primitives::{sha3_256, Shake256}`)* | native `Shake256` inherent API ✓ |
| `signing/hybrid/combinators.rs:14` | `use sha3::digest::{ExtendableOutput, Update, XofReader};` | *(remove; line 21 imports native `Shake128,Shake256`)* | inherent API ✓ |
| `Cargo.toml:46` | `sha3 = "0.11"` | *(delete from `[dependencies]`)* | after all sites green (keep as dev-dep for the cross-check gate until Phase 2) |

### Why this is safe and not a rewrite
- `keccakf1600`, `xor_bytes`, `extract_bytes` are *already* in-tree and KAT-green (SHA3-256/512 tests at `internal/sha3.rs:349-413`). SHAKE reuses the verified permutation.
- SHAKE128/256 output is *byte-identical* to the external crate by construction (same FIPS 202 sponge); the KAT gate proves it before the re-export flips.
- No consumer-visible symbol changes; `Shake128`/`Shake256` keep their names and method signatures.

## 4. Verification gates (hard gates, not self-consistency)

Per `references/cross_check_crypto.md`: self-consistency tests pass even with a wrong block size / broken chaining. The gates below are the *independent reference* pattern your corpus requires.

| Gate | What | Reference | Command |
|---|---|---|---|
| G1 native SHA3 parity | SHA3-256/512 unchanged after SHAKE addition | NIST FIPS 202 §7 vectors already in `internal/sha3.rs::tests` | `cargo test --lib internal::sha3` |
| G2 SHAKE KAT match | native SHAKE128/256 vs FIPS 202 known answers | NIST CAVP `SHAKE128ShortPattern` / `SHAKE256ShortPattern` (Monte Carlo) — hard-code 5 vectors incl. empty + 1-byte + >rate + multi-squeeze | `cargo test --lib internal::sha3::shake::kat` |
| G3 SHAKE differential | native == RustCrypto `sha3` crate byte-for-byte | the *current* `sha3` dep as reference (not removed until green) | `cargo test --lib --features shake_differential` |
| G4 full lib suite | regression across all 499 tests | itself | `cargo test --lib` |
| G5 supply-chain | no bans/relaxed sources | `cargo-deny` (licenses/bans/sources/advisories) | `cargo deny check` |
| G6 consumer ABI | 4 pinned crates build against new lockfile | `origin-tools`, `signet`, `mnemos`, `stoa` | per-crate `cargo build` in CI |

- The differential gate (G3) uses a **separate `shake_differential` feature** that keeps `sha3` as a dev-dep and asserts native-vs-external over a 1 KiB random input + NIST patterns. The feature is dropped from CI after G3 is green and `sha3` exits `[dependencies]`. This keeps the "audit but verify execution" lesson (Juniper/EUCLEAK) explicit: the reference impl is present *at test time* but absent from the shipped graph.
- All KAT vectors sourced from FIPS 202 §7 (in-repo, no network at test time), matching the precedent in `internal/sha3.rs` which already embeds NIST vectors.

## 5. The "own vs keep" rubric (extracted from the corpus — apply to every future dep)

This is the rule the Obsidian evidence actually supports. A primitive is **owned in-tree** when ALL of these hold; if any fails, it **stays external**:

| Criterion | Corpus source | Phase 1 verdict |
|---|---|---|
| **Spec is short & self-contained (≤ few pages), no hidden state** | Cluster A (BLAKE3/Salsa specs); Cluster B (Ed41417 field laws) | SHAKE ✓ (FIPS 202 §3.2); Falcon ✗ (discrete-Gaussian sampler hidden state) |
| **Differential-testable against a reference impl** | Cluster D (Sequoia interop found ≥92 bugs in 10 impls; WireGuard "no agility + one impl + interop tests") | SHAKE ✓ (byte-equal); Lattice ✗ (interop vectors exist but impls diverge on sampler edge cases) |
| **Used on a security-critical *and executed* path** (the Juniper/EUCLEAK test: is the audited branch the branch run?) | Cluster E (Juniper `prng_temporary` dead branch; EUCLEAK hidden non-CT inversion) | SHAKE ✓ (NTRU Prime CCA, seed/gen, hybrid combinators); `sha3` crate was ✗ (Skein/SHAKE dead on the CCA success path) |
| **No standardized interop counterpart we must wire-format with** | Cluster C (lattice-risks: NIST-selected KEMs are interop surfaces); ENISA integration study | Ed25519/Skein/Serpent: own ✓; ML-DSA/ML-KEM/SLH-DSA/Falcon: interop ✗ → keep |

**Inversion of the K256 precedent:** `DESIGN_AUDIT.md` §12 replaced native `secp256k1` → `k256` because the hand-rolled code was *not* byte-equivalence-gated. The rule is *symmetric*: own it IF you can prove byte equality + CT-correctness via differential tests; if you cannot, keep the audited upstream.

## 6. Risk tiers & sequencing

| Tier | Primitives | Decision | Why now |
|---|---|---|---|
| **T1 — Dead weight** | `ring` | Remove (Task 1.1) | Zero use sites; pure narrative + tree cost |
| **T1 — Mis-placed dev** | `chacha20poly1305` | Dev-dep (Task 1.2) | Only the diff-test reference; native AEAD is 219 L in-tree |
| **T2 — Redirect to native twin** | `sha3`, `subtle` | Native (Task 1.3–1.5) | Keccak + CT-eq already native; remove the only non-audited-execution gap |
| **T3 — Feature-gate (no delete)** | `serpent`, `skein` | `[features]` (Task 2.1/2.2) | Skein is in the hybrid struct layout; gating preserves ABI |
| **T4 — Own (Phase 3, on trigger)** | Native SHA-2, native Ed25519 (curve25519 via curve41417 retarget) | Deferred | Code-ownership only; `sha2` is transitive-via-passkey so this is assurance, not dep removal |
| **T5 — Keep & pin** | `argon2`, `blake3`, Falcon, ML-DSA, ML-KEM, SLH-DSA, dalek, k256, p256, ed448 | Pinned, documented upstreams | The classes the corpus says break when owned |

**Default sequencing:** T1 → T2 (KAT gate) → T3 → Checkpoint A. T4/T5 deferred until an upstream incident or a deliberate audit slot. The plan is **not** proceeding to native Falcon/Ed25519 unless a supply-chain event forces it — that is the explicit, corpus-aligned call.

## 7. Open questions (sign-off needed before Task 1.1)

1. **`symmetric`/`serpent` reachability:** Is `origin_crypto_sdk::aead::symmetric` (Serpent CBC) referenced by any of the 12 consumer crates? A grep across the consumer repos is required before gating (Task 2.1). If used, gate as `symmetric = ["dep:serpent"]` and leave on; if unused, gate it OFF by default.
2. **`ShakeReader` API ergonomics:** native `finalize_xof()->Reader; Reader.read(&mut)` vs the RustCrypto `XofReader` trait — the in-tree call sites use both a `Hasher.update(...)` then `finalize_xof().read(...)` pattern (`seed/gen.rs`, `combinators.rs`) and a shorter `Shake256::digest`-style? (verify none). The redirect map assumes the reader pattern only; confirm no site calls `.finalize()` directly on a Shake type.
   - **Verified (2026-10-15):** `grep` over `src/` for `Shake(128\|256).*\.finalize\(\)` returns **0** matches. Every Shake site uses `.finalize_xof()` + `.read(&mut)`. The native reader API is therefore a 1:1 port; the redirect map in §3 is correct as written.
3. **`sha3` crate removal timing:** keep `sha3` as a dev-dep for the G3 differential gate until Phase 2, then drop. Acceptable to ship v0.7.3 with `sha3` dev-only for one release? (recommended: yes, for rollback safety.)
4. **Consumer rebuild scope:** confirm the 4 crates (`origin-tools`, `signet`, `mnemos`, `stoa`) are the only ones touching the hash/SHAKE surface; `origin-network` (X25519) is out of Phase 1 scope but should be smoke-built.

## 8. Change-log (this design)
- 2026-10-15: initial draft (Phase 1 architecture + redirect map + rubric).

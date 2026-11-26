# Dependency Reduction & First-Party Crypto Plan

> **For Hermes:** Execute task-by-task; one task per focused session, full TDD cycle per task.
> **Goal:** Lessen unverifiable third-party crypto dependencies so the SDK owns its security-critical code paths, without a net reduction in FIPS/NIST interop or a break of consumer wire formats.
> **Start date:** 2026-10 (Phase 1: zero-risk dead-weight removal + native SHAKE).
> **Status:** Phase 1 design approved → task list ready
> **Tech stack:** Rust 1.95, cargo-deny (licensing/bans/advisories already `ok`), `pyblake3`/`sha3` Python reference for cross-check.

---

## Architecture Decision (the premise you gave me)

> *"I want this control to circumvent any [undesirable] and unforeseen circumstances."*

The Obsidian forensics (Dual EC, Juniper, EUCLEAK) show the attack surface is **vendor-chosen constants and unverifiable code paths**, not "a dependency exists." So the goal is **verifiable control of the security-critical paths**, not maximal dep removal. The plan is staged so the highest-assurance wins come first and the highest-risk reimplementations are deferred behind a gate.

## Honest Constraints From the Audit

These are real and change scope. Do not argue with them mid-flight — they bound the plan.

1. **`sha2` cannot be removed in Phase 1.** It is a *transitive* dep of `k256`, `p256`, and `ed448-goldilocks` (ES256 / WebAuthn / secp256k1 Schnorr passkeys). Dropping the `sha2` crate requires dropping the passkey/ECDSA path — consumer-breaking. Same for `digest` (trait glue, transitive).
2. **`getrandom 0.2` cannot be removed.** The SDK's own `internal::getrandom.rs` calls the external crate (`getrandom::getrandom` / `getrandom::fill`) on the non-wasm path. Removing it requires a from-scratch OS entropy impl — Phase 3.
3. **`blake3`, `argon2`, `hmac`, `sha1` must stay** for reasons the corpus supports: blake3 is fast+audited and is the hybrid hash (owning it = ~400 LOC + SIMD, not worth it); argon2 is RFC 9106 / PHC and memory-hard (owning it risks the KEM/session-key path — see ENISA bug-surface argument); sha1/hmac are **interop-critical** (TOTP/HOTP RFC 4226/6238 — RFC mandates SHA1).
4. **`sha3` (RustCrypto) is removable as a *direct* dependency** (only `origin-crypto-sdk` pulls it — not transitive), but it currently provides `Shake128`/`Shake256` **and** `Sha3_256`/`Sha3_512`/`Digest`/`ExtendableOutput`/`XofReader`, used in **28 src sites** (NTRU Prime KEM, SLH-DSA, recovery codec, seed gen, hybrid combinators). Removal = own SHAKE + redirect those sites. This is Phase 1's centerpiece.
5. **`serpent` / `skein` are non-NIST decorative.** Serpent is in the `symmetric` paranoid-mode module (not feature-gated, comment: "to be replaced in future phase"); Skein is in `signing::hybrid::combinators` and shapes the `Ed25519Skein`/`Ed41417Skein` signature struct. Removing Skein changes algorithm IDs + struct layout → consumer wire format. → Phase 2 (feature-gate, not delete).
6. **`ring = "0.17"` is dead.** Zero `use ring` / `ring::` in `src/`, `tests/`, `benches/`, `examples/`, `fuzz/`; `cargo tree -i ring` shows only the SDK pulls it directly. Pure removal.

## Design Rationale (why these primitives, why now)

- **SHAKE → native (Phase 1 B4).** SHAKE = Keccak-f[1600] (already native, 414 L in `internal/sha3.rs`) + the `0x1F` domain suffix + XOF squeeze. It's the primitive the **NTRU Prime CCA session-key derivation depends on** (`hash_session`/`hash_confirm`/`hash_confirm`). Putting an *auditable, first-party* SHAKE in front of sntrup761 decap is the single highest-leverage control point — it's where a backdoored-XOF would collapse CCA. The corpus (Cluster B/C) supports owning the hash layer; it warns against owning lattice samplers.
- **`subtle`→native, `chacha20poly1305`/`ring`→dev/dead (Phase 1 A/B).** Mechanical reductions; the native `internal::subtle` already exists.
- **No native Falcon / ML-DSA / ML-KEM (deferred).** Per the corpus (lattice-risks cluster), the discrete-Gaussian sampler and NTT are where implementations break. FIPS 204/205/206 are interop-surface standards. Own the *wrapper* (you do) + keep the standardized core audited upsteam. Flagged as the explicit exception to "own everything."
- **No native Ed25519 (Phase 3 only).** You *have* the field/scalar arithmetic in `curve41417` (~1,474 L). Curve25519 retargeting + a 32-byte SHA512-based clamping/H interleaving is a known-difficulty job; the corpus (djb Ed25519 design) is the reference, and `ed25519-dalek` is the audited reference impl. Byte-equivalence test vs the crate is the gate.

---

## Task List

### Phase 1 — Kill dead code + own the SHAKE layer (no consumer impact)

#### Task 1.1: Remove dead `ring` dependency
- **Files:** `Cargo.toml:94` (delete `ring = "0.17"`)
- **Step 1 — verify dead:** `cargo tree -i ring` (expect: nothing; ring pulled only by root)
- **Step 2 — patch:** delete the line
- **Step 3 — gate:** `cargo build --lib` succeeds; `cargo deny check bans`
- **Verify:** `grep -rn 'ring::' src/ tests/ benches/ examples/ fuzz/` → exit 0, 0 lines
- **Deps:** `ring` + transitives (`spin`, `cc`, `libc` if nothing else holds them) leave the tree.
- **Dependencies:** None

#### Task 1.2: Demote `chacha20poly1305` to a dev-dependency
- **Files:** `Cargo.toml:42` (move to `[dev-dependencies]`), `tests/differential_tests.rs` (confirm sole consumer)
- **Pre-verify:** `cargo tree -i chacha20poly1305` shows only `origin-crypto-sdk` (no transitive consumer) — confirmed.
- **Step 1 — patch:** cut the line from `[dependencies]`, add `chacha20poly1305 = { version = "=0.10.1", features = ["getrandom"] }` under `[dev-dependencies]`.
- **Verify:** `cargo build --lib`; `cargo test --test differential_tests`; `cargo deny check bans`. External `chacha20poly1305` now dev-only → dropped from end-user `cargo metadata --format-version` runtime graph.
- **Dependencies:** Task 1.1

#### Task 1.3: Redirect external `subtle` → `internal::subtle` (drop the crate)
- **Files:** `src/x25519.rs:46`, `src/recovery/phrase.rs:23`, `src/ocra.rs:195` (swap import), `src/internal/subtle.rs` (ensure `ConstantTimeEq` + `Choice` are pub), `Cargo.toml:72` (drop `subtle = "2.6.1"`)
- **Pre-verify:** `grep -rn 'use subtle::' src/` → the 3 sites above (NTRU Prime already uses `internal::subtle::...`)
- **Verify:** `cargo test --lib` full pass (CT-eq paths covered by NTRU/EdDSA tests). `cargo tree -i subtle` → not present as a *direct* dep.
- **Dependencies:** None

#### Task 1.4: Implement native SHAKE128/SHAKE256 (core of the SHAKE layer)
- **Files:** `src/internal/sha3.rs` (add), `src/primitives/sha3.rs` (re-export swap)
- **Spec:** SHAKE = Keccak[2·c] with domain suffix `0x1F` (bits `11110` then zero-pad to rate block), XOF squeeze. Reuse the existing native Keccak-f[1600] permutation state in `internal/sha3.rs`.
- **Step 1 — write the failing test against the RustCrypto `sha3` crate KATs first** (RFC / NIST CAVP `SHAKE128ShortPattern` `SHAKE256ShortPattern`): pull a few deterministic test vectors from the `sha3` crate's own test vector file and assert the *external* impl produces them. This locks the reference before touching anything.
- **Step 2 — implement native `Shake128`/`Shake256`** with an `Update`-like + `finalize_xof` → `XofReader`-like API so the call sites that currently do `sha3::digest::{ExtendableOutput, Update, XofReader}` can be a 1:1 swap.
- **Step 3 — cross-check test `test_shake_matches_reference`:** assert native output == RustCrypto output over ≥32 vectors incl. empty, 1-byte, >rate-length (multi-block squeeze), and the `0x1F` suffix boundary. Run `python —c "import sha3..."`? No upstream python SHAKE in stdlib; instead use the **RustCrypto `sha3` crate itself as the reference** (same pattern as `cross_check_crypto.md` uses Python for HMAC-BLAKE3).
- **Verify:** `cargo test --lib internal::sha3::shake` passes; `cargo deny check bans`.
- **Dependencies:** Task 1.1 (independent)

#### Task 1.5: Swap public SHAKE re-export from `sha3::` to native (remove crate)
- **Files:** `src/primitives/sha3.rs:22` (`pub use sha3::{Shake128, Shake256};` → `pub use crate::internal::sha3::{Shake128, Shake256};`), all 28 sites from Task 1.4, then `Cargo.toml:46` (drop `sha3 = "0.11"`).
- **Step 1 — redirect call sites:** the non-shake sites (`slhdsa.rs:109`, `recovery/*`) import `Sha3_256`/`Digest` from the external `sha3` crate → re-point them to `crate::internal::sha3::Sha3_256` (already pub-exported at `primitives/sha3.rs:21`) and either own the `Digest` trait use or convert to the free functions `sha3_256()`/`sha3_512()`.
- **Step 2 — drop the crate:** delete `sha3 = "0.11"` from `[dependencies]`.
- **Verify:** full `cargo test --lib` (499 tests) green; `cargo tree -i sha3` → absent; `cargo deny check`.
- **Blast radius:** none to consumers — the public re-export name (`Shake128`/`Shake256`) is unchanged; only the origin is native.
- **Dependencies:** Task 1.4

### Phase 2 — Non-NIST decorative, gated behind a feature (no default-bloat)

#### Task 2.1: Feature-gate `serpent` + the `aead::symmetric` module
- **Files:** `Cargo.toml` (mark `serpent` optional; add feature `symmetric = ["dep:serpent"]`), `src/aead/mod.rs` (`#[cfg(feature="symmetric")] pub mod symmetric;`)
- **Pre-check:** confirm `pub mod symmetric` is not referenced on the default path by consumers (grep `aead::symmetric` across the 12 consumer crates — likely none, given `secp256k1`/`symmetric` is the paranoid-mode path).
- **Verify:** `cargo build --lib` (default, serpent out); `cargo build --lib --features symmetric` (serpent in). `cargo test --lib kdf::aead::symmetric` for the feature path.
- **Dependencies:** None

#### Task 2.2: Feature-gate `skein` + the Skein hybrid combinators
- **Files:** `Cargo.toml` (mark `skein` optional; add feature `skein = ["dep:skein"]`), `src/signing/hybrid/mod.rs` / `combinators.rs` (`#[cfg(feature="skein")]`), update `public_ed25519_types_gap.md` notes on struct layout.
- **Consumer note:** Skein drives the `Ed25519Skein{512,1024}` algorithm IDs. Gating it (not deleting) preserves interop for anyone depending on the struct, while **removing it from the default dep graph.** Document the algorithm-ID reservation in `algorithm_id.rs`.
- **Verify:** `cargo build --lib`; `cargo build --lib --features skein`; no default-feature test references break.
- **Dependencies:** None

### Checkpoint A — Phase 1+2 complete
- [ ] `cargo build --lib` (default features) succeeds
- [ ] `cargo test --lib` (499 tests) green, default features
- [ ] `cargo deny check` = advisories/bans/licenses/sources all `ok`
- [ ] `cargo tree -e normal --no-default-features` no longer contains `ring`, `chacha20poly1305` (dev only), `sha3`, `subtle`
- [ ] Default-feature compile does not pull `serpent`/`skein`
- [ ] No consumer crate breakage: build the 4 downstream crates that pin the SDK (`origin-tools`, `signet`, `mnemos`, `stoa`) against the new lockfile.
- [ ] Review with human before Phase 3.

### Phase 3 — High-risk primitives (explicitly deferred)

> These invert the K256 precedent (`docs/DESIGN_AUDIT.md` §12: hand-rolled → audited upstream). **Do not start without a written security review + external audit slot budget.**

#### Task 3.1: Native SHA-2 (SHA-256/512)
- **Rationale:** `sha2` is still pulled by k256/p256/ed448 transitively, so this is **code ownership, not dep removal.** Only worth it as a "no `sha2` dep on the NTRU Prime NIST path" hardening. SHA-2 is short (~150 LOC), fully specified, NTRU-ECDSA differential-testable.
- **Gate:** KAT (NIST FIPS 180-4) vectors + byte-equality with the crate across ≥100 cases.
- **Decision needed:** worth it? (Low ROI — defer.)

#### Task 3.2: Native Ed25519 via curve41417 retargeting
- **Rationale:** `ed25519-dalek` has no transitive escape (it IS the public provider). Retargeting `curve41417`'s field/scalar ops to curve25519 is a real but bounded job. The precedent that matters: this is the *reverse* of the K256 decision — only justified if a supply-chain incident in dalek surfaces.
- **Gate:** RFC 8032 test vectors + `cargo test --test ed25519_differential` byte-equality vs `ed25519-dalek` over ≥10k cases; constant-time property test.
- **Decision needed:** only if a supply-chain incident in dalek surfaces.

#### Task 3.3 (DO NOT START) — Native Falcon / ML-DSA / ML-KEM
- **Blocked by corpus evidence:** Falcon's discrete-Gaussian sampler and ML-DSA/ML-KEM's NTT masking are exactly the implementation-risk classes the Obsidian lattice cluster (`latticerisks`) calls out. These are also FIPS 204/205/206 interop surfaces — owning them silently loses wire compatibility.
- **Action:** none. Keep `falcon-rs`/`ml-dsa`/`ml-kem`/`slh-dsa` as gated, pinned, documented upstreams. This is the honest, evidence-aligned position — "own everything" is the wrong reading of the Dual-EC lesson for *algorithms*, which is why the plan keeps the lattice cores external.

---

## Supply-Chain Hygiene for What Stays External (ongoing)

These harden the retained deps without reimplementing them — they're the correct complement to first-party crypto:

1. **`Cargo.lock` pinned & committed** (root crate publishes, so lockfile applies to downstream reproducible builds) — already vendored via `cargo vendor`? add a CI gate.
2. **`deny.toml` ban regrowth** (add to the template):
   ```toml
   [bans]
   deny = [
     { crate = "ring@0.17.*", reason = "removed 2026-10; re-adding requires SDK-team sign-off" },
     { crate = "sha3@0.11.*", reason = "replaced by native internal::sha3 SHAKE + SHA3; re-adding requires sign-off" },
     { crate = "subtle@2.*",   reason = "replaced by internal::subtle" },
   ]
   ```
   So a future PR that accidentally pulls `sha3`/`ring`/`subtle` again fails CI.
3. **`cargo audit` CI step** on every PR.
4. **KAT differential gates** in CI for every native primitive (Task 1.4's cross-check pattern generalized) — this is the *real* substitute for "own it": independent reference + byte equality.

## Definition of Done (this plan)
- Phase 1 complete, checkpoint A green, human sign-off.
- Phase 2 complete, `cargo tree` confirms `serpent`/`skein` absent from default build.
- Phase 3 documented as deferred-with-trigger; no code written unless trigger fires.
- `deny.toml` bans active; `cargo deny check` green on CI.
- Downstream crates (`origin-tools`, `signet`, `mnemos`, `stoa`) build against new lockfile with no code change.

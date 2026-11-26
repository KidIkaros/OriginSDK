# Dependency Reduction — Task Tracker

## Phase 1 — Dead-weight removal + native SHAKE (no consumer impact)

- [ ] 1.1 Remove dead `ring` dependency
- [ ] 1.2 Demote `chacha20poly1305` to dev-dependency
- [ ] 1.3 Redirect external `subtle` → `internal::subtle`; drop crate
- [ ] 1.4 Implement native SHAKE128/SHAKE256 (cross-check vs RustCrypto sha3 KATs)
- [ ] 1.5 Swap SHAKE re-export to native; drop `sha3` crate; redirect 28 sites

### Checkpoint A — Phase 1+2
- [ ] default `cargo build --lib`
- [ ] `cargo test --lib` (499 tests) green
- [ ] `cargo deny check` ok
- [ ] `cargo tree -e normal --no-default-features` lacks ring/chacha20poly1305/sha3/subtle
- [ ] downstream crates build

## Phase 2 — Feature-gate decorative non-NIST
- [ ] 2.1 Feature-gate `serpent` + `aead::symmetric`
- [ ] 2.2 Feature-gate `skein` + hybrid combinators

## Phase 3 — Deferred (needs audit slot)
- [ ] 3.1 Native SHA-2 (conditional)
- [ ] 3.2 Native Ed25519 via curve41417 retarget (conditional)
- [ ] 3.3 Native Falcon/ML-DSA/ML-KEM/SLH-DSA — DO NOT START

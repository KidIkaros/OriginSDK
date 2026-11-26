# Audit Note: Hybrid Signature Combiner — Separability Analysis

**Date:** 2026-12-21 · **Scope:** `src/signing/hybrid/` · **Method:** literature-anchored
internal review (IETF hybrid-signature design requirements, composite-signature
practices) · **Status:** internal finding, external review still required

## Summary

The hybrid constructions implement the AND-combiner correctly for the core
unforgeability property, but deviate from emerging standard practice on
**non-separability**: component signatures are raw algorithm signatures over
the raw message, so any component can be stripped from a hybrid artifact and
presented as a valid standalone signature on the same message.

## What is correct (verified)

1. **AND-combiner unforgeability** — both component signatures cover the
   identical message and both must verify (`both_must_verify`). The hybrid
   inherits the strength of the stronger component: forging requires breaking
   every component still standing. This is the correct hybrid property.
2. **Key derivation domain separation** — `HybridSigningKeyBundle::from_seed`
   derives per-algorithm seeds through HKDF with distinct info strings
   (`domain ‖ "ed25519"`, `domain ‖ "falcon1024"`). Cross-algorithm key
   reuse is excluded by construction.
3. **Format-layer algorithm binding** — `algorithm_id.rs` versions operations
   explicitly with a downgrade policy, so artifacts declare their expected
   verification algorithm suite.
4. **Verification hygiene** — constant-time digest comparison, fallible
   variants at every panic-capable site.

## Finding H-1 (medium): component signatures are extractable

`Ed25519Falcon1024::sign` computes `ed25519_sk.sign(message)` and
`falcon_sign(message)` over the raw message. Nothing in either signature
binds it to the hybrid context. Consequently:

- The Ed25519 component of any hybrid signature is a valid **standalone**
  Ed25519 signature on the same message, indistinguishable from one produced
  outside the hybrid scheme. The same holds for the Falcon component.
- **Cross-construction confusion**: constructions sharing a component key
  (`Ed25519Blake3`, `Ed25519Shake256`, `Ed25519Skein512`, the Falcon
  variants) produce mutually interchangeable components — a component lifted
  from one construction's artifact verifies inside any other.

**Why this matters:** the emerging standard practice for composite/hybrid
signatures (IETF LAMPS composite-signature design) prefixes a fixed
domain-separator (the composite algorithm identifier) into the signed
payload of each component precisely so components are non-extractable.
The downgrade resistance therefore does not rely solely on format-layer
discipline at every verifier, forever.

**Current mitigation:** the algorithm-ID system binds algorithm suites at
the envelope layer. The finding's severity depends on a question external
review should answer: are there consumption paths where a component key is
*also* used standalone (or where an artifact type confusion is possible)?
If every verifier strictly honors the algorithm-ID layer, exploitation
requires a verifier bug; if any component key ever signs standalone traffic,
extraction is live today.

**Remediation options** (wire-format breaking — requires a format version
bump, so a design decision, not a patch):

1. Sign `DOMAIN_SEP ‖ message` in each component, where `DOMAIN_SEP` is
   construction-specific (e.g. `b"origin-hybrid-ed25519-falcon1024-v1"`).
   Components become non-extractable and constructions non-confusable.
   This is the composite-signature practice.
2. Alternatively/additionally: cross-bind components into each other's
   signed payload (Ed25519 signs `message ‖ falcon_sig` or a digest of it),
   giving non-separability even where the format layer is ignored.

## Finding H-2 (informational): digest-binding constructions add no unforgeability

`Ed25519Blake3`/`Ed25519Shake256`/`Ed25519Skein512` combine a signature with
a hash of the same message. The digest is public-coin recomputation — it
commits the artifact to the message through a second hash function but adds
no second unforgeability assumption. These constructions are not harmful,
but their security contribution should not be represented as "hybrid" in
the AND-combiner sense; consumers comparing construction names may
overestimate them. Recommend documenting the distinction in the module
docs or renaming the family.

## References

- IETF hybrid signature design requirements (draft-ietf-pquip-hybrid-signature-spectrums lineage): weak/strong non-separability definitions
- Composite ML-DSA practice (draft-ietf-lamps-pq-composite-sigs): domain-separated component payloads
- Shaw, "quantum-safe" (arXiv:2605.17061): insecure combiner implementations as a known production risk; externally-anchored readiness dimensions

## Disposition

Open. Awaiting owner decision on wire-format version bump (H-1 remediation)
and external review. This note should ship with the audit package.

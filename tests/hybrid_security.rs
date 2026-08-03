// SPDX-License-Identifier: Apache-2.0

//! Hybrid signature security tests.
//!
//! These tests verify security properties specific to hybrid constructions:
//! - Component substitution: swapping Ed25519 or Falcon component fails
//! - Key mismatch: verifying with wrong key fails
//! - Message mismatch: verifying with different message fails
//! - Signature splicing: combining components from different signatures fails
//! - Domain separation: different domains produce different keys
//! - Seed sensitivity: different seeds produce different keys
//!
//! Classification: security property evidence
//! Purpose: verify that the hybrid construction's "both must verify" property
//! holds under adversarial conditions.

use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};

fn make_bundle(domain: &str) -> HybridSigningKeyBundle {
    let seed = [0x42u8; 32];
    HybridSigningKeyBundle::from_seed(&seed, domain).expect("bundle creation failed")
}

fn make_bundle_from_seed(seed: &[u8; 32], domain: &str) -> HybridSigningKeyBundle {
    HybridSigningKeyBundle::from_seed(seed, domain).expect("bundle creation failed")
}

// ── Component substitution: swapping one component fails ───────────────

#[test]
fn hybrid_component_substitution_fails() {
    let bundle_a = make_bundle("domain-a");
    let bundle_b = make_bundle("domain-b");
    let message = b"component substitution test";

    let sig_a = bundle_a.sign_hybrid(message);
    let sig_b = bundle_b.sign_hybrid(message);

    // Create a spliced signature: Ed25519 from A, Falcon from B
    let spliced = Ed25519Falcon1024 {
        ed25519_sig: sig_a.ed25519_sig.clone(),
        falcon_sig: sig_b.falcon_sig.clone(),
    };

    // Verifying with A's keys must fail (Falcon component doesn't match)
    assert!(
        Ed25519Falcon1024::verify(
            bundle_a.ed25519_pk(),
            bundle_a.falcon1024_pk(),
            message,
            &spliced
        )
        .is_err(),
        "spliced signature with wrong Falcon component must fail verification"
    );

    // Verifying with B's keys must fail (Ed25519 component doesn't match)
    assert!(
        Ed25519Falcon1024::verify(
            bundle_b.ed25519_pk(),
            bundle_b.falcon1024_pk(),
            message,
            &spliced
        )
        .is_err(),
        "spliced signature with wrong Ed25519 component must fail verification"
    );
}

// ── Message mismatch: different message fails ──────────────────────────

#[test]
fn hybrid_message_mismatch_fails() {
    let bundle = make_bundle("msg-mismatch");
    let msg_a = b"message A";
    let msg_b = b"message B";

    let sig_a = bundle.sign_hybrid(msg_a);

    assert!(
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), msg_b, &sig_a)
            .is_err(),
        "signature for message A must not verify against message B"
    );
}

// ── Key mismatch: wrong key fails ──────────────────────────────────────

#[test]
fn hybrid_key_mismatch_fails() {
    let bundle_a = make_bundle("key-mismatch-a");
    let bundle_b = make_bundle("key-mismatch-b");
    let message = b"key mismatch test";

    let sig_a = bundle_a.sign_hybrid(message);

    assert!(
        Ed25519Falcon1024::verify(
            bundle_b.ed25519_pk(),
            bundle_b.falcon1024_pk(),
            message,
            &sig_a
        )
        .is_err(),
        "signature from key A must not verify with key B"
    );
}

// ── Domain separation: different domains produce different keys ────────

#[test]
fn hybrid_domain_separation_different_keys() {
    let seed = [0x42u8; 32];
    let bundle_a = make_bundle_from_seed(&seed, "domain-a");
    let bundle_b = make_bundle_from_seed(&seed, "domain-b");

    // Ed25519 public keys must differ
    assert_ne!(
        bundle_a.ed25519_pk().to_bytes(),
        bundle_b.ed25519_pk().to_bytes(),
        "different domains must produce different Ed25519 keys"
    );

    // Falcon public keys must differ
    assert_ne!(
        bundle_a.falcon1024_pk().as_bytes(),
        bundle_b.falcon1024_pk().as_bytes(),
        "different domains must produce different Falcon keys"
    );
}

#[test]
fn hybrid_domain_separation_same_domain_same_keys() {
    let seed = [0x42u8; 32];
    let bundle_a = make_bundle_from_seed(&seed, "same-domain");
    let bundle_b = make_bundle_from_seed(&seed, "same-domain");

    assert_eq!(
        bundle_a.ed25519_pk().to_bytes(),
        bundle_b.ed25519_pk().to_bytes(),
        "same domain + same seed must produce same Ed25519 keys"
    );
}

// ── Seed sensitivity: different seeds produce different keys ───────────

#[test]
fn hybrid_seed_sensitivity() {
    let seed_a = [0x01u8; 32];
    let seed_b = [0x02u8; 32];
    let bundle_a = make_bundle_from_seed(&seed_a, "same-domain");
    let bundle_b = make_bundle_from_seed(&seed_b, "same-domain");

    assert_ne!(
        bundle_a.ed25519_pk().to_bytes(),
        bundle_b.ed25519_pk().to_bytes(),
        "different seeds must produce different Ed25519 keys"
    );
    assert_ne!(
        bundle_a.falcon1024_pk().as_bytes(),
        bundle_b.falcon1024_pk().as_bytes(),
        "different seeds must produce different Falcon keys"
    );
}

// ── Signature determinism: same key + message = same Ed25519 signature ─

#[test]
fn hybrid_ed25519_signature_determinism() {
    let bundle = make_bundle("determinism-test");
    let message = b"deterministic signature test";

    let sig_a = bundle.sign_hybrid(message);
    let sig_b = bundle.sign_hybrid(message);

    assert_eq!(
        sig_a.ed25519_sig, sig_b.ed25519_sig,
        "Ed25519 component must be deterministic"
    );
    // Note: Falcon signatures may be randomized, so we only check Ed25519
}

// ── Empty message handling ─────────────────────────────────────────────

#[test]
fn hybrid_empty_message_sign_verify() {
    let bundle = make_bundle("empty-msg");
    let message = b"";

    let sig = bundle.sign_hybrid(message);
    assert!(
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), message, &sig)
            .is_ok(),
        "empty message must sign and verify correctly"
    );
}

// ── Large message handling ─────────────────────────────────────────────

#[test]
fn hybrid_large_message_sign_verify() {
    let bundle = make_bundle("large-msg");
    let message = vec![0xabu8; 100_000];

    let sig = bundle.sign_hybrid(&message);
    assert!(
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), &message, &sig)
            .is_ok(),
        "large message must sign and verify correctly"
    );
}

// ── Tampered Ed25519 component fails ───────────────────────────────────

#[test]
fn hybrid_tampered_ed25519_component_fails() {
    let bundle = make_bundle("tamper-ed");
    let message = b"tamper ed25519 test";

    let sig = bundle.sign_hybrid(message);

    // Tamper with the Ed25519 signature bytes
    let mut ed_bytes = sig.ed25519_sig.to_bytes();
    ed_bytes[0] ^= 0x01;

    let tampered_sig = Ed25519Falcon1024 {
        ed25519_sig: ed25519_dalek::Signature::from_bytes(&ed_bytes),
        falcon_sig: sig.falcon_sig.clone(),
    };

    assert!(
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            message,
            &tampered_sig
        )
        .is_err(),
        "tampered Ed25519 component must fail verification"
    );
}

// ── Cross-decrypt: Origin signature verifies with correct keys ─────────

#[test]
fn hybrid_valid_signature_always_verifies() {
    // Verify that correctly signed messages always pass verification
    // with the correct keys. This is the positive control for the
    // negative tests above.
    for i in 0u8..5 {
        let bundle = make_bundle(&format!("valid-{i}"));
        let message = format!("test message {i}");
        let sig = bundle.sign_hybrid(message.as_bytes());
        assert!(
            Ed25519Falcon1024::verify(
                bundle.ed25519_pk(),
                bundle.falcon1024_pk(),
                message.as_bytes(),
                &sig
            )
            .is_ok(),
            "valid signature must verify for iteration {i}"
        );
    }
}

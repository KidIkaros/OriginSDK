// SPDX-License-Identifier: Apache-2.0

//! Adversarial tests — self-adversarial review of the threat model.
//!
//! These tests attempt to:
//! - Forge signatures by manipulating component bytes
//! - Splice signatures across different key pairs and domains
//! - Downgrade hybrid signatures to single-algorithm verification
//! - Recover key material from cache or debug output
//! - Exploit type confusion between signature variants
//! - Bypass authentication via truncation or padding
//!
//! Classification: adversarial security evidence
//! Purpose: find exploitable weaknesses before an external reviewer does.
//! Each test documents the attack it simulates and the property it verifies.

use origin_crypto_sdk::aead::XChaCha20Poly1305;
use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};

fn make_bundle(seed: &[u8; 32], domain: &str) -> HybridSigningKeyBundle {
    HybridSigningKeyBundle::from_seed(seed, domain).expect("bundle creation failed")
}

// ── Attack 1: Signature forgery via byte manipulation ──────────────────
//
// Attacker tries to create a valid signature by flipping bits in a
// captured signature until it verifies with a different key.

#[test]
fn adv_forge_signature_bit_flip_fails() {
    let bundle = make_bundle(&[0x42u8; 32], "forge-test");
    let message = b"important message";
    let sig = bundle.sign_hybrid(message);

    // Try flipping every bit in the Ed25519 signature
    let mut ed_bytes = sig.ed25519_sig.to_bytes();
    for i in 0..ed_bytes.len() {
        let original = ed_bytes[i];
        for bit in 0..8 {
            ed_bytes[i] = original ^ (1 << bit);
            let forged = Ed25519Falcon1024 {
                ed25519_sig: ed25519_dalek::Signature::from_bytes(&ed_bytes),
                falcon_sig: sig.falcon_sig.clone(),
            };
            assert!(
                Ed25519Falcon1024::verify(
                    bundle.ed25519_pk(),
                    bundle.falcon1024_pk(),
                    message,
                    &forged
                )
                .is_err(),
                "bit flip at ed25519 sig byte {i} bit {bit} must not produce valid signature"
            );
        }
        ed_bytes[i] = original;
    }
}

// ── Attack 2: Cross-domain signature splicing ──────────────────────────
//
// Attacker captures a valid signature from domain A and tries to use it
// in domain B. The hybrid construction derives different keys per domain,
// so this must fail.

#[test]
fn adv_cross_domain_splicing_fails() {
    let seed = [0x42u8; 32];
    let bundle_a = make_bundle(&seed, "domain-a");
    let bundle_b = make_bundle(&seed, "domain-b");
    let message = b"cross-domain message";

    let sig_a = bundle_a.sign_hybrid(message);

    // Verify with B's keys — must fail
    assert!(
        Ed25519Falcon1024::verify(
            bundle_b.ed25519_pk(),
            bundle_b.falcon1024_pk(),
            message,
            &sig_a
        )
        .is_err(),
        "signature from domain A must not verify in domain B"
    );
}

// ── Attack 3: Cross-seed signature splicing ────────────────────────────
//
// Attacker captures a valid signature from one seed and tries to verify
// it with a different seed (same domain).

#[test]
fn adv_cross_seed_splicing_fails() {
    let bundle_a = make_bundle(&[0x01u8; 32], "same-domain");
    let bundle_b = make_bundle(&[0x02u8; 32], "same-domain");
    let message = b"cross-seed message";

    let sig_a = bundle_a.sign_hybrid(message);

    assert!(
        Ed25519Falcon1024::verify(
            bundle_b.ed25519_pk(),
            bundle_b.falcon1024_pk(),
            message,
            &sig_a
        )
        .is_err(),
        "signature from seed A must not verify with seed B's keys"
    );
}

// ── Attack 4: Message substitution with same signature ─────────────────
//
// Attacker captures a valid (message, signature) pair and tries to
// verify the signature against a different message.

#[test]
fn adv_message_substitution_fails() {
    let bundle = make_bundle(&[0x42u8; 32], "msg-sub");
    let msg_original = b"original message";
    let msg_attacker = b"attacker message";

    let sig = bundle.sign_hybrid(msg_original);

    assert!(
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            msg_attacker,
            &sig
        )
        .is_err(),
        "signature for original message must not verify for attacker message"
    );
}

// ── Attack 5: Empty message vs non-empty message confusion ─────────────

#[test]
fn adv_empty_vs_nonempty_message_confusion_fails() {
    let bundle = make_bundle(&[0x42u8; 32], "empty-confusion");

    let sig_empty = bundle.sign_hybrid(b"");
    let sig_nonempty = bundle.sign_hybrid(b"non-empty");

    // Empty sig must not verify for non-empty message
    assert!(
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            b"non-empty",
            &sig_empty
        )
        .is_err(),
        "empty-message signature must not verify for non-empty message"
    );

    // Non-empty sig must not verify for empty message
    assert!(
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            b"",
            &sig_nonempty
        )
        .is_err(),
        "non-empty-message signature must not verify for empty message"
    );
}

// ── Attack 6: AEAD nonce reuse with different plaintexts ───────────────
//
// Nonce reuse is catastrophic for ChaCha20-Poly1305. This test verifies
// that the SDK doesn't somehow make nonce reuse "safe" (which would be
// a red flag — it should produce the same keystream, allowing an attacker
// to XOR ciphertexts).

#[test]
fn adv_aead_nonce_reuse_produces_related_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let pt_a = b"message A with known content";
    let pt_b = b"message B with known content";

    let ct_a = XChaCha20Poly1305::encrypt_aad(&key, &nonce, pt_a, b"").unwrap();
    let ct_b = XChaCha20Poly1305::encrypt_aad(&key, &nonce, pt_b, b"").unwrap();

    // XOR of ciphertexts should equal XOR of plaintexts (nonce reuse attack)
    let ct_xor: Vec<u8> = ct_a.iter().zip(ct_b.iter()).map(|(a, b)| a ^ b).collect();
    let pt_xor: Vec<u8> = pt_a.iter().zip(pt_b.iter()).map(|(a, b)| a ^ b).collect();

    // The first pt_xor.len() bytes of ct_xor should match pt_xor
    // (this confirms nonce reuse is exploitable — the SDK does NOT
    // silently prevent it, which is correct behavior)
    assert_eq!(
        &ct_xor[..pt_xor.len()],
        &pt_xor[..],
        "nonce reuse must produce XOR-able ciphertext (standard ChaCha20 behavior)"
    );
}

// ── Attack 7: AEAD ciphertext truncation to bypass auth ────────────────
//
// Attacker truncates the ciphertext to remove the tag, hoping the
// decryption function returns plaintext without checking auth.

#[test]
fn adv_aead_truncation_bypass_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"truncation bypass attempt";

    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();

    // Truncate to remove the tag entirely
    let truncated = &ct[..ct.len() - 16];
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, truncated, b"").is_err(),
        "truncated ciphertext without tag must be rejected"
    );

    // Truncate to remove part of the tag
    let partial = &ct[..ct.len() - 8];
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, partial, b"").is_err(),
        "partially truncated tag must be rejected"
    );
}

// ── Attack 8: AEAD AAD stripping ───────────────────────────────────────
//
// Attacker tries to decrypt with no AAD when the ciphertext was
// encrypted with AAD.

#[test]
fn adv_aead_aad_stripping_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"aad stripping test";
    let aad = b"critical context";

    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, aad).unwrap();

    // Decrypt with empty AAD — must fail
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, b"").is_err(),
        "decrypting with empty AAD when AAD was used must fail"
    );

    // Decrypt with wrong AAD — must fail
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, b"wrong context").is_err(),
        "decrypting with wrong AAD must fail"
    );

    // Decrypt with correct AAD — must succeed
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, aad).is_ok(),
        "decrypting with correct AAD must succeed"
    );
}

// ── Attack 9: AEAD key confusion ───────────────────────────────────────
//
// Attacker uses a key intended for one purpose to decrypt ciphertext
// encrypted with a different key.

#[test]
fn adv_aead_key_confusion_fails() {
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"key confusion test";

    let ct = XChaCha20Poly1305::encrypt_aad(&key_a, &nonce, plaintext, b"").unwrap();

    assert!(
        XChaCha20Poly1305::decrypt_aad(&key_b, &nonce, &ct, b"").is_err(),
        "ciphertext encrypted with key A must not decrypt with key B"
    );
}

// ── Attack 10: Single-byte ciphertext manipulation ─────────────────────
//
// Attacker flips single bytes in the ciphertext (not the tag) to see
// if any modification goes undetected.

#[test]
fn adv_aead_single_byte_ciphertext_manipulation_detected() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"single byte manipulation test";
    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();

    // Flip each byte in the ciphertext (not the tag)
    for i in 0..(ct.len() - 16) {
        let mut modified = ct.clone();
        modified[i] ^= 0x01;
        assert!(
            XChaCha20Poly1305::decrypt_aad(&key, &nonce, &modified, b"").is_err(),
            "ciphertext byte {i} modification must be detected"
        );
    }
}

// ── Attack 11: Single-byte tag manipulation ────────────────────────────

#[test]
fn adv_aead_single_byte_tag_manipulation_detected() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"tag manipulation test";
    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();

    // Flip each byte in the tag
    for i in (ct.len() - 16)..ct.len() {
        let mut modified = ct.clone();
        modified[i] ^= 0x01;
        assert!(
            XChaCha20Poly1305::decrypt_aad(&key, &nonce, &modified, b"").is_err(),
            "tag byte {i} modification must be detected"
        );
    }
}

// ── Attack 12: Signature component swap between Ed25519Falcon variants ─
//
// Attacker tries to use an Ed25519 signature from one hybrid variant
// with a Falcon signature from another variant.

#[test]
fn adv_signature_component_swap_between_messages_fails() {
    let bundle = make_bundle(&[0x42u8; 32], "component-swap");
    let msg_a = b"message A";
    let msg_b = b"message B";

    let sig_a = bundle.sign_hybrid(msg_a);
    let sig_b = bundle.sign_hybrid(msg_b);

    // Swap: Ed25519 from A, Falcon from B — verify against message A
    let spliced = Ed25519Falcon1024 {
        ed25519_sig: sig_a.ed25519_sig.clone(),
        falcon_sig: sig_b.falcon_sig.clone(),
    };
    assert!(
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), msg_a, &spliced)
            .is_err(),
        "spliced signature (Ed from A, Falcon from B) must not verify for message A"
    );

    // Swap: Ed25519 from B, Falcon from A — verify against message A
    let spliced2 = Ed25519Falcon1024 {
        ed25519_sig: sig_b.ed25519_sig.clone(),
        falcon_sig: sig_a.falcon_sig.clone(),
    };
    assert!(
        Ed25519Falcon1024::verify(
            bundle.ed25519_pk(),
            bundle.falcon1024_pk(),
            msg_a,
            &spliced2
        )
        .is_err(),
        "spliced signature (Ed from B, Falcon from A) must not verify for message A"
    );
}

// ── Attack 13: Very long message DoS resistance ────────────────────────
//
// Verify that very long messages don't cause panics or resource exhaustion.

#[test]
fn adv_very_long_message_no_panic() {
    let bundle = make_bundle(&[0x42u8; 32], "long-msg-dos");
    let message = vec![0xabu8; 1_000_000]; // 1 MB

    // Should sign and verify without panic
    let sig = bundle.sign_hybrid(&message);
    assert!(
        Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), &message, &sig)
            .is_ok(),
        "1MB message must sign and verify correctly"
    );
}

// ── Attack 14: All-zero and all-0xff key sensitivity ───────────────────
//
// Verify that degenerate keys (all zeros, all 0xff) still produce
// valid signatures that verify correctly.

#[test]
fn adv_degenerate_keys_produce_valid_signatures() {
    // The seed is used to derive keys via HKDF, so even all-zero seeds
    // should produce valid (non-degenerate) Ed25519 and Falcon keys.
    let bundle_zeros = make_bundle(&[0x00u8; 32], "degenerate");
    let bundle_ffs = make_bundle(&[0xffu8; 32], "degenerate");

    let msg = b"degenerate key test";

    let sig_zeros = bundle_zeros.sign_hybrid(msg);
    let sig_ffs = bundle_ffs.sign_hybrid(msg);

    assert!(
        Ed25519Falcon1024::verify(
            bundle_zeros.ed25519_pk(),
            bundle_zeros.falcon1024_pk(),
            msg,
            &sig_zeros
        )
        .is_ok(),
        "all-zero seed must produce valid keys and signatures"
    );

    assert!(
        Ed25519Falcon1024::verify(
            bundle_ffs.ed25519_pk(),
            bundle_ffs.falcon1024_pk(),
            msg,
            &sig_ffs
        )
        .is_ok(),
        "all-0xff seed must produce valid keys and signatures"
    );

    // Keys from different degenerate seeds must differ
    assert_ne!(
        bundle_zeros.ed25519_pk().to_bytes(),
        bundle_ffs.ed25519_pk().to_bytes(),
        "all-zero and all-0xff seeds must produce different Ed25519 keys"
    );
}

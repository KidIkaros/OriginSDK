// SPDX-License-Identifier: Apache-2.0

//! Differential tests — compare Origin's implementations against independent
//! reference implementations.
//!
//! These tests verify that Origin's native XChaCha20-Poly1305 produces
//! byte-identical output to the `chacha20poly1305` crate (RustCrypto)
//! for the same inputs.
//!
//! Classification: correctness evidence (differential testing)
//! Purpose: detect implementation bugs by comparing against an
//! independent, audited implementation.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305 as RefXChaCha20Poly1305,
};
use origin_crypto_sdk::aead::XChaCha20Poly1305;

/// Compare Origin's XChaCha20-Poly1305 against the RustCrypto reference
/// for a given key, nonce, plaintext, and AAD.
fn assert_xchacha20poly1305_matches(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) {
    // Origin implementation
    let origin_ct =
        XChaCha20Poly1305::encrypt_aad(key, nonce, plaintext, aad).expect("Origin encrypt failed");

    // Reference implementation (RustCrypto chacha20poly1305 crate)
    let ref_cipher = RefXChaCha20Poly1305::new(key.into());
    let ref_ct = ref_cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("Reference encrypt failed");

    assert_eq!(
        origin_ct, ref_ct,
        "Origin and reference XChaCha20-Poly1305 ciphertext must match"
    );

    // Verify both decrypt to the same plaintext
    let origin_pt =
        XChaCha20Poly1305::decrypt_aad(key, nonce, &origin_ct, aad).expect("Origin decrypt failed");
    let ref_pt = ref_cipher
        .decrypt(nonce.into(), Payload { msg: &ref_ct, aad })
        .expect("Reference decrypt failed");

    assert_eq!(origin_pt, ref_pt, "Decrypted plaintext must match");
    assert_eq!(
        origin_pt,
        plaintext.to_vec(),
        "Decrypted must match original"
    );
}

#[test]
fn diff_xchacha20poly1305_basic() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"Hello, differential testing!";
    let aad = b"associated data";
    assert_xchacha20poly1305_matches(&key, &nonce, plaintext, aad);
}

#[test]
fn diff_xchacha20poly1305_empty_plaintext() {
    let key = [0xabu8; 32];
    let nonce = [0xcdu8; 24];
    assert_xchacha20poly1305_matches(&key, &nonce, b"", b"");
}

#[test]
fn diff_xchacha20poly1305_empty_aad() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 24];
    let plaintext = b"no aad here";
    assert_xchacha20poly1305_matches(&key, &nonce, plaintext, b"");
}

#[test]
fn diff_xchacha20poly1305_large_aad() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 24];
    let plaintext = b"large aad test";
    let aad = vec![0x55u8; 1000];
    assert_xchacha20poly1305_matches(&key, &nonce, plaintext, &aad);
}

#[test]
fn diff_xchacha20poly1305_large_plaintext() {
    let key = [0x66u8; 32];
    let nonce = [0x77u8; 24];
    let plaintext = vec![0xabu8; 10_000];
    assert_xchacha20poly1305_matches(&key, &nonce, &plaintext, b"");
}

#[test]
fn diff_xchacha20poly1305_sequential_keys() {
    // Test with several different keys to ensure no key-dependent bugs
    for i in 0u8..10 {
        let key = [i; 32];
        let nonce = [i.wrapping_add(1); 24];
        let plaintext = [i.wrapping_add(2); 100];
        let aad = [i.wrapping_add(3); 10];
        assert_xchacha20poly1305_matches(&key, &nonce, &plaintext, &aad);
    }
}

#[test]
fn diff_xchacha20poly1305_varied_nonce() {
    let key = [0x99u8; 32];
    let plaintext = b"nonce variation test";
    let aad = b"aad";

    // Test with different nonce patterns
    let mut nonce = [0u8; 24];
    for i in 0..10 {
        nonce[0] = i;
        nonce[23] = i;
        assert_xchacha20poly1305_matches(&key, &nonce, plaintext, aad);
    }
}

#[test]
fn diff_xchacha20poly1305_cross_decrypt() {
    // Origin encrypts, reference decrypts, and vice versa
    let key = [0xf0u8; 32];
    let nonce = [0x0fu8; 24];
    let plaintext = b"cross-decrypt test";
    let aad = b"cross-aad";

    // Origin encrypt → reference decrypt
    let origin_ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, aad).unwrap();
    let ref_cipher = RefXChaCha20Poly1305::new(&key.into());
    let ref_pt = ref_cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &origin_ct,
                aad,
            },
        )
        .expect("reference must decrypt Origin ciphertext");
    assert_eq!(ref_pt, plaintext);

    // Reference encrypt → Origin decrypt
    let ref_ct = ref_cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    let origin_pt = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ref_ct, aad).unwrap();
    assert_eq!(origin_pt, plaintext);
}

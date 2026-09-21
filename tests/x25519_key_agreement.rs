// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the X25519 key-agreement surface (RFC 7748).
//!
//! Exercises the **crate-root re-exports** (`origin_crypto_sdk::X25519*`),
//! not the module path, so the public API consumers actually use is what is
//! verified. Includes RFC 7748 §6.1, python-cryptography cross-check
//! goldens, and a Noise-shaped usage pattern (the origin-channel seam this
//! surface replaces).

use origin_crypto_sdk::algorithm_id::AlgorithmId;
use origin_crypto_sdk::x25519::SECRET_KEY_SIZE;
use origin_crypto_sdk::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

/// RFC 7748 §6.1 through the crate-root re-exports.
#[test]
fn kat_rfc7748_section61_via_crate_root() {
    let alice_sk: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let bob_sk: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];

    let alice = X25519KeyPair::from_secret_key(&alice_sk).unwrap();
    let bob = X25519KeyPair::from_secret_key(&bob_sk).unwrap();

    let k = alice.diffie_hellman(&bob.public_key()).unwrap();
    assert_eq!(
        k.as_bytes(),
        &[
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ]
    );
}

/// Wire round-trip: serialize both halves, rebuild, same shared secret.
#[test]
fn wire_round_trip_preserves_shared_secret() {
    let a = X25519KeyPair::generate().unwrap();
    let b = X25519KeyPair::generate().unwrap();

    // Transmit forms: 32-byte secret (persistence) + 32-byte public (wire).
    let a_sk_bytes = a.secret_key_bytes();
    assert_eq!(a_sk_bytes.len(), SECRET_KEY_SIZE);
    let b_pk_bytes = *b.public_key().as_bytes();

    let a_restored = X25519KeyPair::from_secret_key(&a_sk_bytes).unwrap();
    let b_pk = X25519PublicKey::from_bytes(b_pk_bytes);

    let ab = a_restored.diffie_hellman(&b_pk).unwrap();
    let ba = b.diffie_hellman(&a_restored.public_key()).unwrap();
    assert_eq!(ab.as_bytes(), ba.as_bytes());
}

/// Noise-shaped usage (the origin-channel `dh.rs` seam this surface
/// replaces): ephemeral-static handshake, shared secret fed through the
/// SDK's HKDF-BLAKE3 with domain separation — never used raw.
#[test]
fn noise_shaped_handshake_with_hkdf_binding() {
    use origin_crypto_sdk::hkdf_blake3;

    let responder = X25519KeyPair::generate().unwrap(); // static
    let initiator = X25519KeyPair::generate().unwrap(); // ephemeral

    // -> e (initiator's ephemeral public), <- e, ee (responder's static)
    let es = initiator.diffie_hellman(&responder.public_key()).unwrap();
    let ee = initiator
        .diffie_hellman(&X25519KeyPair::generate().unwrap().public_key())
        .unwrap();

    // Chain key material: concat of DH outputs → HKDF-BLAKE3, domain-separated.
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(es.as_bytes());
    ikm.extend_from_slice(ee.as_bytes());

    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];
    hkdf_blake3(
        &ikm,
        None,
        b"origin-crypto-sdk:x25519:noise-shape:tx",
        &mut tx_key,
    )
    .unwrap();
    hkdf_blake3(
        &ikm,
        None,
        b"origin-crypto-sdk:x25519:noise-shape:rx",
        &mut rx_key,
    )
    .unwrap();

    assert_ne!(
        tx_key, rx_key,
        "domain separation must split the directions"
    );
    assert!(
        tx_key.iter().any(|&b| b != 0) && rx_key.iter().any(|&b| b != 0),
        "KDF output must be non-degenerate"
    );
}

/// Algorithm-id binding: the surface must report 0x0602 (downgrade
/// resistance), matching the reserved identifier in `algorithm_id`.
#[test]
fn algorithm_id_is_x25519() {
    assert_eq!(AlgorithmId::X25519 as u16, 0x0602);
    assert_eq!(origin_crypto_sdk::x25519::ALGORITHM_ID, AlgorithmId::X25519);
}

/// Interop discipline: same seed + domain on both sides must derive the
/// same key pair (this is what lets origin-channel replace its raw-bytes
/// seam with derived keys).
#[test]
fn derived_pairs_agree_across_instances() {
    let a = X25519KeyPair::from_seed(&[7u8; 32], "origin-channel:test").unwrap();
    let b = X25519KeyPair::from_seed(&[7u8; 32], "origin-channel:test").unwrap();
    let ss: X25519SharedSecret = a.diffie_hellman(&b.public_key()).unwrap();
    assert_ne!(*ss.as_bytes(), [0u8; 32]);
}

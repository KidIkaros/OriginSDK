// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: ChaCha40 encrypt/decrypt roundtrip
//!
//! Splits the input into key (64B) + nonce (12B) + plaintext.
//! Verifies that encrypt then decrypt returns the original plaintext
//! and that operations never panic on arbitrary input.
//!
//! Run with: cargo +nightly fuzz run fuzz_chacha40

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::chacha40::chacha40_encrypt;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 + 12 {
        return;
    }
    let key: [u8; 64] = data[..64].try_into().unwrap();
    let nonce: [u8; 12] = data[64..76].try_into().unwrap();
    let plaintext = &data[76..];

    // Roundtrip with counter=0
    let ciphertext = chacha40_encrypt(&key, 0, &nonce, plaintext);
    let decrypted = chacha40_encrypt(&key, 0, &nonce, &ciphertext);
    assert_eq!(decrypted, plaintext, "ChaCha40 roundtrip failed");

    // Wrong key produces different output (with high probability)
    let mut wrong_key = key;
    wrong_key[0] ^= 0x01;
    let wrong_ct = chacha40_encrypt(&wrong_key, 0, &nonce, plaintext);
    assert_ne!(wrong_ct, ciphertext, "wrong key should produce different ciphertext");
});

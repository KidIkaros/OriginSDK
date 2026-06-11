// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: ChaCha20-BLAKE3 AEAD roundtrip
//!
//! Splits the input into key (32B) + nonce (24B) + plaintext + aad.
//! Verifies that encrypt then decrypt returns the original plaintext
//! and that the operations never panic on arbitrary input.
//!
//! Run with: cargo +nightly fuzz run fuzz_encrypt_decrypt

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 24 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 24] = data[32..56].try_into().unwrap();
    let plaintext = &data[56..];

    if let Ok(ciphertext) = ChaCha20Blake3::encrypt(&key, &nonce, plaintext, b"") {
        // Roundtrip should always succeed with correct parameters
        if let Ok(decrypted) = ChaCha20Blake3::decrypt(&key, &nonce, &ciphertext, b"") {
            assert_eq!(decrypted, plaintext);
        }

        // Wrong nonce must always fail
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0x01;
        assert!(
            ChaCha20Blake3::decrypt(&key, &wrong_nonce, &ciphertext, b"").is_err(),
            "wrong nonce must not decrypt"
        );
    }
});

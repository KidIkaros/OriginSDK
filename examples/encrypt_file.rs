// SPDX-License-Identifier: Apache-2.0
//
// Symmetric encryption with ChaCha20-BLAKE3 (committing AEAD).
// Recommended over XChaCha20-Poly1305 due to partitioning-oracle resistance.
//
//   cargo run --example encrypt_file
//
// This example demonstrates the recommended newtype wrappers (Seed, XNonce)
// that catch length mismatches at construction time.

use origin_crypto_sdk::chacha20_blake3::ChaCha20Blake3;
use origin_crypto_sdk::types::XNonce;

fn main() {
    println!("=== ChaCha20-BLAKE3 Encryption (Committing AEAD) ===\n");

    // 1. Generate a 32-byte key and a 24-byte XNonce using the newtype wrappers.
    //
    //    In production, the key comes from your KDF (Argon2id / HKDF),
    //    not from random generation each time. The key length is enforced
    //    by XNonce::LEN at compile time — you can't pass a wrong-sized buffer.
    let key: [u8; 32] = [0x42u8; 32]; // demo: deterministic. Use getrandom in prod.
    let nonce = XNonce::random(); // 24 bytes, CSPRNG-sourced
    assert_eq!(nonce.as_bytes().len(), XNonce::LEN); // compile-time guarantee

    println!("Key:   {} bytes", key.len());
    println!("Nonce: {} bytes (XNonce)", nonce.as_bytes().len());

    // 2. Encrypt a message with associated data (AAD).
    //    AAD is authenticated but NOT encrypted — useful for headers/metadata.
    let plaintext = b"Sensitive data that must remain confidential";
    let aad = b"file-version:1|algorithm:chacha20-blake3";

    let ciphertext = ChaCha20Blake3::encrypt(&key, nonce.as_bytes(), plaintext, aad)
        .expect("encryption failed");

    println!("\nPlaintext:  {} bytes", plaintext.len());
    println!("Ciphertext: {} bytes (includes 32-byte auth tag)", ciphertext.len());

    // 3. Decrypt — must provide the same AAD
    let decrypted = ChaCha20Blake3::decrypt(&key, nonce.as_bytes(), &ciphertext, aad)
        .expect("decryption failed");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("\nRoundtrip: PASSED");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // 4. Wrong AAD — must fail
    let wrong_aad = b"file-version:2|algorithm:chacha20-blake3";
    match ChaCha20Blake3::decrypt(&key, nonce.as_bytes(), &ciphertext, wrong_aad) {
        Ok(_) => println!("\nWrong AAD: PASSED (BUG — should have failed!)"),
        Err(_) => println!("\nWrong AAD: correctly REJECTED"),
    }

    // 5. Tampered ciphertext — must fail
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    match ChaCha20Blake3::decrypt(&key, nonce.as_bytes(), &tampered, aad) {
        Ok(_) => println!("Tampered CT: PASSED (BUG — should have failed!)"),
        Err(_) => println!("Tampered CT: correctly REJECTED"),
    }
}

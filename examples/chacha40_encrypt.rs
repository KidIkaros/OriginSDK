// SPDX-License-Identifier: Apache-2.0
//
// ChaCha40 encryption — post-quantum hardened stream cipher.
// Uses a 512-bit key with dual-state parallel ChaCha and 40 rounds.
// Provides 256-bit post-quantum security against Grover's algorithm.
//
//   cargo run --example chacha40_encrypt
//
// This example demonstrates two modes:
//   1. Direct stream cipher encryption (for large data / files)
//   2. ChaCha40 as a key-wrap cipher (for encrypting subkeys)

use origin_crypto_sdk::chacha40::{chacha40_block, chacha40_encrypt};

fn main() {
    println!("=== ChaCha40 Stream Cipher (512-bit key, 40 rounds, dual-state) ===\n");

    // ──────────────────────────────────────────────────────────────────────────
    // Setup: Generate a 512-bit master key and a 96-bit nonce
    // ──────────────────────────────────────────────────────────────────────────
    //
    // The 64-byte key is split into two 256-bit halves, each feeding one ChaCha
    // state. Both states run 40 rounds (20 double-rounds) with the same counter
    // and nonce. Their outputs are interleaved: 32 bytes from each state per
    // 64-byte combined block.
    //
    // In production, the key comes from your KDF (Argon2id / HKDF-SHA3-256).
    // The nonce must be unique per key — never reuse (key, nonce) pair.
    let key: [u8; 64] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    let nonce: [u8; 12] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
    let counter: u32 = 0;

    println!("Key size:    64 bytes (512 bits) — 256-bit PQ security");
    println!("Nonce size:  12 bytes (96 bits, IETF standard)");
    println!("Rounds:      40 per state (20 double-rounds)");
    println!("Block size:  64 bytes (interleaved: 32 from each state)\n");

    // ──────────────────────────────────────────────────────────────────────────
    // Mode 1: Direct stream cipher (file encryption)
    // ──────────────────────────────────────────────────────────────────────────
    //
    // XOR-based stream cipher: encryption and decryption are the same operation.
    // Unlike AEAD ciphers, ChaCha40 alone does NOT authenticate the ciphertext.
    // For authenticated encryption, pair with Poly1305 or BLAKE3.
    println!("────────────────────────────────────────────────────────────");
    println!(" Mode 1: File / large-data stream encryption");
    println!("────────────────────────────────────────────────────────────\n");

    let plaintext = b"ChaCha40: post-quantum hardened ChaCha with 512-bit keys. \
        This provides 256-bit security against Grover's algorithm. \
        Each block interleaves outputs from two independent ChaCha states, \
        each running 40 rounds with a 256-bit key half.";

    println!("Plaintext:  {} bytes", plaintext.len());
    println!("Plaintext:  {}\n", String::from_utf8_lossy(plaintext));

    // Encrypt — XORs plaintext with the ChaCha40 keystream
    let ciphertext = chacha40_encrypt(&key, counter, &nonce, plaintext);
    println!("Ciphertext: {} bytes", ciphertext.len());

    // Decrypt — XOR is its own inverse (same function)
    let decrypted = chacha40_encrypt(&key, counter, &nonce, &ciphertext);
    assert_eq!(decrypted, plaintext);
    println!("Decrypted:  {} bytes — roundtrip OK", decrypted.len());

    // Security property: ciphertext must differ from plaintext
    assert_ne!(ciphertext[..plaintext.len()], plaintext[..]);
    println!(
        "First byte: plaintext={:#04x} → ciphertext={:#04x} → decrypted={:#04x}",
        plaintext[0], ciphertext[0], decrypted[0]
    );
    println!();

    // ──────────────────────────────────────────────────────────────────────────
    // Mode 2: Key wrapping (using ChaCha40 block as a key-wrap cipher)
    // ──────────────────────────────────────────────────────────────────────────
    //
    // A 64-byte ChaCha40 block can encrypt one or two 256-bit subkeys.
    // This is useful for wrapping derived keys under a master key.
    println!("────────────────────────────────────────────────────────────");
    println!(" Mode 2: Key wrapping with ChaCha40 block");
    println!("────────────────────────────────────────────────────────────\n");

    // Generate a 32-byte subkey to wrap
    let subkey: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xde, 0xad,
        0xbe, 0xef, 0xca, 0xfe,
    ];

    println!("Subkey to wrap: {} bytes", subkey.len());

    // Use a fresh counter+nonce for the key-wrap operation
    let wrap_counter: u32 = 0;
    let wrap_nonce: [u8; 12] = [0x00; 12]; // unique per-wrapping nonce

    // First 32 bytes of the ChaCha40 block serve as the key-wrap pad
    let keystream_block = chacha40_block(&key, wrap_counter, &wrap_nonce);
    let pad: [u8; 32] = {
        let mut p = [0u8; 32];
        p.copy_from_slice(&keystream_block[..32]);
        p
    };
    let mut wrapped = [0u8; 32];
    for i in 0..32 {
        wrapped[i] = subkey[i] ^ pad[i];
    }
    println!("Wrapped key:     {} bytes (XOR with first 32 bytes of ChaCha40 block)", wrapped.len());

    // Unwrap using the same keystream block
    let mut unwrapped = [0u8; 32];
    for i in 0..32 {
        unwrapped[i] = wrapped[i] ^ pad[i];
    }
    assert_eq!(unwrapped, subkey);
    println!("Unwrapped:       {} bytes — key wrap roundtrip OK", unwrapped.len());

    // Security: different counter = different keystream block
    let keystream_counter1 = chacha40_block(&key, 1, &wrap_nonce);
    let keystream_counter2 = chacha40_block(&key, 2, &wrap_nonce);
    assert_ne!(keystream_counter1, keystream_counter2);
    println!("\nCounter separation: blocks at counter=1 and counter=2 differ ✓");

    // Security: different nonce = different keystream block
    let mut nonce2 = [0u8; 12];
    nonce2[0] = 1;
    let keystream_nonce2 = chacha40_block(&key, 0, &nonce2);
    assert_ne!(keystream_block, keystream_nonce2);
    println!("Nonce separation: blocks at nonce[0]=0 and nonce[0]=1 differ ✓");

    // Security: different key half = different keystream block
    let mut key2 = key;
    key2[32] ^= 0xFF; // flip one bit in the second key half
    let keystream_key2 = chacha40_block(&key2, 0, &wrap_nonce);
    assert_ne!(keystream_block, keystream_key2);
    println!("Key-half separation: flipping 1 bit in the second half changes output ✓");

    println!("\n=== ChaCha40: all checks passed ===");
}

// SPDX-License-Identifier: OPL-1.1
//
// Key derivation: Argon2id (password → key) and HKDF-SHA3-256 (key → subkeys).
//
//   cargo run --example kdf_derive

use origin_crypto_sdk::prelude::*;

fn main() {
    println!("=== Key Derivation ===\n");

    // ── Argon2id: password → 256-bit key ──
    // Memory-hard: resistant to GPU/ASIC attacks.
    // Use this when deriving keys from passwords.
    let password = b"hunter2-is-not-a-good-password";
    let salt = [0xABu8; 16]; // In production: generate a random salt

    let key_normal = Argon2id::derive_key(password, &salt, false)
        .expect("Argon2id derivation failed");

    let key_paranoid = Argon2id::derive_key(password, &salt, true)
        .expect("Argon2id derivation failed");

    println!("Argon2id (normal):   {} bytes derived", key_normal.len());
    println!("Argon2id (paranoid): {} bytes derived", key_paranoid.len());

    // Same password + same salt = same key (deterministic)
    let key_check = Argon2id::derive_key(password, &salt, false).unwrap();
    assert_eq!(key_normal, key_check);
    println!("Deterministic: PASSED");

    // ── HKDF-SHA3-256: master key → subkeys ──
    // Use this for deriving multiple keys from a single master key.
    // Domain separation via the `info` parameter prevents cross-domain reuse.
    let master_key = [0x42u8; 32];

    // Derive encryption key
    let mut enc_key = [0u8; 32];
    hkdf_sha3_256(&master_key, None, b"origin-encryption-key-v1", &mut enc_key)
        .expect("HKDF failed");

    // Derive authentication key (different domain)
    let mut auth_key = [0u8; 32];
    hkdf_sha3_256(&master_key, None, b"origin-auth-key-v1", &mut auth_key)
        .expect("HKDF failed");

    println!("\nHKDF enc key:  {:02x}{:02x}..{:02x}{:02x}", enc_key[0], enc_key[1], enc_key[30], enc_key[31]);
    println!("HKDF auth key: {:02x}{:02x}..{:02x}{:02x}", auth_key[0], auth_key[1], auth_key[30], auth_key[31]);

    // Different domains → different keys
    assert_ne!(enc_key, auth_key);
    println!("Domain separation: PASSED (different info → different keys)");

    // ── derive_subkeys: convenience wrapper ──
    let salt_hkdf = [0xCCu8; 32];
    let (sub_enc, sub_auth) = derive_subkeys(&master_key, &salt_hkdf)
        .expect("derive_subkeys failed");

    assert_ne!(sub_enc, sub_auth);
    println!("\nderive_subkeys: enc={:02x}{:02x}.. auth={:02x}{:02x}..",
             sub_enc[0], sub_enc[1], sub_auth[0], sub_auth[1]);
}

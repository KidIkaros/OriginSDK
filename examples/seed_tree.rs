// SPDX-License-Identifier: Apache-2.0
//
// Hierarchical seed derivation: master seed -> domain-separated child seeds.
//
//   cargo run --example seed_tree

use origin_crypto_sdk::prelude::*;
use std::time::Duration;

fn main() {
    println!("=== Hierarchical Seed Derivation ===\n");

    // 1. Create a master seed handle with a 1-hour TTL.
    //    The seed is held in memory and zeroized on drop.
    //    Sovereign tier would use mlock to prevent swapping.
    let master_seed = [0xDEu8; 32];
    let handle = SeedHandle::new(&master_seed, Some(Duration::from_secs(3600)));

    println!(
        "Master seed: {} bytes, TTL: 3600s",
        handle.as_bytes().unwrap().len()
    );
    println!("Expired: {}", handle.is_expired());

    // 2. Derive child seeds for different domains.
    //    Each domain gets a deterministically different seed.
    let seed_bytes = handle.as_bytes().unwrap();
    let child_signing = derive_child_seed(seed_bytes, "signing-v1").unwrap();
    let child_encryption = derive_child_seed(seed_bytes, "encryption-v1").unwrap();
    let child_kem = derive_child_seed(seed_bytes, "kem-v1").unwrap();

    println!("\nChild seeds:");
    println!(
        "  signing:    {:02x}{:02x}..{:02x}{:02x} ({} bytes)",
        child_signing[0],
        child_signing[1],
        child_signing[30],
        child_signing[31],
        child_signing.len()
    );
    println!(
        "  encryption: {:02x}{:02x}..{:02x}{:02x} ({} bytes)",
        child_encryption[0],
        child_encryption[1],
        child_encryption[30],
        child_encryption[31],
        child_encryption.len()
    );
    println!(
        "  kem:        {:02x}{:02x}..{:02x}{:02x} ({} bytes)",
        child_kem[0],
        child_kem[1],
        child_kem[30],
        child_kem[31],
        child_kem.len()
    );

    // 3. Domain separation: different labels -> different seeds
    assert_ne!(child_signing.as_slice(), child_encryption.as_slice());
    assert_ne!(child_signing.as_slice(), child_kem.as_slice());
    assert_ne!(child_encryption.as_slice(), child_kem.as_slice());
    println!("\nDomain separation: PASSED (all child seeds differ)");

    // 4. Deterministic: same master + same label = same child
    let child_signing_again = derive_child_seed(seed_bytes, "signing-v1").unwrap();
    assert_eq!(child_signing.as_slice(), child_signing_again.as_slice());
    println!("Deterministic: PASSED");

    // 5. Derive signing keys (Ed25519 + Falcon-1024) from a child seed
    let (signing_key, falcon_packed) =
        derive_signing_keys(&child_signing, "signing-v1").expect("key derivation failed");

    println!(
        "\nDerived Ed25519 signing key: {} bytes",
        signing_key.len()
    );
    println!(
        "Derived Falcon packed (SK+PK): {} bytes",
        falcon_packed.len()
    );

    // 6. Extract verifying keys from the signing keys
    let (ed25519_pk, falcon_pk) =
        derive_verifying_keys(&signing_key, &falcon_packed).expect("verifying key extraction failed");
    println!("\nEd25519 verifying key: {} bytes", ed25519_pk.len());
    println!("Falcon verifying key: {} bytes", falcon_pk.len());

    // 7. SeedHandle also has a convenient derive_key method
    let enc_key = handle
        .derive_key("encryption", "aes-256", 32)
        .expect("derive_key failed");
    let auth_key = handle
        .derive_key("authentication", "hmac", 32)
        .expect("derive_key failed");
    assert_ne!(enc_key, auth_key);
    println!("\nSeedHandle.derive_key domain separation: PASSED");
}

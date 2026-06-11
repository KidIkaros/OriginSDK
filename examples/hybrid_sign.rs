// SPDX-License-Identifier: OPL-1.1
//
// Hybrid signing: Ed25519 + Falcon-1024 from a single seed.
// This is the recommended default for new applications.
//
//   cargo run --example hybrid_sign
//
// This example shows the `Seed` newtype wrapper for the master seed.

use origin_crypto_sdk::signing::hybrid::{Ed25519Falcon1024, HybridSigningKeyBundle};
use origin_crypto_sdk::types::Seed;

fn main() {
    println!("=== Hybrid Signing (Ed25519 + Falcon-1024) ===\n");

    // 1. Create a hybrid signing key bundle from a 32-byte master seed.
    //    The same seed always produces the same keypair (deterministic).
    //    Using the `Seed` newtype catches length mismatches at construction:
    //    `Seed::from_slice(&[0u8; 16])` would fail with InvalidKeyLength.
    let master_seed = Seed::from([0x42u8; 32]);
    let bundle = HybridSigningKeyBundle::from_seed(master_seed.as_bytes(), "my-app-domain")
        .expect("seed derivation failed");

    // 2. Sign a message. This produces a hybrid signature where BOTH
    //    the classical (Ed25519) and post-quantum (Falcon-1024) components
    //    must verify. An attacker must break both algorithms to forge.
    let message = b"The quantum resistance is strong with this one";
    let signature = bundle.sign_hybrid(message);

    println!("Message:    {}", String::from_utf8_lossy(message));
    let ed_len = signature.ed25519_sig.to_bytes().len();
    let fq_len = signature.falcon_sig.as_bytes().len();
    println!("Sig length: {} bytes (Ed25519: {}, Falcon: {})", ed_len + fq_len, ed_len, fq_len);

    // 3. Verify the signature using the public keys
    let ed_pk = bundle.ed25519_pk();
    let falcon_pk = bundle.falcon1024_pk();

    match Ed25519Falcon1024::verify(ed_pk, falcon_pk, message, &signature) {
        Ok(()) => println!("\nVerification: PASSED (both Ed25519 + Falcon-1024)"),
        Err(e) => println!("\nVerification FAILED: {}", e),
    }

    // 4. Tamper with the message — verification must fail
    let tampered = b"The quantum resistance is WRONG with this one";
    match Ed25519Falcon1024::verify(ed_pk, falcon_pk, tampered, &signature) {
        Ok(()) => println!("\nTampered verification: PASSED (BUG -- should have failed!)"),
        Err(_) => println!("\nTampered verification: correctly REJECTED"),
    }

    // 5. Deterministic: same seed + same domain = same keys
    let bundle2 = HybridSigningKeyBundle::from_seed(master_seed.as_bytes(), "my-app-domain")
        .expect("seed derivation failed");
    let ed_pk2 = bundle2.ed25519_pk();
    println!(
        "\nDeterministic: same seed + same domain = same Ed25519 PK: {}",
        ed_pk == ed_pk2
    );

    // 6. Different domain = different keys
    let bundle3 = HybridSigningKeyBundle::from_seed(master_seed.as_bytes(), "other-domain")
        .expect("seed derivation failed");
    let ed_pk3 = bundle3.ed25519_pk();
    println!(
        "Domain separation: different domain = different Ed25519 PK: {}",
        ed_pk != ed_pk3
    );
}

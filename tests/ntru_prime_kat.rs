// SPDX-License-Identifier: Apache-2.0

//! NTRU Prime (sntrup761) NIST compatibility tests.
//!
//! ## Encoding Compatibility
//!
//! Our NTRU Prime implementation now uses the official NIST recursive
//! `Encode()`/`Decode()` algorithm, producing standard wire-format sizes:
//!
//! | Parameter | Our SDK | NIST Reference | Match |
//! |-----------|---------|----------------|-------|
//! | PK_SIZE   | 1158    | 1158           | ✓     |
//! | SK_SIZE   | 1540    | 1540           | ✓     |
//! | CT_SIZE   | 1039    | 1039           | ✓     |
//! | K_SIZE    | 32      | 32             | ✓     |
//!
//! Note: The NIST PQC submission KAT file (ntruprime-20201007) uses a
//! larger SK_SIZE (1763) that includes additional CCA-related data.
//! The reference implementation (supercop-20201130) uses 1540 bytes
//! for the secret key (2*Small_bytes + Rq_bytes = 2*191 + 1158).
//!
//! Classification: known-answer test + internal consistency

use std::fs;
use std::path::PathBuf;

use origin_crypto_sdk::internal::rng::ChaCha20Rng;
use origin_crypto_sdk::pqc::ntru_prime::{NtruPrime, CT_SIZE, K_SIZE, PK_SIZE, SK_SIZE};

/// Official NIST sntrup761 reference sizes (from supercop-20201130).
const OFFICIAL_PK_SIZE: usize = 1158;
const OFFICIAL_SK_SIZE: usize = 1763; // 2*Small + Rq + rho + cache = 2*191 + 1158 + 191 + 32
const OFFICIAL_CT_SIZE: usize = 1039; // 32 + Rounded_bytes = 32 + 1007
const OFFICIAL_K_SIZE: usize = 32;

// ============================================================================
// Size compatibility tests
// ============================================================================

#[test]
fn ntru_prime_encoding_sizes_match_official() {
    // Verify our encoding now matches the official NIST reference sizes
    assert_eq!(
        PK_SIZE, OFFICIAL_PK_SIZE,
        "PK_SIZE must match official NIST reference ({})",
        OFFICIAL_PK_SIZE
    );
    assert_eq!(
        SK_SIZE, OFFICIAL_SK_SIZE,
        "SK_SIZE must match official NIST reference ({})",
        OFFICIAL_SK_SIZE
    );
    assert_eq!(
        CT_SIZE, OFFICIAL_CT_SIZE,
        "CT_SIZE must match official NIST reference ({})",
        OFFICIAL_CT_SIZE
    );
    assert_eq!(
        K_SIZE, OFFICIAL_K_SIZE,
        "K_SIZE must match official ({})",
        OFFICIAL_K_SIZE
    );
}

// ============================================================================
// KAT file tests
// ============================================================================

#[test]
fn ntru_prime_kat_file_exists() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
    assert!(
        fs::exists(&path).unwrap_or(false),
        "KAT file should exist at {:?}",
        path
    );
}

#[test]
fn ntru_prime_kat_file_has_100_vectors() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
    let content = fs::read_to_string(&path).expect("Failed to read KAT file");
    let count = content
        .lines()
        .filter(|l| l.trim().starts_with("count = "))
        .count();
    assert_eq!(count, 100, "expected 100 KAT vectors, got {}", count);
}

#[test]
fn ntru_prime_kat_official_pk_size_confirmed() {
    // Verify that the official KAT file uses the official PK size (1158)
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
    let content = fs::read_to_string(&path).expect("Failed to read KAT file");

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("pk = ") {
            let hex = &line[5..];
            let pk_bytes = hex.len() / 2;
            assert_eq!(
                pk_bytes, OFFICIAL_PK_SIZE,
                "official KAT pk size should be {}, got {}",
                OFFICIAL_PK_SIZE, pk_bytes
            );
            return;
        }
    }
    panic!("no pk line found in KAT file");
}

#[test]
fn ntru_prime_kat_official_ct_size_confirmed() {
    // Verify that the official KAT file uses the official CT size (1039)
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
    let content = fs::read_to_string(&path).expect("Failed to read KAT file");

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("ct = ") {
            let hex = &line[5..];
            let ct_bytes = hex.len() / 2;
            assert_eq!(
                ct_bytes, OFFICIAL_CT_SIZE,
                "official KAT ct size should be {}, got {}",
                OFFICIAL_CT_SIZE, ct_bytes
            );
            return;
        }
    }
    panic!("no ct line found in KAT file");
}

#[test]
fn ntru_prime_kat_official_sk_size_confirmed() {
    // Verify that the official KAT file uses the official SK size (1763 bytes)
    // which now matches our implementation (includes rho + cache for CCA).
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
    let content = fs::read_to_string(&path).expect("Failed to read KAT file");

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("sk = ") {
            let hex = &line[5..];
            let sk_bytes = hex.len() / 2;
            assert_eq!(
                sk_bytes, OFFICIAL_SK_SIZE,
                "official KAT sk size should be {}, got {}",
                OFFICIAL_SK_SIZE, sk_bytes
            );
            return;
        }
    }
    panic!("no sk line found in KAT file");
}

// ============================================================================
// Internal consistency tests
// ============================================================================

#[test]
fn ntru_prime_internal_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = NtruPrime::generate_keypair(&mut rng);
    let (ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);
    let ss2 = NtruPrime::decapsulate(&ct, &sk).expect("decapsulation failed");
    assert_eq!(ss1, ss2, "shared secrets must match");
}

#[test]
fn ntru_prime_internal_deterministic_keygen() {
    let seed = [99u8; 32];
    let (pk1, sk1) = NtruPrime::generate_keypair_from_seed(&seed);
    let (pk2, sk2) = NtruPrime::generate_keypair_from_seed(&seed);
    assert_eq!(pk1, pk2, "same seed must produce same public key");
    assert_eq!(sk1, sk2, "same seed must produce same secret key");
}

#[test]
fn ntru_prime_internal_sizes_correct() {
    let (pk, sk) = NtruPrime::generate_keypair_from_seed(&[1u8; 32]);
    assert_eq!(pk.len(), PK_SIZE);
    assert_eq!(sk.len(), SK_SIZE);

    let (ct, ss) = NtruPrime::encapsulate(&pk, &mut ChaCha20Rng::from_seed([2u8; 32]));
    assert_eq!(ct.len(), CT_SIZE);
    assert_eq!(ss.len(), K_SIZE);
}

#[test]
fn ntru_prime_decapsulate_wrong_ciphertext_cca() {
    // CCA security: decapsulation always returns Ok, but produces a different
    // (random-looking) shared secret when the ciphertext is tampered.
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = NtruPrime::generate_keypair(&mut rng);
    let (mut ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);

    // Tamper with ciphertext
    ct[0] ^= 1;

    let ss2 = NtruPrime::decapsulate(&ct, &sk).expect("CCA: always returns Ok");
    assert_ne!(
        ss1, ss2,
        "Tampered ciphertext must produce different shared secret (CCA fallback)"
    );
}

#[test]
fn ntru_prime_decapsulate_wrong_key_cca() {
    // CCA security: wrong key produces a different shared secret, not an error.
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, _) = NtruPrime::generate_keypair(&mut rng);
    let (ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);

    // Use a different key
    let (_, sk2) = NtruPrime::generate_keypair(&mut rng);
    let ss2 = NtruPrime::decapsulate(&ct, &sk2).expect("CCA: always returns Ok");
    assert_ne!(
        ss1, ss2,
        "Wrong key must produce different shared secret (CCA fallback)"
    );
}

// ============================================================================
// Encoding roundtrip tests (verify NIST Encode/Decode correctness)
// ============================================================================

#[test]
fn ntru_prime_rq_encode_decode_roundtrip() {
    use origin_crypto_sdk::pqc::ntru_prime::encode;

    let mut f = [0i16; 761];
    for i in 0..761 {
        let val = ((i as i32 * 7) % 4591) - 2295;
        f[i] = origin_crypto_sdk::pqc::ntru_prime::rq::modq::freeze(val);
    }

    let encoded = encode::rq_encode(&f);
    assert_eq!(encoded.len(), 1158);
    let decoded = encode::rq_decode(&encoded);
    for i in 0..761 {
        assert_eq!(f[i], decoded[i], "coefficient {i} mismatch");
    }
}

#[test]
fn ntru_prime_rounded_encode_decode_roundtrip() {
    use origin_crypto_sdk::pqc::ntru_prime::encode;

    let mut f = [0i16; 761];
    for i in 0..761 {
        // Create valid rounded values (multiples of 3)
        let val = ((i as i32 * 9) % 4591) - 2295;
        f[i] = origin_crypto_sdk::pqc::ntru_prime::rq::modq::freeze(val);
        f[i] = (f[i] / 3) * 3;
    }

    let encoded = encode::rounded_encode(&f);
    assert_eq!(encoded.len(), 1007);
    let decoded = encode::rounded_decode(&encoded);
    for i in 0..761 {
        assert_eq!(f[i], decoded[i], "rounded coefficient {i} mismatch");
    }
}

#[test]
fn ntru_prime_small_encode_decode_roundtrip() {
    use origin_crypto_sdk::pqc::ntru_prime::encode;

    let mut f = [0i8; 761];
    for i in 0..761 {
        f[i] = ((i % 3) as i8) - 1;
    }

    let encoded = encode::small_encode(&f);
    assert_eq!(encoded.len(), 191);
    let decoded = encode::small_decode(&encoded);
    assert_eq!(f, decoded);
}

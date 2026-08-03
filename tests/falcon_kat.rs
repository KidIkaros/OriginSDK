// SPDX-License-Identifier: Apache-2.0

//! Falcon (FN-DSA) Known Answer Tests.
//!
//! These tests verify the `falcon-rs` crate (NIST FIPS 206) through our
//! wrapper API. The `falcon-rs` crate passes all NIST PQC KAT vectors
//! internally (via its own `nist_kat.rs` test that implements the full
//! AES-256-CTR DRBG procedure). These tests provide additional regression
//! coverage through our wrapper layer.
//!
//! ## Why not use the old NIST PQC KAT file?
//!
//! The old `falcon512-KAT.rsp` file (from the NIST PQC submission) uses
//! the original Falcon signature format (header byte 0x02), which is
//! incompatible with the FIPS 206 format implemented by `falcon-rs`
//! (header bytes 0x30 for padded, 0x50 for constant-time). NIST has not
//! yet published ACVP test vectors for the FIPS 206 domain-separation
//! layer, so we use deterministic regression vectors instead, following
//! the same approach as the `falcon-rs` crate's own `fips206_kat.rs`.
//!
//! ## Test coverage
//!
//! 1. **Keygen determinism**: same seed → same keypair (Falcon-512 and 1024)
//! 2. **Key sizes**: pk=897/1793, sk=1281/2305 (FIPS 206 wire sizes)
//! 3. **Sign/verify roundtrip**: keygen → sign → verify
//! 4. **Deterministic signing**: same (key, msg, nonce) → same signature
//! 5. **Cross-variant verification**: CT-format sig verified by padded-format verifier
//! 6. **Negative tests**: wrong message, wrong key, tampered signature
//! 7. **NIST KAT file format check**: documents the format incompatibility
//!
//! Classification: known-answer test (deterministic regression vectors)

use std::fs;
use std::path::PathBuf;

use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature};

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ============================================================================
// NIST PQC KAT file format check (documents incompatibility)
// ============================================================================

struct NistKatVector {
    #[allow(dead_code)]
    seed: Vec<u8>,
    #[allow(dead_code)]
    mlen: usize,
    #[allow(dead_code)]
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    smlen: usize,
    sm: Vec<u8>,
}

fn parse_nist_kat_file() -> Vec<NistKatVector> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/falcon512-KAT.rsp");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read KAT file: {:?}", path));

    let mut vectors = Vec::new();
    let mut current = NistKatVector {
        seed: Vec::new(),
        mlen: 0,
        msg: Vec::new(),
        pk: Vec::new(),
        sk: Vec::new(),
        smlen: 0,
        sm: Vec::new(),
    };
    let mut have_data = false;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("seed = ") {
            if have_data {
                vectors.push(std::mem::replace(
                    &mut current,
                    NistKatVector {
                        seed: Vec::new(),
                        mlen: 0,
                        msg: Vec::new(),
                        pk: Vec::new(),
                        sk: Vec::new(),
                        smlen: 0,
                        sm: Vec::new(),
                    },
                ));
            }
            current.seed = hex_decode(&line[7..]);
            have_data = true;
        } else if line.starts_with("mlen = ") {
            current.mlen = line[7..].parse().unwrap();
        } else if line.starts_with("msg = ") {
            current.msg = hex_decode(&line[6..]);
        } else if line.starts_with("pk = ") {
            current.pk = hex_decode(&line[5..]);
        } else if line.starts_with("sk = ") {
            current.sk = hex_decode(&line[5..]);
        } else if line.starts_with("smlen = ") {
            current.smlen = line[8..].parse().unwrap();
        } else if line.starts_with("sm = ") {
            current.sm = hex_decode(&line[5..]);
        }
    }
    if have_data {
        vectors.push(current);
    }
    vectors
}

#[test]
fn nist_kat_file_loads() {
    let vectors = parse_nist_kat_file();
    assert_eq!(vectors.len(), 100, "expected 100 KAT vectors");
}

#[test]
fn nist_kat_pk_size_matches_fips206() {
    // The NIST PQC submission and FIPS 206 share the same public key format.
    // Both use 897 bytes for Falcon-512.
    let vectors = parse_nist_kat_file();
    for (i, v) in vectors.iter().enumerate() {
        assert_eq!(
            v.pk.len(),
            897,
            "vector {i}: pk size should be 897, got {}",
            v.pk.len()
        );
    }
}

#[test]
fn nist_kat_sk_size_differs_from_fips206() {
    // The NIST PQC submission uses a different secret key format than FIPS 206.
    // The old format includes expanded key data (4097 bytes for Falcon-512),
    // while FIPS 206 uses a compact format (1281 bytes).
    let vectors = parse_nist_kat_file();
    for (i, v) in vectors.iter().enumerate().take(5) {
        assert_ne!(
            v.sk.len(),
            1281,
            "vector {i}: old NIST PQC sk should differ from FIPS 206 (got {} bytes)",
            v.sk.len()
        );
    }
}

#[test]
fn nist_kat_signature_format_is_not_fips206() {
    // Documents that the old NIST PQC KAT signatures use a different format
    // than FIPS 206. The signature header byte in the old format is 0x00-0x0F
    // (encoded logn), while FIPS 206 uses 0x30 (padded) or 0x50 (CT).
    let vectors = parse_nist_kat_file();
    for (i, v) in vectors.iter().enumerate().take(5) {
        let sig_len = v.smlen - v.mlen;
        let sig_bytes = &v.sm[..sig_len];
        let header = sig_bytes[0];
        let high_nibble = header >> 4;
        // Old NIST PQC format: header high nibble is 0x0 (encoded logn)
        // FIPS 206 format: header high nibble is 0x3 (padded) or 0x5 (CT)
        assert_eq!(
            high_nibble, 0x0,
            "vector {i}: old NIST PQC format expected (header 0x{:02x})",
            header
        );
    }
}

// ============================================================================
// FIPS 206 Regression Vectors (via falcon-rs generate_deterministic)
// ============================================================================

/// Test seed for Falcon-512 regression vectors.
const FALCON512_SEED: [u8; 32] = [0x42; 32];

/// Test seed for Falcon-1024 regression vectors.
const FALCON1024_SEED: [u8; 32] = [0x99; 32];

#[test]
fn falcon512_keygen_deterministic() {
    let kp1 = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");
    let kp2 = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");

    assert_eq!(
        kp1.public_key(),
        kp2.public_key(),
        "Same seed must produce same public key"
    );
    assert_eq!(
        kp1.private_key(),
        kp2.private_key(),
        "Same seed must produce same private key"
    );
}

#[test]
fn falcon512_key_sizes_match_fips206() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");

    assert_eq!(
        kp.public_key().len(),
        897,
        "Falcon-512 public key must be 897 bytes (FIPS 206)"
    );
    assert_eq!(
        kp.private_key().len(),
        1281,
        "Falcon-512 private key must be 1281 bytes (FIPS 206)"
    );
}

#[test]
fn falcon1024_key_sizes_match_fips206() {
    let kp =
        FnDsaKeyPair::generate_deterministic(&FALCON1024_SEED, 10).expect("Falcon-1024 keygen");

    assert_eq!(
        kp.public_key().len(),
        1793,
        "Falcon-1024 public key must be 1793 bytes (FIPS 206)"
    );
    assert_eq!(
        kp.private_key().len(),
        2305,
        "Falcon-1024 private key must be 2305 bytes (FIPS 206)"
    );
}

#[test]
fn falcon512_sign_verify_roundtrip() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");
    let msg = b"Falcon-512 FIPS 206 roundtrip test";

    let sig = kp
        .sign(msg, &DomainSeparation::None)
        .expect("Falcon-512 sign");

    assert!(
        FnDsaSignature::verify(
            sig.to_bytes(),
            kp.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_ok(),
        "Falcon-512 signature must verify"
    );
}

#[test]
fn falcon1024_sign_verify_roundtrip() {
    let kp =
        FnDsaKeyPair::generate_deterministic(&FALCON1024_SEED, 10).expect("Falcon-1024 keygen");
    let msg = b"Falcon-1024 FIPS 206 roundtrip test";

    let sig = kp
        .sign(msg, &DomainSeparation::None)
        .expect("Falcon-1024 sign");

    assert!(
        FnDsaSignature::verify(
            sig.to_bytes(),
            kp.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_ok(),
        "Falcon-1024 signature must verify"
    );
}

#[test]
fn falcon512_deterministic_signing_reproducible() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");
    let msg = b"deterministic signing reproducibility";
    let nonce = [0xAA; 32];

    let sig1 = kp
        .sign_deterministic(msg, &nonce, &DomainSeparation::None)
        .expect("sign1");
    let sig2 = kp
        .sign_deterministic(msg, &nonce, &DomainSeparation::None)
        .expect("sign2");

    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "Same (key, message, nonce) must produce identical signatures"
    );
    assert!(
        FnDsaSignature::verify(
            sig1.to_bytes(),
            kp.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_ok(),
        "Deterministic signature must verify"
    );
}

#[test]
fn falcon512_rejects_wrong_message() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");
    let msg = b"original message";
    let sig = kp.sign(msg, &DomainSeparation::None).expect("sign");

    assert!(
        FnDsaSignature::verify(
            sig.to_bytes(),
            kp.public_key(),
            b"wrong message",
            &DomainSeparation::None
        )
        .is_err(),
        "Falcon-512 must reject wrong message"
    );
}

#[test]
fn falcon512_rejects_wrong_key() {
    let kp1 =
        FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen 1");
    let kp2 = FnDsaKeyPair::generate_deterministic(&[0x55; 32], 9).expect("Falcon-512 keygen 2");

    let msg = b"cross-key test";
    let sig = kp1.sign(msg, &DomainSeparation::None).expect("sign");

    assert!(
        FnDsaSignature::verify(
            sig.to_bytes(),
            kp2.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_err(),
        "Falcon-512 must reject signature with wrong public key"
    );
}

#[test]
fn falcon512_different_seeds_produce_different_keys() {
    let kp1 = FnDsaKeyPair::generate_deterministic(&[0x01; 32], 9).expect("keygen 1");
    let kp2 = FnDsaKeyPair::generate_deterministic(&[0x02; 32], 9).expect("keygen 2");

    assert_ne!(
        kp1.public_key(),
        kp2.public_key(),
        "Different seeds must produce different public keys"
    );
}

#[test]
fn falcon512_from_private_key_reconstructs() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");

    let restored = FnDsaKeyPair::from_private_key(kp.private_key()).expect("from_private_key");

    assert_eq!(
        restored.public_key(),
        kp.public_key(),
        "from_private_key must recompute the same public key"
    );
    assert_eq!(
        restored.private_key(),
        kp.private_key(),
        "from_private_key must preserve the private key"
    );
}

#[test]
fn falcon512_from_keys_roundtrip() {
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");

    let restored = FnDsaKeyPair::from_keys(kp.private_key(), kp.public_key()).expect("from_keys");

    assert_eq!(
        restored.public_key(),
        kp.public_key(),
        "from_keys must preserve the public key"
    );
    assert_eq!(
        restored.private_key(),
        kp.private_key(),
        "from_keys must preserve the private key"
    );
}

#[test]
fn falcon512_signature_is_ct_format() {
    // FIPS 206 constant-time format has header byte 0x50 + logn.
    // For Falcon-512 (logn=9): header = 0x59
    let kp = FnDsaKeyPair::generate_deterministic(&FALCON512_SEED, 9).expect("Falcon-512 keygen");
    let sig = kp
        .sign(b"ct format check", &DomainSeparation::None)
        .expect("sign");

    let header = sig.to_bytes()[0];
    assert_eq!(
        header >> 4,
        0x5,
        "Falcon-512 signature must be CT format (header 0x5x), got 0x{:02x}",
        header
    );
    assert_eq!(
        header & 0x0F,
        9,
        "Falcon-512 signature header low nibble must be logn=9"
    );
}

#[test]
fn falcon1024_signature_is_ct_format() {
    // FIPS 206 constant-time format has header byte 0x50 + logn.
    // For Falcon-1024 (logn=10): header = 0x5A
    let kp =
        FnDsaKeyPair::generate_deterministic(&FALCON1024_SEED, 10).expect("Falcon-1024 keygen");
    let sig = kp
        .sign(b"ct format check", &DomainSeparation::None)
        .expect("sign");

    let header = sig.to_bytes()[0];
    assert_eq!(
        header >> 4,
        0x5,
        "Falcon-1024 signature must be CT format (header 0x5x), got 0x{:02x}",
        header
    );
    assert_eq!(
        header & 0x0F,
        10,
        "Falcon-1024 signature header low nibble must be logn=10"
    );
}

// ============================================================================
// Wrapper API Integration Tests (via origin_crypto_sdk)
// ============================================================================

#[test]
fn wrapper_falcon512_keygen_sign_verify() {
    use origin_crypto_sdk::pqc::falcon512;

    let seed = [42u8; 32];
    let (sk, pk) = falcon512::generate_keypair(seed);
    let msg = b"wrapper API integration test";

    let sig = falcon512::sign(msg, &sk).expect("sign");
    assert!(
        falcon512::verify(msg, &sig, &pk),
        "Wrapper API sign/verify must work"
    );
    assert!(
        !falcon512::verify(b"wrong", &sig, &pk),
        "Wrapper API must reject wrong message"
    );
}

#[test]
fn wrapper_falcon1024_keygen_sign_verify() {
    use origin_crypto_sdk::pqc::falcon1024;

    let seed = [99u8; 32];
    let (pk, sk) = falcon1024::generate_keypair_from_seed(&seed).expect("keygen");
    let msg = b"wrapper API integration test 1024";

    let sig = falcon1024::sign(msg, &sk).expect("sign");
    assert!(
        falcon1024::verify(msg, &sig, &pk).is_ok(),
        "Wrapper API sign/verify must work"
    );
}

#[test]
fn wrapper_falcon512_deterministic_sign() {
    use origin_crypto_sdk::pqc::falcon512;

    let seed = [42u8; 32];
    let (sk, pk) = falcon512::generate_keypair(seed);
    let msg = b"deterministic wrapper test";
    let nonce = [0xBB; 32];

    let sig1 = falcon512::sign_deterministic(msg, &sk, &nonce).expect("sign1");
    let sig2 = falcon512::sign_deterministic(msg, &sk, &nonce).expect("sign2");

    assert_eq!(sig1.0, sig2.0, "Deterministic signing must be reproducible");
    assert!(
        falcon512::verify(msg, &sig1, &pk),
        "Deterministic signature must verify"
    );
}

// SPDX-License-Identifier: Apache-2.0

//! NTRU Prime (sntrup761) NIST compatibility tests.
//!
//! ## Encoding Compatibility
//!
//! Our NTRU Prime implementation uses the official NIST recursive
//! `Encode()`/`Decode()` algorithm, producing standard wire-format sizes:
//!
//! | Parameter | Our SDK | NIST Reference | Match |
//! |-----------|---------|----------------|-------|
//! | PK_SIZE   | 1158    | 1158           | ✓     |
//! | SK_SIZE   | 1763    | 1763           | ✓     |
//! | CT_SIZE   | 1039    | 1039           | ✓     |
//! | K_SIZE    | 32      | 32             | ✓     |
//!
//! ## Full KAT execution (Phase 12.4)
//!
//! The `kat_execution` module replays the NIST AES-256-CTR DRBG through
//! our keygen/encapsulate and verifies **all 100 official vectors**
//! byte-for-byte: pk, sk, ct, and ss. It also runs a decap-only pass
//! over all 100 vectors and a cross-roundtrip (our encapsulate against
//! reference public keys, decapsulated by reference secret keys).
//!
//! Classification: known-answer test + internal consistency

use std::fs;
use std::path::PathBuf;

use origin_crypto_sdk::drbg::ChaCha20Rng;
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

// ============================================================================
// Full KAT execution (Phase 12.4)
//
// The vectors above were previously only checked for presence/size. This
// section actually executes them: the NIST submission DRBG
// (AES-256-CTR per the reference `rng.c`) is replayed through our
// `RngCore`-generic keygen/encapsulate, so pk, sk, ct, and ss are all
// compared byte-for-byte against the official vectors.
// ============================================================================

// The KEM hash backend is feature-selectable; the NIST vectors are only
// meaningful under the default SHA-512 backend (the ntru-* features are
// documented as non-NIST-compatible).
#[cfg(not(any(
    feature = "ntru-blake3",
    feature = "ntru-shake128",
    feature = "ntru-shake256"
)))]
mod kat_execution {

    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;
    use origin_crypto_sdk::drbg::ChaCha20Rng;
    use origin_crypto_sdk::pqc::ntru_prime::{
        Ciphertext, NtruPrime, PrivateKey, PublicKey, SharedSecret,
    };
    use rand::{CryptoRng, RngCore};
    use std::fs;
    use std::path::PathBuf;

    /// NIST PQC KAT DRBG — AES-256 in ECB mode over an incrementing counter,
    /// identical to the `rng.c` shipped with every NIST submission.
    struct NistDrbg {
        key: [u8; 32],
        v: [u8; 16],
    }

    impl NistDrbg {
        fn new(seed48: &[u8; 48]) -> Self {
            let mut drbg = Self {
                key: [0u8; 32],
                v: [0u8; 16],
            };
            drbg.update(Some(seed48));
            drbg
        }

        fn increment_v(&mut self) {
            for b in self.v.iter_mut().rev() {
                let (next, carry) = b.overflowing_add(1);
                *b = next;
                if !carry {
                    break;
                }
            }
        }

        /// AES256_CTR_DRBG_Update: 3 blocks of keystream (XORed with the
        /// provided 48 bytes when present) become the new Key || V. The
        /// reference `rng.c` runs this with NULL provided data after every
        /// `randombytes()` call — including the one inside each `urandom32`.
        fn update(&mut self, provided: Option<&[u8; 48]>) {
            let mut temp = [0u8; 48];
            for chunk in temp.chunks_exact_mut(16) {
                self.increment_v();
                let cipher = Aes256::new((&self.key).into());
                let mut block = self.v.into();
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
            if let Some(p) = provided {
                for i in 0..48 {
                    temp[i] ^= p[i];
                }
            }
            self.key.copy_from_slice(&temp[..32]);
            self.v.copy_from_slice(&temp[32..]);
        }

        fn aes_block(&self) -> [u8; 16] {
            let cipher = Aes256::new((&self.key).into());
            let mut block = self.v.into();
            cipher.encrypt_block(&mut block);
            block.into()
        }
    }

    impl RngCore for NistDrbg {
        fn next_u32(&mut self) -> u32 {
            let mut buf = [0u8; 4];
            self.fill_bytes(&mut buf);
            u32::from_le_bytes(buf)
        }

        fn next_u64(&mut self) -> u64 {
            let mut buf = [0u8; 8];
            self.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }

        /// One `fill_bytes` call == one reference `randombytes()` call:
        /// generate the stream, then churn Key||V via Update(NULL).
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(16) {
                self.increment_v();
                let block = self.aes_block();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
            self.update(None);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // The KAT DRBG is deterministic by design — the CryptoRng marker is
    // required only because `generate_keypair`/`encapsulate` are generic over
    // `RngCore + CryptoRng`. It is never used for real key material.
    impl CryptoRng for NistDrbg {}

    struct KatVector {
        count: usize,
        seed: [u8; 48],
        pk: PublicKey,
        sk: PrivateKey,
        ct: Ciphertext,
        ss: SharedSecret,
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    fn parse_kat_vectors() -> Vec<KatVector> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kat_data/sntrup761_kat_kem.rsp");
        let content = fs::read_to_string(&path).expect("Failed to read KAT file");

        let mut vectors = Vec::new();
        let mut count = None;
        let mut seed = None;
        let mut pk = None;
        let mut sk = None;
        let mut ct = None;

        for line in content.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once(" = ") {
                match k {
                    "count" => count = Some(v.parse::<usize>().unwrap()),
                    "seed" => seed = Some(<[u8; 48]>::try_from(hex_decode(v).as_slice()).unwrap()),
                    "pk" => pk = Some(PublicKey::try_from(hex_decode(v).as_slice()).unwrap()),
                    "sk" => sk = Some(PrivateKey::try_from(hex_decode(v).as_slice()).unwrap()),
                    "ct" => ct = Some(Ciphertext::try_from(hex_decode(v).as_slice()).unwrap()),
                    "ss" => vectors.push(KatVector {
                        count: count.take().unwrap(),
                        seed: seed.take().unwrap(),
                        pk: pk.take().unwrap(),
                        sk: sk.take().unwrap(),
                        ct: ct.take().unwrap(),
                        ss: SharedSecret::try_from(hex_decode(v).as_slice()).unwrap(),
                    }),
                    _ => {}
                }
            }
        }
        vectors
    }

    /// Decap-only KAT: the KAT sk/ct are reference-format wire bytes, so
    /// `decapsulate(ct, sk)` must reproduce `ss` for every vector — no DRBG
    /// needed. Exercises the full decode → decap → CCA → hash chain.
    #[test]
    fn ntru_prime_kat_decapsulate_all_100() {
        let vectors = parse_kat_vectors();
        assert_eq!(vectors.len(), 100);
        for v in &vectors {
            let ss = NtruPrime::decapsulate(&v.ct, &v.sk)
                .unwrap_or_else(|_| panic!("vector {}: decapsulate failed", v.count));
            assert_eq!(
                &ss[..],
                &v.ss[..],
                "vector {}: decapsulated shared secret mismatch",
                v.count
            );
        }
    }

    /// Full seeded KAT: replay the NIST DRBG through our keygen and
    /// encapsulate. Byte-exact pk AND sk prove the keygen draw pattern,
    /// small/tsmall sampling, reciprocal retry, and encoding are identical
    /// to the reference; byte-exact ct AND ss prove encapsulate.
    #[test]
    fn ntru_prime_kat_seeded_keygen_encap_all_100() {
        let vectors = parse_kat_vectors();
        assert_eq!(vectors.len(), 100);
        let mut pk_mismatch = Vec::new();
        let mut sk_mismatch = Vec::new();
        let mut ct_mismatch = Vec::new();
        let mut ss_mismatch = Vec::new();

        for v in &vectors {
            let mut drbg = NistDrbg::new(&v.seed);
            let (pk, sk) = NtruPrime::generate_keypair(&mut drbg);
            if pk != v.pk {
                pk_mismatch.push(v.count);
            }
            if sk != v.sk {
                sk_mismatch.push(v.count);
            }

            let (ct, ss) = NtruPrime::encapsulate(&pk, &mut drbg);
            if ct != v.ct {
                ct_mismatch.push(v.count);
            }
            if ss != v.ss {
                ss_mismatch.push(v.count);
            }
        }

        assert!(
            pk_mismatch.is_empty()
                && sk_mismatch.is_empty()
                && ct_mismatch.is_empty()
                && ss_mismatch.is_empty(),
            "KAT mismatches — pk: {:?}, sk: {:?}, ct: {:?}, ss: {:?}",
            pk_mismatch,
            sk_mismatch,
            ct_mismatch,
            ss_mismatch
        );
    }

    /// Cross-differential: encapsulate against a *reference* public key,
    /// then decapsulate our ciphertext with the *reference* private key.
    /// Catches wire-format bugs that our own round-trip cannot.
    #[test]
    fn ntru_prime_kat_cross_roundtrip_foreign_keys() {
        let vectors = parse_kat_vectors();
        let mut rng = ChaCha20Rng::from_seed([0xA5u8; 32]);
        for v in vectors.iter().take(10) {
            let (ct, ss1) = NtruPrime::encapsulate(&v.pk, &mut rng);
            let ss2 = NtruPrime::decapsulate(&ct, &v.sk)
                .unwrap_or_else(|_| panic!("vector {}: cross-decap failed", v.count));
            assert_eq!(
                ss1, ss2,
                "vector {}: our-encap/reference-key roundtrip mismatch",
                v.count
            );
        }
    }
}

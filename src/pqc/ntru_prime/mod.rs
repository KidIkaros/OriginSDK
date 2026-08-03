// SPDX-License-Identifier: Apache-2.0

//! Streamlined NTRU Prime Implementation (sntrup761)
//!
//! A modern Rust implementation of Streamlined NTRU Prime, the post-quantum
//! KEM used by OpenSSH. Parameters: p=761, q=4591, w=286
//!
//! This provides ~256-bit quantum security with better side-channel resistance
//! than Kyber due to its simpler algebraic structure.
//!
//! ## NIST Compatibility
//!
//! This implementation uses the official NIST recursive `Encode()`/`Decode()`
//! algorithm and the NIST KEM hashing scheme (SHA-2-512 with domain-separation
//! prefixes, public key binding via cache, and CCA fallback via rho).
//!
//! Wire-format sizes match the NIST reference (supercop-20201130):
//! - Public key: 1158 bytes
//! - Secret key: 1763 bytes (includes rho and cache for CCA security)
//! - Ciphertext: 1039 bytes
//! - Shared secret: 32 bytes
//!
//! Reference: <https://ntruprime.cr.yp.to/>
//!
//! # Experimental
//!
//! This is a custom implementation that has not undergone independent
//! cryptographic review. Use the external AEAD APIs (`aead` module) for
//! production workloads. This module is provided for research and
//! environments requiring zero external crypto dependencies.

pub mod constants;
pub mod encode;
#[cfg(feature = "test-utils")]
#[allow(dead_code)]
pub mod ntt;
#[cfg(not(feature = "test-utils"))]
#[allow(dead_code)]
mod ntt;
mod r3;
pub mod rq;
mod zx;

use crate::error::Result;
use rand::{CryptoRng, RngCore};

// KEM hash backend: select based on feature flags.
// Default: NIST SHA-2-512 (wire-compatible with sntrup761 reference).
// ntru-blake3: BLAKE3 (3.4× faster, not NIST-compatible).
// ntru-shake128/shake256: SHAKE XOFs (not NIST-compatible, for benchmarking).
#[cfg(not(any(
    feature = "ntru-blake3",
    feature = "ntru-shake128",
    feature = "ntru-shake256"
)))]
use crate::primitives::sha3 as kem_hash;

#[cfg(feature = "ntru-blake3")]
use crate::primitives::sha3::blake3_kem as kem_hash;

#[cfg(all(feature = "ntru-shake128", not(feature = "ntru-blake3")))]
use crate::primitives::sha3::shake128_kem as kem_hash;

#[cfg(all(
    feature = "ntru-shake256",
    not(any(feature = "ntru-blake3", feature = "ntru-shake128"))
))]
use crate::primitives::sha3::shake256_kem as kem_hash;

/// Re-export KEM hash functions for benchmarking and testing.
pub mod kem_hashing {
    pub use crate::primitives::sha3::{hash4, hash_confirm, hash_prefix, hash_session, HASH_BYTES};

    #[cfg(feature = "ntru-shake128")]
    pub use crate::primitives::sha3::shake128_kem;

    #[cfg(feature = "ntru-shake256")]
    pub use crate::primitives::sha3::shake256_kem;

    #[cfg(feature = "ntru-blake3")]
    pub use crate::primitives::sha3::blake3_kem;
}

pub use constants::*;

/// NTRU Prime public key (1158 bytes, NIST wire format)
pub type PublicKey = [u8; PK_SIZE];

/// NTRU Prime private key (1763 bytes, NIST KEM format)
pub type PrivateKey = [u8; SK_SIZE];

/// NTRU Prime ciphertext (1039 bytes, NIST wire format)
pub type Ciphertext = [u8; CT_SIZE];

/// NTRU Prime shared secret (32 bytes)
pub type SharedSecret = [u8; K_SIZE];

/// NTRU Prime KEM implementation
#[derive(Debug)]
pub struct NtruPrime;

// SK layout offsets
const SK_F_OFFSET: usize = 0;
const SK_GR_OFFSET: usize = SMALL_BYTES;
const SK_H_OFFSET: usize = 2 * SMALL_BYTES;
const SK_RHO_OFFSET: usize = 2 * SMALL_BYTES + RQ_BYTES;
const SK_CACHE_OFFSET: usize = 2 * SMALL_BYTES + RQ_BYTES + INPUTS_BYTES;

// CT layout offsets
const CT_CONFIRM_OFFSET: usize = ROUNDED_BYTES;

impl NtruPrime {
    /// Generate an NTRU Prime key pair deterministically from a 32-byte seed.
    ///
    /// Uses ChaCha20 as a CSPRNG seeded with `seed`, producing the same
    /// keypair for the same seed every time. This enables HKDF-style
    /// derivation in `signet-core::Identity`.
    pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> (PublicKey, PrivateKey) {
        use crate::internal::rng::ChaCha20Rng;
        let mut rng = ChaCha20Rng::from_seed(*seed);
        Self::generate_keypair(&mut rng)
    }

    /// Generate an NTRU Prime key pair using the provided RNG.
    ///
    /// This is deterministic given the same RNG state, allowing for
    /// reproducible key derivation from a seeded CSPRNG.
    ///
    /// SK layout: Small(f) || Small(gr) || Rq(h) || rho || cache
    pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicKey, PrivateKey) {
        // Generate g with valid reciprocal
        let mut g = [0i8; P];
        let gr = loop {
            zx::random::random_small(&mut g, rng);
            let (mask, gr) = r3::reciprocal(g);
            if mask == 0 {
                break gr;
            }
        };

        // Generate f
        let mut f = [0i8; P];
        zx::random::random_tsmall(&mut f, rng);

        // Core keygen: h = 3/f * g in Rq
        let (pk, f_enc, gr_enc) = derive_core_keypair(f, g, gr);

        // Generate rho (random fallback for CCA security)
        let mut rho = [0u8; INPUTS_BYTES];
        rng.fill_bytes(&mut rho);

        // Compute cache = Hash4(pk) = SHA-512(0x04 || pk)[..32]
        let cache = kem_hash::hash4(&pk);

        // Assemble full SK: f || gr || h || rho || cache
        let mut sk = [0u8; SK_SIZE];
        sk[SK_F_OFFSET..SK_F_OFFSET + SMALL_BYTES].copy_from_slice(&f_enc);
        sk[SK_GR_OFFSET..SK_GR_OFFSET + SMALL_BYTES].copy_from_slice(&gr_enc);
        sk[SK_H_OFFSET..SK_H_OFFSET + RQ_BYTES].copy_from_slice(&pk);
        sk[SK_RHO_OFFSET..SK_RHO_OFFSET + INPUTS_BYTES].copy_from_slice(&rho);
        sk[SK_CACHE_OFFSET..SK_CACHE_OFFSET + HASH_BYTES].copy_from_slice(&cache);

        (pk, sk)
    }

    /// Encapsulate a shared secret using the public key.
    ///
    /// Returns (ciphertext, shared_secret).
    ///
    /// CT layout: Rounded(c) || confirm
    pub fn encapsulate<R: RngCore + CryptoRng>(
        pk: &PublicKey,
        rng: &mut R,
    ) -> (Ciphertext, SharedSecret) {
        // Generate random r (ternary, weight W)
        let mut r = [0i8; P];
        zx::random::random_tsmall(&mut r, rng);

        // Compute cache = Hash4(pk)
        let cache = kem_hash::hash4(pk);

        // Encode r for hashing
        let r_enc = zx::encoding::encode(r);

        // Encrypt: c = Round(h * r)
        let h = rq::encoding::decode(pk);
        let mut c = [0i16; P];
        rq::mult(&mut c, h, r);
        rq::round3(&mut c);
        let c_enc = rq::encoding::encode_rounded(c);

        // Compute confirmation hash: HashConfirm(r_enc, cache)
        let confirm = kem_hash::hash_confirm(&r_enc, &cache);

        // Assemble ciphertext: c || confirm
        let mut ciphertext = [0u8; CT_SIZE];
        ciphertext[..ROUNDED_BYTES].copy_from_slice(&c_enc);
        ciphertext[CT_CONFIRM_OFFSET..].copy_from_slice(&confirm);

        // Compute session key: HashSession(1, r_enc, confirm)
        let session = kem_hash::hash_session(1, &r_enc, &confirm);

        let mut shared_secret = [0u8; K_SIZE];
        shared_secret.copy_from_slice(&session);

        (ciphertext, shared_secret)
    }

    /// Decapsulate a shared secret using the private key.
    ///
    /// Uses CCA fallback: if re-encryption doesn't match the ciphertext,
    /// the session key is derived from `rho` (random secret in SK) instead
    /// of the recovered `r`, preventing adaptive chosen-ciphertext attacks.
    pub fn decapsulate(ciphertext: &Ciphertext, sk: &PrivateKey) -> Result<SharedSecret> {
        // Extract SK components
        let f = zx::encoding::decode(&sk[SK_F_OFFSET..SK_GR_OFFSET]);
        let gr = zx::encoding::decode(&sk[SK_GR_OFFSET..SK_H_OFFSET]);
        let pk = &sk[SK_H_OFFSET..SK_RHO_OFFSET];
        let rho = &sk[SK_RHO_OFFSET..SK_CACHE_OFFSET];
        let cache = &sk[SK_CACHE_OFFSET..];
        let cache_arr: &[u8; HASH_BYTES] = cache.try_into().unwrap();

        // Extract ciphertext components
        let c_enc = &ciphertext[..ROUNDED_BYTES];
        let confirm = &ciphertext[CT_CONFIRM_OFFSET..];
        let confirm_arr: &[u8; HASH_BYTES] = confirm.try_into().unwrap();

        // Decrypt: recover r from c using f and gr
        let c = rq::encoding::decode_rounded(c_enc);

        let mut t = [0i16; P];
        rq::mult(&mut t, c, f);

        let mut t3 = [0i8; P];
        for i in 0..P {
            t3[i] = r3::mod3::freeze(rq::modq::freeze(3 * t[i] as i32) as i32);
        }

        let mut r = [0i8; P];
        r3::mult(&mut r, t3, gr);

        // Check weight constraint
        let w = count_weight(&r);
        let weight_ok = w == W as i32;

        // Re-encrypt to verify: cnew = Round(h * r), confirm_new = HashConfirm(r_enc, cache)
        let h = rq::encoding::decode(pk);
        let mut hr = [0i16; P];
        rq::mult(&mut hr, h, r);
        rq::round3(&mut hr);
        let cnew_enc = rq::encoding::encode_rounded(hr);

        let r_enc = zx::encoding::encode(r);
        let confirm_new = kem_hash::hash_confirm(&r_enc, cache_arr);

        // Constant-time comparison: check c_enc == cnew_enc AND confirm == confirm_new
        let c_match = constant_time_eq(c_enc, &cnew_enc);
        let confirm_match =
            crate::internal::subtle::ConstantTimeEq::ct_eq(confirm, &confirm_new).0 as i32;

        // mask = 0 if everything matches, -1 if any mismatch
        let weight_match = crate::internal::subtle::Choice::from_bool(weight_ok).0 as i32;
        let all_match = c_match & confirm_match & weight_match;
        let mask: i32 = if all_match == 1 { 0 } else { -1 };

        // CCA fallback: if mask != 0, replace r_enc with rho
        // r_enc[i] ^= mask & (r_enc[i] ^ rho[i])
        let mut r_enc_masked = [0u8; INPUTS_BYTES];
        for i in 0..INPUTS_BYTES {
            let m = (mask as u8) & (r_enc[i] ^ rho[i]);
            r_enc_masked[i] = r_enc[i] ^ m;
        }

        // Session key: HashSession(1 + mask, r_enc_masked, confirm)
        // On success: HashSession(1, r_enc, confirm)
        // On failure: HashSession(0, rho, confirm)
        let b = (1 + mask) as u8;
        let session = kem_hash::hash_session(b, &r_enc_masked, confirm_arr);

        let mut shared_secret = [0u8; K_SIZE];
        shared_secret.copy_from_slice(&session);

        // Always return Ok — CCA security means we never reveal whether
        // decapsulation succeeded or failed (the session key is just different)
        Ok(shared_secret)
    }
}

/// Constant-time comparison of two byte slices.
/// Returns 1 if equal, 0 if different.
fn constant_time_eq(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    // 1 if diff == 0 (equal), 0 otherwise
    let is_zero = (diff as u32).wrapping_sub(1) >> 31;
    is_zero as i32
}

fn count_weight(r: &[i8; P]) -> i32 {
    r.iter().map(|&x| x.abs() as i32).sum()
}

/// Core keygen: compute h = 3/f * g, return (pk, f_enc, gr_enc)
fn derive_core_keypair(
    f: [i8; P],
    g: [i8; P],
    gr: [i8; P],
) -> (PublicKey, [u8; SMALL_BYTES], [u8; SMALL_BYTES]) {
    let f3r = rq::reciprocal3(f);
    let mut h = [0i16; P];
    rq::mult(&mut h, f3r, g);

    let pk = rq::encoding::encode(h);
    let f_enc = zx::encoding::encode(f);
    let gr_enc = zx::encoding::encode(gr);

    (pk, f_enc, gr_enc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::rng::ChaCha20Rng;

    #[test]
    fn test_ntru_prime_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Generate keypair
        let (pk, sk) = NtruPrime::generate_keypair(&mut rng);

        // Encapsulate
        let (ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);

        // Decapsulate
        let ss2 = NtruPrime::decapsulate(&ct, &sk).expect("Decapsulation should succeed");

        // Verify shared secrets match
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_deterministic_keypair() {
        let seed = [99u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let (pk1, sk1) = NtruPrime::generate_keypair(&mut rng1);

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let (pk2, sk2) = NtruPrime::generate_keypair(&mut rng2);

        assert_eq!(pk1, pk2, "Same seed should produce same public key");
        assert_eq!(sk1, sk2, "Same seed should produce same private key");
    }

    #[test]
    fn test_key_sizes() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let (pk, sk) = NtruPrime::generate_keypair(&mut rng);

        assert_eq!(pk.len(), PK_SIZE);
        assert_eq!(sk.len(), SK_SIZE);
    }

    #[test]
    fn test_ciphertext_size() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let (pk, _) = NtruPrime::generate_keypair(&mut rng);
        let (ct, _) = NtruPrime::encapsulate(&pk, &mut rng);
        assert_eq!(ct.len(), CT_SIZE);
    }

    #[test]
    fn test_decapsulate_wrong_ciphertext() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let (pk, sk) = NtruPrime::generate_keypair(&mut rng);
        let (mut ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);

        // Tamper with ciphertext
        ct[0] ^= 1;

        // CCA: decapsulation should still return Ok (but different shared secret)
        let ss2 = NtruPrime::decapsulate(&ct, &sk).expect("CCA: always returns Ok");
        assert_ne!(
            ss1, ss2,
            "Tampered ciphertext must produce different shared secret (CCA fallback)"
        );
    }

    #[test]
    fn test_decapsulate_wrong_key() {
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

    #[test]
    fn test_zx_decode_short_input_does_not_panic() {
        // Defensive bounds check: short input returns zeros instead of panicking.
        let short = [0u8; 10];
        let f = zx::encoding::decode(&short);
        assert_eq!(f, [0i8; P]);
    }

    #[test]
    fn test_rq_decode_short_input_does_not_panic() {
        let short = [0u8; 100];
        let f = rq::encoding::decode(&short);
        assert_eq!(f, [0i16; P]);
        let f2 = rq::encoding::decode_rounded(&short);
        assert_eq!(f2, [0i16; P]);
    }

    #[test]
    fn test_sk_layout_offsets() {
        assert_eq!(SK_F_OFFSET, 0);
        assert_eq!(SK_GR_OFFSET, 191);
        assert_eq!(SK_H_OFFSET, 382);
        assert_eq!(SK_RHO_OFFSET, 1540);
        assert_eq!(SK_CACHE_OFFSET, 1731);
        assert_eq!(SK_CACHE_OFFSET + HASH_BYTES, SK_SIZE);
    }

    #[test]
    fn test_ct_layout_offsets() {
        assert_eq!(CT_CONFIRM_OFFSET, ROUNDED_BYTES);
        assert_eq!(CT_CONFIRM_OFFSET + CONFIRM_BYTES, CT_SIZE);
    }

    #[test]
    fn test_multiple_roundtrips() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (pk, sk) = NtruPrime::generate_keypair(&mut rng);

        for _ in 0..10 {
            let (ct, ss1) = NtruPrime::encapsulate(&pk, &mut rng);
            let ss2 = NtruPrime::decapsulate(&ct, &sk).unwrap();
            assert_eq!(ss1, ss2, "Roundtrip must produce matching shared secrets");
        }
    }
}

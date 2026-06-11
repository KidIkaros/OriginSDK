// SPDX-License-Identifier: Apache-2.0

//! Streamlined NTRU Prime Implementation (sntrup761)
//!
//! A modern Rust implementation of Streamlined NTRU Prime, the post-quantum
//! KEM used by OpenSSH. Parameters: p=761, q=4591, w=286
//!
//! This provides ~256-bit quantum security with better side-channel resistance
//! than Kyber due to its simpler algebraic structure.
//!
//! Reference: <https://ntruprime.cr.yp.to/>

pub mod constants;
mod r3;
mod rq;
mod zx;

use crate::error::{CryptoError, Result};
use crate::primitives::sha3 as native_sha3;
use rand::{CryptoRng, RngCore};

pub use constants::*;

/// NTRU Prime public key (1218 bytes)
pub type PublicKey = [u8; PK_SIZE];

/// NTRU Prime private key (1600 bytes)
pub type PrivateKey = [u8; SK_SIZE];

/// NTRU Prime ciphertext (1047 bytes)
pub type Ciphertext = [u8; CT_SIZE];

/// NTRU Prime shared secret (32 bytes)
pub type SharedSecret = [u8; K_SIZE];

/// NTRU Prime KEM implementation
pub struct NtruPrime;

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

        derive_keypair(f, g, gr)
    }

    /// Encapsulate a shared secret using the public key.
    ///
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate<R: RngCore + CryptoRng>(
        pk: &PublicKey,
        rng: &mut R,
    ) -> (Ciphertext, SharedSecret) {
        let mut r = [0i8; P];
        zx::random::random_tsmall(&mut r, rng);
        create_ciphertext(r, *pk)
    }

    /// Decapsulate a shared secret using the private key.
    pub fn decapsulate(ciphertext: &Ciphertext, sk: &PrivateKey) -> Result<SharedSecret> {
        let f = zx::encoding::decode(&sk[..191]);
        let c = rq::encoding::decode_rounded(&ciphertext[32..]);

        let mut t = [0i16; P];
        rq::mult(&mut t, c, f);

        let mut t3 = [0i8; P];
        for i in 0..P {
            t3[i] = r3::mod3::freeze(rq::modq::freeze(3 * t[i] as i32) as i32);
        }

        let gr = zx::encoding::decode(&sk[191..382]);
        let mut r = [0i8; P];
        r3::mult(&mut r, t3, gr);

        let w = count_weight(&r);
        let weight_check = w == W as i32;

        let h = rq::encoding::decode(&sk[382..]);
        let mut hr = [0i16; P];
        rq::mult(&mut hr, h, r);
        rq::round3(&mut hr);

        let mut c_check = true;
        for i in 0..P {
            c_check &= (hr[i] - c[i]) == 0;
        }

        let s = native_sha3::sha3_512(&zx::encoding::encode(r));
        let hash_check = s[..32] == ciphertext[..32];

        if weight_check && c_check && hash_check {
            let mut shared_secret = [0u8; K_SIZE];
            shared_secret.copy_from_slice(&s[32..64]);
            Ok(shared_secret)
        } else {
            Err(CryptoError::Decryption(
                "NTRU Prime decapsulation failed".to_string(),
            ))
        }
    }
}

fn count_weight(r: &[i8; P]) -> i32 {
    r.iter().map(|&x| x.abs() as i32).sum()
}

fn derive_keypair(f: [i8; P], g: [i8; P], gr: [i8; P]) -> (PublicKey, PrivateKey) {
    let f3r = rq::reciprocal3(f);
    let mut h = [0i16; P];
    rq::mult(&mut h, f3r, g);

    let pk = rq::encoding::encode(h);

    let mut sk = [0u8; SK_SIZE];
    sk[..191].copy_from_slice(&zx::encoding::encode(f));
    sk[191..382].copy_from_slice(&zx::encoding::encode(gr));
    sk[382..].copy_from_slice(&pk);

    (pk, sk)
}

fn create_ciphertext(r: [i8; P], pk: PublicKey) -> (Ciphertext, SharedSecret) {
    let h = rq::encoding::decode(&pk);
    let mut c = [0i16; P];
    rq::mult(&mut c, h, r);
    rq::round3(&mut c);

    let s = native_sha3::sha3_512(&zx::encoding::encode(r));

    let mut shared_secret = [0u8; K_SIZE];
    shared_secret.copy_from_slice(&s[32..64]);

    let mut ciphertext = [0u8; CT_SIZE];
    ciphertext[..32].copy_from_slice(&s[..32]);
    ciphertext[32..].copy_from_slice(&rq::encoding::encode_rounded(c));

    (ciphertext, shared_secret)
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
}

// SPDX-License-Identifier: Apache-2.0

//! Migration helpers: 0.6.x sntrup761 key material → 0.7.x NIST wire format.
//!
//! Version 0.7.0 replaced the pre-NIST encodings with the official submission
//! `Encode`/`Decode`, changing wire sizes (pk 1218→1158, sk 1600→1763,
//! ct 1047→1039) and the KEM hashing scheme. Key material itself is unchanged:
//! the `f` and `g^{-1}` polynomials were already stored in the same 191-byte
//! `Small` encoding, so a 0.6.x secret key migrates by re-encoding `h` and
//! appending fresh `rho`/`cache` fields.
//!
//! What can and cannot migrate:
//!
//! - **Public keys**: decodable from the old 1218-byte format, re-encodable in
//!   the new 1158-byte format. Same key, new wire bytes.
//! - **Private keys**: `f`/`gr` bytes carry over verbatim; `h` is re-encoded;
//!   `rho` is drawn fresh; `cache = H4(pk)` is recomputed. The migrated key
//!   decapsulates the same shared secrets as the original would have under the
//!   0.7.x hashing scheme — *not* the 0.6.x scheme (see below).
//! - **Ciphertexts**: not migratable. The 0.6.x layout was `confirm || rounded`
//!   with a different session hash; a KEM ciphertext is ephemeral, so there is
//!   nothing to migrate — re-encapsulate instead.
//! - **Shared secrets**: differ between versions by design. 0.6.x and 0.7.x
//!   use different session derivation (and 0.7.x binds the full ciphertext).
//!   If a 0.6.x shared secret was used to encrypt data, that data must be
//!   re-keyed; migration preserves the *keypair*, not past session outputs.
//!
//! # Experimental
//!
//! This is a custom implementation that has not undergone independent
//! cryptographic review.

#![allow(clippy::needless_range_loop)]

use super::{
    encode, rq::modq, PrivateKey, PublicKey, INPUTS_BYTES, RQ_BYTES, SK_SIZE, SMALL_BYTES,
};
use crate::error::{CryptoError, Result};
use rand::RngCore;

// Same backend selection as the KEM: the migrated key's cache field must use
// whichever H4 the active hashing scheme computes.
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

/// 0.6.x public key size (old Rq encoding)
pub const V06_PK_SIZE: usize = 1218;
/// 0.6.x private key size: `Small(f) ‖ Small(gr) ‖ Rq_v06(h)`
pub const V06_SK_SIZE: usize = 1600;
/// 0.6.x ciphertext size (`confirm ‖ Rounded_v06`) — not migratable
pub const V06_CT_SIZE: usize = 1047;

const V06_SK_H_OFFSET: usize = 2 * SMALL_BYTES;

/// Migrate a 0.6.x public key to the NIST wire format.
///
/// The returned key encodes the same `h` as the input; it is interchangeable
/// with the original for encapsulation under the 0.7.x scheme.
pub fn migrate_public_key(old_pk: &[u8]) -> Result<PublicKey> {
    if old_pk.len() != V06_PK_SIZE {
        return Err(CryptoError::Serialization(format!(
            "expected {V06_PK_SIZE}-byte 0.6.x public key, got {}",
            old_pk.len()
        )));
    }
    Ok(encode::rq_encode(&v06_rq::decode(old_pk)))
}

/// Migrate a 0.6.x private key to the NIST KEM format.
///
/// `f`/`gr` are copied verbatim (the 0.6.x `Small` encoding is identical to
/// the NIST one); `h` is re-encoded from the old public-key field; `rho` is
/// drawn from `rng`; `cache` is recomputed as `H4(pk)`.
///
/// The result is a self-contained 0.7.x secret key. Verify a migrated keypair
/// with an encapsulate/decapsulate roundtrip before relying on it.
pub fn migrate_private_key<R: RngCore>(old_sk: &[u8], rng: &mut R) -> Result<PrivateKey> {
    if old_sk.len() != V06_SK_SIZE {
        return Err(CryptoError::Serialization(format!(
            "expected {V06_SK_SIZE}-byte 0.6.x private key, got {}",
            old_sk.len()
        )));
    }
    let pk = migrate_public_key(&old_sk[V06_SK_H_OFFSET..])?;

    let mut sk = [0u8; SK_SIZE];
    sk[..2 * SMALL_BYTES].copy_from_slice(&old_sk[..2 * SMALL_BYTES]);
    sk[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES].copy_from_slice(&pk);
    rng.fill_bytes(&mut sk[2 * SMALL_BYTES + RQ_BYTES..2 * SMALL_BYTES + RQ_BYTES + INPUTS_BYTES]);
    sk[SK_SIZE - 32..].copy_from_slice(&kem_hash::hash4(&pk));
    Ok(sk)
}

/// Pre-NIST (0.6.x) Rq codec — 5 coefficients per 8 bytes, QSHIFT = 2295.
/// Ported verbatim from the 0.6.x `rq::encoding` module so the old wire
/// format can still be read. Not part of the public API.
mod v06_rq {
    use super::super::constants::P;
    use super::modq;

    #[cfg(test)]
    pub fn encode(f: [i16; P]) -> [u8; 1218] {
        const QSHIFT: i32 = 2295;
        let mut f0: i32;
        let mut f1: i32;
        let mut f2: i32;
        let mut f3: i32;
        let mut f4: i32;

        let mut c = [0u8; 1218];

        let mut j = 0;
        let mut k = 0;
        for _ in 0..152 {
            f0 = f[j] as i32 + QSHIFT;
            f1 = (f[j + 1] as i32 + QSHIFT) * 3;
            f2 = (f[j + 2] as i32 + QSHIFT) * 9;
            f3 = (f[j + 3] as i32 + QSHIFT) * 27;
            f4 = (f[j + 4] as i32 + QSHIFT) * 81;

            j += 5;
            f0 += f1 << 11;
            c[k] = f0 as u8;
            f0 >>= 8;
            c[k + 1] = f0 as u8;
            f0 >>= 8;
            f0 += f2 << 6;
            c[k + 2] = f0 as u8;
            f0 >>= 8;
            c[k + 3] = f0 as u8;
            f0 >>= 8;
            f0 += f3 << 1;
            c[k + 4] = f0 as u8;
            f0 >>= 8;
            f0 += f4 << 4;
            c[k + 5] = f0 as u8;
            f0 >>= 8;
            c[k + 6] = f0 as u8;
            f0 >>= 8;
            c[k + 7] = f0 as u8;
            k += 8;
        }

        f0 = f[760] as i32 + QSHIFT;
        c[1216] = f0 as u8;
        c[1217] = (f0 >> 8) as u8;
        c
    }

    pub fn decode(c: &[u8]) -> [i16; P] {
        const QSHIFT: i32 = 2295;
        const Q: i32 = 4591;

        let mut f0: i32;
        let mut f1: i32;
        let mut f2: i32;
        let mut f3: i32;
        let mut f4: i32;

        let mut c0: i64;
        let mut c1: i64;
        let mut c2: i64;
        let mut c3: i64;
        let mut c4: i64;
        let mut c5: i64;
        let mut c6: i64;
        let mut c7: i64;

        let mut f = [0i16; P];
        let mut j = 0;
        let mut k = 0;

        for _ in 0..152 {
            c0 = c[j] as i64;
            c1 = c[j + 1] as i64;
            c2 = c[j + 2] as i64;
            c3 = c[j + 3] as i64;
            c4 = c[j + 4] as i64;
            c5 = c[j + 5] as i64;
            c6 = c[j + 6] as i64;
            c7 = c[j + 7] as i64;

            j += 8;
            c6 += c7 << 8;
            f4 = ((103_564_i64 * c6 + 405 * (c5 + 1)) >> 19) as i32;
            c5 += c6 << 8;
            c5 -= (f4 as i64 * 81) << 4;
            c4 += c5 << 8;
            f3 = ((9_709_i64 * (c4 + 2)) >> 19) as i32;
            c4 -= (f3 as i64 * 27) << 1;
            c3 += c4 << 8;
            f2 = ((233_017_i64 * c3 + 910 * (c2 + 2)) >> 19) as i32;
            c2 += c3 << 8;
            c2 -= (f2 as i64 * 9) << 6;
            c1 += c2 << 8;
            f1 = ((21_845_i64 * (c1 + 2) + 85 * c0) >> 19) as i32;
            c1 -= (f1 as i64 * 3) << 3;
            c0 += c1 << 8;
            f0 = c0 as i32;

            f[k] = modq::freeze(f0 + Q - QSHIFT);
            f[k + 1] = modq::freeze(f1 + Q - QSHIFT);
            f[k + 2] = modq::freeze(f2 + Q - QSHIFT);
            f[k + 3] = modq::freeze(f3 + Q - QSHIFT);
            f[k + 4] = modq::freeze(f4 + Q - QSHIFT);
            k += 5;
        }

        c0 = c[1216] as i64;
        c1 = c[1217] as i64;
        c0 += c1 << 8;
        f[760] = modq::freeze((c0 + Q as i64 - QSHIFT as i64) as i32);
        f
    }
}

#[cfg(test)]
mod tests {
    use super::v06_rq;
    use super::*;
    use crate::internal::rng::ChaCha20Rng;
    use crate::pqc::ntru_prime::NtruPrime;

    fn fabricate_v06_keypair() -> ([u8; V06_PK_SIZE], [u8; V06_SK_SIZE]) {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (pk, sk) = NtruPrime::generate_keypair(&mut rng);
        let old_pk = v06_rq::encode(encode::rq_decode(&pk));
        let mut old_sk = [0u8; V06_SK_SIZE];
        old_sk[..2 * SMALL_BYTES].copy_from_slice(&sk[..2 * SMALL_BYTES]);
        old_sk[V06_SK_H_OFFSET..].copy_from_slice(&old_pk);
        (old_pk, old_sk)
    }

    #[test]
    fn v06_rq_codec_roundtrips() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let (pk, _) = NtruPrime::generate_keypair(&mut rng);
        let h = encode::rq_decode(&pk);
        assert_eq!(v06_rq::decode(&v06_rq::encode(h)), h);
    }

    #[test]
    fn migrate_public_key_preserves_h() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let (pk, _) = NtruPrime::generate_keypair(&mut rng);
        let old_pk = v06_rq::encode(encode::rq_decode(&pk));
        assert_eq!(migrate_public_key(&old_pk).unwrap(), pk);
    }

    #[test]
    fn migrated_private_key_decapsulates() {
        let (old_pk, old_sk) = fabricate_v06_keypair();
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);

        let new_pk = migrate_public_key(&old_pk).unwrap();
        let new_sk = migrate_private_key(&old_sk, &mut rng).unwrap();

        // Migrated keypair must function end-to-end under the 0.7.x scheme.
        let (ct, ss_enc) = NtruPrime::encapsulate(&new_pk, &mut rng);
        let ss_dec = NtruPrime::decapsulate(&ct, &new_sk).unwrap();
        assert_eq!(ss_enc, ss_dec);

        // And the pk inside the migrated sk must match the migrated pk.
        assert_eq!(
            &new_sk[2 * SMALL_BYTES..2 * SMALL_BYTES + RQ_BYTES],
            &new_pk[..]
        );
    }

    #[test]
    fn migrate_rejects_wrong_sizes() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        assert!(migrate_public_key(&[0u8; 1217]).is_err());
        assert!(migrate_private_key(&[0u8; 1599], &mut rng).is_err());
    }

    #[test]
    fn migrated_rho_and_cache_layout() {
        let (old_pk, old_sk) = fabricate_v06_keypair();
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let new_sk = migrate_private_key(&old_sk, &mut rng).unwrap();
        let new_pk = migrate_public_key(&old_pk).unwrap();
        assert_eq!(
            &new_sk[SK_SIZE - 32..],
            &kem_hash::hash4(&new_pk)[..],
            "cache must be H4(pk)"
        );
    }

    /// Prints a fabricated 0.6.x keypair as hex for manual CLI testing:
    /// `cargo test --lib print_v06_fixture -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_v06_fixture() {
        let (old_pk, old_sk) = fabricate_v06_keypair();
        eprintln!("pk={}", hex::encode(old_pk));
        eprintln!("sk={}", hex::encode(old_sk));
    }

    #[test]
    fn old_f_gr_bytes_carry_over() {
        let (_, old_sk) = fabricate_v06_keypair();
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let new_sk = migrate_private_key(&old_sk, &mut rng).unwrap();
        assert_eq!(&new_sk[..2 * SMALL_BYTES], &old_sk[..2 * SMALL_BYTES]);
    }
}

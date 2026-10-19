// SPDX-License-Identifier: Apache-2.0

//! Hybrid (classical + post-quantum) key encapsulation.
//!
//! A *hybrid* KEM runs several component KEMs in parallel between the same two
//! parties and combines their shared secrets into one key. It is secure if
//! **any** component is secure, so it survives the break of a single primitive
//! — the same "both must hold" philosophy as [`crate::signing::hybrid`], applied
//! to key establishment.
//!
//! # Construction
//!
//! For a recipient public key `pk = (pk_1, …, pk_n)`, the sender produces one
//! ciphertext/shared-secret pair per leg and combines:
//!
//! ```text
//! (ct_i, ss_i) ← KEM_i.Encap(pk_i)            for i = 1 … n
//! K            ← Combine(context, (ct_1 … ct_n), (ss_1 … ss_n))
//! ```
//!
//! [`combine_shared_secrets`] is the combiner: HKDF-SHA3-256 with
//!
//! - **IKM**  = `ss_1 ‖ ss_2 ‖ … ‖ ss_n`
//! - **salt** = `len(context) ‖ context ‖ len(ct_1) ‖ ct_1 ‖ …` — binds the
//!   caller's context (e.g. a handshake transcript hash) and every ciphertext
//! - **info** = a fixed domain label
//!
//! Ever input is length-prefixed, so `("ab","c")` and `("a","bc")` cannot
//! collide, and no leg is silently dropped or reordered.
//!
//! ## Combiner lemma (informal)
//!
//! If at least one component KEM is IND-CCA, then no efficient adversary can
//! distinguish `K` from uniform **unless** it also breaks HKDF-SHA3-256 as a
//! PRF with adversarially-influenced IKM (the dual-PRF property). The
//! ciphertext binding prevents mix-and-match across sessions. The remaining
//! assumption is standard for hybrid KEMs; this module does not prove it.
//!
//! # Suites
//!
//! | id | suite | feature |
//! |----|-------|---------|
//! | `0x0001` | X25519 + sntrup761 | always |
//! | `0x0002` | X25519 + ML-KEM-768 | `ml-kem` |
//! | `0x0003` | X25519 + sntrup761 + ML-KEM-768 | `ml-kem` |
//!
//! The suite id is a *label*; it is fed into the combiner's `context` so two
//! suites can never derive the same key from the same secrets.
//!
//! # Experimental
//!
//! This is a novel composition (see [`crate::kem`] docs). The X25519 and NTRU
//! Prime components come from the SDK's own implementations; ML-KEM is the
//! pinned RustCrypto crate. None of the *compositions* have been independently
//! reviewed.

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use crate::x25519::{X25519KeyPair, X25519PublicKey};
use rand::{CryptoRng, RngCore};

// ──────────────────────────────────────────────────────────────────────
// Suite identifiers
// ──────────────────────────────────────────────────────────────────────

/// Suite id: `X25519 + sntrup761`.
pub const SUITE_X25519_SNTRUP761: u16 = 0x0001;
/// Suite id: `X25519 + ML-KEM-768`.
#[cfg(feature = "ml-kem")]
pub const SUITE_X25519_MLKEM768: u16 = 0x0002;
/// Suite id: `X25519 + sntrup761 + ML-KEM-768`.
#[cfg(feature = "ml-kem")]
pub const SUITE_X25519_SNTRUP761_MLKEM768: u16 = 0x0003;

/// Fixed domain label for the combiner HKDF `info`.
const COMBINER_INFO: &[u8] = b"origin-crypto-sdk:kem:hybrid:v1";
/// Domain label for seed-derived sub-key material.
const DERIVE_INFO: &[u8] = b"origin-crypto-sdk:kem:hybrid:derive:v1";

/// Maximum HKDF-SHA3-256 output (255 × 32 bytes).
const MAX_OUTPUT: usize = 255 * 32;

// ──────────────────────────────────────────────────────────────────────
// The combiner
// ──────────────────────────────────────────────────────────────────────

/// Combine component KEM shared secrets into a single key.
///
/// See the [module docs](self) for the exact input layout and the security
/// argument. `context` binds caller-supplied data (e.g. a transcript hash) into
/// the derivation; pass an empty slice when there is none.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParameter`] if there are no component secrets,
/// if `output` is empty, or if `output` exceeds 8160 bytes
/// (255 × SHA3-256 output).
///
/// # Example
///
/// ```
/// use origin_crypto_sdk::kem::hybrid::combine_shared_secrets;
///
/// let mut key = [0u8; 32];
/// combine_shared_secrets(
///     b"transcript-hash",
///     &[&[0x11u8; 32]],
///     &[&[0x22u8; 32]],
///     &mut key,
/// )
/// .unwrap();
/// assert_ne!(key, [0u8; 32]);
/// ```
pub fn combine_shared_secrets(
    context: &[u8],
    ciphertexts: &[&[u8]],
    shared_secrets: &[&[u8]],
    output: &mut [u8],
) -> Result<()> {
    if shared_secrets.is_empty() {
        return Err(CryptoError::InvalidParameter(
            "hybrid KEM combiner: no component shared secrets".to_string(),
        ));
    }
    if output.is_empty() || output.len() > MAX_OUTPUT {
        return Err(CryptoError::InvalidParameter(format!(
            "hybrid KEM combiner: invalid output length {} (must be 1..={MAX_OUTPUT})",
            output.len()
        )));
    }

    // salt = len(context) ‖ context ‖ (len(ct) ‖ ct)* — binds transcript + cts.
    let mut salt = Vec::with_capacity(context.len() + 64 * (ciphertexts.len() + 1));
    salt.extend_from_slice(&(context.len() as u32).to_be_bytes());
    salt.extend_from_slice(context);
    for ct in ciphertexts {
        salt.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        salt.extend_from_slice(ct);
    }

    // IKM = ss_1 ‖ ss_2 ‖ … — the component secrets.
    let mut ikm = Vec::with_capacity(64 * shared_secrets.len());
    for ss in shared_secrets {
        ikm.extend_from_slice(ss);
    }

    let result = crate::kdf::hkdf::hkdf_sha3_256(&ikm, Some(&salt), COMBINER_INFO, output);

    ikm.zeroize();
    salt.zeroize();

    result
}

// ──────────────────────────────────────────────────────────────────────
// Shared leg helpers
// ──────────────────────────────────────────────────────────────────────

/// X25519 encapsulation leg: samples an ephemeral scalar, returns
/// `(ephemeral_public, shared_secret)`.
fn x25519_encaps<R: RngCore + CryptoRng>(pk: &[u8; 32], rng: &mut R) -> Result<([u8; 32], [u8; 32])> {
    let mut scalar = [0u8; 32];
    rng.fill_bytes(&mut scalar);
    let eph = X25519KeyPair::from_secret_key(&scalar)?;
    scalar.zeroize();

    let peer = X25519PublicKey::from_bytes(*pk);
    let ss = eph.diffie_hellman(&peer)?;

    let mut out_pk = [0u8; 32];
    out_pk.copy_from_slice(eph.public_key().as_bytes());
    let mut out_ss = [0u8; 32];
    out_ss.copy_from_slice(ss.as_bytes());
    Ok((out_pk, out_ss))
}

/// X25519 decapsulation leg: `X25519(sk, ct_ephemeral_public)`.
fn x25519_decaps(sk: &[u8; 32], ct_pk: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = X25519KeyPair::from_secret_key(sk)?;
    let peer = X25519PublicKey::from_bytes(*ct_pk);
    let ss = sk.diffie_hellman(&peer)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_bytes());
    Ok(out)
}

/// Derive `N` bytes of sub-key material from a master seed and a `label`.
fn derive_n(master: &[u8], label: &[u8], out: &mut [u8]) -> Result<()> {
    let info = [DERIVE_INFO, label].concat();
    crate::kdf::hkdf::hkdf_sha3_256(master, None, &info, out)
}

/// Suite-id bytes as combiner context.
fn suite_context(suite: u16) -> [u8; 2] {
    suite.to_be_bytes()
}

// ──────────────────────────────────────────────────────────────────────
// Suite 0x0001 — X25519 + sntrup761
// ──────────────────────────────────────────────────────────────────────

mod ntru {
    pub use crate::pqc::ntru_prime::{Ciphertext, NtruPrime, PrivateKey, PublicKey};
}

/// Public key for the `X25519 + sntrup761` suite.
///
/// Wire form: `x25519 (32 B) ‖ ntru (1158 B)` = **1190 bytes**.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519NtruPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; 32],
    /// sntrup761 public key (1158 bytes, NIST wire format).
    pub ntru: ntru::PublicKey,
}

impl std::fmt::Debug for X25519NtruPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruPublicKey")
            .field("x25519", &"32-byte key")
            .field("ntru", &"1158-byte key")
            .finish()
    }
}

/// Secret key for the `X25519 + sntrup761` suite. Zeroizes on drop.
#[derive(Clone)]
pub struct X25519NtruSecretKey {
    x25519: [u8; 32],
    ntru: ntru::PrivateKey,
}

impl Drop for X25519NtruSecretKey {
    fn drop(&mut self) {
        self.x25519.zeroize();
        self.ntru.as_mut_slice().zeroize();
    }
}

impl std::fmt::Debug for X25519NtruSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruSecretKey").finish_non_exhaustive()
    }
}

/// Ciphertext for the `X25519 + sntrup761` suite.
///
/// Wire form: `x25519 (32 B) ‖ ntru (1039 B)` = **1071 bytes**.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519NtruCiphertext {
    /// Ephemeral X25519 public key (32 bytes).
    pub x25519: [u8; 32],
    /// sntrup761 ciphertext (1039 bytes, NIST wire format).
    pub ntru: ntru::Ciphertext,
}

impl std::fmt::Debug for X25519NtruCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruCiphertext")
            .field("x25519", &"32-byte ct")
            .field("ntru", &"1039-byte ct")
            .finish()
    }
}

/// `X25519 + sntrup761` hybrid KEM (suite `0x0001`).
#[derive(Debug)]
pub struct X25519NtruKem;

impl X25519NtruKem {
    /// Generate a key pair from OS entropy.
    pub fn generate_keypair() -> Result<(X25519NtruPublicKey, X25519NtruSecretKey)> {
        let mut seed = [0u8; 32];
        crate::fill_random(&mut seed)?;
        let kp = Self::generate_keypair_from_seed(&seed)?;
        seed.zeroize();
        Ok(kp)
    }

    /// Deterministically derive a key pair from a 32-byte seed.
    pub fn generate_keypair_from_seed(
        seed: &[u8; 32],
    ) -> Result<(X25519NtruPublicKey, X25519NtruSecretKey)> {
        let mut x_scalar = [0u8; 32];
        derive_n(seed, b"x25519", &mut x_scalar)?;
        // Validate/clamp by constructing a pair; keep the derived scalar as the
        // storage form — `from_secret_key` clamps on use, so it agrees.
        let x_public = X25519KeyPair::from_secret_key(&x_scalar)?
            .public_key()
            .as_bytes()
            .to_owned();

        let mut ntru_seed = [0u8; 32];
        derive_n(seed, b"ntru-prime", &mut ntru_seed)?;
        let (ntru_pk, ntru_sk) = ntru::NtruPrime::generate_keypair_from_seed(&ntru_seed);
        ntru_seed.zeroize();

        let public = X25519NtruPublicKey {
            x25519: x_public,
            ntru: ntru_pk,
        };
        Ok((public, X25519NtruSecretKey { x25519: x_scalar, ntru: ntru_sk }))
    }

    /// Encapsulate to a peer public key. Returns `(ciphertext, 32-byte key)`.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        pk: &X25519NtruPublicKey,
        rng: &mut R,
    ) -> Result<(X25519NtruCiphertext, [u8; 32])> {
        let (x_ct, ss_x) = x25519_encaps(&pk.x25519, rng)?;
        let (ntru_ct, ss_n) = ntru::NtruPrime::encapsulate(&pk.ntru, rng);

        let ct = X25519NtruCiphertext { x25519: x_ct, ntru: ntru_ct };
        let mut key = [0u8; 32];
        combine_shared_secrets(
            &suite_context(SUITE_X25519_SNTRUP761),
            &[&ct.x25519, &ct.ntru],
            &[&ss_x, &ss_n],
            &mut key,
        )?;
        Ok((ct, key))
    }

    /// Decapsulate a ciphertext to the 32-byte key.
    pub fn decapsulate(
        sk: &X25519NtruSecretKey,
        ct: &X25519NtruCiphertext,
    ) -> Result<[u8; 32]> {
        let ss_x = x25519_decaps(&sk.x25519, &ct.x25519)?;
        let ss_n = ntru::NtruPrime::decapsulate(&ct.ntru, &sk.ntru)?;
        let mut key = [0u8; 32];
        combine_shared_secrets(
            &suite_context(SUITE_X25519_SNTRUP761),
            &[&ct.x25519, &ct.ntru],
            &[&ss_x, &ss_n],
            &mut key,
        )?;
        Ok(key)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Suite 0x0002/0x0003 — X25519 + ML-KEM-768 (+ sntrup761)
// ──────────────────────────────────────────────────────────────────────

#[cfg(feature = "ml-kem")]
mod mlkem {
    pub use crate::pqc::ml_kem::{
        Ciphertext, CiphertextBytes, DecapsulationKey, EncapsulationKey, EncapsulationKeyBytes,
        MlKem768Kem, Seed, SEED_SIZE,
    };
}

/// Public key for the hybrid ML-KEM suites.
///
/// Wire form (suite `0x0003`):
/// `x25519 (32 B) ‖ ntru (1158 B) ‖ ml-kem (1184 B)` = **2374 bytes**.
#[cfg(feature = "ml-kem")]
#[derive(Clone, PartialEq, Eq)]
pub struct X25519NtruMlKemPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; 32],
    /// sntrup761 public key (1158 bytes).
    pub ntru: ntru::PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub ml_kem: mlkem::EncapsulationKeyBytes,
}

#[cfg(feature = "ml-kem")]
impl std::fmt::Debug for X25519NtruMlKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruMlKemPublicKey")
            .field("x25519", &"32-byte key")
            .field("ntru", &"1158-byte key")
            .field("ml_kem", &"1184-byte key")
            .finish()
    }
}

/// Secret key for the hybrid ML-KEM suites. Zeroizes on drop.
///
/// ML-KEM is stored as its 64-byte FIPS 203 seed (`d ‖ z`), the storage form.
#[cfg(feature = "ml-kem")]
#[derive(Clone)]
pub struct X25519NtruMlKemSecretKey {
    x25519: [u8; 32],
    ntru: ntru::PrivateKey,
    ml_kem: mlkem::Seed,
}

#[cfg(feature = "ml-kem")]
impl Drop for X25519NtruMlKemSecretKey {
    fn drop(&mut self) {
        self.x25519.zeroize();
        self.ntru.as_mut_slice().zeroize();
        self.ml_kem.as_mut_slice().zeroize();
    }
}

#[cfg(feature = "ml-kem")]
impl std::fmt::Debug for X25519NtruMlKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruMlKemSecretKey")
            .finish_non_exhaustive()
    }
}

/// Ciphertext for the hybrid ML-KEM suites.
///
/// Wire form (suite `0x0003`):
/// `x25519 (32 B) ‖ ntru (1039 B) ‖ ml-kem (1088 B)` = **2159 bytes**.
#[cfg(feature = "ml-kem")]
#[derive(Clone, PartialEq, Eq)]
pub struct X25519NtruMlKemCiphertext {
    /// Ephemeral X25519 public key (32 bytes).
    pub x25519: [u8; 32],
    /// sntrup761 ciphertext (1039 bytes).
    pub ntru: ntru::Ciphertext,
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub ml_kem: mlkem::CiphertextBytes,
}

#[cfg(feature = "ml-kem")]
impl std::fmt::Debug for X25519NtruMlKemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519NtruMlKemCiphertext")
            .field("x25519", &"32-byte ct")
            .field("ntru", &"1039-byte ct")
            .field("ml_kem", &"1088-byte ct")
            .finish()
    }
}

/// `X25519 + sntrup761 + ML-KEM-768` hybrid KEM (suite `0x0003`).
///
/// The triple composition is deliberate: the two post-quantum legs are
/// *independently implemented* (SDK NTRU Prime vs pinned RustCrypto ML-KEM), so
/// an implementation fault in either is covered by the other. It does **not**
/// protect against a break of the lattice family itself — both PQ legs are
/// lattice-lineage. See [`crate::kem`].
#[cfg(feature = "ml-kem")]
#[derive(Debug)]
pub struct X25519NtruMlKemKem;

#[cfg(feature = "ml-kem")]
impl X25519NtruMlKemKem {
    /// Generate a key pair from OS entropy.
    pub fn generate_keypair() -> Result<(X25519NtruMlKemPublicKey, X25519NtruMlKemSecretKey)> {
        let mut seed = [0u8; 32];
        crate::fill_random(&mut seed)?;
        let kp = Self::generate_keypair_from_seed(&seed)?;
        seed.zeroize();
        Ok(kp)
    }

    /// Deterministically derive a key pair from a 32-byte seed.
    pub fn generate_keypair_from_seed(
        seed: &[u8; 32],
    ) -> Result<(X25519NtruMlKemPublicKey, X25519NtruMlKemSecretKey)> {
        let mut x_scalar = [0u8; 32];
        derive_n(seed, b"x25519", &mut x_scalar)?;
        // Validate/clamp by constructing a pair; keep the derived scalar as the
        // storage form — `from_secret_key` clamps on use, so it agrees.
        let x_public = X25519KeyPair::from_secret_key(&x_scalar)?
            .public_key()
            .as_bytes()
            .to_owned();

        let mut ntru_seed = [0u8; 32];
        derive_n(seed, b"ntru-prime", &mut ntru_seed)?;
        let (ntru_pk, ntru_sk) = ntru::NtruPrime::generate_keypair_from_seed(&ntru_seed);
        ntru_seed.zeroize();

        let mut ml_seed = [0u8; mlkem::SEED_SIZE];
        derive_n(seed, b"ml-kem-768", &mut ml_seed)?;
        let (ml_dk, ml_ek) = mlkem::MlKem768Kem::generate_keypair_from_seed(&ml_seed);
        ml_seed.zeroize();

        let public = X25519NtruMlKemPublicKey {
            x25519: x_public,
            ntru: ntru_pk,
            ml_kem: ml_ek.as_bytes(),
        };
        let secret = X25519NtruMlKemSecretKey {
            x25519: x_scalar,
            ntru: ntru_sk,
            ml_kem: ml_dk.to_seed(),
        };
        Ok((public, secret))
    }

    /// Encapsulate to a peer public key. Returns `(ciphertext, 32-byte key)`.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        pk: &X25519NtruMlKemPublicKey,
        rng: &mut R,
    ) -> Result<(X25519NtruMlKemCiphertext, [u8; 32])> {
        let (x_ct, ss_x) = x25519_encaps(&pk.x25519, rng)?;
        let (ntru_ct, ss_n) = ntru::NtruPrime::encapsulate(&pk.ntru, rng);

        let ek = mlkem::EncapsulationKey::from_bytes(&pk.ml_kem)?;
        let (ml_ct, ss_m) = mlkem::MlKem768Kem::encapsulate(&ek);

        let ct = X25519NtruMlKemCiphertext {
            x25519: x_ct,
            ntru: ntru_ct,
            ml_kem: ml_ct.as_bytes(),
        };
        let mut key = [0u8; 32];
        combine_shared_secrets(
            &suite_context(SUITE_X25519_SNTRUP761_MLKEM768),
            &[&ct.x25519, &ct.ntru, &ct.ml_kem],
            &[&ss_x, &ss_n, &ss_m],
            &mut key,
        )?;
        Ok((ct, key))
    }

    /// Decapsulate a ciphertext to the 32-byte key.
    pub fn decapsulate(
        sk: &X25519NtruMlKemSecretKey,
        ct: &X25519NtruMlKemCiphertext,
    ) -> Result<[u8; 32]> {
        let ss_x = x25519_decaps(&sk.x25519, &ct.x25519)?;
        let ss_n = ntru::NtruPrime::decapsulate(&ct.ntru, &sk.ntru)?;

        let dk = mlkem::DecapsulationKey::from_seed(&sk.ml_kem);
        let ml_ct = mlkem::Ciphertext::from_bytes(&ct.ml_kem)?;
        let ss_m = mlkem::MlKem768Kem::decapsulate(&dk, &ml_ct);

        let mut key = [0u8; 32];
        combine_shared_secrets(
            &suite_context(SUITE_X25519_SNTRUP761_MLKEM768),
            &[&ct.x25519, &ct.ntru, &ct.ml_kem],
            &[&ss_x, &ss_n, &ss_m],
            &mut key,
        )?;
        Ok(key)
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drbg::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    // ── Combiner ──

    #[test]
    fn combiner_is_deterministic() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        combine_shared_secrets(b"ctx", &[&[1u8; 32]], &[&[2u8; 32]], &mut a).unwrap();
        combine_shared_secrets(b"ctx", &[&[1u8; 32]], &[&[2u8; 32]], &mut b).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn combiner_binds_context_ciphertexts_and_secrets() {
        let base = |ctx: &[u8], ct: &[u8], ss: &[u8]| {
            let mut out = [0u8; 32];
            combine_shared_secrets(ctx, &[ct], &[ss], &mut out).unwrap();
            out
        };
        let reference = base(b"ctx", &[1u8; 32], &[2u8; 32]);
        assert_ne!(reference, base(b"other", &[1u8; 32], &[2u8; 32]), "context");
        assert_ne!(reference, base(b"ctx", &[9u8; 32], &[2u8; 32]), "ciphertext");
        assert_ne!(reference, base(b"ctx", &[1u8; 32], &[9u8; 32]), "secret");
    }

    /// Length-prefixing must make `("ab","c")` and `("a","bc")` distinguishable.
    #[test]
    fn combiner_is_unambiguous_under_concatenation() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        combine_shared_secrets(b"", &[b"ab", b"c"], &[&[1u8; 32]], &mut a).unwrap();
        combine_shared_secrets(b"", &[b"a", b"bc"], &[&[1u8; 32]], &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn combiner_rejects_empty_secrets_and_bad_output() {
        let mut out = [0u8; 32];
        assert!(combine_shared_secrets(b"", &[], &[], &mut out).is_err());
        assert!(combine_shared_secrets(b"", &[], &[&[1u8; 32]], &mut []).is_err());
        let mut huge = [0u8; MAX_OUTPUT + 1];
        assert!(combine_shared_secrets(b"", &[], &[&[1u8; 32]], &mut huge).is_err());
    }

    /// Frozen construction vector — protects against accidental changes to the
    /// combiner. Bump the `v1` label if this must ever change.
    #[test]
    fn combiner_frozen_vector() {
        let mut out = [0u8; 32];
        combine_shared_secrets(
            b"vallum/test/context",
            &[&[0x11u8; 32], &[0x22u8; 40]],
            &[&[0x33u8; 32], &[0x44u8; 32]],
            &mut out,
        )
        .unwrap();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "9617883a11f3205a29d45295d97d10172d30f2794ad266aa5f18c283fe67795d");
    }

    // ── Suite 0x0001 ──

    #[test]
    fn x25519_ntru_roundtrip() {
        let (pk, sk) = X25519NtruKem::generate_keypair().unwrap();
        let (ct, k_send) = X25519NtruKem::encapsulate(&pk, &mut rng(1)).unwrap();
        let k_recv = X25519NtruKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(k_send, k_recv);
        assert_ne!(k_send, [0u8; 32]);
    }

    #[test]
    fn x25519_ntru_keygen_is_deterministic() {
        let seed = [7u8; 32];
        let (pk1, _) = X25519NtruKem::generate_keypair_from_seed(&seed).unwrap();
        let (pk2, _) = X25519NtruKem::generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2);

        let (pk3, _) = X25519NtruKem::generate_keypair_from_seed(&[8u8; 32]).unwrap();
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn x25519_ntru_tampering_changes_key() {
        let (pk, sk) = X25519NtruKem::generate_keypair().unwrap();
        let (mut ct, k) = X25519NtruKem::encapsulate(&pk, &mut rng(2)).unwrap();

        // Flip a byte in each leg; the recovered key must differ each time.
        ct.x25519[0] ^= 1;
        assert_ne!(X25519NtruKem::decapsulate(&sk, &ct).unwrap(), k);
        ct.x25519[0] ^= 1;

        ct.ntru[0] ^= 1;
        assert_ne!(X25519NtruKem::decapsulate(&sk, &ct).unwrap(), k);
    }

    /// Debug must never surface secret material.
    #[test]
    fn secret_key_debug_redacts() {
        let (_, sk) = X25519NtruKem::generate_keypair().unwrap();
        let rendered = format!("{sk:?}");
        assert!(!rendered.contains("1763"), "Debug leaked length: {rendered}");
    }

    // ── Suite 0x0003 ──

    #[cfg(feature = "ml-kem")]
    #[test]
    fn tri_hybrid_roundtrip() {
        let (pk, sk) = X25519NtruMlKemKem::generate_keypair().unwrap();
        let (ct, k_send) = X25519NtruMlKemKem::encapsulate(&pk, &mut rng(3)).unwrap();
        let k_recv = X25519NtruMlKemKem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(k_send, k_recv);
        assert_ne!(k_send, [0u8; 32]);
    }

    #[cfg(feature = "ml-kem")]
    #[test]
    fn tri_hybrid_requires_every_leg() {
        let (pk, sk) = X25519NtruMlKemKem::generate_keypair().unwrap();
        let (mut ct, k) = X25519NtruMlKemKem::encapsulate(&pk, &mut rng(4)).unwrap();

        ct.ml_kem[0] ^= 1;
        assert_ne!(X25519NtruMlKemKem::decapsulate(&sk, &ct).unwrap(), k);
        ct.ml_kem[0] ^= 1;

        ct.ntru[0] ^= 1;
        assert_ne!(X25519NtruMlKemKem::decapsulate(&sk, &ct).unwrap(), k);
        ct.ntru[0] ^= 1;

        ct.x25519[0] ^= 1;
        assert_ne!(X25519NtruMlKemKem::decapsulate(&sk, &ct).unwrap(), k);
    }

    #[cfg(feature = "ml-kem")]
    #[test]
    fn tri_hybrid_keygen_is_deterministic() {
        let seed = [0xABu8; 32];
        let (pk1, _) = X25519NtruMlKemKem::generate_keypair_from_seed(&seed).unwrap();
        let (pk2, _) = X25519NtruMlKemKem::generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2);
    }
}

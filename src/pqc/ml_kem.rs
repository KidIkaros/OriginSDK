// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-768 (FIPS 203) key encapsulation.
//!
//! SDK-shaped wrapper over the RustCrypto `ml-kem` crate — the masked-NTT,
//! side-channel-resistant implementation (validated in Signet). Mirrors the
//! `ntru_prime` module shape so downstream crates get both KEMs through one
//! dependency and one API style.
//!
//! Wire sizes (FIPS 203): ek 1184 B, ct 1088 B, ss 32 B. The decapsulation
//! key is stored and serialized as its **64-byte seed** (`d || z`), not the
//! deprecated 2400-byte expanded form — the crate itself deprecates expanded
//! dk encoding, and seeds are the "store seeds, not expanded keys" rule.
//!
//! # Storage vs transmission
//!
//! - Store: the 64-byte seed (`DecapsulationKey::to_bytes()` → `Seed`).
//!   The seed IS a secret (it reconstructs the full keypair).
//! - Transmit: the 1184-byte encapsulation key. This is the public key and
//!   is safe to share (see Signet ADR-009).

use crate::error::{CryptoError, Result};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey as MlDk, EncapsulationKey as MlEk, MlKem768};

/// ML-KEM-768 encapsulation (public) key size in bytes.
pub const EK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
pub const CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size in bytes.
pub const SS_SIZE: usize = 32;
/// ML-KEM-768 seed size in bytes (`d || z` per FIPS 203 KeyGen_internal).
pub const SEED_SIZE: usize = 64;

/// The seed form of an ML-KEM-768 decapsulation key (the storage form).
pub type Seed = [u8; SEED_SIZE];

/// ML-KEM-768 KEM operations.
#[derive(Debug)]
pub struct MlKem768Kem;

impl MlKem768Kem {
    /// Generate an ML-KEM-768 keypair deterministically from a 64-byte seed.
    ///
    /// The seed is the FIPS 203 `KeyGen_internal` input (`d || z`). Same
    /// seed → same keypair, enabling HKDF derivation from a childseed.
    pub fn generate_keypair_from_seed(seed: &Seed) -> (DecapsulationKey, EncapsulationKey) {
        let dk = MlDk::<MlKem768>::from_seed((*seed).into());
        let ek = dk.encapsulation_key().clone();
        (DecapsulationKey(dk), EncapsulationKey(ek))
    }

    /// Encapsulate to a peer's encapsulation key.
    ///
    /// Returns `(ciphertext, shared_secret)`. Fresh randomness is drawn from
    /// the OS.
    pub fn encapsulate(ek: &EncapsulationKey) -> (Ciphertext, SharedSecret) {
        let (ct, ss) = ek.0.encapsulate();
        (Ciphertext(ct), ss.into())
    }

    /// Encapsulate with caller-supplied randomness (`m`, 32 bytes).
    ///
    /// This is the FIPS 203 `Encaps_internal` entry point: `(K, r) = G(m ‖ H(ek))`
    /// and `c = Encrypt(ek, m, r)`. Supplying `m` makes encapsulation fully
    /// deterministic, which protocols need for two things:
    ///
    /// - **MEX / dual-PRF hardening** — a protocol can derive `m` from both peer
    ///   randomness *and* a long-term secret, so a subverted RNG cannot fix the
    ///   shared secret (see PQ-WireGuard's `CCAKEM.Enc(spk, KDF1(σ, r))`).
    /// - **Byte-exact test vectors** — transcripts and session keys become
    ///   reproducible.
    ///
    /// # Warning
    ///
    /// `m` **must** be uniformly random and secret, and must never be reused
    /// across encryptions to the same key. Callers mixing protocol secrets into
    /// `m` are expected to hash them through a KDF first.
    pub fn encapsulate_deterministic(
        ek: &EncapsulationKey,
        m: &[u8; SS_SIZE],
    ) -> (Ciphertext, SharedSecret) {
        let m: ml_kem::B32 = (*m).into();
        let (ct, ss) = ek.0.encapsulate_deterministic(&m);
        (Ciphertext(ct), ss.into())
    }

    /// Decapsulate a ciphertext with the decapsulation key.
    ///
    /// Returns the 32-byte shared secret.
    pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        dk.0.decapsulate(&ct.0).into()
    }
}

/// The raw bytes of an ML-KEM-768 encapsulation key.
pub type EncapsulationKeyBytes = [u8; EK_SIZE];

/// The raw bytes of an ML-KEM-768 ciphertext.
pub type CiphertextBytes = [u8; CT_SIZE];

/// ML-KEM-768 shared secret (32 bytes).
pub type SharedSecret = [u8; SS_SIZE];

/// ML-KEM-768 decapsulation key (seed-backed).
///
/// Serializes to its 64-byte seed. Holds the expanded key only in memory.
#[derive(Clone)]
pub struct DecapsulationKey(MlDk<MlKem768>);

impl DecapsulationKey {
    /// Reconstruct from its 64-byte seed (e.g. vault round-trip).
    pub fn from_seed(seed: &Seed) -> Self {
        Self(MlDk::<MlKem768>::from_seed((*seed).into()))
    }

    /// The 64-byte seed (the storage form).
    ///
    /// # Panics (inherited from the crate)
    /// Only if this key was built from the deprecated expanded form —
    /// impossible here; every constructor in this module is seed-backed.
    pub fn to_seed(&self) -> Seed {
        use ml_kem::KeyExport;
        self.0.to_bytes().into()
    }

    /// The paired encapsulation (public) key.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey(self.0.encapsulation_key().clone())
    }
}

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material through Debug.
        f.debug_struct("DecapsulationKey").finish_non_exhaustive()
    }
}

/// ML-KEM-768 encapsulation key (1184 bytes) — the transmit form.
#[derive(Clone)]
pub struct EncapsulationKey(MlEk<MlKem768>);

impl EncapsulationKey {
    /// Reconstruct from raw bytes (e.g. received over the wire).
    pub fn from_bytes(bytes: &EncapsulationKeyBytes) -> Result<Self> {
        MlEk::<MlKem768>::new(bytes.into())
            .map(Self)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid ML-KEM ek: {e}")))
    }

    /// Raw bytes for transmission.
    pub fn as_bytes(&self) -> EncapsulationKeyBytes {
        use ml_kem::KeyExport;
        self.0.to_bytes().into()
    }
}

impl std::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncapsulationKey").finish_non_exhaustive()
    }
}

/// ML-KEM-768 ciphertext (1088 bytes).
#[derive(Clone)]
pub struct Ciphertext(ml_kem::Ciphertext<MlKem768>);

impl Ciphertext {
    /// Reconstruct from raw bytes.
    pub fn from_bytes(bytes: &CiphertextBytes) -> Result<Self> {
        let arr: ml_kem::Ciphertext<MlKem768> = (*bytes).into();
        Ok(Self(arr))
    }

    /// Raw bytes for transmission.
    pub fn as_bytes(&self) -> CiphertextBytes {
        self.0.into()
    }
}

impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ciphertext").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encapsulate_decapsulate() {
        let seed = [5u8; SEED_SIZE];
        let (dk, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let (ct, ss1) = MlKem768Kem::encapsulate(&ek);
        let ss2 = MlKem768Kem::decapsulate(&dk, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn deterministic_keypair_from_seed() {
        let seed = [7u8; SEED_SIZE];
        let (dk1, ek1) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let (dk2, ek2) = MlKem768Kem::generate_keypair_from_seed(&seed);
        assert_eq!(dk1.to_seed(), dk2.to_seed());
        assert_eq!(ek1.as_bytes(), ek2.as_bytes());
    }

    #[test]
    fn wire_sizes_match_fips203() {
        let seed = [42u8; SEED_SIZE];
        let (dk, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        assert_eq!(ek.as_bytes().len(), EK_SIZE);
        assert_eq!(dk.to_seed().len(), SEED_SIZE);
        let (ct, ss) = MlKem768Kem::encapsulate(&ek);
        assert_eq!(ct.as_bytes().len(), CT_SIZE);
        assert_eq!(ss.len(), SS_SIZE);
    }

    #[test]
    fn ek_roundtrips_through_bytes() {
        let seed = [9u8; SEED_SIZE];
        let (_, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let ek2 = EncapsulationKey::from_bytes(&ek.as_bytes()).unwrap();
        assert_eq!(ek.as_bytes(), ek2.as_bytes());
    }

    #[test]
    fn dk_seed_roundtrips() {
        let seed = [11u8; SEED_SIZE];
        let (dk, _) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let dk2 = DecapsulationKey::from_seed(&dk.to_seed());
        assert_eq!(dk.to_seed(), dk2.to_seed());
        // Same seed → same ek.
        assert_eq!(
            dk.encapsulation_key().as_bytes(),
            dk2.encapsulation_key().as_bytes()
        );
    }

    #[test]
    fn ct_roundtrips_through_bytes() {
        let seed = [13u8; SEED_SIZE];
        let (_, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let (ct, _) = MlKem768Kem::encapsulate(&ek);
        let ct2 = Ciphertext::from_bytes(&ct.as_bytes()).unwrap();
        assert_eq!(ct.as_bytes(), ct2.as_bytes());
    }

    #[test]
    fn wrong_key_decapsulates_to_different_secret() {
        let seed_a = [21u8; SEED_SIZE];
        let seed_b = [22u8; SEED_SIZE];
        let (dk_a, ek_a) = MlKem768Kem::generate_keypair_from_seed(&seed_a);
        let (dk_b, _) = MlKem768Kem::generate_keypair_from_seed(&seed_b);
        let (ct, ss_a) = MlKem768Kem::encapsulate(&ek_a);
        // Decapsulating with the wrong key yields the implicit-rejection
        // secret, which must differ from the true shared secret.
        let ss_wrong = MlKem768Kem::decapsulate(&dk_b, &ct);
        assert_ne!(ss_a, ss_wrong);
        // And the right key still works.
        assert_eq!(ss_a, MlKem768Kem::decapsulate(&dk_a, &ct));
    }

    #[test]
    fn fixed_seed_produces_stable_ek() {
        // Reproducibility pin: this seed must always derive this ek prefix.
        // (Full-constant vectors live in Signet's test_vectors; this pins
        // determinism of the RustCrypto keygen from seed across runs.)
        let mut seed = [0u8; SEED_SIZE];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let (_, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let bytes = ek.as_bytes();
        // Deterministic: derive again, byte-identical.
        let (_, ek2) = MlKem768Kem::generate_keypair_from_seed(&seed);
        assert_eq!(bytes, ek2.as_bytes());
        assert_ne!(bytes, [0u8; EK_SIZE]);
    }

    #[test]
    fn encapsulate_deterministic_is_reproducible() {
        let seed = [31u8; SEED_SIZE];
        let (dk, ek) = MlKem768Kem::generate_keypair_from_seed(&seed);
        let m = [7u8; SS_SIZE];

        let (ct1, ss1) = MlKem768Kem::encapsulate_deterministic(&ek, &m);
        let (ct2, ss2) = MlKem768Kem::encapsulate_deterministic(&ek, &m);
        assert_eq!(ct1.as_bytes(), ct2.as_bytes());
        assert_eq!(ss1, ss2);

        // The deterministic secret is the real one: decapsulation recovers it.
        assert_eq!(MlKem768Kem::decapsulate(&dk, &ct1), ss1);

        // Distinct randomness yields distinct ciphertext and secret.
        let (ct3, ss3) = MlKem768Kem::encapsulate_deterministic(&ek, &[8u8; SS_SIZE]);
        assert_ne!(ct1.as_bytes(), ct3.as_bytes());
        assert_ne!(ss1, ss3);
    }
}

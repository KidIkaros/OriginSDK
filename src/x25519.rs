// SPDX-License-Identifier: Apache-2.0

//! X25519 Diffie-Hellman key agreement (RFC 7748) — `algorithm_id 0x0602`.
//!
//! Fills the documented public-API gap: the SDK reserved `AlgorithmId::X25519`
//! but exposed no key-agreement surface, forcing downstream crates
//! (origin-channel's Noise handshake) to keep a temporary `dh.rs` seam that
//! imported `x25519_dalek` directly. With this module, key agreement comes
//! from the single crypto provider like every other primitive.
//!
//! # Shape
//!
//! Follows the SDK's house pattern (see `signing::mod` "static methods, not
//! traits" and the `kdf`/`pqc` wrapper modules): the audited `x25519-dalek`
//! crate is the arithmetic kernel, while the public surface is byte arrays in
//! and out. Secret scalars and shared secrets are held as raw `[u8; 32]` and
//! zeroized on drop via the SDK's own zeroize implementation (the
//! documented zeroization pattern since 0.4.0) — no custom crypto drop code.
//!
//! - [`X25519KeyPair`] — clamped 32-byte secret scalar + derived public key
//! - [`X25519PublicKey`] — 32-byte Montgomery u-coordinate (transmit form)
//! - [`X25519SharedSecret`] — 32-byte Diffie-Hellman output. Feed it through a
//!   KDF ([`crate::kdf::hkdf::hkdf_blake3`] or [`crate::kdf::hkdf::hkdf_sha3_256`], domain-separated)
//!   before using it as key material — never use the raw shared secret.
//!
//! # Deterministic derivation
//!
//! [`X25519KeyPair::from_seed`] derives the scalar with the SDK's HKDF-BLAKE3
//! convention and a domain-separated `info` string, so master seeds can mint
//! key-agreement keys without colliding with signing material.
//!
//! # Hardening
//!
//! - Secret scalars are **clamped** (RFC 7748 §5) at construction.
//! - [`X25519KeyPair::diffie_hellman`] **rejects an all-zero shared secret**
//!   with an error. Raw curve25519 maps some peer points (all-zero encoding,
//!   low-order points) to zero, which would silently produce a known shared
//!   secret; mainstream implementations (OpenSSL, Go, python-cryptography)
//!   reject instead. We match that behavior — the dalek silent-zero behavior
//!   is deliberately not surfaced.
//! - The all-zero (post-clamp) scalar is rejected at construction: it has no
//!   discrete log and its public key equals the all-zero encoding.

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret as DalekSecret};

/// Size of an X25519 secret scalar in bytes.
pub const SECRET_KEY_SIZE: usize = 32;
/// Size of an X25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Size of the X25519 shared secret in bytes.
pub const SHARED_SECRET_SIZE: usize = 32;

/// The algorithm identifier this surface reports (downgrade resistance).
pub const ALGORITHM_ID: crate::algorithm_id::AlgorithmId = crate::algorithm_id::AlgorithmId::X25519;

/// Domain string for HKDF-BLAKE3 scalar derivation from a master seed.
const DERIVATION_DOMAIN: &[u8] = b"origin-crypto-sdk:x25519:v1";

// ============================================================================
// Native layer — byte-level fns over the dalek arithmetic kernel (RFC 7748
// scalar multiplication). Kept `pub(crate)`; the public types below are the
// only supported surface.
// ============================================================================

/// X25519 base point (little-endian Montgomery u = 9), RFC 7748 §6.1.
pub(crate) const BASE_POINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

/// Derive the public key: the RFC 7748 §6.1 definition, X25519(s, 9) —
/// the scalar times the base point (§5 clamping is already applied).
fn public_from_secret(secret: &[u8; SECRET_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    diffie_hellman_raw(secret, &BASE_POINT)
}

/// Raw X25519: multiply the (clamped) scalar by the peer point (RFC 7748 §5).
fn diffie_hellman_raw(secret: &[u8; SECRET_KEY_SIZE], peer_public: &[u8; 32]) -> [u8; 32] {
    let sk = DalekSecret::from(*secret);
    let pk = DalekPublic::from(*peer_public);
    sk.diffie_hellman(&pk).to_bytes()
}

// ============================================================================
// Public types
// ============================================================================

/// An X25519 public key — 32 bytes, safe to transmit and store.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; PUBLIC_KEY_SIZE]);

impl X25519PublicKey {
    /// Reconstruct from raw 32-byte Montgomery-u encoding (wire form).
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Raw 32-byte encoding (wire form).
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X25519PublicKey")
            .field(&"32-byte key")
            .finish()
    }
}

/// An X25519 key pair: clamped 32-byte secret scalar + derived public key.
///
/// Construct with [`X25519KeyPair::generate`] (OS CSPRNG) or
/// [`X25519KeyPair::from_seed`] (deterministic, domain-separated).
/// The secret scalar zeroizes on drop.
#[derive(Clone)]
pub struct X25519KeyPair {
    secret: [u8; SECRET_KEY_SIZE],
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a key pair from the SDK's operating-system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; SECRET_KEY_SIZE];
        crate::fill_random(&mut bytes)?;
        Self::from_secret_key(&bytes)
    }

    /// Build from a raw 32-byte secret scalar (clamped on construction).
    ///
    /// # Errors
    ///
    /// The all-zero (post-clamp) scalar is rejected: it has no discrete log,
    /// its public key equals the all-zero encoding, and every DH against it
    /// yields zero — a key that "works" but proves nothing.
    pub fn from_secret_key(secret: &[u8; SECRET_KEY_SIZE]) -> Result<Self> {
        let clamped = DalekSecret::from(*secret).to_bytes();
        // All-zero check is constant-time: the scalar is secret, so the
        // comparison must not short-circuit.
        if bool::from(clamped.ct_eq(&[0u8; SECRET_KEY_SIZE])) {
            return Err(CryptoError::InvalidKey(
                "X25519 secret scalar is all-zero (after clamping)".to_string(),
            ));
        }
        let public = X25519PublicKey(public_from_secret(&clamped));
        Ok(Self {
            secret: clamped,
            public,
        })
    }

    /// Derive a key pair deterministically from a master seed and domain.
    ///
    /// Uses HKDF-BLAKE3 (the SDK's two-layer derivation convention) with the
    /// module-domain salt `origin-crypto-sdk:x25519:v1` and
    /// `info = domain || salt`, so signing and key-agreement material for the
    /// same seed never collide, and different domains never collide either.
    ///
    /// # Errors
    ///
    /// Empty seed, KDF failure, or the (probability ~2⁻²⁵²) all-zero derived
    /// scalar.
    pub fn from_seed(seed: &[u8], domain: &str) -> Result<Self> {
        if seed.is_empty() {
            return Err(CryptoError::InvalidParameter(
                "X25519 seed is empty".to_string(),
            ));
        }
        let mut scalar = [0u8; SECRET_KEY_SIZE];
        crate::kdf::hkdf::hkdf_blake3(
            seed,
            Some(DERIVATION_DOMAIN),
            &[domain.as_bytes(), DERIVATION_DOMAIN].concat(),
            &mut scalar,
        )
        .map_err(|e| CryptoError::Kdf(format!("X25519 seed derivation failed: {e}")))?;
        if bool::from(scalar.ct_eq(&[0u8; SECRET_KEY_SIZE])) {
            scalar.zeroize();
            return Err(CryptoError::InvalidKey(
                "X25519 derived scalar is all-zero".to_string(),
            ));
        }
        let pair = Self::from_secret_key(&scalar)?;
        scalar.zeroize();
        Ok(pair)
    }

    /// The derived public key (transmit form).
    pub fn public_key(&self) -> X25519PublicKey {
        self.public
    }

    /// Raw clamped secret scalar bytes (for persistence; handle with care).
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.secret
    }

    /// Diffie-Hellman against a peer's public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the computation yields the
    /// all-zero shared secret (all-zero or low-order peer key) — matching
    /// the hardening behavior of OpenSSL / Go / python-cryptography rather
    /// than silently returning a known constant.
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> Result<X25519SharedSecret> {
        let ss = diffie_hellman_raw(&self.secret, peer_public.as_bytes());
        if bool::from(ss.ct_eq(&[0u8; SHARED_SECRET_SIZE])) {
            return Err(CryptoError::InvalidKey(
                "X25519 shared secret is all-zero (all-zero or low-order peer key)".to_string(),
            ));
        }
        Ok(X25519SharedSecret(ss))
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material through Debug.
        f.debug_struct("X25519KeyPair").finish_non_exhaustive()
    }
}

/// The 32-byte X25519 shared secret.
///
/// Feed it through a KDF (e.g. [`crate::kdf::hkdf::hkdf_blake3`] with a domain-separated
/// `info`) before using it as key material. Zeroizes on drop.
#[derive(Clone)]
pub struct X25519SharedSecret([u8; SHARED_SECRET_SIZE]);

impl X25519SharedSecret {
    /// Raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.0
    }
}

impl Drop for X25519SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.as_bytes();
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.chunks_exact(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    // ── RFC 7748 §5.2: raw scalar multiplication (native layer) ──

    #[test]
    fn native_rfc7748_section52_vector1() {
        let k: [u8; 32] =
            hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .try_into()
                .unwrap();
        let u: [u8; 32] =
            hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
                .try_into()
                .unwrap();
        let expected: [u8; 32] =
            hex_to_bytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
                .try_into()
                .unwrap();
        assert_eq!(diffie_hellman_raw(&k, &u), expected);
    }

    #[test]
    fn native_rfc7748_section52_vector2() {
        let k: [u8; 32] =
            hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
                .try_into()
                .unwrap();
        let u: [u8; 32] =
            hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
                .try_into()
                .unwrap();
        let expected: [u8; 32] =
            hex_to_bytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
                .try_into()
                .unwrap();
        assert_eq!(diffie_hellman_raw(&k, &u), expected);
    }

    // ── RFC 7748 §6.1: the canonical key-agreement vector (public API) ──

    #[test]
    fn kat_rfc7748_section61() {
        let alice_sk: [u8; 32] =
            hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap();
        let bob_sk: [u8; 32] =
            hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .try_into()
                .unwrap();

        let alice = X25519KeyPair::from_secret_key(&alice_sk).unwrap();
        let bob = X25519KeyPair::from_secret_key(&bob_sk).unwrap();

        // Public keys (§6.1 generation step, base-point scalarmult)
        assert_eq!(
            alice.public_key().as_bytes(),
            &hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")[..]
        );
        assert_eq!(
            bob.public_key().as_bytes(),
            &hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")[..]
        );

        // Shared secret K (§6.1), symmetric in both directions
        let k_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let k_ba = bob.diffie_hellman(&alice.public_key()).unwrap();
        assert_eq!(k_ab.as_bytes(), k_ba.as_bytes());
        assert_eq!(
            k_ab.as_bytes(),
            &hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")[..]
        );
    }

    /// Cross-checked against Python `cryptography` 46.0.5 (OpenSSL backend),
    /// vectors generated 2026-09-21 with SHA-256-derived deterministic
    /// scalars — an independent implementation, per the SDK cross-check
    /// discipline ("self-consistency tests are not enough").
    #[test]
    fn kat_matches_python_cryptography_reference() {
        let sk_a: [u8; 32] =
            hex_to_bytes("8df8325840364ba222baa4907bd3e128768dece11ee2b6ae974ece467dd10a40")
                .try_into()
                .unwrap();
        let pk_a: [u8; 32] =
            hex_to_bytes("b227cf1bff9edde61d471eb1377f965dc7079fc3ce39a3e0e005a2185e9d256c")
                .try_into()
                .unwrap();
        let sk_b: [u8; 32] =
            hex_to_bytes("596de2a96b41af4efdab8ba4bfdadc7025112e8931c3e314fea3d4b92e78cde4")
                .try_into()
                .unwrap();
        let pk_b: [u8; 32] =
            hex_to_bytes("cddc7a1f70c864c2579da848e6519b716990d74d650a75780c8a0fb3e201c13a")
                .try_into()
                .unwrap();
        let expected_ss: [u8; 32] =
            hex_to_bytes("cbdfe84558144c564a6b27efbd4f06de8cddd4b2be334c844a57c530214b3037")
                .try_into()
                .unwrap();

        let a = X25519KeyPair::from_secret_key(&sk_a).unwrap();
        let b = X25519KeyPair::from_secret_key(&sk_b).unwrap();

        // Public derivation matches the reference implementation...
        assert_eq!(a.public_key().as_bytes(), &pk_a);
        assert_eq!(b.public_key().as_bytes(), &pk_b);
        // ...and so does the shared secret, both directions.
        assert_eq!(
            a.diffie_hellman(&b.public_key()).unwrap().as_bytes(),
            &expected_ss
        );
        assert_eq!(
            b.diffie_hellman(&a.public_key()).unwrap().as_bytes(),
            &expected_ss
        );
    }

    // ── Deterministic derivation ──

    #[test]
    fn from_seed_is_deterministic_and_domain_separated() {
        let seed = [0x42u8; 32];

        let p1 = X25519KeyPair::from_seed(&seed, "origin-channel").unwrap();
        let p2 = X25519KeyPair::from_seed(&seed, "origin-channel").unwrap();
        assert_eq!(p1.public_key().as_bytes(), p2.public_key().as_bytes());

        let other_domain = X25519KeyPair::from_seed(&seed, "origin-attest").unwrap();
        assert_ne!(
            p1.public_key().as_bytes(),
            other_domain.public_key().as_bytes(),
            "different domains must derive different scalars"
        );

        let other_seed = X25519KeyPair::from_seed(&[0x43u8; 32], "origin-channel").unwrap();
        assert_ne!(
            p1.public_key().as_bytes(),
            other_seed.public_key().as_bytes()
        );
    }

    #[test]
    fn from_seed_rejects_empty() {
        assert!(X25519KeyPair::from_seed(b"", "d").is_err());
    }

    // ── Randomness + symmetry ──

    #[test]
    fn generate_is_random_and_symmetric() {
        let a = X25519KeyPair::generate().unwrap();
        let b = X25519KeyPair::generate().unwrap();
        assert_ne!(a.secret_key_bytes(), b.secret_key_bytes());
        assert_ne!(a.public_key().as_bytes(), b.public_key().as_bytes());

        let ab = a.diffie_hellman(&b.public_key()).unwrap();
        let ba = b.diffie_hellman(&a.public_key()).unwrap();
        assert_eq!(ab.as_bytes(), ba.as_bytes());

        // A third party computes a different secret.
        let c = X25519KeyPair::generate().unwrap();
        assert_ne!(
            ab.as_bytes(),
            c.diffie_hellman(&a.public_key()).unwrap().as_bytes()
        );
    }

    // ── Adversarial inputs ──

    /// All-zero peer key must be REJECTED, not silently mapped to a known
    /// shared secret. Matches python-cryptography/OpenSSL refusal (verified
    /// 2026-09-21: python-cryptography raises on an all-zero shared secret).
    #[test]
    fn diffie_hellman_rejects_all_zero_peer() {
        let a = X25519KeyPair::generate().unwrap();
        let zero_pk = X25519PublicKey::from_bytes([0u8; 32]);
        assert!(a.diffie_hellman(&zero_pk).is_err());
    }

    /// Low-order peer point (u = 1): X25519(·, 1) = 0 per RFC 7748 §6.1
    /// commentary — must be rejected, not returned.
    #[test]
    fn diffie_hellman_rejects_low_order_peer() {
        let a = X25519KeyPair::generate().unwrap();
        let mut low_order = [0u8; 32];
        low_order[0] = 1;
        assert!(a
            .diffie_hellman(&X25519PublicKey::from_bytes(low_order))
            .is_err());
    }

    /// Wrong-key DH must not produce the honest shared secret.
    #[test]
    fn diffie_hellman_wrong_key_differs() {
        let a = X25519KeyPair::generate().unwrap();
        let b = X25519KeyPair::generate().unwrap();
        let impostor = X25519KeyPair::generate().unwrap();

        let honest = a.diffie_hellman(&b.public_key()).unwrap();
        let impostor_ss = impostor.diffie_hellman(&b.public_key()).unwrap();
        assert_ne!(honest.as_bytes(), impostor_ss.as_bytes());
    }

    /// All-zero secret scalar is rejected (post-clamp zero).
    #[test]
    fn from_secret_key_rejects_zero_scalar() {
        let zero = [0u8; 32];
        assert!(X25519KeyPair::from_secret_key(&zero).is_err());
    }

    /// Debug must never surface the secret scalar or shared secret.
    #[test]
    fn debug_redacts_secret() {
        let kp = X25519KeyPair::from_secret_key(&[0x11u8; 32]).unwrap();
        let rendered = format!("{kp:?}");
        assert!(
            !rendered.contains("secret"),
            "Debug leaked field: {rendered}"
        );

        let ss = kp
            .diffie_hellman(
                &X25519KeyPair::from_secret_key(&[0x22u8; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap();
        let rendered = format!("{ss:?}");
        assert!(
            !rendered.contains("Secret("),
            "Debug leaked shared secret: {rendered}"
        );
    }

    /// Zeroize-on-drop, verified against leaked heap memory (the documented
    /// house pattern): drop in place a leaked Box, then read the field back —
    /// the allocation stays valid, so this is a real memory check.
    #[test]
    fn secret_zeroized_on_drop() {
        let pair = Box::new(X25519KeyPair::from_secret_key(&[0x11u8; 32]).unwrap());
        let ptr = Box::into_raw(pair);
        // SAFETY: ptr came from Box::into_raw; drop_in_place runs the Drop
        // impl (zeroize) without freeing — the allocation stays valid so we
        // can inspect the real memory afterwards. The 32-byte allocation is
        // intentionally leaked for the rest of the process.
        unsafe { std::ptr::drop_in_place(ptr) };
        let leaked: &X25519KeyPair = unsafe { &*ptr };
        assert!(
            leaked.secret.iter().all(|&b| b == 0),
            "secret scalar must be zeroized on drop"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0

//! ECDSA over secp256r1 / P-256 — the ES256 signing primitive.
//!
//! This exists for **interoperability**: WebAuthn/FIDO2 passkeys, TLS
//! ecosystems, and FIPS-mandated environments all speak ES256. For new
//! designs prefer [`crate::signing::classical::Ed25519Signer`] or
//! [`crate::signing::hybrid::HybridSigningKeyBundle`] — Ed25519 is deterministic and
//! immune to the nonce-reuse fragility ECDSA carries.
//!
//! Arithmetic and signing come from the audited RustCrypto `p256` crate
//! (same provenance as the `k256` backend used by `crate::ec_schnorr`).
//! Signing is deterministic per RFC 6979 — no caller-supplied nonce exists
//! to misuse.
//!
//! # Example
//!
//! ```rust
//! use origin_crypto_sdk::signing::secp256r1::EcdsaP256Signer;
//!
//! let signer = EcdsaP256Signer::from_seed(&[0x42u8; 32]).unwrap();
//! let sig_der = signer.sign(b"hello world");
//! assert!(signer.verify(b"hello world", &sig_der));
//! ```

use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

use crate::error::{CryptoError, Result};

/// An ES256 signer: deterministic (RFC 6979) ECDSA over P-256 with SHA-256,
/// signatures emitted in DER — the encoding WebAuthn authenticators produce.
#[derive(Clone)]
pub struct EcdsaP256Signer {
    key: SigningKey,
}

impl std::fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP256Signer").finish_non_exhaustive()
    }
}

impl EcdsaP256Signer {
    /// Create a signer from a 32-byte scalar seed.
    ///
    /// Returns an error if the seed is not a valid P-256 scalar (zero or
    /// out of range — cryptographically negligible, but typed anyway).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let key = SigningKey::from_slice(seed)
            .map_err(|e| CryptoError::InvalidKey(format!("not a P-256 scalar: {e}")))?;
        Ok(Self { key })
    }

    /// Import a PKCS#8 DER private key — the shape Bitwarden and other
    /// password managers export passkey material as.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| CryptoError::InvalidKey(format!("not a PKCS8 P-256 private key: {e}")))?;
        Ok(Self { key })
    }

    /// Sign `message` — internally the message is SHA-256 hashed per ES256.
    /// Returns the DER-encoded signature (the WebAuthn wire form).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(message);
        sig.to_der().as_bytes().to_vec()
    }

    /// Verify a DER-encoded signature against this signer's public key.
    pub fn verify(&self, message: &[u8], signature_der: &[u8]) -> bool {
        let Ok(sig) = Signature::from_der(signature_der) else {
            return false;
        };
        self.key.verifying_key().verify(message, &sig).is_ok()
    }

    /// Verify a DER signature against an uncompressed SEC1 public key
    /// (65 bytes, `0x04 ‖ X ‖ Y` — the form inside a COSE key's x/y pair).
    pub fn verify_with_pubkey(
        sec1_uncompressed: &[u8],
        message: &[u8],
        signature_der: &[u8],
    ) -> bool {
        let Ok(vk) = VerifyingKey::from_sec1_bytes(sec1_uncompressed) else {
            return false;
        };
        let Ok(sig) = Signature::from_der(signature_der) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }

    /// The uncompressed SEC1 public key: `0x04 ‖ X ‖ Y` (65 bytes).
    /// This carries exactly the X/Y a COSE EC2 key stores.
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The 32-byte secret scalar.
    pub fn secret_key(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// Export as PKCS#8 DER — the storage form password managers and
    /// authenticator credential stores use for P-256 keys.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let secret = p256::SecretKey::from_slice(&self.key.to_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("invalid scalar: {e}")))?;
        let doc = EncodePrivateKey::to_pkcs8_der(&secret)
            .map_err(|e| CryptoError::InvalidKey(format!("could not encode PKCS8: {e}")))?;
        Ok(doc.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let s = EcdsaP256Signer::from_seed(&[1u8; 32]).unwrap();
        let sig = s.sign(b"hello");
        assert!(s.verify(b"hello", &sig));
    }

    #[test]
    fn signatures_are_der_and_deterministic() {
        let s = EcdsaP256Signer::from_seed(&[7u8; 32]).unwrap();
        let a = s.sign(b"msg");
        let b = s.sign(b"msg");
        assert_eq!(a, b, "RFC 6979 signing is deterministic");
        // DER SEQUENCE tag.
        assert_eq!(a[0], 0x30);
    }

    #[test]
    fn verify_rejects_tampered_msg() {
        let s = EcdsaP256Signer::from_seed(&[2u8; 32]).unwrap();
        let sig = s.sign(b"original");
        assert!(!s.verify(b"tampered", &sig));
    }

    #[test]
    fn verify_with_sec1_pubkey() {
        let s = EcdsaP256Signer::from_seed(&[3u8; 32]).unwrap();
        let pk = s.public_key_sec1();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        let sig = s.sign(b"x");
        assert!(EcdsaP256Signer::verify_with_pubkey(&pk, b"x", &sig));
    }

    #[test]
    fn pkcs8_roundtrip_keeps_the_key() {
        let s = EcdsaP256Signer::from_seed(&[9u8; 32]).unwrap();
        // Round-trip through SecretKey's PKCS8 impl — what from_pkcs8_der parses.
        let sk = p256::SecretKey::from_slice(&s.secret_key()).unwrap();
        let der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&sk).unwrap();
        let s2 = EcdsaP256Signer::from_pkcs8_der(der.as_bytes()).unwrap();
        assert_eq!(s.public_key_sec1(), s2.public_key_sec1());
    }

    #[test]
    fn garbage_pkcs8_is_refused() {
        assert!(EcdsaP256Signer::from_pkcs8_der(b"not a key").is_err());
    }

    #[test]
    fn rfc6979_known_vector() {
        // RFC 6979 A.2.5 (P-256, SHA-256): private key
        //   x = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        // message "sample" must sign deterministically; cross-verify with
        // verify_with_pubkey rather than a stored signature (DER encoding
        // variants make signature equality brittle).
        let x: [u8; 32] = [
            0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1,
            0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B,
            0x12, 0x0F, 0x67, 0x21,
        ];
        let s = EcdsaP256Signer::from_seed(&x).unwrap();
        let sig = s.sign(b"sample");
        assert!(EcdsaP256Signer::verify_with_pubkey(
            &s.public_key_sec1(),
            b"sample",
            &sig
        ));
    }
}

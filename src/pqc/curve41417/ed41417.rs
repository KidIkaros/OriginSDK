// SPDX-License-Identifier: OPL-1.1

use rand::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::Zeroize;

use super::{EdwardsPoint, Scalar, BYTES_SIZE, SCALAR_SIZE};

/// Size in bytes of an Ed41417 signature.
pub const SIGNATURE_SIZE: usize = BYTES_SIZE + SCALAR_SIZE;

const DOM_NONCE: &[u8] = b"DGP-ED41417-NONCE-V1";
const DOM_CHALLENGE: &[u8] = b"DGP-ED41417-CHALLENGE-V1";

/// Ed41417 signing key.
#[derive(Clone)]
pub struct SigningKey {
    scalar: Scalar,
    verifying_key: VerifyingKey,
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SigningKey {
    /// Construct a signing key from a scalar, deriving the corresponding verifying key.
    pub fn from_scalar(scalar: Scalar) -> Self {
        let verifying_key =
            VerifyingKey::from_point(&EdwardsPoint::basepoint().scalar_mul(&scalar.to_bytes()));
        Self {
            scalar,
            verifying_key,
        }
    }

    /// Construct a signing key from bytes reduced modulo the curve order.
    pub fn from_bytes_mod_order(bytes: [u8; SCALAR_SIZE]) -> Self {
        Self::from_scalar(Scalar::from_bytes_mod_order(&bytes))
    }

    /// Generate a random signing key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_scalar(Scalar::random(rng))
    }

    /// Return the verifying key corresponding to this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// Return the bytes of the signing key (scalar).
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.scalar.to_bytes()
    }

    /// Sign `message` and return an Ed41417 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let a_bytes = self.scalar.to_bytes();

        let r = hash_to_scalar(DOM_NONCE, &[&a_bytes, message]);
        let r_bytes = r.to_bytes();

        let r_point = EdwardsPoint::basepoint().scalar_mul(&r_bytes);
        let r_enc = r_point.to_bytes();

        let k = hash_to_scalar(
            DOM_CHALLENGE,
            &[&r_enc, self.verifying_key.as_bytes(), message],
        );

        let s = &r + &(&k * &self.scalar);
        let s_bytes = s.to_bytes();

        Signature {
            r_enc,
            s_enc: s_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Ed41417 verifying key.
pub struct VerifyingKey {
    bytes: [u8; BYTES_SIZE],
}

impl VerifyingKey {
    /// Parse a verifying key from compressed Edwards point bytes.
    pub fn from_bytes(bytes: [u8; BYTES_SIZE]) -> Result<Self> {
        EdwardsPoint::from_bytes(&bytes)
            .ok_or_else(|| CryptoError::InvalidKey("invalid Ed41417 public key".to_string()))?;

        Ok(Self { bytes })
    }

    /// Get the verifying key bytes.
    pub fn as_bytes(&self) -> &[u8; BYTES_SIZE] {
        &self.bytes
    }

    /// Create a verifying key from an Edwards point.
    fn from_point(point: &EdwardsPoint) -> Self {
        Self {
            bytes: point.to_bytes(),
        }
    }

    /// Verify a signature on a message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let r_point =
            EdwardsPoint::from_bytes(&signature.r_enc).ok_or(CryptoError::AuthenticationFailed)?;
        Scalar::from_canonical_bytes(&signature.s_enc).ok_or(CryptoError::AuthenticationFailed)?;

        let a_point = EdwardsPoint::from_bytes(&self.bytes)
            .ok_or_else(|| CryptoError::InvalidKey("invalid Ed41417 public key".to_string()))?;

        let k = hash_to_scalar(DOM_CHALLENGE, &[&signature.r_enc, &self.bytes, message]);
        let k_bytes = k.to_bytes();

        let sb = EdwardsPoint::basepoint().scalar_mul(&signature.s_enc);
        let ka = a_point.scalar_mul(&k_bytes);
        let rhs = r_point.add(&ka);

        if sb == rhs {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Ed41417 signature.
pub struct Signature {
    r_enc: [u8; BYTES_SIZE],
    s_enc: [u8; SCALAR_SIZE],
}

impl Signature {
    /// Serialize this signature to bytes.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..BYTES_SIZE].copy_from_slice(&self.r_enc);
        out[BYTES_SIZE..].copy_from_slice(&self.s_enc);
        out
    }

    /// Deserialize a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidParameter(
                "Invalid signature length".to_string(),
            ));
        }

        let mut r_enc = [0u8; BYTES_SIZE];
        r_enc.copy_from_slice(&bytes[..BYTES_SIZE]);

        let mut s_enc = [0u8; SCALAR_SIZE];
        s_enc.copy_from_slice(&bytes[BYTES_SIZE..]);

        Ok(Self { r_enc, s_enc })
    }
}

fn hash_to_scalar(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    use crate::internal::sha3::Sha3_512;
    let mut hasher = Sha3_512::new();
    hasher.update(domain);
    for p in parts {
        hasher.update(p);
    }
    let hash: [u8; 64] = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash).expect("sha3-512 output is 64 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes_mod_order([42u8; SCALAR_SIZE]);
        let pk = sk.verifying_key();
        let msg = b"hello";
        let sig = sk.sign(msg);
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = SigningKey::from_bytes_mod_order([7u8; SCALAR_SIZE]);
        let pk = sk.verifying_key();
        let msg = b"message";
        let sig = sk.sign(msg);
        assert!(pk.verify(b"other", &sig).is_err());
    }

    #[test]
    fn verify_rejects_non_canonical_s() {
        let sk = SigningKey::from_bytes_mod_order([9u8; SCALAR_SIZE]);
        let pk = sk.verifying_key();
        let msg = b"test";
        let sig = sk.sign(msg);

        let mut bytes = sig.to_bytes();
        bytes[BYTES_SIZE..].copy_from_slice(&super::super::EDWARDS_L_BYTES);

        let sig2 = Signature::from_bytes(&bytes).unwrap();
        assert!(pk.verify(msg, &sig2).is_err());
    }

    #[test]
    fn verify_rejects_invalid_r_encoding() {
        let sk = SigningKey::from_bytes_mod_order([11u8; SCALAR_SIZE]);
        let pk = sk.verifying_key();
        let msg = b"test";
        let sig = sk.sign(msg);

        let mut bytes = sig.to_bytes();
        bytes[51] |= 0x40;

        let sig2 = Signature::from_bytes(&bytes).unwrap();
        assert!(pk.verify(msg, &sig2).is_err());
    }
}

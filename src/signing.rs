// SPDX-License-Identifier: OPL-1.1

//! Hybrid signing keys derived from seed + domain.
//!
//! Provides an OOP interface over the functional `HybridSignature` API.
//! Keys are derived deterministically from a seed handle and domain string
//! using HKDF-SHA3-256.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::pqc::falcon1024;
use crate::seed::{derive_signing_keys, derive_verifying_keys, SeedHandle};
use crate::signature::HybridSignature;

/// A hybrid signing key (Ed25519 + Falcon-1024) derived from seed + domain.
///
/// Derives deterministically: same seed + domain = same key every time.
pub struct HybridSigningKey {
    ed25519_sk: Vec<u8>,
    falcon_sk: Vec<u8>,
    domain: String,
}

impl HybridSigningKey {
    /// Derive a hybrid signing key from a seed handle and domain.
    ///
    /// The key is derived as: HKDF-SHA3-256(salt="signing", ikm=seed, info=domain)
    /// Output is split: first 32 bytes = Ed25519 SK, rest = Falcon-1024 SK.
    pub fn from_handle(handle: &SeedHandle, domain: &str) -> Result<Self, String> {
        let seed = handle.as_bytes().ok_or("Seed handle expired")?;
        let (ed25519_sk, falcon_sk) = derive_signing_keys(seed, domain)?;

        Ok(Self {
            ed25519_sk,
            falcon_sk,
            domain: domain.to_string(),
        })
    }

    /// Sign a message using hybrid (Ed25519 + Falcon-1024) signatures.
    pub fn sign(&self, message: &[u8]) -> Result<HybridSignatureOutput, String> {
        // Ed25519 sign using dalek
        let ed_secret = ed25519_dalek::SigningKey::from_bytes(
            self.ed25519_sk[..32].try_into()
                .map_err(|_| "Invalid Ed25519 secret key length")?
        );
        use ed25519_dalek::Signer;
        let ed_signature = ed_secret.sign(message);
        let ed_sig = ed_signature.to_bytes().to_vec();

        // Falcon sign -- extract SK from packed [SK|PK] bytes
        const FALCON_SK_SIZE: usize = 2305;
        let falcon_sk_bytes = if self.falcon_sk.len() > FALCON_SK_SIZE {
            &self.falcon_sk[..FALCON_SK_SIZE]
        } else {
            &self.falcon_sk
        };
        let falcon_sk = crate::pqc::falcon1024::FalconPrivateKey::from_bytes(falcon_sk_bytes)
            .map_err(|e| format!("Invalid Falcon key: {}", e))?;
        let falcon_sig = crate::pqc::falcon1024::sign(message, &falcon_sk)
            .map_err(|e| format!("Falcon sign failed: {}", e))?;

        Ok(HybridSignatureOutput {
            ed25519_signature: ed_sig,
            falcon_signature: falcon_sig.as_bytes().to_vec(),
        })
    }

    /// Get the public verifying key for this signing key.
    pub fn public_key(&self) -> Result<HybridVerifyingKey, String> {
        let (ed25519_pk, falcon_pk) =
            derive_verifying_keys(&self.ed25519_sk, &self.falcon_sk)?;

        Ok(HybridVerifyingKey {
            ed25519_pk,
            falcon_pk,
            domain: self.domain.clone(),
        })
    }

    /// Get the domain this key was derived for.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        self.ed25519_sk.zeroize();
        self.falcon_sk.zeroize();
    }
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigningKey")
            .field("domain", &self.domain)
            .field("ed25519_sk_len", &self.ed25519_sk.len())
            .field("falcon_sk_len", &self.falcon_sk.len())
            .finish()
    }
}

/// A hybrid verifying (public) key.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed25519_pk: Vec<u8>,
    falcon_pk: Vec<u8>,
    domain: String,
}

impl HybridVerifyingKey {
    /// Verify a hybrid signature against a message.
    ///
    /// Both Ed25519 and Falcon-1024 signatures must be valid.
    pub fn verify(&self, message: &[u8], signature: &HybridSignatureOutput) -> bool {
        // Ed25519 verify using dalek
        let ed_pk_bytes: [u8; 32] = match self.ed25519_pk[..32].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ed_public = match ed25519_dalek::VerifyingKey::from_bytes(&ed_pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let ed_sig_bytes: [u8; 64] = match signature.ed25519_signature[..64].try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ed_signature = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        use ed25519_dalek::Verifier;
        if ed_public.verify(message, &ed_signature).is_err() {
            return false;
        }

        // Falcon verify
        let falcon_pk = match falcon1024::FalconPublicKey::from_bytes(&self.falcon_pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let falcon_sig = match falcon1024::FalconSignature::from_bytes(&signature.falcon_signature)
        {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        falcon1024::verify(message, &falcon_sig, &falcon_pk).is_ok()
    }

    /// Constant-time comparison of verifying keys.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.ed25519_pk.ct_eq(&other.ed25519_pk).into()
            && self.falcon_pk.ct_eq(&other.falcon_pk).into()
    }

    /// Get the domain this key was derived for.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Get Ed25519 public key bytes.
    pub fn ed25519_pk(&self) -> &[u8] {
        &self.ed25519_pk
    }

    /// Get Falcon-1024 public key bytes.
    pub fn falcon_pk(&self) -> &[u8] {
        &self.falcon_pk
    }

    /// Compute a commitment hash (SHA3-256 of concatenated public keys).
    pub fn commitment(&self) -> [u8; 32] {
        use crate::primitives::sha3::sha3_256;
        let mut combined = self.ed25519_pk.clone();
        combined.extend_from_slice(&self.falcon_pk);
        sha3_256(&combined)
    }
}

impl std::fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridVerifyingKey")
            .field("domain", &self.domain)
            .field("ed25519_pk_len", &self.ed25519_pk.len())
            .field("falcon_pk_len", &self.falcon_pk.len())
            .finish()
    }
}

/// Output of a hybrid signature operation.
#[derive(Clone, Debug)]
pub struct HybridSignatureOutput {
    ed25519_signature: Vec<u8>,
    falcon_signature: Vec<u8>,
}

impl HybridSignatureOutput {
    /// Serialize to bytes (ed25519_sig_len + ed25519_sig + falcon_sig).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.ed25519_signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ed25519_signature);
        out.extend_from_slice(&self.falcon_signature);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Signature too short".to_string());
        }
        let ed_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + ed_len {
            return Err("Truncated signature".to_string());
        }
        let ed25519_signature = bytes[4..4 + ed_len].to_vec();
        let falcon_signature = bytes[4 + ed_len..].to_vec();
        Ok(Self {
            ed25519_signature,
            falcon_signature,
        })
    }

    pub fn ed25519_signature(&self) -> &[u8] {
        &self.ed25519_signature
    }

    pub fn falcon_signature(&self) -> &[u8] {
        &self.falcon_signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::SeedHandle;

    #[test]
    fn test_signing_key_derivation() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, None);

        let key1 = HybridSigningKey::from_handle(&handle, "domain1").unwrap();
        let key2 = HybridSigningKey::from_handle(&handle, "domain1").unwrap();
        let key3 = HybridSigningKey::from_handle(&handle, "domain2").unwrap();

        // Same seed + domain = same key
        let pk1 = key1.public_key().unwrap();
        let pk2 = key2.public_key().unwrap();
        assert!(pk1.ct_eq(&pk2), "Same seed+domain should give same key");

        // Different domain = different key
        let pk3 = key3.public_key().unwrap();
        assert!(!pk1.ct_eq(&pk3), "Different domain should give different key");
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let handle = SeedHandle::new(&seed, None);
        let signing_key = HybridSigningKey::from_handle(&handle, "test").unwrap();
        let verifying_key = signing_key.public_key().unwrap();

        let message = b"test message";
        let signature = signing_key.sign(message).unwrap();

        assert!(verifying_key.verify(message, &signature));
    }

    #[test]
    fn test_signature_serialization() {
        let sig = HybridSignatureOutput {
            ed25519_signature: vec![1, 2, 3, 4],
            falcon_signature: vec![5, 6, 7, 8, 9],
        };
        let bytes = sig.to_bytes();
        let restored = HybridSignatureOutput::from_bytes(&bytes).unwrap();
        assert_eq!(restored.ed25519_signature, sig.ed25519_signature);
        assert_eq!(restored.falcon_signature, sig.falcon_signature);
    }
}

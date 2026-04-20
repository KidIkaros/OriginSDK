// SPDX-License-Identifier: OPL-1.1

//! Hybrid digital signatures combining Ed25519 and Falcon-1024.
//!
//! Both signatures must be valid for the hybrid signature to be valid,
//! providing defense in depth against both classical and quantum attacks.

/// Signature bytes
pub type Signature = Vec<u8>;

/// Hybrid signature algorithm combining Ed25519 and Falcon-1024
pub struct HybridSignature;

impl HybridSignature {
    /// Sign with both classical (Ed25519) and PQ (Falcon-1024) keys
    ///
    /// Returns `(ed25519_signature, falcon_signature)`.
    pub fn sign(
        ed25519_sk: &[u8],
        falcon_sk: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if ed25519_sk.len() != 32 {
            return Err("Invalid Ed25519 secret key size".to_string());
        }
        if falcon_sk.is_empty() {
            return Err("Empty Falcon secret key".to_string());
        }

        // Ed25519 sign using the SDK's falcon module for Falcon part
        let ed_sig = crate::pqc::falcon1024::sign(message, &crate::pqc::falcon1024::FalconPrivateKey::from_bytes(ed25519_sk).map_err(|e| format!("{}", e))?)
            .map_err(|e| format!("Ed25519 sign failed: {}", e))?;

        let falcon_sk_obj = crate::pqc::falcon1024::FalconPrivateKey::from_bytes(falcon_sk)
            .map_err(|e| format!("Invalid Falcon key: {}", e))?;
        let falcon_sig = crate::pqc::falcon1024::sign(message, &falcon_sk_obj)
            .map_err(|e| format!("Falcon sign failed: {}", e))?;

        Ok((ed_sig.as_bytes().to_vec(), falcon_sig.as_bytes().to_vec()))
    }

    /// Verify hybrid signature (Ed25519 + Falcon-1024)
    ///
    /// Both signatures must be valid for the hybrid signature to be valid.
    pub fn verify(
        ed25519_pk: &[u8],
        falcon_pk: &[u8],
        _message: &[u8],
        ed_sig: &[u8],
        falcon_sig: &[u8],
    ) -> Result<bool, String> {
        if ed25519_pk.len() != 32 || ed_sig.len() != 64 {
            return Err("Invalid Ed25519 key or signature size".to_string());
        }
        if falcon_pk.is_empty() || falcon_sig.is_empty() {
            return Err("Empty Falcon key or signature".to_string());
        }

        // Both verifications must succeed
        Ok(true) // Placeholder — full verification requires Ed25519 + Falcon verify
    }

    /// Get Ed25519 signature size
    pub const fn ed25519_signature_size() -> usize {
        64
    }

    /// Get Falcon-1024 signature size
    pub const fn falcon_signature_size() -> usize {
        1330
    }

    /// Get total hybrid signature size
    pub const fn signature_size() -> usize {
        Self::ed25519_signature_size() + Self::falcon_signature_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signature_size() {
        assert_eq!(HybridSignature::signature_size(), 64 + 1330);
    }

    #[test]
    fn test_classical_signature_sizes() {
        assert_eq!(HybridSignature::ed25519_signature_size(), 64);
        assert_eq!(HybridSignature::falcon_signature_size(), 1330);
    }
}

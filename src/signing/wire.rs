// SPDX-License-Identifier: Apache-2.0

//! Hybrid-signature wire format — Ed25519 + Falcon-1024, both must verify.
//!
//! Encoding: `[u32 BE falcon_len][falcon sig][64-byte ed25519 sig]`.
//!
//! This is the canonical on-the-wire / on-disk byte format for the hybrid
//! signatures produced by [`crate::signing::hybrid::HybridSigningKeyBundle`].
//! It lives in the SDK (the sole crypto provider) so downstream crates can
//! serialize, transmit, and verify signatures without depending on a
//! transport/peer crate for a bytes format.

use crate::error::{CryptoError, Result};
use crate::pqc::falcon1024::{FalconPublicKey, FalconSignature};
use crate::signing::hybrid::Ed25519Falcon1024;

/// A serialized Ed25519 + Falcon-1024 hybrid signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSig {
    /// The Ed25519 signature (64 bytes).
    pub ed25519: [u8; 64],
    /// The Falcon-1024 signature (variable, ≤ 1577 bytes).
    pub falcon: Vec<u8>,
}

impl HybridSig {
    /// Serialize a hybrid signature produced by the SDK.
    pub fn from_sig(sig: &Ed25519Falcon1024) -> Self {
        Self {
            ed25519: sig.ed25519_sig.to_bytes(),
            falcon: sig.falcon_sig.as_bytes().to_vec(),
        }
    }

    /// Append the encoded form to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.falcon.len() > FalconSignature::max_size() {
            return Err(CryptoError::Serialization(format!(
                "falcon signature too large: {} bytes (max {})",
                self.falcon.len(),
                FalconSignature::max_size()
            )));
        }
        let len = u32::try_from(self.falcon.len())
            .map_err(|_| CryptoError::Serialization("falcon length overflow".into()))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.falcon);
        out.extend_from_slice(&self.ed25519);
        Ok(())
    }

    /// Decode from `buf` at `pos`, advancing `pos`.
    pub fn decode(buf: &[u8], pos: &mut usize) -> Result<Self> {
        let len = read_u32(buf, pos)?;
        if len as usize > FalconSignature::max_size() {
            return Err(CryptoError::Serialization(format!(
                "falcon signature too large: {len} bytes (max {})",
                FalconSignature::max_size()
            )));
        }
        let falcon = take(buf, pos, len as usize)?.to_vec();
        let ed_bytes = take(buf, pos, 64)?;
        let ed25519: [u8; 64] = ed_bytes
            .try_into()
            .map_err(|_| CryptoError::Serialization("bad ed25519 signature".into()))?;
        Ok(Self { ed25519, falcon })
    }

    /// Verify this signature against the signer's public keys.
    pub fn verify(
        &self,
        ed25519_pk: &[u8; 32],
        falcon1024_pk: &[u8],
        message: &[u8],
    ) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pk)
            .map_err(|e| CryptoError::InvalidKey(format!("bad ed25519 pk: {e}")))?;
        let fpk = FalconPublicKey::from_bytes(falcon1024_pk)
            .map_err(|e| CryptoError::InvalidKey(format!("bad falcon pk: {e}")))?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&self.ed25519);
        let f_sig = FalconSignature::from_bytes(&self.falcon)
            .map_err(|e| CryptoError::Serialization(format!("bad falcon sig: {e}")))?;
        let hybrid = Ed25519Falcon1024 {
            ed25519_sig: ed_sig,
            falcon_sig: f_sig,
        };
        Ed25519Falcon1024::verify(&vk, &fpk, message, &hybrid)?;
        Ok(())
    }
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    let raw = take(buf, pos, 4)?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn take<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| CryptoError::Serialization("offset overflow".into()))?;
    if end > buf.len() {
        return Err(CryptoError::Serialization("truncated payload".into()));
    }
    let out = &buf[*pos..end];
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let sig = HybridSig {
            ed25519: [0xAB; 64],
            falcon: vec![0xCD; 1200],
        };
        let mut out = Vec::new();
        sig.encode(&mut out).unwrap();
        let mut pos = 0;
        let back = HybridSig::decode(&out, &mut pos).unwrap();
        assert_eq!(back, sig);
        assert_eq!(pos, out.len());
    }

    #[test]
    fn oversized_falcon_rejected() {
        let mut out = Vec::new();
        let sig = HybridSig {
            ed25519: [0u8; 64],
            falcon: vec![0u8; FalconSignature::max_size() + 1],
        };
        assert!(sig.encode(&mut out).is_err());
    }

    #[test]
    fn truncated_decode_rejected() {
        let sig = HybridSig {
            ed25519: [0u8; 64],
            falcon: vec![0u8; 32],
        };
        let mut out = Vec::new();
        sig.encode(&mut out).unwrap();
        let mut pos = 0;
        // Drop the ed25519 tail.
        assert!(HybridSig::decode(&out[..out.len() - 10], &mut pos).is_err());
    }

    #[test]
    fn sign_encode_verify_roundtrip() {
        let master_seed = [0x42u8; 32];
        let bundle =
            crate::signing::hybrid::HybridSigningKeyBundle::from_seed(&master_seed, "wire")
                .expect("valid seed");
        let msg = b"sign this";
        let sig = bundle.sign_hybrid(msg);
        let wire = HybridSig::from_sig(&sig);
        let mut out = Vec::new();
        wire.encode(&mut out).unwrap();
        let mut pos = 0;
        let back = HybridSig::decode(&out, &mut pos).unwrap();
        assert_eq!(back, wire);
        back.verify(
            &bundle.ed25519_pk().to_bytes(),
            bundle.falcon1024_pk().as_bytes(),
            msg,
        )
        .unwrap();
        // Wrong message must fail.
        assert!(back
            .verify(
                &bundle.ed25519_pk().to_bytes(),
                bundle.falcon1024_pk().as_bytes(),
                b"tampered"
            )
            .is_err());
    }
}

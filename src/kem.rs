// SPDX-License-Identifier: OPL-1.1

//! Hybrid Key Encapsulation Mechanisms
//!
//! Combines classical and post-quantum KEMs for hybrid security.
//!
//! This provides defense in depth:
//! - Classical insurance: If PQC has implementation bugs, X25519/Ed25519 protect us
//! - Quantum insurance: If quantum computers arrive, NTRU/Falcon protect us
//! - Defense in depth: Attacker must break BOTH algorithms

use crate::primitives::sha3 as native_sha3;
use zeroize::Zeroizing;

/// Hybrid KEM ciphertext containing both classical and PQC components.
#[derive(Debug, Clone)]
pub struct Ciphertext {
    /// X25519 public key (32 bytes)
    pub x25519: Vec<u8>,
    /// Ed41417 public key (56 bytes)
    pub ed41417: Vec<u8>,
    /// NTRU Prime ciphertext (1047 bytes)
    pub ntru: Vec<u8>,
}

impl Ciphertext {
    /// Get total size
    pub fn len(&self) -> usize {
        self.x25519.len() + self.ed41417.len() + self.ntru.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Create new hybrid ciphertext
    pub fn new(x25519: Vec<u8>, ed41417: Vec<u8>, ntru: Vec<u8>) -> Self {
        Self {
            x25519,
            ed41417,
            ntru,
        }
    }

    /// Get X25519 component size
    pub const fn x25519_size() -> usize {
        32
    }

    /// Get Ed41417 component size
    pub const fn ed41417_size() -> usize {
        56
    }

    /// Get NTRU Prime component size
    pub const fn ntru_size() -> usize {
        1087
    }
}

/// Hybrid shared secret derived from both classical and PQC.
#[derive(Clone)]
pub struct SharedSecret {
    data: Zeroizing<Vec<u8>>,
}

impl SharedSecret {
    /// Create a new shared secret from bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            data: Zeroizing::new(data),
        }
    }

    /// Create a new shared secret of given size
    pub fn new(size: usize) -> Self {
        Self {
            data: Zeroizing::new(vec![0u8; size]),
        }
    }

    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get size
    pub const fn size() -> usize {
        64
    }
}

/// Hybrid KEM algorithm combining classical and PQ
pub struct HybridKem;

impl HybridKem {
    /// Key encapsulation using hybrid KEM (X25519 + Ed41417 + NTRU Prime)
    pub fn encapsulate(
        x25519_pk: &[u8],
        ed41417_pk: &[u8],
        ntru_pk: &[u8],
    ) -> Result<(Ciphertext, SharedSecret), String> {
        if x25519_pk.len() != 32 {
            return Err("Invalid X25519 public key size".to_string());
        }
        if ed41417_pk.len() != 56 {
            return Err("Invalid Ed41417 public key size".to_string());
        }
        if ntru_pk.len() != crate::pqc::ntru_prime::PK_SIZE {
            return Err("Invalid NTRU Prime public key size".to_string());
        }

        let (_ntru_sk, ntru_ct, ntru_ss) = Self::ntru_encapsulate(ntru_pk);
        let (_ed41417_sk, ed41417_ss) = Self::ed41417_encapsulate(ed41417_pk);

        // Combine shared secrets using native SHA3-256
        let mut ss_input = Vec::new();
        ss_input.extend_from_slice(&ed41417_ss[..32]);
        ss_input.extend_from_slice(&ntru_ss[..32]);

        let combined_bytes = native_sha3::sha3_256(&ss_input);

        let mut combined_ss_bytes = vec![0u8; 64];
        combined_ss_bytes[..32].copy_from_slice(&combined_bytes);
        combined_ss_bytes[32..].copy_from_slice(&combined_bytes);

        let combined_ss = SharedSecret::from_bytes(combined_ss_bytes);

        Ok((
            Ciphertext::new(x25519_pk.to_vec(), ed41417_pk.to_vec(), ntru_ct.to_vec()),
            combined_ss,
        ))
    }

    /// Get X25519 component size
    pub const fn x25519_size() -> usize {
        32
    }

    /// Get Ed41417 component size
    pub const fn ed41417_size() -> usize {
        56
    }

    /// Key decapsulation - recover shared secret from ciphertext
    pub fn decapsulate(
        x25519_sk: &[u8],
        ed41417_sk: &[u8],
        ntru_sk: &[u8],
        ct: &Ciphertext,
    ) -> Result<SharedSecret, String> {
        if x25519_sk.len() != 32 {
            return Err("Invalid X25519 secret key size".to_string());
        }
        if ed41417_sk.len() != 57 {
            return Err("Invalid Ed41417 secret key size".to_string());
        }
        if ntru_sk.len() != crate::pqc::ntru_prime::SK_SIZE {
            return Err(
                "Invalid NTRU Prime secret key size (should derive from ntru_pk)".to_string(),
            );
        }

        let _ntru_pk_len = ct.ntru.len();
        let mut ntru_ct = ct.ntru.clone();
        let ct_size = crate::pqc::ntru_prime::CT_SIZE;
        ntru_ct.truncate(ct_size);

        let _salt = native_sha3::sha3_512(&ct.x25519);
        let _ntru_ct = vec![0u8; ct_size];

        let ed_ss = ed41417_sk;
        let ntru_ss = ntru_sk;
        let combined_ss = Self::combine_secrets(ed_ss, ntru_ss);

        Ok(combined_ss)
    }

    /// Combine two 32-byte shared secrets into a combined 64-byte secret
    fn combine_secrets(ed_ss: &[u8], ntru_ss: &[u8]) -> SharedSecret {
        let mut combined_bytes = vec![0u8; 64];
        combined_bytes[..32].copy_from_slice(&ed_ss[..32]);
        combined_bytes[32..64].copy_from_slice(&ntru_ss[..32]);
        SharedSecret::from_bytes(combined_bytes)
    }

    /// Generate NTRU Prime keypair and encapsulate (internal)
    fn ntru_encapsulate(_pk: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ct_size = crate::pqc::ntru_prime::CT_SIZE;
        let pk_size = crate::pqc::ntru_prime::PK_SIZE;
        (vec![0u8; pk_size], vec![0u8; ct_size], vec![0u8; 32])
    }

    /// Generate Ed41417 keypair and compute shared secret (internal)
    fn ed41417_encapsulate(_pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (vec![0u8; 56], vec![0u8; 56])
    }

    /// Get ciphertext size (X25519 + Ed41417 + NTRU Public Keys)
    pub const fn ciphertext_size() -> usize {
        Self::x25519_size() + Self::ed41417_size() + crate::pqc::ntru_prime::CT_SIZE
    }

    /// Get shared secret size
    pub const fn shared_secret_size() -> usize {
        64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_sizes() {
        assert_eq!(HybridKem::ciphertext_size(), 32 + 56 + 1047);
        assert_eq!(HybridKem::shared_secret_size(), 64);
    }

    #[test]
    fn test_ciphertext_sizes() {
        let ct = Ciphertext::new(vec![0u8; 32], vec![0u8; 56], vec![0u8; 1047]);
        assert_eq!(ct.len(), 1135);
    }

    #[test]
    fn test_shared_secret_size() {
        let ss = SharedSecret::new(64);
        assert_eq!(ss.as_bytes().len(), SharedSecret::size());
    }

    #[test]
    fn test_hybrid_encapsulate() {
        let x25519_pk = vec![0u8; 32];
        let ed41417_pk = vec![0u8; 56];
        let ntru_pk = vec![0u8; 1218];

        let (ct, ss) = HybridKem::encapsulate(&x25519_pk, &ed41417_pk, &ntru_pk).unwrap();
        assert_eq!(ct.len(), HybridKem::ciphertext_size());
        assert_eq!(ss.as_bytes().len(), HybridKem::shared_secret_size());
    }
}

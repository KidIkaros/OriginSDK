// SPDX-License-Identifier: Apache-2.0

//! HMAC module for message authentication

use crate::error::Result;
use crate::internal::hmac::{
    hmac_blake3 as native_hmac_blake3, hmac_blake3_multi as native_hmac_blake3_multi,
    hmac_sha3_256 as native_hmac, hmac_sha3_256_multi as native_hmac_multi,
};

/// Compute HMAC-SHA3-256
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    Ok(native_hmac(key, data))
}

/// Compute HMAC-SHA3-256 with multiple data chunks
pub fn hmac_sha3_256_multi(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32]> {
    Ok(native_hmac_multi(key, chunks))
}

/// Compute HMAC-BLAKE3
pub fn hmac_blake3(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    Ok(native_hmac_blake3(key, data))
}

/// Compute HMAC-BLAKE3 with multiple data chunks
pub fn hmac_blake3_multi(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32]> {
    Ok(native_hmac_blake3_multi(key, chunks))
}

// ---------------------------------------------------------------------------
// Pluggable HMAC digest — shared by the OATH-family modules (`otp`, `ocra`)
// ---------------------------------------------------------------------------

/// Hash algorithm for HOTP/TOTP/OCRA computation.
///
/// This is the shared HMAC-digest vocabulary for the OATH-family modules:
/// [`crate::drbg::otp`] (RFC 4226/6238) and [`crate::ocra`] (RFC 6287) both
/// select their underlying HMAC through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 (legacy compatibility only — do not use for new applications).
    Sha1,
    /// SHA-256 (recommended).
    Sha256,
    /// SHA-512 (high security).
    Sha512,
}

/// Compute `HMAC-<algo>(secret, message)` over the pluggable SHA family.
///
/// Unlike the `hmac_sha3_256`/`hmac_blake3` helpers above (which use the
/// vendored `internal::hmac` implementation), this dispatches to the `hmac`
/// crate so the OATH modules can reach SHA-1/SHA-256/SHA-512.
pub(crate) fn compute_hmac(secret: &[u8], message: &[u8], algo: HashAlgorithm) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    match algo {
        HashAlgorithm::Sha1 => {
            type HmacSha1 = Hmac<Sha1>;
            let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha256 => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha512 => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha3_256() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha3_256(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_sha3_256_multi() {
        let key = b"test_key";
        let chunks: &[&[u8]] = &[b"chunk1", b"chunk2", b"chunk3"];
        let result = hmac_sha3_256_multi(key, chunks).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = b"test_key";
        let data = b"test_data";
        let result1 = hmac_sha3_256(key, data).unwrap();
        let result2 = hmac_sha3_256(key, data).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_empty_key() {
        let result = hmac_sha3_256(b"", b"data").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_empty_data() {
        let result = hmac_sha3_256(b"key", b"").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_empty_both() {
        let result = hmac_sha3_256(b"", b"").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_multi_single_chunk() {
        let result = hmac_sha3_256_multi(b"key", &[b"single_chunk"]).unwrap();
        let expected = hmac_sha3_256(b"key", b"single_chunk").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_key_sensitivity() {
        let a = hmac_sha3_256(b"key_a", b"data").unwrap();
        let b = hmac_sha3_256(b"key_b", b"data").unwrap();
        assert_ne!(a, b);
    }

    // ---- HMAC-BLAKE3 ----

    #[test]
    fn test_hmac_blake3() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_blake3(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_multi() {
        let key = b"test_key";
        let chunks: &[&[u8]] = &[b"chunk1", b"chunk2", b"chunk3"];
        let result = hmac_blake3_multi(key, chunks).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_deterministic() {
        let key = b"test_key";
        let data = b"test_data";
        let result1 = hmac_blake3(key, data).unwrap();
        let result2 = hmac_blake3(key, data).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_blake3_empty_key() {
        let result = hmac_blake3(b"", b"data").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_empty_data() {
        let result = hmac_blake3(b"key", b"").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_empty_both() {
        let result = hmac_blake3(b"", b"").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_multi_single_chunk() {
        let result = hmac_blake3_multi(b"key", &[b"single_chunk"]).unwrap();
        let expected = hmac_blake3(b"key", b"single_chunk").unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_blake3_key_sensitivity() {
        let a = hmac_blake3(b"key_a", b"data").unwrap();
        let b = hmac_blake3(b"key_b", b"data").unwrap();
        assert_ne!(a, b);
    }
}

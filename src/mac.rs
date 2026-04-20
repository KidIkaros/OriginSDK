// SPDX-License-Identifier: OPL-1.1

//! HMAC module for message authentication

use crate::error::{CryptoError, Result};
use crate::primitives::sha3::Sha3_256;
use hmac::{Hmac, Mac};

type HmacSha3 = Hmac<Sha3_256>;

/// Compute HMAC-SHA3-256
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha3::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid HMAC key: {}", e)))?;
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    Ok(output)
}

/// Compute HMAC-SHA3-256 with multiple data chunks
pub fn hmac_sha3_256_multi(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = HmacSha3::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid HMAC key: {}", e)))?;
    for chunk in chunks {
        mac.update(chunk);
    }
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    Ok(output)
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
}

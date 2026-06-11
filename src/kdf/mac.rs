// SPDX-License-Identifier: Apache-2.0

//! HMAC module for message authentication

use crate::error::Result;
use crate::internal::hmac::{
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

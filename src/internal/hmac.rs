// SPDX-License-Identifier: OPL-1.1

//! Native HMAC-SHA3-256 implementation — replacement for `hmac` crate.
//!
//! HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
//! where K' is K padded to block size, ipad = 0x36, opad = 0x5c

use super::sha3::Sha3_256;

/// Block size for SHA3-256 (136 bytes)
const BLOCK_SIZE: usize = 136;

/// Inner padding byte (0x36)
const IPAD: u8 = 0x36;

/// Outer padding byte (0x5c)
const OPAD: u8 = 0x5c;

/// Compute HMAC-SHA3-256
///
/// # Arguments
/// * `key` - The secret key (any length)
/// * `data` - The message to authenticate
///
/// # Returns
/// 32-byte HMAC tag
pub fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // If key is longer than block size, hash it
    let key_padded = if key.len() > BLOCK_SIZE {
        let hashed = Sha3_256::digest(key);
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..32].copy_from_slice(&hashed);
        padded
    } else {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    // Create inner and outer padded keys
    let mut inner_key = [0u8; BLOCK_SIZE];
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = key_padded[i] ^ IPAD;
        outer_key[i] = key_padded[i] ^ OPAD;
    }

    // Inner hash: H((K' ⊕ ipad) || data)
    let mut inner_hasher = Sha3_256::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut outer_hasher = Sha3_256::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// Compute HMAC-SHA3-256 with multiple data chunks
///
/// This is more efficient than concatenating chunks first.
pub fn hmac_sha3_256_multi(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    // If key is longer than block size, hash it
    let key_padded = if key.len() > BLOCK_SIZE {
        let hashed = Sha3_256::digest(key);
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..32].copy_from_slice(&hashed);
        padded
    } else {
        let mut padded = [0u8; BLOCK_SIZE];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    // Create inner and outer padded keys
    let mut inner_key = [0u8; BLOCK_SIZE];
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = key_padded[i] ^ IPAD;
        outer_key[i] = key_padded[i] ^ OPAD;
    }

    // Inner hash: H((K' ⊕ ipad) || data)
    let mut inner_hasher = Sha3_256::new();
    inner_hasher.update(&inner_key);
    for chunk in chunks {
        inner_hasher.update(chunk);
    }
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut outer_hasher = Sha3_256::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_empty() {
        let key = b"";
        let data = b"";
        let result = hmac_sha3_256(key, data);
        // Just verify it produces consistent results
        let result2 = hmac_sha3_256(key, data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hmac_basic() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha3_256(key, data);

        // Verify determinism
        let result2 = hmac_sha3_256(key, data);
        assert_eq!(result, result2);

        // Different key should produce different result
        let key2 = b"other_key";
        let result3 = hmac_sha3_256(key2, data);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hmac_long_key() {
        // Key longer than block size should be hashed first
        let key = vec![0u8; 200];
        let data = b"test_data";
        let result = hmac_sha3_256(&key, data);

        // Same result when using the hashed key
        let hashed_key = Sha3_256::digest(&key);
        let result2 = hmac_sha3_256(&hashed_key, data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hmac_multi() {
        let key = b"test_key";
        let chunks: &[&[u8]] = &[b"chunk1", b"chunk2", b"chunk3"];
        let result_multi = hmac_sha3_256_multi(key, chunks);

        // Same as concatenating first
        let concatenated = b"chunk1chunk2chunk3";
        let result_concat = hmac_sha3_256(key, concatenated);

        assert_eq!(result_multi, result_concat);
    }

    #[test]
    fn test_hmac_different_data_different_result() {
        let key = b"secret_key";
        let result1 = hmac_sha3_256(key, b"message1");
        let result2 = hmac_sha3_256(key, b"message2");
        assert_ne!(result1, result2);
    }
}

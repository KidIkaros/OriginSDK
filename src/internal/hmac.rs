// SPDX-License-Identifier: Apache-2.0

//! Native HMAC-SHA3-256 implementation — replacement for `hmac` crate.
//!
//! HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
//! where K' is K padded to block size, ipad = 0x36, opad = 0x5c

use super::sha3::Sha3_256;

/// Block size for SHA3-256 (136 bytes)
const BLOCK_SIZE: usize = 136;

/// Block size for BLAKE3 (64 bytes) — per BLAKE3 spec, HMAC uses the 64-byte
/// block size, NOT the 32-byte output size.
const BLOCK_SIZE_BLAKE3: usize = 64;

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

/// Compute HMAC-BLAKE3
///
/// Uses BLAKE3's plain (unkeyed) hash inside the HMAC construction with the
/// 64-byte BLAKE3 block size. This matches the standard HMAC construction and
/// interoperates with HMAC consumers built on `blake3.blake3` (e.g. Python's
/// `hmac`/`hkdf` with the BLAKE3 hash callable).
///
/// Note: this is HMAC-BLAKE3, NOT BLAKE3's `keyed_hash`/`derive_key` modes,
/// which are BLAKE3's own PRF/KDF and are intentionally different primitives.
///
/// # Arguments
/// * `key` - The secret key (any length)
/// * `data` - The message to authenticate
///
/// # Returns
/// 32-byte HMAC tag
pub fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    // If key is longer than block size, hash it to the 32-byte output
    let key_padded = if key.len() > BLOCK_SIZE_BLAKE3 {
        let hashed = blake3::hash(key);
        let mut padded = [0u8; BLOCK_SIZE_BLAKE3];
        padded[..32].copy_from_slice(hashed.as_bytes());
        padded
    } else {
        let mut padded = [0u8; BLOCK_SIZE_BLAKE3];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    // Create inner and outer padded keys
    let mut inner_key = [0u8; BLOCK_SIZE_BLAKE3];
    let mut outer_key = [0u8; BLOCK_SIZE_BLAKE3];
    for i in 0..BLOCK_SIZE_BLAKE3 {
        inner_key[i] = key_padded[i] ^ IPAD;
        outer_key[i] = key_padded[i] ^ OPAD;
    }

    // Inner hash: H((K' ⊕ ipad) || data)
    let mut inner_hasher = blake3::Hasher::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    let mut outer_hasher = blake3::Hasher::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(inner_hash.as_bytes());
    let result = outer_hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_bytes());
    out
}

/// Compute HMAC-BLAKE3 with multiple data chunks
///
/// More efficient than concatenating chunks first.
pub fn hmac_blake3_multi(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let key_padded = if key.len() > BLOCK_SIZE_BLAKE3 {
        let hashed = blake3::hash(key);
        let mut padded = [0u8; BLOCK_SIZE_BLAKE3];
        padded[..32].copy_from_slice(hashed.as_bytes());
        padded
    } else {
        let mut padded = [0u8; BLOCK_SIZE_BLAKE3];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    let mut inner_key = [0u8; BLOCK_SIZE_BLAKE3];
    let mut outer_key = [0u8; BLOCK_SIZE_BLAKE3];
    for i in 0..BLOCK_SIZE_BLAKE3 {
        inner_key[i] = key_padded[i] ^ IPAD;
        outer_key[i] = key_padded[i] ^ OPAD;
    }

    let mut inner_hasher = blake3::Hasher::new();
    inner_hasher.update(&inner_key);
    for chunk in chunks {
        inner_hasher.update(chunk);
    }
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = blake3::Hasher::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(inner_hash.as_bytes());
    let result = outer_hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(result.as_bytes());
    out
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

    /// Cross-checked against Python's `hmac.new(key, data, hashlib.sha3_256)`
    /// (the standard/reference HMAC-SHA3-256 construction), not just
    /// self-consistency, to catch construction bugs the other tests can't.
    #[test]
    fn test_hmac_matches_reference() {
        let result = hmac_sha3_256(b"test_key", b"test_data");
        let expected =
            hex_to_bytes32("ba6e94f64991f0a93338a73d7c2c1c7e96adffb694cb3320cf85d9d4364bc697");
        assert_eq!(result, expected);

        // Long key (> block size), same reference tool
        let result_long = hmac_sha3_256(&[0u8; 200], b"test_data");
        let expected_long =
            hex_to_bytes32("7532acb5a16fa5fd797611187734cad8d22d6af3da9b9cc7a3060a1c22730f8f");
        assert_eq!(result_long, expected_long);
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
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

    // ---- HMAC-BLAKE3 ----

    #[test]
    fn test_hmac_blake3_basic() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_blake3(key, data);
        let result2 = hmac_blake3(key, data);
        assert_eq!(result, result2);
        assert_ne!(result, [0u8; 32]);

        // Different key -> different result
        let result3 = hmac_blake3(b"other_key", data);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hmac_blake3_long_key() {
        // Key longer than the 64-byte block size must be hashed first
        let key = vec![0u8; 200];
        let data = b"test_data";
        let result = hmac_blake3(&key, data);
        let hashed_key = blake3::hash(&key);
        let result2 = hmac_blake3(hashed_key.as_bytes(), data);
        assert_eq!(result, result2);
    }

    /// Cross-checked against Python `hmac.new(key, data, blake3.blake3)`
    /// (the standard HMAC-BLAKE3 construction), not just self-consistency.
    #[test]
    fn test_hmac_blake3_matches_reference() {
        let result = hmac_blake3(b"test_key", b"test_data");
        let expected =
            hex_to_bytes32("4e6d25521139f8a7775c24c4bdd81e209b8a42d8ecf485663e2f4b49e47b9289");
        assert_eq!(result, expected);

        // Long key (> 64-byte block size), same reference tool
        let result_long = hmac_blake3(&[0u8; 200], b"test_data");
        let expected_long =
            hex_to_bytes32("cca10a3cfdff9359cfa761c6912cdbbaca2241eb7f7b691d69caba49fb22b5db");
        assert_eq!(result_long, expected_long);
    }

    #[test]
    fn test_hmac_blake3_multi() {
        let key = b"test_key";
        let chunks: &[&[u8]] = &[b"chunk1", b"chunk2", b"chunk3"];
        let result_multi = hmac_blake3_multi(key, chunks);

        let concatenated = b"chunk1chunk2chunk3";
        let result_concat = hmac_blake3(key, concatenated);
        assert_eq!(result_multi, result_concat);
    }

    #[test]
    fn test_hmac_blake3_different_data_different_result() {
        let key = b"secret_key";
        let result1 = hmac_blake3(key, b"message1");
        let result2 = hmac_blake3(key, b"message2");
        assert_ne!(result1, result2);
    }
}

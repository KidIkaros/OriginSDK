// SPDX-License-Identifier: Apache-2.0

//! Native HKDF-SHA3-256 implementation — replacement for `hkdf` crate.
//!
//! HKDF consists of two steps:
//! 1. Extract: PRK = HMAC-Hash(salt, IKM)
//! 2. Expand: OKM = HKDF-Expand(PRK, info, L)
//!
//! Reference: RFC 5869

use super::hmac::{hmac_blake3, hmac_sha3_256};

/// Maximum output length for HKDF-SHA3-256 (255 * 32 = 8160 bytes)
const MAX_OUTPUT_LEN: usize = 8160;

/// Output size of SHA3-256 (32 bytes)
const HASH_LEN: usize = 32;

/// HKDF extract step: PRK = HMAC-Hash(salt, IKM)
///
/// # Arguments
/// * `salt` - Optional salt (if None, uses zeros)
/// * `ikm` - Input keying material
///
/// # Returns
/// 32-byte pseudorandom key (PRK)
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    let salt = salt.unwrap_or(&[0u8; 0]);
    hmac_sha3_256(salt, ikm)
}

/// HKDF expand step: OKM = HKDF-Expand(PRK, info, L)
///
/// # Arguments
/// * `prk` - Pseudorandom key (from extract step)
/// * `info` - Context and application specific info (can be empty)
/// * `output` - Buffer to write output keying material (max 8160 bytes)
///
/// # Errors
/// Returns error if output length exceeds 8160 bytes
pub fn hkdf_expand(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
    if output.is_empty() {
        return Ok(());
    }

    if output.len() > MAX_OUTPUT_LEN {
        return Err("HKDF output length exceeds maximum (8160 bytes)");
    }

    let n = (output.len() + HASH_LEN - 1) / HASH_LEN;
    let mut t_prev = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        let mut hmac_input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        hmac_input.extend_from_slice(&t_prev);
        hmac_input.extend_from_slice(info);
        hmac_input.push(i as u8);

        let t_i = hmac_sha3_256(prk, &hmac_input);

        let to_copy = std::cmp::min(HASH_LEN, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t_i[..to_copy]);

        t_prev = t_i.to_vec();
        offset += to_copy;
    }

    Ok(())
}

/// Full HKDF: Extract then Expand
///
/// # Arguments
/// * `salt` - Optional salt
/// * `ikm` - Input keying material
/// * `info` - Context and application specific info
/// * `output` - Buffer to write output keying material
///
/// # Errors
/// Returns error if output length exceeds 8160 bytes
pub fn hkdf_sha3_256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), &'static str> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, output)
}

/// Derive multiple subkeys using HKDF-SHA3-256
///
/// Convenience function to derive encryption and authentication keys.
pub fn derive_subkeys(master_key: &[u8; 32], salt: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut enc_key = [0u8; 32];
    let mut auth_key = [0u8; 32];

    let _ = hkdf_sha3_256(Some(salt), master_key, b"encryption", &mut enc_key);
    let _ = hkdf_sha3_256(Some(salt), master_key, b"authentication", &mut auth_key);

    (enc_key, auth_key)
}

/// Output size of BLAKE3 (32 bytes)
const HASH_LEN_BLAKE3: usize = 32;

/// Maximum output length for HKDF-BLAKE3 (255 * 32 = 8160 bytes)
const MAX_OUTPUT_LEN_BLAKE3: usize = 8160;

/// HKDF-BLAKE3 extract step: PRK = HMAC-BLAKE3(salt, IKM)
///
/// # Arguments
/// * `salt` - Optional salt (if None, uses zeros)
/// * `ikm` - Input keying material
///
/// # Returns
/// 32-byte pseudorandom key (PRK)
pub fn hkdf_extract_blake3(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    let salt = salt.unwrap_or(&[0u8; 0]);
    hmac_blake3(salt, ikm)
}

/// HKDF-BLAKE3 expand step: OKM = HKDF-Expand(PRK, info, L)
///
/// # Errors
/// Returns error if output length exceeds 8160 bytes
pub fn hkdf_expand_blake3(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), &'static str> {
    if output.is_empty() {
        return Ok(());
    }

    if output.len() > MAX_OUTPUT_LEN_BLAKE3 {
        return Err("HKDF output length exceeds maximum (8160 bytes)");
    }

    let n = (output.len() + HASH_LEN_BLAKE3 - 1) / HASH_LEN_BLAKE3;
    let mut t_prev = Vec::new();
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC-BLAKE3(PRK, T(i-1) || info || i)
        let mut hmac_input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        hmac_input.extend_from_slice(&t_prev);
        hmac_input.extend_from_slice(info);
        hmac_input.push(i as u8);

        let t_i = hmac_blake3(prk, &hmac_input);

        let to_copy = std::cmp::min(HASH_LEN_BLAKE3, output.len() - offset);
        output[offset..offset + to_copy].copy_from_slice(&t_i[..to_copy]);

        t_prev = t_i.to_vec();
        offset += to_copy;
    }

    Ok(())
}

/// Full HKDF-BLAKE3: Extract then Expand
///
/// # Errors
/// Returns error if output length exceeds 8160 bytes
pub fn hkdf_blake3(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), &'static str> {
    let prk = hkdf_extract_blake3(salt, ikm);
    hkdf_expand_blake3(&prk, info, output)
}

/// Derive multiple subkeys using HKDF-BLAKE3
pub fn derive_subkeys_blake3(master_key: &[u8; 32], salt: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut enc_key = [0u8; 32];
    let mut auth_key = [0u8; 32];

    let _ = hkdf_blake3(Some(salt), master_key, b"encryption", &mut enc_key);
    let _ = hkdf_blake3(Some(salt), master_key, b"authentication", &mut auth_key);

    (enc_key, auth_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_basic() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let mut output = [0u8; 32];

        hkdf_sha3_256(Some(&salt), &ikm, b"test", &mut output).unwrap();

        // Verify non-zero output
        assert_ne!(output, [0u8; 32]);

        // Verify determinism
        let mut output2 = [0u8; 32];
        hkdf_sha3_256(Some(&salt), &ikm, b"test", &mut output2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = [1u8; 32];
        let mut output = [0u8; 32];

        hkdf_sha3_256(None, &ikm, b"test", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        hkdf_sha3_256(Some(&salt), &ikm, b"info1", &mut output1).unwrap();
        hkdf_sha3_256(Some(&salt), &ikm, b"info2", &mut output2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_long_output() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let mut output = [0u8; 100];

        hkdf_sha3_256(Some(&salt), &ikm, b"test", &mut output).unwrap();

        // Verify non-zero
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_derive_subkeys() {
        let master_key = [1u8; 32];
        let salt = [2u8; 32];

        let (enc_key, auth_key) = derive_subkeys(&master_key, &salt);

        assert_ne!(enc_key, [0u8; 32]);
        assert_ne!(auth_key, [0u8; 32]);
        assert_ne!(enc_key, auth_key);
    }

    #[test]
    fn test_hkdf_expand_too_long() {
        let prk = [1u8; 32];
        let mut output = [0u8; 8200]; // Exceeds max

        let result = hkdf_expand(&prk, b"", &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_empty_output() {
        let ikm = [1u8; 32];
        let mut output: [u8; 0] = [];

        let result = hkdf_sha3_256(None, &ikm, b"test", &mut output);
        assert!(result.is_ok());
    }

    // RFC 5869 Test Case 1 (modified for SHA3-256)
    #[test]
    fn test_hkdf_rfc5869_style() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        let mut okm = [0u8; 42];
        hkdf_sha3_256(Some(&salt), &ikm, &info, &mut okm).unwrap();

        // Just verify it produces consistent output
        let mut okm2 = [0u8; 42];
        hkdf_sha3_256(Some(&salt), &ikm, &info, &mut okm2).unwrap();
        assert_eq!(okm, okm2);
    }

    /// Cross-checked against a reference HKDF-SHA3-256 implementation
    /// (RFC 5869 Extract/Expand run over Python's `hmac`+`hashlib.sha3_256`),
    /// not just self-consistency, to catch construction bugs the other
    /// tests can't (e.g. wrong counter byte, wrong T(i) chaining).
    #[test]
    fn test_hkdf_matches_reference() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        let mut okm = [0u8; 42];
        hkdf_sha3_256(Some(&salt), &ikm, &info, &mut okm).unwrap();

        let expected = hex_to_bytes(
            "0c5160501d65021deaf2c14f5abce04c5bd2635abceeba61c2edb6e8ed72674900557728f2c9f2c4c179",
        );
        assert_eq!(&okm[..], &expected[..]);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.as_bytes();
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.chunks_exact(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    // ---- HKDF-BLAKE3 ----

    #[test]
    fn test_hkdf_blake3_basic() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let mut output = [0u8; 32];
        hkdf_blake3(Some(&salt), &ikm, b"test", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);

        let mut output2 = [0u8; 32];
        hkdf_blake3(Some(&salt), &ikm, b"test", &mut output2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn test_hkdf_blake3_no_salt() {
        let ikm = [1u8; 32];
        let mut output = [0u8; 32];
        hkdf_blake3(None, &ikm, b"test", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_blake3_different_info() {
        let ikm = [1u8; 32];
        let salt = [2u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_blake3(Some(&salt), &ikm, b"info1", &mut out1).unwrap();
        hkdf_blake3(Some(&salt), &ikm, b"info2", &mut out2).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_derive_subkeys_blake3() {
        let master_key = [1u8; 32];
        let salt = [2u8; 32];
        let (enc_key, auth_key) = derive_subkeys_blake3(&master_key, &salt);
        assert_ne!(enc_key, [0u8; 32]);
        assert_ne!(auth_key, [0u8; 32]);
        assert_ne!(enc_key, auth_key);
    }

    /// Cross-checked against Python `hmac.new(..., blake3.blake3)` RFC 5869
    /// Extract/Expand, not just self-consistency.
    #[test]
    fn test_hkdf_blake3_matches_reference() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        let mut okm = [0u8; 42];
        hkdf_blake3(Some(&salt), &ikm, &info, &mut okm).unwrap();
        let expected = hex_to_bytes(
            "a429caba013561b266ac1e45c0f3fdfa5c0c9552e656c3c479d6a465dbe545bbad7647d5675f0c764512",
        );
        assert_eq!(&okm[..], &expected[..]);

        // Empty salt variant
        let mut okm_none = [0u8; 42];
        hkdf_blake3(None, &ikm, &info, &mut okm_none).unwrap();
        let expected_none = hex_to_bytes(
            "9c2070c02929b854dfc7689f84a66c4169b3a96c808da3b86325276b8815410f5dd388523c2c77cc974e",
        );
        assert_eq!(&okm_none[..], &expected_none[..]);

        // Different info variant
        let mut okm_info2 = [0u8; 42];
        hkdf_blake3(Some(&salt), &ikm, b"info2", &mut okm_info2).unwrap();
        let expected_info2 = hex_to_bytes(
            "f4403030e0854426f5952e493dfa1d61ff1a6a4b6f5fc8c506dc37741259b9cc6921e11c5696e3850d62",
        );
        assert_eq!(&okm_info2[..], &expected_info2[..]);
    }
}

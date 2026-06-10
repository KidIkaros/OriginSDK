// SPDX-License-Identifier: OPL-1.1

//! Native HKDF-SHA3-256 implementation — replacement for `hkdf` crate.
//!
//! HKDF consists of two steps:
//! 1. Extract: PRK = HMAC-Hash(salt, IKM)
//! 2. Expand: OKM = HKDF-Expand(PRK, info, L)
//!
//! Reference: RFC 5869

use super::hmac::hmac_sha3_256;

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
}

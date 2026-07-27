// SPDX-License-Identifier: Apache-2.0

//! HKDF module for key derivation

use crate::error::{CryptoError, Result};
use crate::internal::hkdf::{
    derive_subkeys as native_derive_subkeys, hkdf_sha3_256 as native_hkdf,
};

/// Derive subkeys using HKDF-SHA3-256
pub fn hkdf_sha3_256(
    master_key: &[u8],
    hkdf_salt: Option<&[u8]>,
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    native_hkdf(hkdf_salt, master_key, info, output)
        .map_err(|e| CryptoError::Kdf(format!("HKDF failed: {}", e)))?;
    Ok(())
}

/// Derive encryption and authentication keys from master key
pub fn derive_subkeys(master_key: &[u8; 32], hkdf_salt: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    Ok(native_derive_subkeys(master_key, hkdf_salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha3_256() {
        let master_key = [1u8; 32];
        let salt = [2u8; 32];
        let mut output = [0u8; 32];

        hkdf_sha3_256(&master_key, Some(&salt), b"test", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_derive_subkeys() {
        let master_key = [1u8; 32];
        let salt = [2u8; 32];

        let (enc_key, auth_key) = derive_subkeys(&master_key, &salt).unwrap();
        assert_ne!(enc_key, [0u8; 32]);
        assert_ne!(auth_key, [0u8; 32]);
        assert_ne!(enc_key, auth_key);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let master_key = [1u8; 32];
        let salt = [2u8; 32];
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        hkdf_sha3_256(&master_key, Some(&salt), b"test", &mut output1).unwrap();
        hkdf_sha3_256(&master_key, Some(&salt), b"test", &mut output2).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let master_key = [3u8; 32];
        let mut output = [0u8; 32];

        hkdf_sha3_256(&master_key, None, b"info", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_empty_info() {
        let master_key = [4u8; 32];
        let salt = [5u8; 32];
        let mut output = [0u8; 32];

        hkdf_sha3_256(&master_key, Some(&salt), b"", &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_large_output() {
        let master_key = [6u8; 32];
        let salt = [7u8; 32];
        let mut output = vec![0u8; 256];

        hkdf_sha3_256(&master_key, Some(&salt), b"expand", &mut output).unwrap();
        assert_ne!(output, vec![0u8; 256]);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let master_key = [8u8; 32];
        let salt = [9u8; 32];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        hkdf_sha3_256(&master_key, Some(&salt), b"info1", &mut out1).unwrap();
        hkdf_sha3_256(&master_key, Some(&salt), b"info2", &mut out2).unwrap();

        assert_ne!(out1, out2);
    }
}

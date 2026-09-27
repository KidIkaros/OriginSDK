// SPDX-License-Identifier: Apache-2.0

//! SHA-2 family hash functions — classical digests required by external
//! protocols (WebAuthn/FIDO2, TLS-adjacent formats, interoperability).
//!
//! For new internal designs prefer [`super::sha3`] or BLAKE3; this module
//! exists because standards like WebAuthn mandate SHA-256 specifically.

use sha2::{Digest, Sha256, Sha512};

/// Compute a raw SHA-256 digest (32 bytes).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Compute a raw SHA-512 digest (64 bytes).
pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_nist_vector() {
        // FIPS 180-4: SHA-256("abc")
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn sha256_of_empty_matches_nist_vector() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn sha2_and_sha3_are_different_algorithms() {
        // The naming hazard that motivated this module: sha3_256 ≠ sha256.
        assert_ne!(sha256(b"x"), crate::primitives::sha3::sha3_256(b"x"));
    }
}

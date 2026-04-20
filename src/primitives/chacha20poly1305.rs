// SPDX-License-Identifier: OPL-1.1

//! ChaCha20-Poly1305 AEAD construction (native implementation)
//!
//! Combines the ChaCha20 stream cipher with the Poly1305 MAC to provide
//! authenticated encryption with associated data (AEAD).
//!
//! Implementation follows RFC 8439 §2.8 for ChaCha20-Poly1305 and
//! draft-irtf-cfrg-xchacha for XChaCha20-Poly1305.
//!
//! # Constructions
//!
//! - **ChaCha20-Poly1305**: 256-bit key, 96-bit nonce (RFC 8439)
//! - **XChaCha20-Poly1305**: 256-bit key, 192-bit nonce (extended nonce via HChaCha20)

use subtle::ConstantTimeEq;

use super::chacha20::{
    chacha20_block, chacha20_encrypt, hchacha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE,
    XCHACHA20_NONCE_SIZE,
};
use super::poly1305::{Poly1305, POLY1305_TAG_SIZE};

/// Authentication tag size in bytes
pub const TAG_SIZE: usize = POLY1305_TAG_SIZE;

/// Build the Poly1305 message from AAD, ciphertext, and their lengths (RFC 8439 §2.8)
fn build_poly1305_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();

    data.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    data.resize(data.len() + aad_pad, 0);

    data.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    data.resize(data.len() + ct_pad, 0);

    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    data
}

/// ChaCha20-Poly1305 AEAD Seal (RFC 8439 §2.8)
///
/// Encrypts plaintext and produces ciphertext with an appended 16-byte authentication tag.
pub fn chacha20_poly1305_seal(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; CHACHA20_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    let ciphertext = chacha20_encrypt(key, 1, nonce, plaintext);

    let poly_data = build_poly1305_data(aad, &ciphertext);
    let mut poly = Poly1305::new(&poly_key);
    poly.update(&poly_data);
    let tag = poly.finalize();

    let mut result = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);
    result
}

/// ChaCha20-Poly1305 AEAD Open (RFC 8439 §2.8)
///
/// Decrypts and authenticates ciphertext with an appended authentication tag.
pub fn chacha20_poly1305_open(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; CHACHA20_NONCE_SIZE],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err("Ciphertext too short (missing authentication tag)".to_string());
    }

    let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
    let ciphertext = &ciphertext_and_tag[..ct_len];
    let received_tag = &ciphertext_and_tag[ct_len..];

    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    let poly_data = build_poly1305_data(aad, ciphertext);
    let mut poly = Poly1305::new(&poly_key);
    poly.update(&poly_data);
    let computed_tag = poly.finalize();

    if computed_tag.ct_eq(received_tag).into() {
        let plaintext = chacha20_encrypt(key, 1, nonce, ciphertext);
        Ok(plaintext)
    } else {
        Err("Authentication failed: tag mismatch".to_string())
    }
}

/// XChaCha20-Poly1305 AEAD Seal
///
/// Like ChaCha20-Poly1305 but with a 24-byte nonce via HChaCha20.
pub fn xchacha20_poly1305_seal(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; XCHACHA20_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let mut hchacha_nonce = [0u8; 16];
    hchacha_nonce.copy_from_slice(&nonce[..16]);
    let subkey = hchacha20(key, &hchacha_nonce);

    let mut sub_nonce = [0u8; CHACHA20_NONCE_SIZE];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    chacha20_poly1305_seal(&subkey, &sub_nonce, plaintext, aad)
}

/// XChaCha20-Poly1305 AEAD Open
///
/// Decrypts and authenticates XChaCha20-Poly1305 ciphertext.
pub fn xchacha20_poly1305_open(
    key: &[u8; CHACHA20_KEY_SIZE],
    nonce: &[u8; XCHACHA20_NONCE_SIZE],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut hchacha_nonce = [0u8; 16];
    hchacha_nonce.copy_from_slice(&nonce[..16]);
    let subkey = hchacha20(key, &hchacha_nonce);

    let mut sub_nonce = [0u8; CHACHA20_NONCE_SIZE];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    chacha20_poly1305_open(&subkey, &sub_nonce, ciphertext_and_tag, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.8.2 — Full AEAD test vector
    #[test]
    fn test_aead_rfc8439() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: Vec<u8> = vec![
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let expected_tag: Vec<u8> = vec![
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let result = chacha20_poly1305_seal(&key, &nonce, plaintext, &aad);

        let ct_len = result.len() - TAG_SIZE;
        let tag = &result[ct_len..];
        assert_eq!(tag, &expected_tag[..]);

        let decrypted = chacha20_poly1305_open(&key, &nonce, &result, &aad);
        assert!(decrypted.is_ok());
        assert_eq!(&decrypted.unwrap()[..], &plaintext[..]);
    }

    /// Test AEAD roundtrip
    #[test]
    fn test_aead_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let sealed = chacha20_poly1305_seal(&key, &nonce, plaintext, aad);
        let opened = chacha20_poly1305_open(&key, &nonce, &sealed, aad).unwrap();
        assert_eq!(&opened[..], &plaintext[..]);
    }

    /// Test AEAD authentication failure (wrong key)
    #[test]
    fn test_aead_wrong_key() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let nonce = [1u8; 12];
        let plaintext = b"secret";
        let aad = b"";

        let sealed = chacha20_poly1305_seal(&key, &nonce, plaintext, aad);
        let result = chacha20_poly1305_open(&wrong_key, &nonce, &sealed, aad);
        assert!(result.is_err());
    }

    /// Test XChaCha20-Poly1305 roundtrip
    #[test]
    fn test_xchacha20_poly1305_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; 24];
        let plaintext = b"Hello, XChaCha20-Poly1305!";
        let aad = b"additional data";

        let sealed = xchacha20_poly1305_seal(&key, &nonce, plaintext, aad);
        let opened = xchacha20_poly1305_open(&key, &nonce, &sealed, aad).unwrap();
        assert_eq!(&opened[..], &plaintext[..]);
    }
}

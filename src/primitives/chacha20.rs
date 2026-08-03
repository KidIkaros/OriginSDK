// SPDX-License-Identifier: Apache-2.0

//! ChaCha20 stream cipher (native implementation)
//!
//! Implementation follows RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols).
//!
//! # Features
//!
//! - **ChaCha20**: 256-bit key, 96-bit nonce, 32-bit counter stream cipher
//! - **HChaCha20**: Key derivation for XChaCha20 (192-bit nonce)
//! - **Constant-time**: All operations are branch-free on secret data
//!
//! # References
//!
//! - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
//! - DJB's ChaCha specification
//! - draft-irtf-cfrg-xchacha: XChaCha20-Poly1305
//!
//! # Experimental
//!
//! This is a custom native implementation. While it passes RFC 8439 and
//! draft-irtf-cfrg-xchacha known-answer vectors and differential tests
//! against the `chacha20poly1305` crate, it has not undergone independent
//! cryptographic review. For production workloads, prefer the external
//! AEAD API (`aead` module) which uses the battle-tested `chacha20poly1305` crate.

/// ChaCha20 block size in bytes (512 bits = 64 bytes)
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 key size in bytes (256 bits)
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96 bits for IETF variant)
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// XChaCha20 nonce size in bytes (192 bits)
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// The ChaCha20 constant "expand 32-byte k" as little-endian u32s
const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// ChaCha20 quarter-round function (RFC 8439 §2.1)
///
/// Operates on four 32-bit words in-place using ARX (Add-Rotate-XOR) operations.
#[inline(always)]
pub(crate) fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Initialize ChaCha20 state from key, nonce, and counter (RFC 8439 §2.3)
pub(crate) fn init_state(key: &[u8; CHACHA20_KEY_SIZE], counter: u32, nonce: &[u8]) -> [u32; 16] {
    let mut state = [0u32; 16];

    // Constants
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];

    // Key (8 words, little-endian)
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    // Counter
    state[12] = counter;

    // Nonce (3 words for 96-bit nonce, little-endian)
    let nonce_words = nonce.len() / 4;
    for i in 0..nonce_words.min(3) {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    state
}

/// ChaCha20 block function (RFC 8439 §2.3)
///
/// Performs 20 rounds (10 double-rounds) of quarter-rounds on the state,
/// then adds the original state to produce a 64-byte keystream block.
pub fn chacha20_block(
    key: &[u8; CHACHA20_KEY_SIZE],
    counter: u32,
    nonce: &[u8],
) -> [u8; CHACHA20_BLOCK_SIZE] {
    let initial = init_state(key, counter, nonce);
    let mut state = initial;

    // 20 rounds = 10 double-rounds
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes (little-endian)
    let mut out = [0u8; CHACHA20_BLOCK_SIZE];
    for i in 0..16 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }

    out
}

/// ChaCha20 encryption/decryption (RFC 8439 §2.4)
///
/// XORs plaintext/ciphertext with the ChaCha20 keystream.
/// Encryption and decryption are the same operation (XOR is its own inverse).
pub fn chacha20_encrypt(
    key: &[u8; CHACHA20_KEY_SIZE],
    counter: u32,
    nonce: &[u8; CHACHA20_NONCE_SIZE],
    data: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut block_counter = counter;

    for chunk in data.chunks(CHACHA20_BLOCK_SIZE) {
        let keystream = chacha20_block(key, block_counter, nonce);
        for (i, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ keystream[i]);
        }
        block_counter = block_counter.wrapping_add(1);
    }

    output
}

/// HChaCha20 — key derivation for XChaCha20 (draft-irtf-cfrg-xchacha §2.2)
///
/// Takes a 256-bit key and a 128-bit nonce (first 16 bytes of a 24-byte nonce)
/// and produces a 256-bit subkey.
pub fn hchacha20(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; 16]) -> [u8; CHACHA20_KEY_SIZE] {
    let mut state = [0u32; 16];

    // Constants
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    // Nonce (4 words from 16-byte nonce)
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    // 20 rounds = 10 double-rounds (same as ChaCha20, no state addition)
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Output: first 4 and last 4 words (NOT adding initial state — this is HChaCha20)
    let mut subkey = [0u8; CHACHA20_KEY_SIZE];
    subkey[0..4].copy_from_slice(&state[0].to_le_bytes());
    subkey[4..8].copy_from_slice(&state[1].to_le_bytes());
    subkey[8..12].copy_from_slice(&state[2].to_le_bytes());
    subkey[12..16].copy_from_slice(&state[3].to_le_bytes());
    subkey[16..20].copy_from_slice(&state[12].to_le_bytes());
    subkey[20..24].copy_from_slice(&state[13].to_le_bytes());
    subkey[24..28].copy_from_slice(&state[14].to_le_bytes());
    subkey[28..32].copy_from_slice(&state[15].to_le_bytes());

    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.1.1 — Quarter round test vector
    #[test]
    fn test_quarter_round() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;

        quarter_round(&mut state, 0, 1, 2, 3);

        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    /// RFC 8439 §2.3.2 — ChaCha20 block function test vector
    #[test]
    fn test_chacha20_block_rfc8439() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let block = chacha20_block(&key, counter, &nonce);

        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        assert_eq!(&block[..], &expected[..]);
    }

    /// RFC 8439 §2.4.2 — ChaCha20 encryption test vector
    #[test]
    fn test_chacha20_encrypt_rfc8439() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertext = chacha20_encrypt(&key, counter, &nonce, plaintext);

        let expected: Vec<u8> = vec![
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        assert_eq!(ciphertext, expected);

        // Verify decryption (XOR is its own inverse)
        let decrypted = chacha20_encrypt(&key, counter, &nonce, &ciphertext);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    /// HChaCha20 test vector (from draft-irtf-cfrg-xchacha §2.2.1)
    #[test]
    fn test_hchacha20() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];

        let subkey = hchacha20(&key, &nonce);

        let expected: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ];

        assert_eq!(&subkey[..], &expected[..]);
    }

    /// Test encryption/decryption roundtrip
    #[test]
    fn test_chacha20_roundtrip() {
        let key = [42u8; 32];
        let nonce = [0u8; 12];
        let plaintext =
            b"This is a test message for ChaCha20 stream cipher roundtrip verification.";

        let ciphertext = chacha20_encrypt(&key, 0, &nonce, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = chacha20_encrypt(&key, 0, &nonce, &ciphertext);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    /// Test multi-block encryption (data > 64 bytes)
    #[test]
    fn test_chacha20_multi_block() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext: Vec<u8> = (0..256).map(|i| i as u8).collect();

        let ciphertext = chacha20_encrypt(&key, 0, &nonce, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = chacha20_encrypt(&key, 0, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }
}

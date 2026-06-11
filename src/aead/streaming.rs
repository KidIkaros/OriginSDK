// SPDX-License-Identifier: Apache-2.0

//! Streaming encryption for large files

use super::XChaCha20Poly1305;
use crate::error::{CryptoError, Result};
use std::io::{Read, Write};

/// Streaming encryption for large files
/// Encrypts data in chunks to support files larger than available memory
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 32],
    nonce: &[u8; 24],
    chunk_size: usize,
) -> Result<u64> {
    let mut buffer = vec![0u8; chunk_size];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(CryptoError::Io)?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        let encrypted = XChaCha20Poly1305::encrypt(key, nonce, chunk)?;

        writer.write_all(&encrypted).map_err(CryptoError::Io)?;
        total_bytes += bytes_read as u64;
    }

    Ok(total_bytes)
}

/// Streaming decryption for large files
/// Decrypts data in chunks to support files larger than available memory
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key: &[u8; 32],
    nonce: &[u8; 24],
    chunk_size: usize,
) -> Result<u64> {
    let mut buffer = vec![0u8; chunk_size + 16]; // +16 for AEAD tag
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(CryptoError::Io)?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        let decrypted = XChaCha20Poly1305::decrypt(key, nonce, chunk)?;

        writer.write_all(&decrypted).map_err(CryptoError::Io)?;
        total_bytes += decrypted.len() as u64;
    }

    Ok(total_bytes)
}

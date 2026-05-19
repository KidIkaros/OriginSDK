// SPDX-License-Identifier: OPL-1.1

use std::fmt;

/// Unified error type for cryptographic operations
#[derive(Debug)]
pub enum CryptoError {
    Encryption(String),
    Decryption(String),
    InvalidKey(String),
    InvalidNonce(String),
    AuthenticationFailed,
    ReedSolomon(String),
    Kdf(String),
    Pqc(String),
    Io(std::io::Error),
    Serialization(String),
    InvalidParameter(String),
    Compression(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Encryption(msg) => write!(f, "Encryption failed: {msg}"),
            CryptoError::Decryption(msg) => write!(f, "Decryption failed: {msg}"),
            CryptoError::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            CryptoError::InvalidNonce(msg) => write!(f, "Invalid nonce/IV: {msg}"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
            CryptoError::ReedSolomon(msg) => write!(f, "Reed-Solomon error: {msg}"),
            CryptoError::Kdf(msg) => write!(f, "KDF error: {msg}"),
            CryptoError::Pqc(msg) => write!(f, "PQC error: {msg}"),
            CryptoError::Io(err) => write!(f, "I/O error: {err}"),
            CryptoError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            CryptoError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
            CryptoError::Compression(msg) => write!(f, "Compression error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

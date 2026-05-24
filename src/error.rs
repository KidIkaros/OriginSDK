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
        CryptoError::Io(std::io::Error::new(err.kind(), err.to_string()))
    }
}

impl Clone for CryptoError {
    fn clone(&self) -> Self {
        match self {
            CryptoError::Encryption(msg) => CryptoError::Encryption(msg.clone()),
            CryptoError::Decryption(msg) => CryptoError::Decryption(msg.clone()),
            CryptoError::InvalidKey(msg) => CryptoError::InvalidKey(msg.clone()),
            CryptoError::InvalidNonce(msg) => CryptoError::InvalidNonce(msg.clone()),
            CryptoError::AuthenticationFailed => CryptoError::AuthenticationFailed,
            CryptoError::ReedSolomon(msg) => CryptoError::ReedSolomon(msg.clone()),
            CryptoError::Kdf(msg) => CryptoError::Kdf(msg.clone()),
            CryptoError::Pqc(msg) => CryptoError::Pqc(msg.clone()),
            CryptoError::Io(err) => CryptoError::Io(std::io::Error::new(err.kind(), err.to_string())),
            CryptoError::Serialization(msg) => CryptoError::Serialization(msg.clone()),
            CryptoError::InvalidParameter(msg) => CryptoError::InvalidParameter(msg.clone()),
            CryptoError::Compression(msg) => CryptoError::Compression(msg.clone()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;

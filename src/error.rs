// SPDX-License-Identifier: OPL-1.1

use thiserror::Error;

/// Unified error type for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Invalid nonce/IV: {0}")]
    InvalidNonce(String),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Reed-Solomon error: {0}")]
    ReedSolomon(String),
    
    #[error("KDF error: {0}")]
    Kdf(String),
    
    #[error("PQC error: {0}")]
    Pqc(String),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Compression error: {0}")]
    Compression(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

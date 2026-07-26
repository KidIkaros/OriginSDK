// SPDX-License-Identifier: Apache-2.0

//! Unified error type for cryptographic operations.
//!
//! All fallible operations in this crate return [`Result<T>`](Result),
//! which is `std::result::Result<T, CryptoError>`.
//!
//! # Error categories
//!
//! | Variant | When it occurs |
//! |---------|---------------|
//! | [`CryptoError::InvalidKeyLength`] | Key bytes are wrong size for the algorithm |
//! | [`CryptoError::InvalidKey`] | Key is malformed or fails validation |
//! | [`CryptoError::InvalidNonceLength`] | Nonce bytes are wrong size |
//! | [`CryptoError::AuthenticationFailed`] | Signature or AEAD tag verification failed |
//! | [`CryptoError::Encryption`] | Encryption failed (rare — usually a bug) |
//! | [`CryptoError::Decryption`] | Decryption failed (ciphertext tampered, wrong key, etc.) |
//! | [`CryptoError::Kdf`] | Key derivation failed (bad params, Argon2 failure, etc.) |
//! | [`CryptoError::Pqc`] | Post-quantum primitive failed |
//! | [`CryptoError::ReedSolomon`] | Error correction encode/decode failed |
//! | [`CryptoError::InvalidParameter`] | Invalid input parameter (empty seed, expired handle, etc.) |
//! | [`CryptoError::Io`] | Underlying I/O error |
//! | [`CryptoError::Serialization`] | Serialization or deserialization failed |
//! | [`CryptoError::Compression`] | Compression or decompression failed |

use std::fmt;

/// Unified error type for cryptographic operations.
///
/// See [module-level documentation](self) for a description of each variant.
#[derive(Debug)]
pub enum CryptoError {
    // ── Key / nonce errors (structured) ──
    /// Key bytes are the wrong length for the algorithm.
    ///
    /// Example: passed 16 bytes to a function expecting a 32-byte key.
    InvalidKeyLength {
        /// Name of the algorithm (e.g. "Ed25519", "Falcon-1024").
        algorithm: &'static str,
        /// Required length in bytes.
        expected: usize,
        /// Actual length received.
        got: usize,
    },

    /// Key is structurally valid in length but fails algorithmic validation.
    ///
    /// Example: Ed25519 public key does not encode a valid curve point,
    /// or Falcon secret key fails deserialization.
    InvalidKey(String),

    /// Nonce bytes are the wrong length.
    InvalidNonceLength {
        /// Name of the algorithm (e.g. "XChaCha20-Poly1305").
        algorithm: &'static str,
        /// Required nonce length in bytes.
        expected: usize,
        /// Actual length received.
        got: usize,
    },

    // ── Verification failures ──
    /// Authentication tag or signature verification failed.
    ///
    /// This is the normal "wrong key / tampered data" error. No further
    /// detail is given to avoid oracle attacks.
    AuthenticationFailed,

    // ── Operation failures (string detail) ──
    /// Encryption failed.
    Encryption(String),

    /// Decryption failed (wrong key, tampered ciphertext, etc.).
    Decryption(String),

    /// Key derivation failed.
    Kdf(String),

    /// Post-quantum primitive operation failed.
    Pqc(String),

    /// Reed-Solomon encode/decode error.
    ReedSolomon(String),

    /// Invalid input parameter.
    InvalidParameter(String),

    /// Serialization or deserialization error.
    Serialization(String),

    /// Compression or decompression error.
    Compression(String),

    /// Underlying I/O error.
    Io(std::io::Error),

    // ── Recovery phrase (unicode_cipher) errors ──
    /// Recovery phrase truncated-SHA-3-256 checksum did not match the
    /// encoded entropy.
    ChecksumMismatch {
        /// Expected checksum bits (`SHA3-256(entropy)[..n_bits]`).
        expected: u32,
        /// Checksum bits decoded from the phrase tail.
        got: u32,
    },

    /// Recovery phrase contained a codepoint whose NFKC canonical form
    /// differs from the input. We strictly reject — silent canonicalization
    /// would enable malleability attacks.
    InvalidNormalization {
        /// The offending codepoint.
        codepoint: char,
        /// Why NFKC canonicalization failed.
        reason: &'static str,
    },

    /// Recovery phrase contained a codepoint from a forbidden class
    /// (ZWJ, Variation Selector, combining mark, BIDI mark,
    /// default-ignorable, or control).
    RejectedCodepointClass {
        /// The offending codepoint.
        codepoint: char,
        /// The forbidden class: "ZWJ" | "VARIATION_SELECTOR"
        /// | "COMBINING_MARK" | "BIDI_MARK" | "DEFAULT_IGNORABLE"
        /// | "CONTROL".
        class: &'static str,
    },

    /// Custom-alphabet phrase would encode fewer than the safety floor
    /// of entropy bits.
    InsufficientEntropy {
        /// Entropy bits the requested phrase would encode.
        got_bits: f64,
        /// Minimum entropy bits required (currently 128).
        required_min: f64,
    },

    /// A recovery-phrase operation failed in a way not captured by the
    /// structured variants above. Reserved for future subclasses.
    RecoveryPhrase(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength {
                algorithm,
                expected,
                got,
            } => write!(
                f,
                "Invalid key length for {algorithm}: expected {expected} bytes, got {got}"
            ),
            CryptoError::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            CryptoError::InvalidNonceLength {
                algorithm,
                expected,
                got,
            } => write!(
                f,
                "Invalid nonce length for {algorithm}: expected {expected} bytes, got {got}"
            ),
            CryptoError::AuthenticationFailed => write!(
                f,
                "Authentication failed (wrong key, tampered data, or invalid signature)"
            ),
            CryptoError::Encryption(msg) => write!(f, "Encryption failed: {msg}"),
            CryptoError::Decryption(msg) => write!(f, "Decryption failed: {msg}"),
            CryptoError::Kdf(msg) => write!(f, "KDF error: {msg}"),
            CryptoError::Pqc(msg) => write!(f, "PQC error: {msg}"),
            CryptoError::ReedSolomon(msg) => write!(f, "Reed-Solomon error: {msg}"),
            CryptoError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
            CryptoError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            CryptoError::Compression(msg) => write!(f, "Compression error: {msg}"),
            CryptoError::Io(err) => write!(f, "I/O error: {err}"),
            CryptoError::ChecksumMismatch { expected, got } => write!(
                f,
                "Recovery phrase checksum mismatch (expected 0x{expected:0width$x}, got 0x{got:0width$x})",
                width = 8
            ),
            CryptoError::InvalidNormalization { codepoint, reason } => write!(
                f,
                "Recovery phrase rejected codepoint U+{:04X}: {reason}",
                *codepoint as u32
            ),
            CryptoError::RejectedCodepointClass { codepoint, class } => write!(
                f,
                "Recovery phrase rejected codepoint U+{:04X}: forbidden class {class}",
                *codepoint as u32
            ),
            CryptoError::InsufficientEntropy { got_bits, required_min } => write!(
                f,
                "Custom alphabet phrase yields {got_bits:.1} bits of entropy, below the {required_min:.1}-bit floor"
            ),
            CryptoError::RecoveryPhrase(msg) => write!(f, "Recovery phrase error: {msg}"),
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

impl Clone for CryptoError {
    fn clone(&self) -> Self {
        match self {
            CryptoError::InvalidKeyLength {
                algorithm,
                expected,
                got,
            } => CryptoError::InvalidKeyLength {
                algorithm,
                expected: *expected,
                got: *got,
            },
            CryptoError::InvalidKey(msg) => CryptoError::InvalidKey(msg.clone()),
            CryptoError::InvalidNonceLength {
                algorithm,
                expected,
                got,
            } => CryptoError::InvalidNonceLength {
                algorithm,
                expected: *expected,
                got: *got,
            },
            CryptoError::AuthenticationFailed => CryptoError::AuthenticationFailed,
            CryptoError::Encryption(msg) => CryptoError::Encryption(msg.clone()),
            CryptoError::Decryption(msg) => CryptoError::Decryption(msg.clone()),
            CryptoError::Kdf(msg) => CryptoError::Kdf(msg.clone()),
            CryptoError::Pqc(msg) => CryptoError::Pqc(msg.clone()),
            CryptoError::ReedSolomon(msg) => CryptoError::ReedSolomon(msg.clone()),
            CryptoError::InvalidParameter(msg) => CryptoError::InvalidParameter(msg.clone()),
            CryptoError::Serialization(msg) => CryptoError::Serialization(msg.clone()),
            CryptoError::Compression(msg) => CryptoError::Compression(msg.clone()),
            CryptoError::Io(err) => {
                CryptoError::Io(std::io::Error::new(err.kind(), err.to_string()))
            }
            CryptoError::ChecksumMismatch { expected, got } => CryptoError::ChecksumMismatch {
                expected: *expected,
                got: *got,
            },
            CryptoError::InvalidNormalization { codepoint, reason } => {
                CryptoError::InvalidNormalization {
                    codepoint: *codepoint,
                    reason,
                }
            }
            CryptoError::RejectedCodepointClass { codepoint, class } => {
                CryptoError::RejectedCodepointClass {
                    codepoint: *codepoint,
                    class,
                }
            }
            CryptoError::InsufficientEntropy {
                got_bits,
                required_min,
            } => CryptoError::InsufficientEntropy {
                got_bits: *got_bits,
                required_min: *required_min,
            },
            CryptoError::RecoveryPhrase(msg) => CryptoError::RecoveryPhrase(msg.clone()),
        }
    }
}

/// Result alias for all fallible operations in this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_key_length_display() {
        let err = CryptoError::InvalidKeyLength {
            algorithm: "Falcon-1024",
            expected: 32,
            got: 16,
        };
        let msg = err.to_string();
        assert!(msg.contains("Falcon-1024"));
        assert!(msg.contains("expected 32"));
        assert!(msg.contains("got 16"));
    }

    #[test]
    fn test_auth_failed_display() {
        let err = CryptoError::AuthenticationFailed;
        assert!(err.to_string().contains("Authentication failed"));
    }

    #[test]
    fn test_clone_roundtrip() {
        let err = CryptoError::InvalidKeyLength {
            algorithm: "Ed25519",
            expected: 32,
            got: 31,
        };
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_io_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated");
        let crypto_err: CryptoError = io_err.into();
        assert!(matches!(crypto_err, CryptoError::Io(_)));
        assert!(crypto_err.to_string().contains("truncated"));
    }
}

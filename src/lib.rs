// SPDX-License-Identifier: OPL-1.1

//! Origin Crypto SDK - Production-Ready Cryptographic Primitives
//!
//! A standalone cryptographic SDK providing post-quantum and classical
//! cryptographic primitives with a unified, developer-friendly API.
//!
//! # Features
//!
//! - **AEAD Encryption**: XChaCha20-Poly1305, ChaCha20-BLAKE3 (committing)
//! - **Key Derivation**: Argon2id with configurable security levels
//! - **Post-Quantum Crypto**: NTRU Prime KEM, Falcon-512/1024 signatures
//! - **Error Correction**: Reed-Solomon with parallel encoding support
//! - **Symmetric Encryption**: Serpent CBC for paranoid mode
//!
//! # Quick Start
//!
//! ## Encrypt Data with ChaCha20-BLAKE3 (Committing AEAD)
//!
//! ```rust
//! use origin_crypto_sdk::{chacha20_blake3, kdf};
//!
//! // Derive key from password
//! let password = b"secure_password";
//! let salt = [1u8; 16];
//! let key = kdf::Argon2id::derive_key(password, &salt, false).unwrap();
//!
//! // Generate nonce and encrypt
//! let nonce = chacha20_blake3::ChaCha20Blake3::generate_nonce();
//! let plaintext = b"Hello, World!";
//! let ciphertext = chacha20_blake3::ChaCha20Blake3::encrypt(&key, &nonce, plaintext, b"").unwrap();
//!
//! // Decrypt
//! let decrypted = chacha20_blake3::ChaCha20Blake3::decrypt(&key, &nonce, &ciphertext, b"").unwrap();
//! assert_eq!(plaintext.to_vec(), decrypted);
//! ```
//!
//! ## Or use XChaCha20-Poly1305 (non-committing, faster)
//!
//! ```rust
//! use origin_crypto_sdk::aead;
//!
//! let key = aead::XChaCha20Poly1305::generate_key();
//! let nonce = aead::generate_nonce();
//! let plaintext = b"Hello, World!";
//! let encrypted = aead::XChaCha20Poly1305::encrypt(&key, &nonce, plaintext).unwrap();
//! ```
//!
//! ## Post-Quantum Signatures with Falcon-512
//!
//! ```rust
//! use origin_crypto_sdk::pqc::falcon512;
//!
//! // Generate keypair from seed
//! let seed = [42u8; 32];
//! let (sk, pk) = falcon512::generate_keypair(seed);
//!
//! // Sign message
//! let message = b"Important message";
//! let signature = falcon512::sign(message, &sk).unwrap();
//!
//! // Verify signature
//! assert!(falcon512::verify(message, &signature, &pk));
//! ```
//!
//! ## NTRU Prime Key Encapsulation
//!
//! ```
//! use origin_crypto_sdk::pqc::ntru_prime;
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
//!
//! // Generate keypair
//! let (pk, sk) = ntru_prime::NtruPrime::generate_keypair(&mut rng);
//!
//! // Encapsulate shared secret
//! let (ciphertext, shared_secret_1) = ntru_prime::NtruPrime::encapsulate(&pk, &mut rng);
//!
//! // Decapsulate
//! let shared_secret_2 = ntru_prime::NtruPrime::decapsulate(&ciphertext, &sk).unwrap();
//!
//! assert_eq!(shared_secret_1, shared_secret_2);
//! ```
//!
//! ## Reed-Solomon Error Correction
//!
//! ```
//! use origin_crypto_sdk::error_correction::ReedSolomonCodec;
//!
//! let codec = ReedSolomonCodec::new(16, 8); // 16 data shards, 8 parity shards
//! let data = b"Important data that needs protection";
//!
//! // Encode
//! let encoded = codec.encode(data).unwrap();
//!
//! // Decode (can recover from up to 8 corrupted shards)
//! let decoded = codec.decode(&encoded).unwrap();
//! assert_eq!(data.to_vec(), decoded);
//! ```
//!
//! # Security Notes
//!
//! - Always use unique nonces for XChaCha20-Poly1305 encryption
//! - Use unique salts for Argon2id key derivation
//! - Store seeds securely for deterministic key generation
//! - Use paranoid mode for high-security applications (slower but more secure)

pub mod aead;
pub mod chacha20_blake3;  // ChaCha20-BLAKE3 AEAD (committing, secure)
pub mod blob;
pub mod compression;
pub mod drbg;
pub mod error;
pub mod error_correction;
pub mod kdf;
pub mod kem;
pub mod mac;
pub mod pqc;
pub mod primitives;
pub mod seed;
pub mod signature;
pub mod signing;
pub mod siphash;
pub mod streaming;
pub mod symmetric;
pub mod validation;

pub use error::{CryptoError, Result};

// Re-export commonly used types
pub use aead::XChaCha20Poly1305;
pub use blob::{create_blob, recover_seed, rotate_blob};
pub use compression::{compress, decompress};
pub use drbg::ChaCha20Drbg;
pub use kdf::Argon2id;
pub use kdf::hkdf::{hkdf_sha3_256, derive_subkeys};
pub use kem::{HybridKem, Ciphertext as HybridCiphertext, SharedSecret as HybridSharedSecret};
pub use mac::hmac_sha3_256;
pub use primitives::{sha3, MemoryTier};
pub use signature::HybridSignature;
pub use siphash::siphash_expand;

// Re-export PQC types
pub use pqc::falcon512::{self as falcon_512, Falcon512PublicKey, Falcon512PrivateKey, Falcon512Signature};
pub use pqc::falcon1024::{self as falcon_1024, FalconPublicKey as Falcon1024PublicKey, FalconPrivateKey as Falcon1024PrivateKey, FalconSignature as Falcon1024Signature};

// Re-export seed, signing, and validation types
pub use seed::{derive_child_seed, derive_signing_keys, derive_verifying_keys, SeedHandle};
pub use signing::{HybridSigningKey, HybridSignatureOutput, HybridVerifyingKey};
pub use validation::{validate_did, validate_info_string};

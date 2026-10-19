// SPDX-License-Identifier: Apache-2.0

//! Prelude — re-exports the most commonly used types.
//!
//! For most users, `use origin_crypto_sdk::prelude::*;` is enough:
//!
//! ```rust
//! use origin_crypto_sdk::prelude::*;
//!
//! let seed = [0x42u8; 32];
//! let bundle = HybridSigningKeyBundle::from_seed(&seed, "my-app")
//!     .expect("valid seed");
//! let sig = bundle.sign_hybrid(b"hello");
//! ```
//!
//! For low-level PQC primitives, import directly from their modules:
//!
//! ```rust,ignore
//! use origin_crypto_sdk::pqc::falcon1024;
//! use origin_crypto_sdk::pqc::ed448;
//! use origin_crypto_sdk::pqc::curve41417::ed41417;
//! ```
//!
//! For SLH-DSA and ML-DSA (feature-gated):
//!
//! ```rust,ignore
//! use origin_crypto_sdk::pqc::slhdsa;
//! use origin_crypto_sdk::pqc::mldsa;
//! ```

// ── Errors ──
pub use crate::error::{CryptoError, Result};

// ── Encryption ──
pub use crate::aead::XChaCha20Poly1305;
pub use crate::chacha20_blake3::ChaCha20Blake3;

// ── Key agreement ──
pub use crate::x25519::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

// ── Key encapsulation (hybrid) ──
pub use crate::kem::hybrid::{
    combine_shared_secrets, X25519NtruCiphertext, X25519NtruKem, X25519NtruPublicKey,
    X25519NtruSecretKey,
};
#[cfg(feature = "ml-kem")]
pub use crate::kem::hybrid::{
    X25519NtruMlKemCiphertext, X25519NtruMlKemKem, X25519NtruMlKemPublicKey,
    X25519NtruMlKemSecretKey,
};

// ── KDF ──
pub use crate::kdf::hkdf::{derive_subkeys, hkdf_sha3_256};
pub use crate::kdf::Argon2id;
pub use crate::kdf::Argon2idBuilder;

// ── MAC ──
pub use crate::kdf::mac::hmac_sha3_256;

// ── Hashes ──
pub use crate::primitives::blake3;
pub use crate::primitives::sha3;
pub use crate::primitives::{MemoryTier, Shake128, Shake256};

// ── DRBG ──
pub use crate::drbg::ChaCha20Drbg;

// ── Seed handling ──
pub use crate::seed::{derive_child_seed, derive_signing_keys, derive_verifying_keys, SeedHandle};

// ── Compression ──
pub use crate::compression::{compress, decompress};

// ── Hybrid signing (recommended default) ──
pub use crate::signing::hybrid::{falcon1024_keygen, HybridSigningKeyBundle};
pub use crate::signing::hybrid::{skein1024, skein512};
pub use crate::signing::wire::HybridSig;

// ── OCRA (RFC 6287) ──
pub use crate::ocra::{ocra, OcraRequest, OcraResponse};

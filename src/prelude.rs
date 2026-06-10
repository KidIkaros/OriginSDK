// SPDX-License-Identifier: OPL-1.1

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

// Errors
pub use crate::error::{CryptoError, Result};

// Encryption
pub use crate::aead::XChaCha20Poly1305;
pub use crate::chacha20_blake3::ChaCha20Blake3;

// KDF
pub use crate::kdf::Argon2id;
pub use crate::kdf::hkdf::{derive_subkeys, hkdf_sha3_256};

// MAC
pub use crate::mac::hmac_sha3_256;

// Hashes
pub use crate::primitives::blake3;
pub use crate::primitives::sha3;
pub use crate::primitives::{MemoryTier, Shake128, Shake256};

// DRBG
pub use crate::drbg::ChaCha20Drbg;

// Seed handling
pub use crate::seed::{SeedHandle, derive_child_seed, derive_signing_keys, derive_verifying_keys};

// SipHash
pub use crate::siphash::siphash_expand;

// Compression
pub use crate::compression::{compress, decompress};

// Signatures — re-exports
pub use crate::signing::{HybridSignatureOutput, HybridSigningKey, HybridVerifyingKey};

// Hybrid bundle (canonical PQ-hybrid signing)
pub use crate::signing::hybrid::{falcon1024_keygen, HybridSigningKeyBundle};
pub use crate::signing::hybrid::{skein1024, skein512};

// PQC direct access — Falcon-1024
pub use crate::pqc::falcon1024::{
    self as falcon_1024, FalconPrivateKey as Falcon1024PrivateKey,
    FalconPublicKey as Falcon1024PublicKey, FalconSignature as Falcon1024Signature,
};

// PQC direct access — Falcon-512 (smaller signatures, ~20x less secure)
pub use crate::pqc::falcon512::{
    self as falcon_512, Falcon512PrivateKey, Falcon512PublicKey, Falcon512Signature,
};

// PQC direct access — SLH-DSA (hash-based, FIPS 205, optional feature)
#[cfg(feature = "slh-dsa")]
pub use crate::pqc::slhdsa::{
    generate_keypair_from_seed as slhdsa_keygen, sign as slhdsa_sign, verify as slhdsa_verify,
    SlhDsaPrivateKey, SlhDsaPublicKey,
};

// PQC direct access — ML-DSA (lattice, FIPS 204, optional feature)
#[cfg(feature = "ml-dsa")]
pub use crate::pqc::mldsa::{MldsaPrivateKey, MldsaPublicKey};

// Ed448 — Curve41417 exposed under the standard name
pub use crate::pqc::curve41417 as ed448;
pub use crate::pqc::curve41417::ed41417 as ed448_raw;

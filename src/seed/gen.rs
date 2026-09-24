// SPDX-License-Identifier: Apache-2.0

//! Multi-hash seed generation with hash diversity.
//!
//! Generates cryptographic seeds by chaining multiple hash families,
//! ported from the cryp Python prototype. Each construction uses two
//! independent hash primitives so that a break in one family does not
//! compromise the seed.
//!
//! # Constructions
//!
//! | Variant             | Chain                              | Output    |
//! |---------------------|------------------------------------|-----------|
//! | `Blake2bShake256`   | keyed-BLAKE2b → SHAKE-256          | 256 bits  |
//! | `Blake2bSha3_256`   | keyed-BLAKE2b → SHA3-256           | 256 bits  |
//! | `Blake2bSha512`     | keyed-BLAKE2b → SHA-512            | 512 bits  |
//! | `Shake256Sha3_256`  | SHAKE-256 → SHA3-256               | 256 bits  |
//!
//! # Quick start
//!
//! ```
//! use origin_crypto_sdk::seed::gen::{generate, SeedVariant};
//!
//! let result = generate(SeedVariant::Blake2bShake256);
//! assert_eq!(result.seed.len(), 32);
//! assert_eq!(result.salt.len(), 16);
//! ```

use crate::error::{CryptoError, Result};
use crate::internal::getrandom;
use crate::internal::zeroize::Zeroize;
use crate::primitives::sha3::{sha3_256, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Seed generation variant — selects the hash chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedVariant {
    /// keyed-BLAKE2b (32 bytes) → SHAKE-256 (32 bytes)
    Blake2bShake256,
    /// keyed-BLAKE2b (32 bytes) → SHA3-256 (32 bytes)
    Blake2bSha3_256,
    /// keyed-BLAKE2b (32 bytes) → SHA-512 truncated to 32 bytes
    Blake2bSha512,
    /// SHAKE-256 (32 bytes) → SHA3-256 (32 bytes)
    Shake256Sha3_256,
}

/// Output of [`generate`].
#[derive(Debug, Clone)]
pub struct GeneratedSeed {
    /// The derived seed bytes.
    pub seed: Vec<u8>,
    /// Randomly generated salt used in derivation.
    pub salt: Vec<u8>,
    /// Which variant produced this seed.
    pub variant: SeedVariant,
}

impl Drop for GeneratedSeed {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a seed using the chosen hash chain.
///
/// Returns `(seed, salt)` where `seed` is 32 bytes and `salt` is 16 bytes
/// unless the variant specifies otherwise.
///
/// # Panics
/// Panics if the OS RNG fails. Use [`try_generate`] for a fallible variant.
pub fn generate(variant: SeedVariant) -> GeneratedSeed {
    try_generate(variant).expect("OS RNG failed")
}

/// Generate a seed using the chosen hash chain, returning an error on
/// OS RNG failure.
pub fn try_generate(variant: SeedVariant) -> Result<GeneratedSeed> {
    try_generate_with_entropy(variant, None)
}

/// Generate a seed, optionally using caller-supplied entropy (for testing).
///
/// When `entropy` is `None`, fresh random bytes are drawn from the OS RNG.
///
/// # Panics
/// Panics if the OS RNG fails (unreachable when `entropy` is `Some`).
/// Use [`try_generate_with_entropy`] for a fallible variant.
pub fn generate_with_entropy(variant: SeedVariant, entropy: Option<&[u8]>) -> GeneratedSeed {
    try_generate_with_entropy(variant, entropy).expect("OS RNG failed")
}

/// Generate a seed, optionally using caller-supplied entropy, returning an
/// error on OS RNG failure.
///
/// Caller-supplied `entropy` of any length is hash-compressed with
/// SHA3-256 into the 32-byte key pool — it is never truncated or silently
/// replaced.
pub fn try_generate_with_entropy(
    variant: SeedVariant,
    entropy: Option<&[u8]>,
) -> Result<GeneratedSeed> {
    // Key material: 32 bytes of randomness, or caller-supplied entropy
    // compressed with a domain tag so it stays distinct from the msg pool
    // (sha3_256(e) below). The pre-0.7.x code fed raw bytes through
    // try_into::<[u8; 32]>, which silently produced an all-zero key
    // whenever the entropy length differed from 32.
    const ENTROPY_KEY_DOMAIN: &[u8] = b"seed-gen-key";
    let mut key_bytes: [u8; 32] = match entropy {
        Some(e) => sha3_256(&[e, ENTROPY_KEY_DOMAIN].concat()),
        None => {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf).map_err(|e| CryptoError::Io(std::io::Error::other(e)))?;
            buf
        }
    };

    // Message material: 32 bytes of randomness
    let mut msg_bytes = if let Some(e) = entropy {
        // Derive a second pool via SHA3-256 to avoid reusing the same bytes
        sha3_256(e).to_vec()
    } else {
        let mut buf = vec![0u8; 32];
        getrandom::fill(&mut buf).map_err(|e| CryptoError::Io(std::io::Error::other(e)))?;
        buf
    };

    // Salt: 16 bytes
    let mut salt = [0u8; 16];
    if let Some(e) = entropy {
        // Derive salt from entropy too for deterministic testing
        let salt_input = [0xDEu8; 16]; // domain separator
        let hash = sha3_256(&[e, &salt_input[..]].concat());
        salt.copy_from_slice(&hash[..16]);
    } else {
        getrandom::fill(&mut salt).map_err(|e| CryptoError::Io(std::io::Error::other(e)))?;
    }

    let seed = match variant {
        SeedVariant::Blake2bShake256 => {
            // Round 1: keyed-BLAKE2b
            let blake_hash = blake3::keyed_hash(&key_bytes, &msg_bytes);

            // Round 2: SHAKE-256
            let mut hasher = Shake256::default();
            hasher.update(blake_hash.as_bytes());
            hasher.update(&salt);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 32];
            reader.read(&mut out);
            out.to_vec()
        }

        SeedVariant::Blake2bSha3_256 => {
            // Round 1: keyed-BLAKE2b
            let blake_hash = blake3::keyed_hash(&key_bytes, &msg_bytes);

            // Round 2: SHA3-256
            let mut input = Vec::with_capacity(32 + 16);
            input.extend_from_slice(blake_hash.as_bytes());
            input.extend_from_slice(&salt);
            sha3_256(&input).to_vec()
        }

        SeedVariant::Blake2bSha512 => {
            // Round 1: keyed-BLAKE2b
            let blake_hash = blake3::keyed_hash(&key_bytes, &msg_bytes);

            // Round 2: SHA-512, truncate to 32 bytes (256 bits)
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(blake_hash.as_bytes());
            hasher.update(&salt);
            let hash = hasher.finalize();
            hash[..32].to_vec()
        }

        SeedVariant::Shake256Sha3_256 => {
            // Round 1: SHAKE-256
            let mut hasher = Shake256::default();
            hasher.update(&key_bytes);
            hasher.update(&msg_bytes);
            let mut reader = hasher.finalize_xof();
            let mut shake_out = [0u8; 32];
            reader.read(&mut shake_out);

            // Round 2: SHA3-256
            let mut input = Vec::with_capacity(32 + 16);
            input.extend_from_slice(&shake_out);
            input.extend_from_slice(&salt);
            sha3_256(&input).to_vec()
        }
    };

    // Wipe intermediate material
    key_bytes.zeroize();
    msg_bytes.zeroize();

    Ok(GeneratedSeed {
        seed,
        salt: salt.to_vec(),
        variant,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let entropy = [0xABu8; 64];
        for &variant in &[
            SeedVariant::Blake2bShake256,
            SeedVariant::Blake2bSha3_256,
            SeedVariant::Blake2bSha512,
            SeedVariant::Shake256Sha3_256,
        ] {
            let a = generate_with_entropy(variant, Some(&entropy));
            let b = generate_with_entropy(variant, Some(&entropy));
            assert_eq!(a.seed, b.seed, "determinism failed for {variant:?}");
        }
    }

    #[test]
    fn all_variants_produce_32_bytes() {
        for &variant in &[
            SeedVariant::Blake2bShake256,
            SeedVariant::Blake2bSha3_256,
            SeedVariant::Blake2bSha512,
            SeedVariant::Shake256Sha3_256,
        ] {
            let gen = generate(variant);
            assert_eq!(gen.seed.len(), 32, "seed length for {variant:?}");
            assert_eq!(gen.salt.len(), 16, "salt length for {variant:?}");
        }
    }

    #[test]
    fn different_variants_produce_different_seeds() {
        let entropy = [0x42u8; 64];
        let variants = [
            SeedVariant::Blake2bShake256,
            SeedVariant::Blake2bSha3_256,
            SeedVariant::Blake2bSha512,
            SeedVariant::Shake256Sha3_256,
        ];
        let seeds: Vec<Vec<u8>> = variants
            .iter()
            .map(|v| generate_with_entropy(*v, Some(&entropy)).seed.clone())
            .collect();

        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(
                    seeds[i], seeds[j],
                    "variants {i} and {j} produced same seed"
                );
            }
        }
    }

    #[test]
    fn randomness() {
        // Two random seeds must differ (probability of collision ~2^{-256})
        let a = generate(SeedVariant::Blake2bShake256);
        let b = generate(SeedVariant::Blake2bShake256);
        assert_ne!(a.seed, b.seed);
    }
}

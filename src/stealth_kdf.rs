// SPDX-License-Identifier: OPL-1.1

//! Stealth key derivation module.
//!
//! Derives stealth address master keys from a SeedHandle using HKDF-SHA3-256.
//! Each stealth address gets a unique set of viewing, spending, and ephemeral
//! keys derived from the master keys at a specific index.
//!
//! # When to use
//!
//! Use this when building privacy-preserving payment or identity systems where
//! recipients need unlinkable addresses derived from a single master key.
//!
//! For general-purpose key derivation, use [`hkdf_sha3_256`](crate::kdf::hkdf::hkdf_sha3_256)
//! or [`derive_child_seed`](crate::seed::derive_child_seed) instead.
//!
//! # Security
//!
//! - All keys are derived via HKDF-SHA3-256 with domain separation
//! - Different indices produce computationally independent keys
//! - Viewing and spending keys are derived from separate domains
//!
//! See also: [`stealth_pow`](crate::stealth_pow), [`seed`](crate::seed).

use crate::error::{CryptoError, Result};
use crate::kdf::hkdf::hkdf_sha3_256;
use crate::seed::SeedHandle;

/// Master keys for stealth address derivation.
#[derive(Debug, Clone)]
pub struct StealthMasterKeys {
    /// Master viewing key (for deriving per-address viewing secrets).
    pub viewing: [u8; 32],
    /// Master spending key (for deriving per-address spending secrets).
    pub spending: [u8; 32],
    /// Master ephemeral key (for deriving per-address ephemeral secrets).
    pub ephemeral: [u8; 32],
}

/// Per-address stealth keys derived at a specific index.
#[derive(Debug, Clone)]
pub struct StealthAddressKeys {
    /// Viewing secret key for this address.
    pub viewing_secret: [u8; 32],
    /// Spending secret key for this address.
    pub spending_secret: [u8; 32],
    /// Ephemeral secret key for this address.
    pub ephemeral_secret: [u8; 32],
}

/// Derive stealth master keys from a seed handle.
///
/// Uses three separate HKDF derivations with domain separation:
/// - Viewing:   HKDF(seed, salt="stealth:viewing:master",   info="origin-stealth-v1")
/// - Spending:  HKDF(seed, salt="stealth:spending:master",  info="origin-stealth-v1")
/// - Ephemeral: HKDF(seed, salt="stealth:ephemeral:master", info="origin-stealth-v1")
pub fn derive_stealth_master(seed: &SeedHandle) -> Result<StealthMasterKeys> {
    let seed_bytes = seed
        .as_bytes()
        .ok_or_else(|| CryptoError::InvalidParameter("Seed handle expired".into()))?;

    let mut viewing = [0u8; 32];
    let mut spending = [0u8; 32];
    let mut ephemeral = [0u8; 32];

    hkdf_sha3_256(
        seed_bytes,
        Some(b"stealth:viewing:master"),
        b"origin-stealth-v1",
        &mut viewing,
    )?;
    hkdf_sha3_256(
        seed_bytes,
        Some(b"stealth:spending:master"),
        b"origin-stealth-v1",
        &mut spending,
    )?;
    hkdf_sha3_256(
        seed_bytes,
        Some(b"stealth:ephemeral:master"),
        b"origin-stealth-v1",
        &mut ephemeral,
    )?;

    Ok(StealthMasterKeys {
        viewing,
        spending,
        ephemeral,
    })
}

/// Derive stealth address keys at a specific index from master keys.
///
/// Each key is derived as:
/// HKDF(master_key, salt=index_be_bytes || context, info="stealth-derive-v1")
pub fn derive_stealth_at_index(
    master: &StealthMasterKeys,
    index: u64,
) -> Result<StealthAddressKeys> {
    let index_bytes = index.to_be_bytes();

    let mut viewing_secret = [0u8; 32];
    let mut spending_secret = [0u8; 32];
    let mut ephemeral_secret = [0u8; 32];

    // Viewing: salt = index || "viewing"
    let mut salt_v = [0u8; 40];
    salt_v[0..8].copy_from_slice(&index_bytes);
    salt_v[8..15].copy_from_slice(b"viewing");
    hkdf_sha3_256(
        &master.viewing,
        Some(&salt_v),
        b"stealth-derive-v1",
        &mut viewing_secret,
    )?;

    // Spending: salt = index || "spending"
    let mut salt_s = [0u8; 40];
    salt_s[0..8].copy_from_slice(&index_bytes);
    salt_s[8..16].copy_from_slice(b"spending");
    hkdf_sha3_256(
        &master.spending,
        Some(&salt_s),
        b"stealth-derive-v1",
        &mut spending_secret,
    )?;

    // Ephemeral: salt = index || "ephemeral"
    let mut salt_e = [0u8; 40];
    salt_e[0..8].copy_from_slice(&index_bytes);
    salt_e[8..17].copy_from_slice(b"ephemeral");
    hkdf_sha3_256(
        &master.ephemeral,
        Some(&salt_e),
        b"stealth-derive-v1",
        &mut ephemeral_secret,
    )?;

    Ok(StealthAddressKeys {
        viewing_secret,
        spending_secret,
        ephemeral_secret,
    })
}

/// Derive stealth keys directly from a seed at a specific index.
///
/// Convenience function that combines `derive_stealth_master` and
/// `derive_stealth_at_index`.
pub fn derive_stealth_from_seed(seed: &SeedHandle, index: u64) -> Result<StealthAddressKeys> {
    let master = derive_stealth_master(seed)?;
    derive_stealth_at_index(&master, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_derive_stealth_master_deterministic() {
        let seed = SeedHandle::new(&[42u8; 32], None);
        let master1 = derive_stealth_master(&seed).unwrap();
        let master2 = derive_stealth_master(&seed).unwrap();

        assert_eq!(master1.viewing, master2.viewing);
        assert_eq!(master1.spending, master2.spending);
        assert_eq!(master1.ephemeral, master2.ephemeral);
    }

    #[test]
    fn test_different_seeds_different_masters() {
        let seed1 = SeedHandle::new(&[1u8; 32], None);
        let seed2 = SeedHandle::new(&[2u8; 32], None);

        let master1 = derive_stealth_master(&seed1).unwrap();
        let master2 = derive_stealth_master(&seed2).unwrap();

        assert_ne!(master1.viewing, master2.viewing);
        assert_ne!(master1.spending, master2.spending);
        assert_ne!(master1.ephemeral, master2.ephemeral);
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = SeedHandle::new(&[42u8; 32], None);
        let master = derive_stealth_master(&seed).unwrap();

        let keys0 = derive_stealth_at_index(&master, 0).unwrap();
        let keys1 = derive_stealth_at_index(&master, 1).unwrap();
        let keys2 = derive_stealth_at_index(&master, 2).unwrap();

        assert_ne!(keys0.viewing_secret, keys1.viewing_secret);
        assert_ne!(keys1.viewing_secret, keys2.viewing_secret);
        assert_ne!(keys0.spending_secret, keys1.spending_secret);
        assert_ne!(keys0.ephemeral_secret, keys1.ephemeral_secret);
    }

    #[test]
    fn test_derive_at_index_deterministic() {
        let seed = SeedHandle::new(&[42u8; 32], None);
        let master = derive_stealth_master(&seed).unwrap();

        let keys_a = derive_stealth_at_index(&master, 5).unwrap();
        let keys_b = derive_stealth_at_index(&master, 5).unwrap();

        assert_eq!(keys_a.viewing_secret, keys_b.viewing_secret);
        assert_eq!(keys_a.spending_secret, keys_b.spending_secret);
        assert_eq!(keys_a.ephemeral_secret, keys_b.ephemeral_secret);
    }

    #[test]
    fn test_derive_from_seed_convenience() {
        let seed = SeedHandle::new(&[42u8; 32], None);

        let direct = derive_stealth_from_seed(&seed, 3).unwrap();
        let master = derive_stealth_master(&seed).unwrap();
        let stepped = derive_stealth_at_index(&master, 3).unwrap();

        assert_eq!(direct.viewing_secret, stepped.viewing_secret);
        assert_eq!(direct.spending_secret, stepped.spending_secret);
        assert_eq!(direct.ephemeral_secret, stepped.ephemeral_secret);
    }

    #[test]
    fn test_expired_seed_fails() {
        let seed = SeedHandle::new(&[42u8; 32], Some(Duration::from_nanos(1)));
        // Let it expire
        std::thread::sleep(Duration::from_millis(10));
        assert!(derive_stealth_master(&seed).is_err());
    }

    #[test]
    fn test_master_keys_are_different_from_each_other() {
        let seed = SeedHandle::new(&[42u8; 32], None);
        let master = derive_stealth_master(&seed).unwrap();

        // The three master keys should all be different
        assert_ne!(master.viewing, master.spending);
        assert_ne!(master.viewing, master.ephemeral);
        assert_ne!(master.spending, master.ephemeral);
    }

    #[test]
    fn test_large_index() {
        let seed = SeedHandle::new(&[42u8; 32], None);
        let master = derive_stealth_master(&seed).unwrap();

        let keys = derive_stealth_at_index(&master, u64::MAX).unwrap();
        // Should not panic and should produce valid-looking keys
        assert!(keys.viewing_secret.iter().any(|&b| b != 0));
    }
}

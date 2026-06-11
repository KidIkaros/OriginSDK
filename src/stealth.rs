// SPDX-License-Identifier: OPL-1.1

//! Stealth address primitives.
//!
//! # Submodules
//!
//! - [`kdf`] — Key derivation (master keys + per-index subkeys)
//! - [`pow`] — Hashcash-based proof-of-work to rate-limit enumeration

pub mod kdf {
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

}

pub mod pow {
    use crate::error::{CryptoError, Result};
    use crate::primitives::sha3::sha3_256;

    /// Configuration for the stealth PoW system.
    #[derive(Debug, Clone)]
    pub struct StealthPowConfig {
        /// Base difficulty (leading zero bits required). Default: 20.
        pub base_difficulty: u32,
        /// Difficulty increment per address generated. Default: 0.
        pub per_address_increment: u32,
        /// Maximum difficulty cap. Default: 32.
        pub max_difficulty: u32,
    }

    impl Default for StealthPowConfig {
        fn default() -> Self {
            Self {
                base_difficulty: 20,
                per_address_increment: 0,
                max_difficulty: 32,
            }
        }
    }

    /// A proof-of-work solution for stealth address generation.
    #[derive(Debug, Clone)]
    pub struct StealthPowProof {
        /// The nonce that satisfies the difficulty requirement.
        pub nonce: [u8; 32],
        /// Extra data (can be used for additional binding).
        pub extra: [u8; 16],
        /// Counter incremented during mining.
        pub counter: u64,
        /// The difficulty this proof was mined at.
        pub difficulty: u32,
    }

    /// Solve the Hashcash PoW for stealth address generation.
    ///
    /// # Arguments
    /// * `identity_pk`     — The identity's public key (for binding)
    /// * `destination_hint` — A hint about the destination (e.g., recipient's pubkey hash)
    /// * `difficulty`      — Number of leading zero bits required
    ///
    /// # Returns
    /// A `StealthPowProof` and the number of hash iterations performed.
    pub fn solve(
        identity_pk: &[u8],
        destination_hint: &[u8],
        difficulty: u32,
    ) -> Result<(StealthPowProof, u64)> {
        if difficulty == 0 {
            // Trivial: any nonce works
            let nonce = [0u8; 32];
            let extra = [0u8; 16];
            return Ok((
                StealthPowProof {
                    nonce,
                    extra,
                    counter: 0,
                    difficulty: 0,
                },
                0,
            ));
        }

        if difficulty > 32 {
            return Err(CryptoError::InvalidParameter(
                "Difficulty cannot exceed 32 bits".into(),
            ));
        }

        let target = compute_target(difficulty);
        let mut counter: u64 = 0;
        let mut nonce = [0u8; 32];
        let mut extra = [0u8; 16];

        // Use a deterministic but varied starting nonce
        let mut seed_input = Vec::with_capacity(16 + identity_pk.len() + destination_hint.len());
        seed_input.extend_from_slice(b"stealth-pow-seed");
        seed_input.extend_from_slice(identity_pk);
        seed_input.extend_from_slice(destination_hint);
        let seed_hash = sha3_256(&seed_input);
        nonce.copy_from_slice(&seed_hash);
        extra.copy_from_slice(&seed_hash[0..16]);

        loop {
            let hash = compute_hash(identity_pk, destination_hint, &nonce, &extra, counter);

            if meets_target(&hash, &target, difficulty) {
                return Ok((
                    StealthPowProof {
                        nonce,
                        extra,
                        counter,
                        difficulty,
                    },
                    counter + 1,
                ));
            }

            counter += 1;

            // Increment nonce as a big-endian counter (wraps around)
            for i in (0..32).rev() {
                if nonce[i] == 0xff {
                    nonce[i] = 0;
                } else {
                    nonce[i] += 1;
                    break;
                }
            }

            // Safety: prevent infinite loops in test environments
            if counter > 100_000_000 {
                return Err(CryptoError::InvalidParameter(
                    "PoW solve exceeded maximum iterations".into(),
                ));
            }
        }
    }

    /// Verify a stealth PoW proof.
    ///
    /// # Arguments
    /// * `proof`           — The proof to verify
    /// * `identity_pk`     — The identity's public key
    /// * `destination_hint` — The destination hint used during solving
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid at the claimed difficulty.
    pub fn verify(
        proof: &StealthPowProof,
        identity_pk: &[u8],
        destination_hint: &[u8],
    ) -> Result<bool> {
        if proof.difficulty == 0 {
            return Ok(true);
        }

        if proof.difficulty > 32 {
            return Ok(false);
        }

        let target = compute_target(proof.difficulty);
        let hash = compute_hash(
            identity_pk,
            destination_hint,
            &proof.nonce,
            &proof.extra,
            proof.counter,
        );

        Ok(meets_target(&hash, &target, proof.difficulty))
    }

    /// Compute the effective difficulty for a given address index.
    pub fn effective_difficulty(config: &StealthPowConfig, address_index: u64) -> u32 {
        let effective = config.base_difficulty + config.per_address_increment * address_index as u32;
        effective.min(config.max_difficulty)
    }

    // --- Internal functions ---

    fn compute_hash(
        identity_pk: &[u8],
        destination_hint: &[u8],
        nonce: &[u8; 32],
        extra: &[u8; 16],
        counter: u64,
    ) -> [u8; 32] {
        let mut input =
            Vec::with_capacity(14 + identity_pk.len() + destination_hint.len() + 32 + 16 + 8);
        input.extend_from_slice(b"stealth-pow-v1");
        input.extend_from_slice(identity_pk);
        input.extend_from_slice(destination_hint);
        input.extend_from_slice(nonce);
        input.extend_from_slice(extra);
        input.extend_from_slice(&counter.to_be_bytes());
        sha3_256(&input)
    }

    fn compute_target(difficulty: u32) -> [u8; 32] {
        let mut target = [0xffu8; 32];
        let full_bytes = (difficulty / 8) as usize;
        let remaining_bits = difficulty % 8;

        for i in 0..full_bytes {
            target[i] = 0x00;
        }

        if full_bytes < 32 && remaining_bits > 0 {
            let mask = 0xffu8 >> remaining_bits;
            target[full_bytes] = mask;
        }

        target
    }

    fn meets_target(hash: &[u8; 32], _target: &[u8; 32], difficulty: u32) -> bool {
        let full_bytes = (difficulty / 8) as usize;
        let remaining_bits = difficulty % 8;

        // Check full zero bytes
        for i in 0..full_bytes {
            if hash[i] != 0x00 {
                return false;
            }
        }

        // Check remaining bits
        if full_bytes < 32 && remaining_bits > 0 {
            let mask = 0xffu8 >> remaining_bits;
            if hash[full_bytes] & mask != 0 {
                return false;
            }
        }

        true
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_solve_verify_roundtrip() {
            let pk = [42u8; 32];
            let hint = b"destination hint";
            let difficulty = 16; // Low difficulty for fast tests

            let (proof, iterations) = solve(&pk, hint, difficulty).unwrap();
            assert!(iterations > 0 || difficulty == 0);
            assert_eq!(proof.difficulty, difficulty);

            assert!(verify(&proof, &pk, hint).unwrap());
        }

        #[test]
        fn test_verify_wrong_pk_fails() {
            let pk = [42u8; 32];
            let wrong_pk = [99u8; 32];
            let hint = b"hint";
            let difficulty = 16;

            let (proof, _) = solve(&pk, hint, difficulty).unwrap();
            assert!(!verify(&proof, &wrong_pk, hint).unwrap());
        }

        #[test]
        fn test_verify_wrong_hint_fails() {
            let pk = [42u8; 32];
            let hint = b"correct hint";
            let wrong_hint = b"wrong hint";
            let difficulty = 16;

            let (proof, _) = solve(&pk, hint, difficulty).unwrap();
            assert!(!verify(&proof, &pk, wrong_hint).unwrap());
        }

        #[test]
        fn test_zero_difficulty_always_valid() {
            let pk = [42u8; 32];
            let hint = b"hint";

            let (proof, iterations) = solve(&pk, hint, 0).unwrap();
            assert_eq!(iterations, 0);
            assert!(verify(&proof, &pk, hint).unwrap());
        }

        #[test]
        fn test_difficulty_scaling() {
            let pk = [42u8; 32];
            let hint = b"hint";

            // Higher difficulty should take more iterations
            let (_, iters_12) = solve(&pk, hint, 12).unwrap();
            let (_, iters_16) = solve(&pk, hint, 16).unwrap();
            // Not guaranteed but very likely
            assert!(
                iters_16 >= iters_12,
                "Higher difficulty should take >= iterations"
            );
        }

        #[test]
        fn test_effective_difficulty() {
            let config = StealthPowConfig {
                base_difficulty: 20,
                per_address_increment: 1,
                max_difficulty: 25,
            };

            assert_eq!(effective_difficulty(&config, 0), 20);
            assert_eq!(effective_difficulty(&config, 3), 23);
            assert_eq!(effective_difficulty(&config, 10), 25); // Capped at max
        }

        #[test]
        fn test_different_proofs_for_different_inputs() {
            let pk1 = [1u8; 32];
            let pk2 = [2u8; 32];
            let hint = b"same hint";
            let difficulty = 16;

            let (proof1, _) = solve(&pk1, hint, difficulty).unwrap();
            let (proof2, _) = solve(&pk2, hint, difficulty).unwrap();

            // Nonces should be different (derived from different seeds)
            assert_ne!(proof1.nonce, proof2.nonce);
        }
    }

}
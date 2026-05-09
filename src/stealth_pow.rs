// SPDX-License-Identifier: OPL-1.1

//! Hashcash-based proof-of-work for stealth address generation.
//!
//! Makes stealth address enumeration computationally expensive, preventing
//! an attacker from scanning the entire address space to find all stealth
//! addresses belonging to an identity.
//!
//! # Algorithm
//!
//! Given an identity's public key and a destination hint, find a nonce `n`
//! such that `SHA3-256(pubkey || hint || nonce || counter)` has at least
//! `difficulty` leading zero bits.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::error::{CryptoError, Result};

/// Configuration for the stealth PoW system.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let mut hasher = Sha3_256::new();
    hasher.update(b"stealth-pow-seed");
    hasher.update(identity_pk);
    hasher.update(destination_hint);
    let seed_hash: [u8; 32] = hasher.finalize().into();
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
    let effective = config.base_difficulty
        + config.per_address_increment * address_index as u32;
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
    let mut hasher = Sha3_256::new();
    hasher.update(b"stealth-pow-v1");
    hasher.update(identity_pk);
    hasher.update(destination_hint);
    hasher.update(nonce);
    hasher.update(extra);
    hasher.update(&counter.to_be_bytes());
    hasher.finalize().into()
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
        assert!(iters_16 >= iters_12, "Higher difficulty should take >= iterations");
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
    fn test_proof_serialization() {
        let pk = [42u8; 32];
        let hint = b"serialization test";
        let difficulty = 14;

        let (proof, _) = solve(&pk, hint, difficulty).unwrap();
        let json = serde_json::to_vec(&proof).unwrap();
        let restored: StealthPowProof = serde_json::from_slice(&json).unwrap();

        assert!(verify(&restored, &pk, hint).unwrap());
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

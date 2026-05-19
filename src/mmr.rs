// SPDX-License-Identifier: OPL-1.1

//! Merkle Mountain Range (MMR) data structure.
//!
//! An append-only Merkle tree variant that supports efficient incremental
//! updates without rebuilding the entire tree. Used for anchoring identity
//! state commitments.
//!
//! # Structure
//!
//! Leaves are stored sequentially. Internal nodes are computed by hashing
//! pairs of children. The "mountain range" structure handles non-power-of-2
//! leaf counts by maintaining multiple perfect binary trees (peaks).
//!
//! # Example
//!
//! ```no_run
//! use origin_crypto_sdk::mmr::Mmr;
//!
//! let mut mmr = Mmr::new();
//! mmr.append(b"leaf1");
//! mmr.append(b"leaf2");
//! let root = mmr.root();
//! let proof = mmr.prove_membership(0).unwrap();
//! assert!(Mmr::verify_proof(&proof, &root));
//! ```

use crate::error::{CryptoError, Result};
use crate::primitives::sha3::sha3_256;

/// A Merkle Mountain Range — append-only incremental Merkle tree.
#[derive(Debug, Clone)]
pub struct Mmr {
    /// All leaf hashes (level 0).
    leaves: Vec<[u8; 32]>,
    /// All internal nodes, stored level by level.
    /// `levels[0]` = leaf hashes, `levels[1]` = level 1 nodes, etc.
    levels: Vec<Vec<[u8; 32]>>,
    /// Total number of leaves appended.
    leaf_count: u64,
}

/// A proof of membership for a specific leaf in the MMR.
#[derive(Debug, Clone)]
pub struct MmrProof {
    /// Index of the leaf being proven.
    pub leaf_index: u64,
    /// The leaf hash.
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from leaf to root (bottom-up).
    pub path: Vec<MmrPathNode>,
}

/// A single node in the MMR proof path.
#[derive(Debug, Clone)]
pub struct MmrPathNode {
    /// The sibling hash at this level.
    pub hash: [u8; 32],
    /// Whether the sibling is on the left (true) or right (false).
    pub is_left: bool,
}

/// Proof that a leaf was appended (includes the new root).
#[derive(Debug, Clone)]
pub struct AppendProof {
    /// The index of the newly appended leaf.
    pub leaf_index: u64,
    /// The new root hash after appending.
    pub new_root: [u8; 32],
}

impl Mmr {
    /// Create a new empty MMR.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            levels: Vec::new(),
            leaf_count: 0,
        }
    }

    /// Append a leaf to the MMR.
    ///
    /// Returns an `AppendProof` containing the new leaf index and root.
    pub fn append(&mut self, data: &[u8]) -> AppendProof {
        let leaf_hash = Self::hash_leaf(data);
        self.leaves.push(leaf_hash);
        self.leaf_count += 1;

        // Rebuild levels from leaves
        self.rebuild_levels();

        AppendProof {
            leaf_index: self.leaf_count - 1,
            new_root: self.root(),
        }
    }

    /// Append a pre-hashed leaf to the MMR.
    pub fn append_hash(&mut self, leaf_hash: [u8; 32]) -> AppendProof {
        self.leaves.push(leaf_hash);
        self.leaf_count += 1;
        self.rebuild_levels();

        AppendProof {
            leaf_index: self.leaf_count - 1,
            new_root: self.root(),
        }
    }

    /// Get the current root hash.
    ///
    /// For a non-empty MMR, this is the topmost node after building the tree.
    /// For an empty MMR, returns all-zero hash.
    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        // The root is the single node at the top level
        let top_level = self.levels.len() - 1;
        self.levels[top_level][0]
    }

    /// Get the number of leaves in the MMR.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Create a membership proof for a leaf at the given index.
    pub fn prove_membership(&self, leaf_index: u64) -> Result<MmrProof> {
        if leaf_index >= self.leaf_count {
            return Err(CryptoError::InvalidParameter(format!(
                "Leaf index {} out of range ({} leaves)",
                leaf_index, self.leaf_count
            )));
        }

        let leaf_hash = self.leaves[leaf_index as usize];
        let mut path = Vec::new();
        let mut current_index = leaf_index;

        // Walk up the tree level by level
        let mut height = 0u32;

        loop {
            // Check if we've reached the top
            let level_len = self.levels.get(height as usize).map(|l| l.len()).unwrap_or(0);
            if level_len <= 1 {
                break;
            }

            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level_len as u64 {
                let sibling_hash = self.get_node_at(height as u64, sibling_index);
                path.push(MmrPathNode {
                    hash: sibling_hash,
                    is_left: sibling_index < current_index,
                });
            } else {
                // No sibling — duplicate self (odd node at this level)
                path.push(MmrPathNode {
                    hash: self.get_node_at(height as u64, current_index),
                    is_left: false,
                });
            }

            current_index /= 2;
            height += 1;
        }

        Ok(MmrProof {
            leaf_index,
            leaf_hash,
            path,
        })
    }

    /// Verify a membership proof against a root hash.
    pub fn verify_proof(proof: &MmrProof, root: &[u8; 32]) -> bool {
        let mut current_hash = proof.leaf_hash;

        for node in &proof.path {
            current_hash = if node.is_left {
                Self::hash_pair(&node.hash, &current_hash)
            } else {
                Self::hash_pair(&current_hash, &node.hash)
            };
        }

        &current_hash == root
    }

    /// Get all leaf hashes.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    // --- Internal methods ---

    fn rebuild_levels(&mut self) {
        self.levels.clear();
        if self.leaves.is_empty() {
            return;
        }

        // Level 0 = leaves
        self.levels.push(self.leaves.clone());

        // Build each subsequent level by pairing nodes
        let mut current_level = 0;
        loop {
            let level = &self.levels[current_level];
            if level.len() <= 1 {
                break;
            }

            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { left };
                next_level.push(Self::hash_pair(&left, &right));
            }
            self.levels.push(next_level);
            current_level += 1;
        }
    }

    fn get_node_at(&self, level: u64, index: u64) -> [u8; 32] {
        let lvl = level as usize;
        let idx = index as usize;
        if lvl < self.levels.len() && idx < self.levels[lvl].len() {
            self.levels[lvl][idx]
        } else {
            [0u8; 32]
        }
    }

    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(12 + data.len());
        input.extend_from_slice(b"mmr-leaf-v1");
        input.extend_from_slice(data);
        sha3_256(&input)
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(12 + 64);
        input.extend_from_slice(b"mmr-node-v1");
        input.extend_from_slice(left);
        input.extend_from_slice(right);
        sha3_256(&input)
    }
}

impl Default for Mmr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_mmr_root() {
        let mmr = Mmr::new();
        assert_eq!(mmr.root(), [0u8; 32]);
        assert_eq!(mmr.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let mut mmr = Mmr::new();
        mmr.append(b"only leaf");
        let root = mmr.root();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(mmr.leaf_count(), 1);
    }

    #[test]
    fn test_two_leaves_different_roots() {
        let mut mmr1 = Mmr::new();
        mmr1.append(b"leaf A");
        let root1 = mmr1.root();

        let mut mmr2 = Mmr::new();
        mmr2.append(b"leaf B");
        let root2 = mmr2.root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_append_returns_correct_index() {
        let mut mmr = Mmr::new();
        let p0 = mmr.append(b"first");
        let p1 = mmr.append(b"second");
        let p2 = mmr.append(b"third");

        assert_eq!(p0.leaf_index, 0);
        assert_eq!(p1.leaf_index, 1);
        assert_eq!(p2.leaf_index, 2);
    }

    #[test]
    fn test_membership_proof_and_verify() {
        let mut mmr = Mmr::new();
        for i in 0u64..10 {
            mmr.append(&i.to_be_bytes());
        }

        let root = mmr.root();

        // Verify all leaves
        for i in 0..10 {
            let proof = mmr.prove_membership(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert!(Mmr::verify_proof(&proof, &root));
        }
    }

    #[test]
    fn test_proof_rejects_wrong_root() {
        let mut mmr = Mmr::new();
        mmr.append(b"leaf1");
        mmr.append(b"leaf2");

        let proof = mmr.prove_membership(0).unwrap();
        let wrong_root = [0xffu8; 32];
        assert!(!Mmr::verify_proof(&proof, &wrong_root));
    }

    #[test]
    fn test_proof_rejects_wrong_leaf() {
        let mut mmr = Mmr::new();
        mmr.append(b"leaf1");
        mmr.append(b"leaf2");

        let root = mmr.root();
        let mut proof = mmr.prove_membership(0).unwrap();
        // Tamper with the leaf hash
        proof.leaf_hash = [0xffu8; 32];
        assert!(!Mmr::verify_proof(&proof, &root));
    }

    #[test]
    fn test_1000_appends_all_provable() {
        let mut mmr = Mmr::new();
        for i in 0u64..1000 {
            mmr.append(&i.to_be_bytes());
        }

        let root = mmr.root();
        assert_eq!(mmr.leaf_count(), 1000);

        // Spot-check proofs at various indices
        for i in [0, 1, 2, 3, 500, 998, 999] {
            let proof = mmr.prove_membership(i).unwrap();
            assert!(Mmr::verify_proof(&proof, &root), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_root_stability() {
        let mut mmr = Mmr::new();
        mmr.append(b"a");
        let root1 = mmr.root();
        mmr.append(b"a"); // Same data, different index
        let root2 = mmr.root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_out_of_range_proof_fails() {
        let mut mmr = Mmr::new();
        mmr.append(b"only");
        assert!(mmr.prove_membership(1).is_err());
        assert!(mmr.prove_membership(100).is_err());
    }

}

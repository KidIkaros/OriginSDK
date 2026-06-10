// SPDX-License-Identifier: OPL-1.1

//! SHA3 hash functions
//!
//! Re-exports from `crate::internal::sha3` for backward compatibility.
//! SHAKE XOFs are re-exported from the external `sha3` crate.

pub use crate::internal::sha3::{Sha3_256, Sha3_512};
pub use sha3::{Shake128, Shake256};

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data)
}

/// Compute SHA3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data)
}

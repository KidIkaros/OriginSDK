// SPDX-License-Identifier: OPL-1.1

//! SHA3 hash functions

pub use sha3::{Sha3_256, Sha3_512, Digest};

/// Compute SHA3-256 hash
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute SHA3-512 hash
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    use sha3::Digest;
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

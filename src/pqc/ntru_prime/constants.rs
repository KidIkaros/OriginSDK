// SPDX-License-Identifier: Apache-2.0

//! NTRU Prime Constants
//!
//! Parameter set for Streamlined NTRU Prime sntrup761

/// Polynomial degree
pub const P: usize = 761;

/// Modulus for Rq operations
pub const Q: usize = 4591;

/// Weight constraint (number of non-zero coefficients)
pub const W: usize = 286;

/// Public key size in bytes
pub const PK_SIZE: usize = 1218;

/// Private key size in bytes
pub const SK_SIZE: usize = 1600;

/// Ciphertext size in bytes  
pub const CT_SIZE: usize = 1047;

/// Shared secret size in bytes
pub const K_SIZE: usize = 32;

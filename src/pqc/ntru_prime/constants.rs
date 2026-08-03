// SPDX-License-Identifier: Apache-2.0

//! NTRU Prime Constants
//!
//! Parameter set for Streamlined NTRU Prime sntrup761
//! (NIST reference implementation sizes, supercop-20201130)
//!
//! SK layout: Small(f) 191 bytes || Small(gr) 191 bytes || Rq(h) 1158 bytes || rho 191 bytes || cache 32 bytes

/// Polynomial degree
pub const P: usize = 761;

/// Modulus for Rq operations
pub const Q: usize = 4591;

/// Weight constraint (number of non-zero coefficients)
pub const W: usize = 286;

/// Public key size in bytes (NIST: Rq_bytes = 1158)
pub const PK_SIZE: usize = 1158;

/// Private key size in bytes (NIST KEM: 2*Small + Rq + rho + cache = 1763)
pub const SK_SIZE: usize = 1763;

/// Ciphertext size in bytes (NIST: 32 + Rounded_bytes = 32 + 1007 = 1039)
pub const CT_SIZE: usize = 1039;

/// Shared secret size in bytes
pub const K_SIZE: usize = 32;

/// Small_bytes: encoded size of a Small (ternary) polynomial
pub const SMALL_BYTES: usize = 191;

/// Rq_bytes: encoded size of an Rq polynomial (public key)
pub const RQ_BYTES: usize = 1158;

/// Rounded_bytes: encoded size of a Rounded polynomial (ciphertext body)
pub const ROUNDED_BYTES: usize = 1007;

/// Confirm_bytes: confirmation hash size
pub const CONFIRM_BYTES: usize = 32;

/// Hash_bytes: hash output size (first half of SHA-512)
pub const HASH_BYTES: usize = 32;

/// SecretKeys_bytes: core secret key (f + ginv) = 2 * Small_bytes
pub const SECRET_KEYS_BYTES: usize = 2 * SMALL_BYTES;

/// Inputs_bytes: encoded size of r (same as Small_bytes for sntrup)
pub const INPUTS_BYTES: usize = SMALL_BYTES;

// SPDX-License-Identifier: Apache-2.0

//! Internal utility modules replacing external crate dependencies.
//!
//! These modules provide zero-overhead replacements for:
//! - `zeroize` — secure memory zeroing
//! - `subtle` — constant-time comparison primitives
//! - `hex` — hexadecimal encoding/decoding
//! - `getrandom` — OS entropy extraction
//! - `rand_chacha` — native ChaCha20 CSPRNG
//! - `sha3` — SHA3-256/512 hashing
//! - `hmac` — HMAC-SHA3-256
//! - `hkdf` — HKDF-SHA3-256 key derivation

pub mod getrandom;
pub mod hex;
pub mod hkdf;
pub mod hmac;
pub mod rng;
pub mod secp256k1;
pub mod sha3;
pub mod subtle;
pub mod zeroize;

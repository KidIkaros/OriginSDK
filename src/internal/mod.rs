// SPDX-License-Identifier: Apache-2.0

//! Internal utility modules replacing external crate dependencies.
//!
//! These modules provide zero-overhead replacements for:
//! - `zeroize` — secure memory zeroing
//! - `subtle` — constant-time comparison primitives
//! - `getrandom` — OS entropy extraction
//! - `rand_chacha` — native ChaCha20 CSPRNG
//! - `sha3` — SHA3-256/512 hashing
//! - `hmac` — HMAC-SHA3-256
//! - `hkdf` — HKDF-SHA3-256 key derivation
//! - `mlock` — Unix memory-locking FFI for the Sovereign memory tier
//!
//! (A `hex` module used to live here; the crate uses the `hex` dependency
//! instead and the vendored copy was removed as dead code.)

pub mod getrandom;
pub mod hkdf;
pub mod hmac;
pub mod mlock;
pub mod sha3;
pub mod subtle;
pub mod zeroize;

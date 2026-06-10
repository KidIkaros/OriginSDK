// SPDX-License-Identifier: OPL-1.1

//! Post-quantum cryptography module for Origin SDK.
//!
//! This module aggregates PQC schemes used by the SDK:
//! - Falcon: NTRU lattice signatures (FIPS 204)
//! - SLH-DSA: Stateless hash-based signatures (FIPS 205) — optional via `slh-dsa` feature

pub mod curve41417;
pub mod falcon1024;
pub mod falcon512;
pub mod ntru_prime;

#[cfg(feature = "slh-dsa")]
pub mod slhdsa;

#[cfg(feature = "ml-dsa")]
pub mod mldsa;
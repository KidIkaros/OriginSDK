// SPDX-License-Identifier: Apache-2.0

//! Post-quantum and high-security classical cryptography module for Origin SDK.
//!
//! This module aggregates the high-security signature schemes used by the SDK:
//!
//! - [ed448] — Ed448 (Mike Hamburg, RFC 8032). 448-bit Goldilocks curve.
//!   Standardized in TLS 1.3 (RFC 8446) and DNSSEC (RFC 8080).
//! - [curve41417] — Curve41417 (Daniel J. Bernstein). 414-bit prime.
//!   Used in X41417 and other protocols.
//! - [falcon1024], [falcon512] — Falcon lattice signatures (FIPS 206).
//! - [ntru_prime] — NTRU Prime KEM.
//! - \[slhdsa\] (feature `slh-dsa`) — Stateless hash-based signatures (FIPS 205).
//! - \[mldsa\] (feature `ml-dsa`) — ML-DSA lattice signatures (FIPS 204).
//!
//! # Ed448 vs Ed41417
//!
//! [ed448] and [curve41417::ed41417] are two DIFFERENT curves:
//!
//! - Ed448 uses a 448-bit prime (Goldilocks), ~223 bits of security,
//!   standardized for TLS 1.3 and DNSSEC.
//! - Ed41417 uses a 414-bit prime, ~207 bits of security, used in
//!   specialized protocols (X41417).
//!
//! For new applications that need a high-security EdDSA, use Ed448.

pub mod curve41417;
pub mod ed448;
pub mod falcon1024;
pub mod falcon512;
pub mod ntru_prime;

#[cfg(feature = "slh-dsa")]
pub mod slhdsa;

#[cfg(feature = "ml-dsa")]
pub mod mldsa;

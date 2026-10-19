// SPDX-License-Identifier: Apache-2.0

//! Key encapsulation mechanisms.
//!
//! The SDK has always shipped the *ingredients* for hybrid KEMs
//! ([`crate::x25519`], [`crate::pqc::ntru_prime`], [`crate::pqc::ml_kem`]) but
//! never the *combination*. This module provides it:
//!
//! - [`hybrid`] — hybrid (classical + post-quantum) KEMs, plus the shared,
//!   suite-agnostic combiner that downstream products (Vallum, Stoa, …) build
//!   on.
//!
//! # Experimental
//!
//! Hybrid compositions are novel. The component primitives are individually
//! studied; the *combination* — domain separation, binding, and leg ordering —
//! is not. See [`hybrid`] for the construction and its combiner lemma.

pub mod hybrid;

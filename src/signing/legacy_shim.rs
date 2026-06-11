// SPDX-License-Identifier: OPL-1.1

//! Legacy hybrid construction shim.
//!
//! **Deprecated.** The canonical implementation lives in [`crate::signing::hybrid`].
//! This module re-exports the same types for backward compatibility.
//!
//! New code should import directly from `signing::hybrid`:
//! ```ignore
//! use origin_crypto_sdk::signing::hybrid::{HybridSigningKeyBundle, falcon1024_keygen};
//! ```

pub use crate::signing::hybrid::*;

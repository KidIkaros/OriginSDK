// SPDX-License-Identifier: Apache-2.0

//! Recovery primitives.
//!
//! Recovery phrases — a structured way to back up a master seed so the
//! user can reconstruct it on a new device. This module currently exposes
//! a Unicode-based codec (`unicode_cipher`) that mirrors BIP-39's
//! algorithm shape (11-bit word indices, truncated SHA-3-256 checksum)
//! but with a curated Unicode codepoint wordlist instead of an English
//! wordlist.
//!
//! See:
//! - [`unicode_cipher`] — encode / decode / custom-alphabet APIs.
//!
//! # Non-BIP-39 compatibility
//!
//! This format is **deliberately not BIP-39 compatible**: it uses a
//! different wordlist (Unicode codepoints, not English words) and a
//! different checksum hash (SHA-3-256, not SHA-256). Phrases generated
//! here **cannot** be recovered by any other BIP-39 wallet. Recovery
//! requires `origin_crypto_sdk::recovery::unicode_cipher`.
//!
//! If you need BIP-39 interop, use the upstream `bip39` crate.

pub mod unicode_cipher;

pub use unicode_cipher::{
    decode_phrase, encode_phrase, encode_phrase_custom, EntropyReport, PhraseLength,
    UnicodeWordlist,
};

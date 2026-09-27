// SPDX-License-Identifier: Apache-2.0

//! Recovery primitives.
//!
//! Recovery phrases back up a master seed so it can be reconstructed on a
//! new device. Two codecs live here:
//!
//! * [`unicode_cipher`](crate::recovery::unicode_cipher) — **v1**, frozen:
//!   a fixed 2048-codepoint wordlist, 11-bit indices, and a truncated
//!   SHA-3-256 checksum, with the format implied by symbol count. It
//!   decodes every phrase it ever produced and gains no new features.
//! * [`alphabet`](crate::recovery::alphabet) +
//!   [`format`](crate::recovery::format) +
//!   [`phrase`](crate::recovery::phrase) — **v2**: an alphabet-agnostic
//!   codec for user-defined recovery methods (a rune block, an emoji pack).
//!   [`RecoveryFormat`](crate::recovery::format::RecoveryFormat) pairs a
//!   [`RecoveryAlphabet`](crate::recovery::alphabet::RecoveryAlphabet) with
//!   an entropy width; [`Phrase`](crate::recovery::phrase::Phrase) is the
//!   canonical text form.
//!
//! # Non-BIP-39 compatibility
//!
//! Neither codec is BIP-39 compatible: Unicode codepoints instead of
//! English words, SHA-3-256 instead of SHA-256. Phrases generated here
//! **cannot** be recovered by any other BIP-39 wallet. For BIP-39 interop,
//! use the upstream `bip39` crate.

mod bits;

pub mod alphabet;
pub mod format;
pub mod phrase;
pub mod unicode_cipher;

pub use alphabet::{RecoveryAlphabet, MAX_ALPHABET_LEN, MIN_ALPHABET_LEN};
pub use format::{
    RecoveryFormat, MAX_ENTROPY_BYTES, MAX_PHRASE_SYMBOLS, MIN_ENTROPY_BYTES,
    SUPPORTED_ENTROPY_BYTES,
};
pub use phrase::{Phrase, SecretBytes};

#[allow(deprecated)]
pub use unicode_cipher::{
    decode_phrase, encode_phrase, encode_phrase_custom, EntropyReport, PhraseLength,
    UnicodeWordlist,
};

// SPDX-License-Identifier: Apache-2.0

//! Recovery alphabets: validated codepoint sets.
//!
//! An alphabet is an ordered set of distinct Unicode codepoints; position *i*
//! encodes the value *i*. It is the user-facing half of a recovery method —
//! users pick the symbol set (runes, hanzi, braille cells, geometric shapes)
//! and the phrase layer supplies the bit packing, checksum, and text form.
//!
//! This module also owns the codepoint policy. The v1 codec
//! ([`crate::recovery::unicode_cipher`]) uses the same `validate_*` helpers,
//! so there is one policy rather than one per codec.
//!
//! Nothing here touches the filesystem or the network.

use crate::error::{CryptoError, Result};
use sha3::{Digest, Sha3_256};
use unicode_normalization::UnicodeNormalization;

/// Smallest alphabet that can encode anything (one bit per symbol).
pub const MIN_ALPHABET_LEN: usize = 2;

/// Largest alphabet the codecs support.
///
/// The phrase layer materializes alphabets as a fixed-capacity table, and a
/// symbol carries at most 12 bits, so this is a hard structural bound rather
/// than a tuning knob.
pub const MAX_ALPHABET_LEN: usize = 4096;

/// Domain tag for alphabet fingerprints.
const ALPHABET_DOMAIN: &[u8] = b"origin-recovery-alphabet-v1";

/// An ordered, validated cipher alphabet of distinct Unicode codepoints.
///
/// Construction enforces the whole policy: size bounds, uniqueness, and the
/// codepoint classes that break text pipelines or enable silent mismatches
/// (see [`validate_codepoint`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAlphabet {
    entries: Box<[char]>,
}

impl RecoveryAlphabet {
    /// Build and validate an alphabet from ordered codepoints.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidParameter`] if `entries` is shorter than
    ///   [`MIN_ALPHABET_LEN`] or longer than [`MAX_ALPHABET_LEN`], or if it
    ///   contains a duplicate codepoint.
    /// * [`CryptoError::RejectedCodepointClass`] /
    ///   [`CryptoError::InvalidNormalization`] if a codepoint fails the
    ///   policy.
    pub fn new(entries: &[char]) -> Result<Self> {
        if entries.len() < MIN_ALPHABET_LEN {
            return Err(CryptoError::InvalidParameter(format!(
                "alphabet needs at least {MIN_ALPHABET_LEN} symbols, got {}",
                entries.len()
            )));
        }
        if entries.len() > MAX_ALPHABET_LEN {
            return Err(CryptoError::InvalidParameter(format!(
                "alphabet size {} exceeds the maximum of {MAX_ALPHABET_LEN}",
                entries.len()
            )));
        }
        validate_unique_codepoints(entries, "alphabet")?;
        validate_input_chars(entries)?;
        Ok(Self {
            entries: entries.to_vec().into_boxed_slice(),
        })
    }

    /// Number of symbols in the alphabet.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always false: construction rejects an empty alphabet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The codepoints in alphabet order.
    pub fn as_slice(&self) -> &[char] {
        &self.entries
    }

    /// The codepoint that encodes `index`, if in range.
    pub fn get(&self, index: usize) -> Option<char> {
        self.entries.get(index).copied()
    }

    /// The value `codepoint` encodes, if it is part of this alphabet.
    pub fn index_of(&self, codepoint: char) -> Option<usize> {
        self.entries.iter().position(|&c| c == codepoint)
    }

    /// Whether `codepoint` is part of this alphabet.
    pub fn contains(&self, codepoint: char) -> bool {
        self.index_of(codepoint).is_some()
    }

    /// Stable digest of the ordered codepoints.
    ///
    /// For descriptor interchange (e.g. a layout authored in a sibling tool)
    /// and for callers that want to bind a phrase to its alphabet explicitly.
    ///
    /// Deliberately **not** mixed into the phrase checksum: a phrase decoded
    /// against the wrong alphabet already fails with probability
    /// `1 - 2^-checksum_bits`, so folding the digest in would add coupling
    /// without adding detection.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(ALPHABET_DOMAIN);
        hasher.update((self.entries.len() as u32).to_le_bytes());
        for codepoint in &self.entries {
            hasher.update((*codepoint as u32).to_le_bytes());
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Codepoint policy
// ---------------------------------------------------------------------------

/// Classify a codepoint into a forbidden class, if any.
///
/// Rejects: ZWJ, Variation Selectors, Combining Diacritical Marks,
/// BIDI marks, default-ignorable invisibles, control characters.
pub(crate) fn reject_class(c: char) -> Option<&'static str> {
    let cp = c as u32;
    if cp == 0x200D {
        return Some("ZWJ");
    }
    if (0xFE00..=0xFE0F).contains(&cp) {
        return Some("VARIATION_SELECTOR");
    }
    if (0x0300..=0x036F).contains(&cp) {
        return Some("COMBINING_MARK");
    }
    if cp == 0x200E || cp == 0x200F {
        return Some("BIDI_MARK");
    }
    if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
        return Some("BIDI_MARK");
    }
    if cp == 0x200B || cp == 0x200C || cp == 0xFEFF || (0x2060..=0x2064).contains(&cp) {
        return Some("DEFAULT_IGNORABLE");
    }
    // U+180E MONGOLIAN VOWEL SEPARATOR (default-ignorable)
    if cp == 0x180E {
        return Some("DEFAULT_IGNORABLE");
    }
    // U+206A..=U+206F additional BIDI / format controls (Arabic,
    // Persian, Mongolian block-inverts etc.)
    if (0x206A..=0x206F).contains(&cp) {
        return Some("BIDI_MARK");
    }
    // U+061C ARABIC LETTER MARK
    if cp == 0x061C {
        return Some("BIDI_MARK");
    }
    if c.is_control() {
        return Some("CONTROL");
    }
    None
}

/// Reject a codepoint whose NFKC canonical form decomposes into MULTIPLE
/// codepoints.
///
/// A multi-codepoint NFKC decomposition (e.g., ligatures that split into
/// base + combining mark) means the user could type the same visual
/// symbol using two different byte sequences — silent recovery failure.
///
/// A single-codepoint NFKC that maps to a *different* single codepoint
/// (e.g., `ⓕ` U+24D5 ↔ `f` U+0066) is NOT rejected because in our curated
/// non-Latin default wordlist the NFKC partner is absent, so a manual
/// typing collision is not realizable.
pub(crate) fn reject_non_canonical(c: char) -> Option<&'static str> {
    let mut multi = 0usize;
    for _x in c.nfkc() {
        multi += 1;
    }
    if multi != 1 {
        Some("NFKC canonical form has multiple codepoints (silent malleability vector)")
    } else {
        None
    }
}

/// Apply the full codepoint policy to one codepoint.
pub(crate) fn validate_codepoint(c: char) -> Result<()> {
    if let Some(class) = reject_class(c) {
        return Err(CryptoError::RejectedCodepointClass {
            codepoint: c,
            class,
        });
    }
    if let Some(reason) = reject_non_canonical(c) {
        return Err(CryptoError::InvalidNormalization {
            codepoint: c,
            reason,
        });
    }
    Ok(())
}

/// Apply the codepoint policy to a slice.
pub(crate) fn validate_input_chars(chars: &[char]) -> Result<()> {
    for &c in chars {
        validate_codepoint(c)?;
    }
    Ok(())
}

/// Reject a repeated codepoint.
///
/// A duplicate would make the symbol→index map ambiguous, so a phrase could
/// decode two ways — the same malleability class the canonical-form guards
/// in the phrase layer close.
pub(crate) fn validate_unique_codepoints(chars: &[char], owner: &str) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for &c in chars {
        if !seen.insert(c) {
            return Err(CryptoError::InvalidParameter(format!(
                "duplicate codepoint U+{:04X} in {owner}",
                c as u32
            )));
        }
    }
    Ok(())
}

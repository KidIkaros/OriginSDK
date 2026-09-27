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
//! so there is one policy rather than one per codec. The UNICODE tooling
//! crate mirrors this policy in its `recovery_safe` predicate for offline
//! alphabet authoring; the two lists must stay in step.
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
    // Combining marks outside U+0300..=U+036F. Only the ranges that are
    // *dedicated* to combining marks are listed: mixed script blocks (Tibetan,
    // Devanagari, Arabic, ...) also carry them, and separating those needs
    // general-category data this crate does not carry. A codepoint that slips
    // through here still has to be a member of the caller's alphabet.
    if (0x0483..=0x0489).contains(&cp)
        || (0x1AB0..=0x1AFF).contains(&cp)
        || (0x1DC0..=0x1DFF).contains(&cp)
        || (0x20D0..=0x20FF).contains(&cp)
        || (0xFE20..=0xFE2F).contains(&cp)
    {
        return Some("COMBINING_MARK");
    }
    // Variation Selectors Supplement: invisible, same channel as U+FE00..=U+FE0F.
    if (0xE0100..=0xE01EF).contains(&cp) {
        return Some("VARIATION_SELECTOR");
    }
    // Soft hyphen and the tag characters render as nothing.
    if cp == 0x00AD || (0xE0000..=0xE007F).contains(&cp) {
        return Some("DEFAULT_IGNORABLE");
    }
    if c.is_control() {
        return Some("CONTROL");
    }
    // Unicode White_Space that is not a control: a whitespace symbol cannot
    // survive the canonical text form, because phrase parsing drops
    // whitespace between symbols — it would silently vanish from its own
    // phrase and the backup would never decode.
    if c.is_whitespace() {
        return Some("WHITESPACE");
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
    // nfkc() yields at least one codepoint, so a second element means the
    // canonical form is multi-codepoint.
    if c.nfkc().nth(1).is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn alphabet(start: u32, len: usize) -> RecoveryAlphabet {
        let symbols: Vec<char> = (0..len as u32)
            .map(|i| char::from_u32(start + i).expect("valid scalar"))
            .collect();
        RecoveryAlphabet::new(&symbols).expect("valid alphabet")
    }

    #[test]
    fn rejects_size_bounds() {
        assert!(RecoveryAlphabet::new(&['a']).is_err());
        let huge: Vec<char> = (0..(MAX_ALPHABET_LEN + 1) as u32)
            .map(|i| char::from_u32(0x4E00 + i).expect("valid scalar"))
            .collect();
        assert!(RecoveryAlphabet::new(&huge).is_err());
        assert!(RecoveryAlphabet::new(&['a', 'b']).is_ok());
    }

    #[test]
    fn rejects_duplicates() {
        assert!(matches!(
            RecoveryAlphabet::new(&['a', 'b', 'a']),
            Err(CryptoError::InvalidParameter(_))
        ));
    }

    #[test]
    fn rejects_invisible_and_control_codepoints() {
        // Each of these sits inside an *allocated* block, so a check that only
        // consults block coverage accepts them.
        let cases: [(char, &str); 10] = [
            ('\u{0}', "CONTROL"),
            ('\u{9}', "CONTROL"),
            ('\u{7F}', "CONTROL"),
            ('\u{85}', "CONTROL"),
            ('\u{200D}', "ZWJ"),
            ('\u{200E}', "BIDI_MARK"),
            ('\u{FEFF}', "DEFAULT_IGNORABLE"),
            ('\u{00AD}', "DEFAULT_IGNORABLE"),
            ('\u{0301}', "COMBINING_MARK"),
            ('\u{E0100}', "VARIATION_SELECTOR"),
        ];
        for (codepoint, expected) in cases {
            let mut symbols = vec!['a', 'b'];
            symbols[1] = codepoint;
            match RecoveryAlphabet::new(&symbols) {
                Err(CryptoError::RejectedCodepointClass { class, .. }) => {
                    assert_eq!(class, expected, "U+{:04X}", codepoint as u32);
                }
                other => panic!(
                    "U+{:04X} should be rejected, got {other:?}",
                    codepoint as u32
                ),
            }
        }
    }

    #[test]
    fn rejects_whitespace_symbols() {
        // Phrase::parse drops whitespace between symbols, so a whitespace
        // codepoint would silently vanish from its own canonical text form.
        // None of these is a control, and all sit inside allocated blocks.
        for cp in [
            0x0020u32, 0x00A0, 0x1680, 0x2007, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        ] {
            let mut symbols = vec!['a', 'b'];
            symbols[1] = char::from_u32(cp).expect("valid scalar");
            assert!(
                matches!(
                    RecoveryAlphabet::new(&symbols),
                    Err(CryptoError::RejectedCodepointClass {
                        class: "WHITESPACE",
                        ..
                    })
                ),
                "U+{cp:04X} is White_Space and must be rejected"
            );
        }
    }

    #[test]
    fn rejects_dedicated_combining_ranges() {
        for cp in [0x0483u32, 0x1AB0, 0x1DC0, 0x20D0, 0xFE20] {
            let mut symbols = vec!['a', 'b'];
            symbols[1] = char::from_u32(cp).expect("valid scalar");
            assert!(
                matches!(
                    RecoveryAlphabet::new(&symbols),
                    Err(CryptoError::RejectedCodepointClass {
                        class: "COMBINING_MARK",
                        ..
                    })
                ),
                "U+{cp:04X} should be a combining mark"
            );
        }
    }

    #[test]
    fn accepts_ordinary_symbols() {
        let alphabet = alphabet(0x16A0, 96);
        assert_eq!(alphabet.len(), 96);
        assert_eq!(alphabet.get(0), Some('\u{16A0}'));
        assert_eq!(alphabet.index_of('\u{16A0}'), Some(0));
        assert_eq!(alphabet.index_of('\u{16FF}'), Some(95));
        assert_eq!(alphabet.index_of('Z'), None);
        assert!(alphabet.contains('\u{16A5}'));
        assert!(!alphabet.is_empty());
        assert_eq!(alphabet.as_slice().len(), 96);
    }

    #[test]
    fn fingerprint_is_stable_and_order_sensitive() {
        let forward = alphabet(0x16A0, 24);
        let again = alphabet(0x16A0, 24);
        assert_eq!(forward.fingerprint(), again.fingerprint());

        let mut reversed: Vec<char> = forward.as_slice().to_vec();
        reversed.reverse();
        let reversed = RecoveryAlphabet::new(&reversed).unwrap();
        assert_ne!(forward.fingerprint(), reversed.fingerprint());

        // Length participates, so a prefix is not the same alphabet.
        assert_ne!(forward.fingerprint(), alphabet(0x16A0, 23).fingerprint());
    }
}

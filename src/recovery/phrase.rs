// SPDX-License-Identifier: Apache-2.0

//! Recovery phrase text form, and recovered secret material.
//!
//! A [`Phrase`] is the canonical way to render and parse a recovery phrase,
//! so consumers do not each invent their own. Before this existed, three
//! callers hand-rolled three different parsers: one stripped whitespace, one
//! split on whitespace, and one took the raw codepoints (and therefore
//! rejected the space-separated form the other two write).
//!
//! Both rendering conventions are accepted on input — concatenated
//! (`ᚠᚢᚦ`) and whitespace-separated (`ᚠ ᚢ ᚦ`) — because both are already
//! in the wild. Output is always the space-separated form, which is what a
//! human can transcribe and check.
//!
//! A phrase is as sensitive as the seed it encodes: [`Phrase`] is zeroized on
//! drop and redacts itself in `Debug`, and decoding returns [`SecretBytes`]
//! rather than a bare `Vec<u8>`.

use crate::error::{CryptoError, Result};
use crate::internal::zeroize::secure_zero_memory;
use std::fmt;
use subtle::ConstantTimeEq;

/// A recovery phrase: an ordered sequence of alphabet symbols.
pub struct Phrase {
    symbols: Vec<char>,
}

impl Phrase {
    /// Wrap already-ordered symbols.
    ///
    /// Purely structural: symbol membership and the codepoint policy are
    /// checked by the codec that consumes the phrase, which is the only place
    /// that knows the expected alphabet.
    pub fn from_symbols(symbols: Vec<char>) -> Self {
        Self { symbols }
    }

    /// The symbols in order.
    pub fn symbols(&self) -> &[char] {
        &self.symbols
    }

    /// Number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the phrase has no symbols.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Parse a phrase from text.
    ///
    /// Tolerates a leading UTF-8 BOM (common when a phrase is pasted from a
    /// Windows-authored note) and any amount of whitespace between symbols,
    /// so concatenated and space-separated forms both parse. Newlines are
    /// whitespace, so one-symbol-per-line also works.
    ///
    /// # Errors
    /// [`CryptoError::RecoveryPhrase`] if the text contains no symbols.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let symbols: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
        if symbols.is_empty() {
            return Err(CryptoError::RecoveryPhrase(
                "phrase contains no symbols".into(),
            ));
        }
        Ok(Self { symbols })
    }

    /// Render the canonical text form: symbols separated by single spaces.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(self.symbols.len() * 4);
        for (i, symbol) in self.symbols.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push(*symbol);
        }
        out
    }
}

impl fmt::Display for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// Redacted: a phrase is seed-equivalent material.
impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Phrase(<redacted, {} symbols>)", self.symbols.len())
    }
}

impl Drop for Phrase {
    fn drop(&mut self) {
        zeroize_chars(&mut self.symbols);
    }
}

/// Recovered entropy. Zeroized on drop; `Debug` redacts.
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The recovered bytes.
    ///
    /// Seed-equivalent material: copy only into the destination that needs
    /// it, and prefer a type that zeroizes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted, {} bytes>)", self.bytes.len())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        secure_zero_memory(&mut self.bytes);
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for SecretBytes {}

/// Overwrite a codepoint buffer in place.
///
/// `char` is 4 bytes and `U+0000` is a valid scalar value, so zeroing the
/// backing bytes leaves the buffer in a representable state.
fn zeroize_chars(symbols: &mut [char]) {
    if symbols.is_empty() {
        return;
    }
    // SAFETY: `char` is a plain 4-byte scalar; reinterpreting the initialized
    // slice as bytes for the duration of the call is sound, and the length is
    // exact.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            symbols.as_mut_ptr() as *mut u8,
            core::mem::size_of_val(symbols),
        )
    };
    secure_zero_memory(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_concatenated_and_separated_forms() {
        let concatenated = Phrase::parse("ᚠᚢᚦ").unwrap();
        let separated = Phrase::parse("ᚠ ᚢ ᚦ").unwrap();
        assert_eq!(concatenated.symbols(), separated.symbols());
        assert_eq!(concatenated.symbols(), &['ᚠ', 'ᚢ', 'ᚦ']);
    }

    #[test]
    fn parses_multiline_and_bom() {
        let phrase = Phrase::parse("\u{feff}ᚠ\nᚢ\r\n  ᚦ\t").unwrap();
        assert_eq!(phrase.symbols(), &['ᚠ', 'ᚢ', 'ᚦ']);
    }

    #[test]
    fn round_trips_through_canonical_text() {
        let phrase = Phrase::from_symbols(vec!['ᚠ', 'ᚢ', 'ᚦ']);
        let text = phrase.to_text();
        assert_eq!(text, "ᚠ ᚢ ᚦ");
        assert_eq!(Phrase::parse(&text).unwrap().symbols(), phrase.symbols());
        assert_eq!(phrase.to_string(), text);
    }

    #[test]
    fn rejects_empty_text() {
        assert!(matches!(
            Phrase::parse("   \n\t "),
            Err(CryptoError::RecoveryPhrase(_))
        ));
        assert!(Phrase::parse("").is_err());
    }

    #[test]
    fn debug_redacts_both_types() {
        let phrase = Phrase::from_symbols(vec!['ᚠ', 'ᚢ']);
        let rendered = format!("{phrase:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains('ᚠ'), "{rendered}");

        let secret = SecretBytes::new(vec![0xAB; 32]);
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("AB"), "{rendered}");
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn secret_bytes_compare_constant_time() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let c = SecretBytes::new(vec![1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn drop_zeroizes_symbols() {
        // The buffer must be scrubbed before the allocation is released; a
        // copy taken beforehand proves the mechanism, not the allocation.
        let mut symbols = vec!['ᚠ', 'ᚢ', 'ᚦ'];
        zeroize_chars(&mut symbols);
        assert!(symbols.iter().all(|&c| c == '\u{0}'), "{symbols:?}");
    }
}

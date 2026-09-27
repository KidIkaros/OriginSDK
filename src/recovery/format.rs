// SPDX-License-Identifier: Apache-2.0

//! Alphabet-agnostic recovery phrases (format v2).
//!
//! The v1 codec ([`crate::recovery::unicode_cipher`]) is frozen: 2048
//! codepoints, 11-bit indices, a 4/8-bit truncated checksum, and a format
//! that is implied by the symbol count. This module is the generalization
//! users need to define their own recovery method:
//!
//! * **Any alphabet size** from 2 to 4096 symbols, not just powers of two —
//!   24 Elder Futhark runes and 33 Ogham letters are valid alphabets here.
//! * **An explicit format**: the caller supplies a [`RecoveryFormat`]
//!   describing the alphabet and entropy width, and the format version is
//!   bound into the checksum, instead of being inferred from symbol count.
//! * **A stronger checksum**: one bit per byte of entropy (16 bits at
//!   128-bit entropy, 32 bits at 256-bit) rather than entropy/32. The v1
//!   8-bit checksum accepted a mistyped 24-symbol phrase as a *different
//!   valid seed* about 1 time in 256.
//!
//! ## Symbol encoding
//!
//! The message is `entropy ‖ checksum` (18 bytes at 128-bit entropy, 36 at
//! 256-bit). It is written as a fixed number of symbols:
//!
//! * power-of-two alphabets use `log2(n)`-bit groups;
//! * other alphabets use base-`n` digits of the message integer.
//!
//! Both are **canonical**: decoding rejects any symbol string whose value
//! exceeds the message range. Without that guard the same seed would have
//! many valid phrases (leading digits above the range), which is the
//! malleability class this codec must not have.
//!
//! ## What this is not
//!
//! This is an encoding, not a cipher: it provides no confidentiality. It is
//! also not BIP-39 compatible and does not interoperate with wallet tooling.

use crate::error::{CryptoError, Result};
use crate::recovery::alphabet::{validate_input_chars, RecoveryAlphabet};
use crate::recovery::phrase::{Phrase, SecretBytes};
use crate::recovery::unicode_cipher::{extract_bits_msb, insert_bits_msb};
use sha3::{Digest, Sha3_256};

/// Bound into the checksum so a phrase from another format version, or from
/// an implementation that forgot the domain, fails verification.
const FORMAT_DOMAIN: &[u8] = b"origin-recovery-phrase-v2";

/// Smallest entropy width accepted, matching the SDK's 128-bit floor.
pub const MIN_ENTROPY_BYTES: usize = 16;

/// Largest entropy width accepted.
pub const MAX_ENTROPY_BYTES: usize = 32;

/// Longest phrase this codec will produce.
///
/// A phrase longer than this cannot be transcribed or checked by a human, so
/// formats that need more symbols (a 16-symbol alphabet at 256-bit entropy
/// wants 72) are rejected at construction rather than shipped as a trap.
pub const MAX_PHRASE_SYMBOLS: usize = 64;

/// Limbs needed for the largest message (256-bit entropy + 32-bit checksum).
const LIMBS: usize = 10;

/// An alphabet plus an entropy width: everything needed to encode and decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFormat {
    alphabet: RecoveryAlphabet,
    entropy_bytes: usize,
}

impl RecoveryFormat {
    /// Build a format from a validated alphabet and an entropy width.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidParameter`] if `entropy_bytes` is not one of
    ///   16, 24, or 32 (whole bytes of checksum are required), or if the
    ///   resulting phrase would exceed [`MAX_PHRASE_SYMBOLS`].
    pub fn new(alphabet: RecoveryAlphabet, entropy_bytes: usize) -> Result<Self> {
        if !matches!(entropy_bytes, MIN_ENTROPY_BYTES | 24 | MAX_ENTROPY_BYTES) {
            return Err(CryptoError::InvalidParameter(format!(
                "entropy width {entropy_bytes} bytes is not one of 16, 24, 32"
            )));
        }
        let format = Self {
            alphabet,
            entropy_bytes,
        };
        let symbols = format.symbol_count();
        if symbols > MAX_PHRASE_SYMBOLS {
            return Err(CryptoError::InvalidParameter(format!(
                "a {}-symbol alphabet at {entropy_bytes}-byte entropy needs {symbols} symbols, \
                 over the {MAX_PHRASE_SYMBOLS}-symbol limit; use a larger alphabet",
                format.alphabet.len()
            )));
        }
        Ok(format)
    }

    /// The alphabet this format encodes with.
    pub fn alphabet(&self) -> &RecoveryAlphabet {
        &self.alphabet
    }

    /// Entropy width in bytes.
    pub fn entropy_bytes(&self) -> usize {
        self.entropy_bytes
    }

    /// Checksum width: one bit per byte of entropy (16 or 32 bits here).
    pub fn checksum_bits(&self) -> usize {
        self.entropy_bytes
    }

    /// Symbols in a phrase produced by this format.
    pub fn symbol_count(&self) -> usize {
        base_n_digits(self.alphabet.len(), self.message_bits())
    }

    /// Bits in `entropy ‖ checksum`.
    pub fn message_bits(&self) -> usize {
        self.message_bytes() * 8
    }

    /// Encode entropy as a phrase.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidKeyLength`] if `entropy` is not exactly
    ///   [`Self::entropy_bytes`] long.
    pub fn encode(&self, entropy: &[u8]) -> Result<Phrase> {
        if entropy.len() != self.entropy_bytes {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: "RecoveryPhrase",
                expected: self.entropy_bytes,
                got: entropy.len(),
            });
        }
        let message = self.message(entropy);
        Ok(Phrase::from_symbols(self.symbols_of_message(&message)?))
    }

    /// Decode a phrase back to entropy.
    ///
    /// # Errors
    /// * [`CryptoError::RecoveryPhrase`] if the symbol count, a symbol's
    ///   membership, or the canonical form is wrong.
    /// * [`CryptoError::RejectedCodepointClass`] /
    ///   [`CryptoError::InvalidNormalization`] for a codepoint outside the
    ///   policy.
    /// * [`CryptoError::ChecksumMismatch`] if the checksum does not verify —
    ///   which is also how a phrase from a *different* alphabet is rejected,
    ///   with probability `1 - 2^-checksum_bits`.
    pub fn decode(&self, phrase: &Phrase) -> Result<SecretBytes> {
        let expected_symbols = self.symbol_count();
        if phrase.len() != expected_symbols {
            return Err(CryptoError::RecoveryPhrase(format!(
                "expected {expected_symbols} symbols for this format, got {}",
                phrase.len()
            )));
        }
        validate_input_chars(phrase.symbols())?;

        let mut indices = Vec::with_capacity(expected_symbols);
        for (position, &symbol) in phrase.symbols().iter().enumerate() {
            let index = self.alphabet.index_of(symbol).ok_or_else(|| {
                CryptoError::RecoveryPhrase(format!(
                    "symbol {position} (U+{:04X}) is not in this alphabet",
                    symbol as u32
                ))
            })?;
            indices.push(index);
        }

        let message = self.message_of_indices(&indices)?;
        if !message.fits_bits(self.message_bits()) {
            return Err(CryptoError::RecoveryPhrase(
                "phrase is not canonical: it decodes beyond this format's bit range".into(),
            ));
        }

        let bytes = message.to_bytes_msb(self.message_bytes());
        let (entropy, decoded_checksum) = bytes.split_at(self.entropy_bytes);
        let got = checksum_from_bytes(decoded_checksum);
        let expected = self.checksum(entropy);
        if expected != got {
            return Err(CryptoError::ChecksumMismatch { expected, got });
        }
        Ok(SecretBytes::new(entropy.to_vec()))
    }

    /// Bytes in `entropy ‖ checksum`.
    fn message_bytes(&self) -> usize {
        self.entropy_bytes + self.checksum_bytes()
    }

    /// Whole bytes of checksum.
    fn checksum_bytes(&self) -> usize {
        self.checksum_bits() / 8
    }

    /// `entropy ‖ checksum` as a big-endian byte string.
    fn message(&self, entropy: &[u8]) -> Vec<u8> {
        let checksum = self.checksum(entropy);
        let mut message = entropy.to_vec();
        message.extend_from_slice(&checksum.to_be_bytes()[4 - self.checksum_bytes()..]);
        message
    }

    /// Truncated SHA-3-256 over the domain tag and the entropy.
    fn checksum(&self, entropy: &[u8]) -> u32 {
        let mut hasher = Sha3_256::new();
        hasher.update(FORMAT_DOMAIN);
        hasher.update(entropy);
        let full: [u8; 32] = hasher.finalize().into();
        checksum_from_bytes(&full[..self.checksum_bytes()])
    }

    /// Write the message as symbol indices.
    fn symbols_of_message(&self, message: &[u8]) -> Result<Vec<char>> {
        let radix = self.alphabet.len();
        let count = self.symbol_count();
        let mut out = Vec::with_capacity(count);
        if radix.is_power_of_two() {
            let width = radix.trailing_zeros() as usize;
            for position in 0..count {
                let value = extract_bits_msb(message, position * width, position * width + width);
                out.push(self.symbol_at(value as usize)?);
            }
        } else {
            let mut value = Message::from_bytes_msb(message);
            let mut digits = vec![0usize; count];
            for slot in digits.iter_mut().rev() {
                *slot = value.div_rem_small(radix as u32) as usize;
            }
            debug_assert!(value.is_zero(), "message must fit the digit count");
            for digit in digits {
                out.push(self.symbol_at(digit)?);
            }
        }
        Ok(out)
    }

    /// Rebuild the message integer from symbol indices.
    fn message_of_indices(&self, indices: &[usize]) -> Result<Message> {
        let radix = self.alphabet.len();
        if radix.is_power_of_two() {
            let width = radix.trailing_zeros() as usize;
            let mut bytes = Vec::new();
            for (position, &index) in indices.iter().enumerate() {
                insert_bits_msb(&mut bytes, index as u32, position * width, width);
            }
            // Bit groups are written MSB-first from the start of the buffer,
            // so group padding lands *past* the message. It must be clear: a
            // set padding bit would give one seed two valid phrases. The
            // buffer is truncated to the message length afterwards, because a
            // padded buffer is not a big-endian integer of the message's
            // width (its bit numbering would shift).
            let message_bits = self.message_bits();
            let total_bits = indices.len() * width;
            for bit in message_bits..total_bits {
                if extract_bits_msb(&bytes, bit, bit + 1) != 0 {
                    return Err(CryptoError::RecoveryPhrase(
                        "phrase is not canonical: it sets bits beyond this format's range".into(),
                    ));
                }
            }
            bytes.truncate(self.message_bytes());
            Ok(Message::from_bytes_msb(&bytes))
        } else {
            let mut value = Message::zero();
            for &index in indices {
                value
                    .mul_add_small(radix as u32, index as u32)
                    .ok_or_else(|| {
                        CryptoError::RecoveryPhrase(
                            "phrase encodes a value beyond this format's range".into(),
                        )
                    })?;
            }
            Ok(value)
        }
    }

    fn symbol_at(&self, index: usize) -> Result<char> {
        self.alphabet.get(index).ok_or_else(|| {
            CryptoError::RecoveryPhrase(format!(
                "internal: symbol index {index} out of range for a {}-symbol alphabet",
                self.alphabet.len()
            ))
        })
    }
}

/// Read a big-endian checksum out of its bytes.
fn checksum_from_bytes(bytes: &[u8]) -> u32 {
    let mut value = 0u32;
    for &byte in bytes {
        value = (value << 8) | byte as u32;
    }
    value
}

/// Smallest `digits` with `radix^digits >= 2^bits`.
///
/// For a power of two this is plain bit packing; otherwise the `f64` estimate
/// is corrected with exact integer arithmetic, because a one-off error here
/// would either drop the top of the message or make the encoding
/// non-canonical.
fn base_n_digits(radix: usize, bits: usize) -> usize {
    if radix.is_power_of_two() {
        return bits.div_ceil(radix.trailing_zeros() as usize);
    }
    let estimate = ((bits as f64) / (radix as f64).log2()).ceil() as usize;
    let mut digits = estimate.max(1);
    while digits > 1 && radix_pow_covers(radix, digits - 1, bits) {
        digits -= 1;
    }
    while !radix_pow_covers(radix, digits, bits) {
        digits += 1;
    }
    digits
}

/// Whether `radix^exponent >= 2^bits`.
fn radix_pow_covers(radix: usize, exponent: usize, bits: usize) -> bool {
    let mut value = Message::zero();
    value.0[0] = 1;
    for _ in 0..exponent {
        if value.mul_add_small(radix as u32, 0).is_none() {
            // Overflowed past 2^320, which is above any message width.
            return true;
        }
    }
    !value.fits_bits(bits)
}

/// Little-endian 32-bit limbs: a fixed-capacity message integer.
///
/// The largest message is 288 bits, so ten limbs (320 bits) cannot overflow
/// silently — [`Message::mul_add_small`] reports the case instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Message([u32; LIMBS]);

impl Message {
    fn zero() -> Self {
        Self([0; LIMBS])
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|&limb| limb == 0)
    }

    /// Read a big-endian byte string.
    fn from_bytes_msb(bytes: &[u8]) -> Self {
        let mut value = Self::zero();
        for &byte in bytes {
            let mut carry = byte as u64;
            for limb in value.0.iter_mut() {
                let shifted = ((*limb as u64) << 8) | carry;
                *limb = shifted as u32;
                carry = shifted >> 32;
            }
        }
        value
    }

    /// Write `len` big-endian bytes.
    fn to_bytes_msb(self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for i in 0..len {
            out[len - 1 - i] = (self.0[i / 4] >> (8 * (i % 4))) as u8;
        }
        out
    }

    /// Divide by a small radix, returning the remainder (a digit).
    fn div_rem_small(&mut self, radix: u32) -> u32 {
        let mut remainder = 0u64;
        for limb in self.0.iter_mut().rev() {
            let current = (remainder << 32) | (*limb as u64);
            *limb = (current / radix as u64) as u32;
            remainder = current % radix as u64;
        }
        remainder as u32
    }

    /// `self * radix + add`, or `None` if the value exceeds the limbs.
    fn mul_add_small(&mut self, radix: u32, add: u32) -> Option<()> {
        let mut carry = add as u64;
        for limb in self.0.iter_mut() {
            let product = (*limb as u64) * (radix as u64) + carry;
            *limb = product as u32;
            carry = product >> 32;
        }
        (carry == 0).then_some(())
    }

    /// Whether the value is below `2^bits` — the canonical-form test.
    fn fits_bits(&self, bits: usize) -> bool {
        let whole = bits / 32;
        let partial = bits % 32;
        for (index, &limb) in self.0.iter().enumerate() {
            if index < whole {
                continue;
            }
            let ok = if index == whole && partial != 0 {
                limb >> partial == 0
            } else {
                limb == 0
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codepoints from a block that passes the policy, offset by `start`.
    fn alphabet_from(start: u32, len: usize) -> RecoveryAlphabet {
        let symbols: Vec<char> = (0..len as u32)
            .map(|i| char::from_u32(start + i).expect("valid scalar"))
            .collect();
        RecoveryAlphabet::new(&symbols).expect("valid alphabet")
    }

    fn format(radix: usize, entropy_bytes: usize) -> RecoveryFormat {
        RecoveryFormat::new(alphabet_from(0x4E00, radix), entropy_bytes).expect("valid format")
    }

    #[test]
    fn power_of_two_alphabet_round_trips() {
        let format = format(2048, 32);
        assert_eq!(format.symbol_count(), 27);
        assert_eq!(format.checksum_bits(), 32);
        let entropy = [0x42u8; 32];
        let phrase = format.encode(&entropy).unwrap();
        assert_eq!(phrase.len(), 27);
        assert_eq!(format.decode(&phrase).unwrap().as_bytes(), &entropy[..]);
    }

    #[test]
    fn non_power_of_two_alphabet_round_trips() {
        // 24 runes, 33 Ogham letters, 96 Runic, 100 hanzi: none is a power of
        // two, which the v1 codec could not express at all.
        for radix in [24usize, 33, 96, 100] {
            for entropy_bytes in [16usize, 32] {
                let format = format(radix, entropy_bytes);
                let entropy: Vec<u8> = (0..entropy_bytes).map(|i| (i * 37 + 11) as u8).collect();
                let phrase = format.encode(&entropy).unwrap();
                assert_eq!(phrase.len(), format.symbol_count());
                let decoded = format.decode(&phrase).unwrap();
                assert_eq!(
                    decoded.as_bytes(),
                    &entropy[..],
                    "radix {radix}, {entropy_bytes} bytes"
                );
            }
        }
    }

    #[test]
    fn base_n_digit_count_is_minimal() {
        // 3^5 = 243 >= 128 but 3^4 = 81 < 128.
        assert_eq!(base_n_digits(3, 7), 5);
        // 24^63 >= 2^288 and 24^62 < 2^288.
        assert_eq!(base_n_digits(24, 288), 63);
        assert!(!radix_pow_covers(24, 62, 288));
        assert!(radix_pow_covers(24, 63, 288));
        // Powers of two stay exact bit packing.
        assert_eq!(base_n_digits(2048, 288), 27);
        assert_eq!(base_n_digits(256, 288), 36);
        assert_eq!(base_n_digits(4096, 288), 24);
    }

    #[test]
    fn all_supported_radices_round_trip() {
        // Small alphabets are rejected at this width by the phrase-length
        // limit (2 symbols would need 144 of them), which is the intended
        // outcome rather than a round-trip case.
        for radix in [2usize, 3, 4] {
            assert!(
                RecoveryFormat::new(alphabet_from(0x4E00, radix), 16).is_err(),
                "radix {radix} should not be usable at 128-bit entropy"
            );
        }
        for radix in [
            5usize, 16, 24, 32, 33, 64, 96, 100, 128, 256, 1000, 2048, 4096,
        ] {
            let format = format(radix, 16);
            let entropy = [0xA5u8; 16];
            let phrase = format.encode(&entropy).unwrap();
            assert!(
                phrase.len() <= MAX_PHRASE_SYMBOLS,
                "radix {radix} produced {} symbols",
                phrase.len()
            );
            assert_eq!(
                format.decode(&phrase).unwrap().as_bytes(),
                &entropy[..],
                "radix {radix}"
            );
        }
    }

    #[test]
    fn canonical_guard_rejects_padding_bits() {
        // 4096 symbols = 12-bit groups; 288 bits over 24 groups leaves no
        // padding, so use a 2048-symbol alphabet (11 bits, 27 groups = 297
        // bits) where the final group has 9 padding bits.
        let format = format(2048, 32);
        assert_eq!(format.symbol_count(), 27);
        let mut symbols = format.encode(&[0x11u8; 32]).unwrap().symbols().to_vec();
        // A maximal last symbol puts ones in the 9 padding bits, which a
        // canonical encoding leaves zero.
        let radix = format.alphabet().len();
        symbols[26] = format.alphabet().get(radix - 1).unwrap();
        assert!(matches!(
            format.decode(&Phrase::from_symbols(symbols)),
            Err(CryptoError::RecoveryPhrase(_))
        ));
    }

    #[test]
    fn canonical_guard_rejects_out_of_range_digits() {
        // 24-symbol alphabet: many symbol strings exceed the message range.
        let format = format(24, 16);
        let radix = format.alphabet().len();
        // All-max digits is the largest string and must be non-canonical.
        let symbols: Vec<char> = (0..format.symbol_count())
            .map(|_| format.alphabet().get(radix - 1).unwrap())
            .collect();
        assert!(matches!(
            format.decode(&Phrase::from_symbols(symbols)),
            Err(CryptoError::RecoveryPhrase(_))
        ));
    }

    #[test]
    fn disjoint_alphabet_is_rejected_by_membership() {
        let format = format(2048, 32);
        let phrase = format.encode(&[0x7Fu8; 32]).unwrap();
        let other = RecoveryFormat::new(alphabet_from(0x3400, 2048), 32).unwrap();
        assert!(matches!(
            other.decode(&phrase),
            Err(CryptoError::RecoveryPhrase(_))
        ));
    }

    #[test]
    fn permuted_alphabet_is_rejected_by_checksum() {
        // Same codepoints, different order: every symbol is still a member,
        // so only the checksum can catch it.
        let format = format(2048, 32);
        let phrase = format.encode(&[0x7Fu8; 32]).unwrap();
        let mut symbols: Vec<char> = (0..2048u32)
            .map(|i| char::from_u32(0x4E00 + i).unwrap())
            .collect();
        symbols.reverse();
        let permuted = RecoveryFormat::new(RecoveryAlphabet::new(&symbols).unwrap(), 32).unwrap();
        // Either the canonical guard or the checksum rejects it; the guard
        // fires first when the remapping also disturbs the padding bits.
        assert!(permuted.decode(&phrase).is_err());
    }

    #[test]
    fn checksum_tamper_is_rejected() {
        // 4096 symbols is 12 bits over exactly 24 groups, so the message has
        // no padding: the canonical guard cannot fire and the checksum is the
        // only thing that can reject a tampered symbol.
        let format = format(4096, 32);
        assert_eq!(format.symbol_count(), 24);
        let phrase = format.encode(&[0x5Au8; 32]).unwrap();
        for position in [0usize, 11, 23] {
            let mut symbols = phrase.symbols().to_vec();
            let index = format.alphabet().index_of(symbols[position]).unwrap();
            symbols[position] = format.alphabet().get(index ^ 1).unwrap();
            assert!(
                matches!(
                    format.decode(&Phrase::from_symbols(symbols)),
                    Err(CryptoError::ChecksumMismatch { .. })
                ),
                "symbol {position} tamper must be caught by the checksum"
            );
        }
    }

    #[test]
    fn symbol_count_mismatch_is_rejected() {
        let format = format(2048, 32);
        let mut symbols = format.encode(&[0x01u8; 32]).unwrap().symbols().to_vec();
        symbols.pop();
        assert!(matches!(
            format.decode(&Phrase::from_symbols(symbols)),
            Err(CryptoError::RecoveryPhrase(_))
        ));
    }

    #[test]
    fn foreign_symbol_is_rejected() {
        let format = format(2048, 16);
        let mut symbols = format.encode(&[0x02u8; 16]).unwrap().symbols().to_vec();
        symbols[5] = 'Z';
        assert!(matches!(
            format.decode(&Phrase::from_symbols(symbols)),
            Err(CryptoError::RecoveryPhrase(_))
        ));
    }

    #[test]
    fn wrong_entropy_length_is_rejected() {
        let format = format(2048, 32);
        assert!(matches!(
            format.encode(&[0u8; 16]),
            Err(CryptoError::InvalidKeyLength {
                algorithm: "RecoveryPhrase",
                expected: 32,
                got: 16,
            })
        ));
    }

    #[test]
    fn rejects_entropy_widths_without_whole_checksum_bytes() {
        for width in [15usize, 17, 20, 33] {
            assert!(
                RecoveryFormat::new(alphabet_from(0x4E00, 256), width).is_err(),
                "width {width} must be rejected"
            );
        }
        for width in [16usize, 24, 32] {
            assert!(RecoveryFormat::new(alphabet_from(0x4E00, 256), width).is_ok());
        }
    }

    #[test]
    fn rejects_formats_needing_unusable_phrase_lengths() {
        // 16 symbols at 256-bit entropy needs 72 symbols — over the limit.
        assert!(RecoveryFormat::new(alphabet_from(0x4E00, 16), 32).is_err());
        // The same alphabet is fine at 128-bit entropy (36 symbols).
        assert!(RecoveryFormat::new(alphabet_from(0x4E00, 16), 16).is_ok());
        // 24 runes at 256-bit is 63 symbols — just inside the limit.
        assert!(RecoveryFormat::new(alphabet_from(0x16A0, 24), 32).is_ok());
    }

    #[test]
    fn encoding_is_deterministic_and_seed_sensitive() {
        let format = format(33, 32);
        let a = format.encode(&[0x01u8; 32]).unwrap().to_text();
        let b = format.encode(&[0x01u8; 32]).unwrap().to_text();
        assert_eq!(a, b);
        let mut other = [0x01u8; 32];
        other[31] ^= 1;
        assert_ne!(a, format.encode(&other).unwrap().to_text());
    }

    #[test]
    fn phrases_round_trip_through_text() {
        let format = format(96, 24);
        let phrase = format.encode(&[0x9Cu8; 24]).unwrap();
        let reparsed = Phrase::parse(&phrase.to_text()).unwrap();
        assert_eq!(
            format.decode(&reparsed).unwrap().as_bytes(),
            &[0x9Cu8; 24][..]
        );
    }

    #[test]
    fn message_limbs_round_trip() {
        let bytes: Vec<u8> = (0..36u8).map(|i| i.wrapping_mul(7) ^ 0x5A).collect();
        let value = Message::from_bytes_msb(&bytes);
        assert_eq!(value.to_bytes_msb(bytes.len()), bytes);
        assert!(!value.is_zero());
    }

    #[test]
    fn message_fits_bits_boundaries() {
        let mut value = Message::zero();
        assert!(value.fits_bits(1));
        value.0[0] = 1;
        assert!(value.fits_bits(1));
        assert!(!value.fits_bits(0));
        value.0[0] = 0;
        value.0[1] = 1; // bit 32
        assert!(value.fits_bits(33));
        assert!(!value.fits_bits(32));
        // Bit 288 is the first bit outside a 288-bit message.
        let mut wide = Message::zero();
        wide.0[9] = 1 << (288 - 9 * 32);
        assert!(!wide.fits_bits(288));
        assert!(wide.fits_bits(289));
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Format v2: alphabet-agnostic recovery phrases.
//!
//! These tests drive the public API the way a downstream tool would: define
//! an alphabet, build a format, and round-trip a seed — including alphabets
//! the v1 codec could not express at all (24 or 33 runes are not powers of
//! two).

use origin_crypto_sdk::recovery::{Phrase, RecoveryAlphabet, RecoveryFormat, MAX_PHRASE_SYMBOLS};

/// First `len` codepoints of a block, as a validated alphabet.
fn alphabet(start: u32, len: usize) -> RecoveryAlphabet {
    let symbols: Vec<char> = (0..len as u32)
        .map(|i| char::from_u32(start + i).expect("valid scalar value"))
        .collect();
    RecoveryAlphabet::new(&symbols).expect("alphabet passes the policy")
}

fn format_for(start: u32, radix: usize, entropy_bytes: usize) -> RecoveryFormat {
    RecoveryFormat::new(alphabet(start, radix), entropy_bytes).expect("valid format")
}

/// Varied seed material, so a golden vector pins real structure rather than
/// the repetition of a constant seed.
fn seed(len: usize, tag: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(tag) ^ 0x5A)
        .collect()
}

/// Golden vectors for the v2 format.
///
/// These pin the wire format: the message layout, the checksum width and
/// domain tag, the base-`n` digit ordering, and the symbol count. A drift in
/// any of them breaks these vectors, which is the point — phrases are seed
/// backups, so silent format changes are unacceptable.
#[test]
fn v2_golden_vectors() {
    let vectors: [(u32, usize, usize, u8, &str); 4] = [
        (0x16A0, 24, 32, 1, RUNE24),
        (0x16A0, 33, 16, 2, RUNIC33),
        (0x4E00, 4096, 32, 3, CJK4096),
        (0x4E00, 256, 16, 4, HANZI256),
    ];
    for (start, radix, entropy_bytes, tag, expected) in vectors {
        let format = format_for(start, radix, entropy_bytes);
        let phrase = format.encode(&seed(entropy_bytes, tag)).expect("encode");
        assert_eq!(
            phrase.to_text(),
            expected,
            "radix {radix}, {entropy_bytes} bytes drifted"
        );
        assert_eq!(phrase.len(), format.symbol_count());
    }
}

const RUNE24: &str = "ᚤ ᚱ ᚷ ᚱ ᚩ ᚯ ᚬ ᚲ ᚦ ᚪ ᚯ ᚰ ᚣ ᚰ ᚤ ᚴ ᚥ ᚬ ᚡ ᚩ ᚢ ᚬ ᚫ ᚧ ᚷ ᚶ ᚭ ᚣ ᚵ ᚯ ᚤ ᚨ ᚦ ᚰ ᚳ ᚥ ᚫ ᚡ ᚦ ᚳ ᚧ ᚱ ᚬ ᚰ ᚶ ᚤ ᚡ ᚴ ᚵ ᚰ ᚦ ᚢ ᚱ ᚮ ᚩ ᚡ ᚴ ᚬ ᚴ ᚭ ᚰ ᚭ ᚱ";
const RUNIC33: &str = "ᚢ ᚫ ᚣ ᚰ ᚼ ᚼ ᚴ ᚬ ᚣ ᚦ ᚦ ᚢ ᚵ ᚶ ᚺ ᚳ ᚾ ᚥ ᚰ ᚾ ᚣ ᚥ ᚲ ᚭ ᚡ ᚦ ᚺ ᚳ ᚿ";
const CJK4096: &str = "厗 倗 傌 實 妵 婱 亢 巀 屛 屓 啀 圢 婹 嚽 卦 夌 借 墟 夅 卮 串 勒 凪 屍";
const HANZI256: &str = "乞 乳 且 丩 仂 仧 亸 九 乶 下 丬 仁 亚 亿 乐 乵 亨 仂";

/// A user-defined recovery method: 24 Elder Futhark runes.
///
/// 24 is not a power of two, so this is impossible with the v1 codec, which
/// requires a power-of-two wordlist of exactly 2048 entries.
#[test]
fn runic_recovery_method_round_trips() {
    let format = RecoveryFormat::new(alphabet(0x16A0, 24), 32).expect("24-rune format");
    assert_eq!(format.symbol_count(), 63);

    let entropy: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(11) ^ 0x5A).collect();
    let phrase = format.encode(&entropy).expect("encode");
    assert_eq!(phrase.len(), 63);
    assert!(phrase.len() <= MAX_PHRASE_SYMBOLS);

    let recovered = format.decode(&phrase).expect("decode");
    assert_eq!(recovered.as_bytes(), &entropy[..]);
}

/// The same seed encodes differently per alphabet, and a phrase does not
/// silently decode under a different method.
#[test]
fn alphabets_produce_distinct_phrases() {
    let entropy = [0x11u8; 32];
    let runic = format_for(0x16A0, 24, 32).encode(&entropy).expect("encode");
    let hanzi = format_for(0x4E00, 256, 32)
        .encode(&entropy)
        .expect("encode");
    assert_ne!(runic.to_text(), hanzi.to_text());
    assert!(format_for(0x4E00, 24, 32).decode(&hanzi).is_err());
    assert!(format_for(0x4E00, 256, 32).decode(&runic).is_err());
}

/// Text form: both conventions parse, output is canonical.
#[test]
fn text_form_round_trips_between_conventions() {
    let format = format_for(0x4E00, 256, 32);
    let phrase = format.encode(&[0x77u8; 32]).expect("encode");

    let canonical = phrase.to_text();
    assert!(canonical.contains(' '));
    let from_canonical = Phrase::parse(&canonical).expect("parse canonical");
    assert_eq!(
        format.decode(&from_canonical).expect("decode").as_bytes(),
        &[0x77u8; 32][..]
    );

    // Concatenated and one-per-line forms parse to the same phrase.
    let concatenated: String = phrase.symbols().iter().collect();
    let multiline: String = phrase.symbols().iter().map(|c| format!("{c}\n")).collect();
    for text in [concatenated, multiline] {
        let parsed = Phrase::parse(&text).expect("parse");
        assert_eq!(parsed.symbols(), phrase.symbols());
    }
}

/// A phrase is seed-equivalent material and must not print itself.
#[test]
fn phrase_does_not_leak_in_debug_output() {
    let format = format_for(0x4E00, 256, 32);
    let phrase = format.encode(&[0x01u8; 32]).expect("encode");
    let rendered = format!("{phrase:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    for symbol in phrase.symbols() {
        assert!(!rendered.contains(*symbol), "Debug leaked a symbol");
    }
    let recovered = format.decode(&phrase).expect("decode");
    let rendered = format!("{recovered:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
}

/// The v1 codec keeps working: the v2 work is additive.
#[test]
fn v1_phrase_is_still_decodable() {
    use origin_crypto_sdk::recovery::unicode_cipher::{
        decode_phrase, encode_phrase, PhraseLength, UnicodeWordlist,
    };
    let list = UnicodeWordlist::default();
    let entropy = [0x5Au8; 16];
    let phrase = encode_phrase(&entropy, &list, PhraseLength::Words12).expect("encode");
    assert_eq!(phrase.len(), 12);
    assert_eq!(
        decode_phrase(&phrase, &list).expect("decode").as_slice(),
        &entropy[..]
    );
    // A v1 phrase is not a v2 phrase for the same alphabet.
    let v2 = RecoveryFormat::new(
        RecoveryAlphabet::new(list.as_slice()).expect("default wordlist is a valid alphabet"),
        16,
    )
    .expect("format");
    let as_v2 = Phrase::from_symbols(phrase);
    assert!(v2.decode(&as_v2).is_err());
}

/// A downloaded pack — symbols as text — plugs straight into a format. This
/// is the feature end to end: pick a pack, get a phrase, restore the seed.
#[test]
fn symbol_pack_round_trips() {
    // Emoticons U+1F600..=U+1F64F: 80 single-codepoint emoji, a pack a user
    // could plausibly download.
    let pack: String = (0x1F600..=0x1F64F)
        .map(|cp| char::from_u32(cp).expect("valid scalar"))
        .collect();
    let (alphabet, skipped) = RecoveryAlphabet::from_pack(&pack).expect("pack parses");
    assert!(skipped.is_empty(), "Emoticons has no unsafe symbols");
    assert_eq!(alphabet.len(), 80);

    let format = RecoveryFormat::new(alphabet, 32).expect("emoji format");
    let entropy = seed(32, 0x0E);
    let phrase = format.encode(&entropy).expect("encode");
    assert_eq!(phrase.len(), format.symbol_count());

    let parsed = Phrase::parse(&phrase.to_text()).expect("parse");
    let recovered = format.decode(&parsed).expect("decode");
    assert_eq!(recovered.as_bytes(), &entropy[..]);
}

/// The pack is part of the backup: a phrase cannot decode under a different
/// pack. Its symbols are not even in the other alphabet (and where packs did
/// overlap, the checksum is the deeper guard) — no silent wrong seed.
#[test]
fn pack_phrase_is_rejected_by_a_different_pack() {
    let entropy = seed(32, 0x5D);
    let emoji_pack: String = (0x1F600..=0x1F64F).filter_map(char::from_u32).collect();
    let emoji = RecoveryAlphabet::from_pack(&emoji_pack).expect("pack").0;
    let emoji_format = RecoveryFormat::new(emoji, 32).expect("format");
    let phrase = emoji_format.encode(&entropy).expect("encode");

    // A different 80-symbol pack renders the same symbol count but a wrong
    // alphabet — decode must fail, not produce a different seed.
    let dingbats = RecoveryAlphabet::from_pack(
        &(0x2700..=0x274F)
            .filter_map(char::from_u32)
            .collect::<String>(),
    )
    .expect("pack")
    .0;
    let dingbats_format = RecoveryFormat::new(dingbats, 32).expect("format");
    assert!(dingbats_format.decode(&phrase).is_err());
}

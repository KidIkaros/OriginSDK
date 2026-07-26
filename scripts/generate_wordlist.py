#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Generator for the default Unicode wordlist used by
`origin_crypto_sdk::recovery::unicode_cipher` (Phase 0).

Source of truth for the 2048 codepoints. Run manually when the
wordlist composition changes:

    cd origin-crypto-sdk
    python3 scripts/generate_wordlist.py > src/recovery/default_wordlist.txt

The output is a flat string of exactly 2048 codepoints (one per char),
no separators, no trailing newline. Default `include_str!`'d into
`src/recovery/unicode_cipher.rs` and parsed at process startup via
`LazyLock`. The 2048-char total is verified at test time.

Block selection policy (matches the encoding-decision rationale we locked):

* Pure-symbols, NO emoji. Zero ZWJ / no skin-tone-modifier / no
  variation-selector risk.
* No Latin / Cyrillic / Greek / Digits — visibility-disjoint by
  block design, no homoglyph attack surface.
* Floor on format coverage: every codepoint is in the BMP or in a
  universally-supported range on Linux/macOS/Windows/iOS/Android
  terminals with the default Unicode font.
* Visually disjoint by Unicode committee design — geometric shapes
  differ in stroke, math symbols differ in glyph structure, arrows
  encode direction.
"""

from __future__ import annotations

import sys
import unicodedata


# Allowed Unicode ranges. Each tuple is (start_inclusive, end_inclusive).
# Order matters: codepoints are sliced in this order; the script
# truncates at exactly 2048 entries.
BLOCKS: list[tuple[int, int]] = [
    (0x2500, 0x257F),  # Box Drawing                (128)
    (0x2580, 0x259F),  # Block Elements             ( 32)
    (0x25A0, 0x25FF),  # Geometric Shapes           ( 96)
    (0x2600, 0x26FF),  # Miscellaneous Symbols      (256)
    (0x2700, 0x27BF),  # Dingbats                   (192)
    (0x2190, 0x21FF),  # Arrows                     (112)
    (0x2900, 0x297F),  # Supplemental Arrows-A      (128)
    (0x2200, 0x22FF),  # Mathematical Operators     (256)
    (0x2A00, 0x2AFF),  # Sup. Mathematical Operators-B (256)
    (0x2300, 0x23FF),  # Miscellaneous Technical    (256)
    (0x2400, 0x243F),  # Control Pictures           ( 64)
    (0x2440, 0x245F),  # Optical Character Recognition ( 32)
    (0x2460, 0x24FF),  # Enclosed Alphanumerics     (160)
    (0x1F700, 0x1F77F),  # Alchemical Symbols        (128)  -- symbols, not emoji
    (0x1F780, 0x1F7FF),  # Geometric Shapes Extended (128)  -- pure geometric extensions
]

# Total pre-filter budget over ~2360 codepoints; the script truncates to
# exactly the first WORDLIST_LEN (=2048).

# Hard cap — must mirror `pub const WORDLIST_LEN` in
# `src/recovery/unicode_cipher.rs`.
WORDLIST_LEN: int = 2048


def is_safe(cp: int) -> bool:
    """Return True iff `cp` should be admitted to the wordlist.

    Rejects control, format, combining-mark, BIDI-mark, default-ignorable,
    Variation-Selector, AND NFKC-multi-codepoint codepoints. See the
    policy in the module doc. The runtime check in Rust mirrors this;
    funnelling both checks through this function keeps the generator
    and the runtime consistent.
    """
    c = chr(cp)
    cat = unicodedata.category(c)
    if cat in ("Cc", "Cf", "Co", "Cs", "Cn"):  # control / format / surrogate / unassigned
        return False
    if unicodedata.combining(c) != 0:  # any combining mark
        return False
    if cp in (0x200B, 0x200C, 0x200D, 0xFEFF):  # ZWSP / ZWNJ / ZWJ / ZWNBSP
        return False
    if 0xFE00 <= cp <= 0xFE0F:  # Variation Selectors
        return False
    if 0x200E <= cp <= 0x200F:  # LRM / RLM (BIDI)
        return False
    if 0x202A <= cp <= 0x202E:  # BIDI embedding controls
        return False
    if 0x2060 <= cp <= 0x2064:  # Word joiner / invisibles
        return False
    # NFKC multi-codepoint decompositions are silent-malleability vectors
    # at decode time (a user could type the same visual symbol in two
    # different byte sequences). Reject them at curation so the runtime
    # check stays compatible with the generated wordlist.
    nfkc = unicodedata.normalize("NFKC", c)
    if len(nfkc) != 1:
        return False
    return True


def main() -> int:
    selected: list[int] = []
    for start, end in BLOCKS:
        for cp in range(start, end + 1):
            if not is_safe(cp):
                continue
            selected.append(cp)
            if len(selected) >= WORDLIST_LEN:
                break
        if len(selected) >= WORDLIST_LEN:
            break

    if len(selected) != WORDLIST_LEN:
        print(
            f"error: selected {len(selected)} codepoints, expected {WORDLIST_LEN}",
            file=sys.stderr,
        )
        return 1

    # Sanity: no duplicates (BLOCKS don't overlap, but be defensive).
    if len(set(selected)) != WORDLIST_LEN:
        print("error: duplicate codepoints in selection", file=sys.stderr)
        return 1

    # Emit a flat UTF-8 string — no separators, no trailing newline
    # so `include_str!` reads exactly 2048 chars.
    sys.stdout.write("".join(chr(cp) for cp in selected))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

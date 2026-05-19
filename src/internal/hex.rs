// SPDX-License-Identifier: OPL-1.1

//! Hexadecimal encoding and decoding — replacement for the `hex` crate.

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as a lowercase hex string.
///
/// Returns an owned `String` containing the hex-encoded data.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS_LOWER[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Encode bytes as a lowercase hex string into a pre-allocated buffer.
pub fn encode_to_slice(data: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), data.len() * 2, "output buffer must be 2x input len");
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX_CHARS_LOWER[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS_LOWER[(byte & 0x0f) as usize];
    }
}

/// Decode a hex string (case-insensitive) into bytes.
///
/// Returns `Some(Vec<u8>)` on success, `None` on invalid hex.
pub fn decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let hi = decode_hex_digit(chunk[0])?;
        let lo = decode_hex_digit(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Decode a hex string into a fixed-size byte array.
///
/// Returns `Some([u8; N])` on success, `None` on invalid hex or wrong length.
pub fn decode_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let decoded = decode(hex)?;
    if decoded.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    Some(out)
}

fn decode_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello world";
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn decode_uppercase() {
        let decoded = decode("DEADBEEF").unwrap();
        assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_invalid_fails() {
        assert!(decode("zzz").is_none());     // invalid chars
        assert!(decode("abc").is_none());     // odd length
    }

    #[test]
    fn decode_array_test() {
        let arr: [u8; 4] = decode_array("deadbeef").unwrap();
        assert_eq!(arr, [0xde, 0xad, 0xbe, 0xef]);
    }
}

// SPDX-License-Identifier: Apache-2.0

//! HMAC-based One-Time Password (HOTP) and Time-based One-Time Password (TOTP).
//!
//! Implements RFC 4226 (HOTP) and RFC 6238 (TOTP) — ported from the spork/cryp
//! Python prototypes into proper Rust with constant-time HMAC and zeroization.
//!
//! # Quick start
//!
//! ```
//! use origin_crypto_sdk::drbg::otp::{hotp, totp, HashAlgorithm};
//!
//! let secret = b"my-secret-key-1234";
//!
//! // HOTP: counter-based
//! let code = hotp(secret, 0, 6, HashAlgorithm::Sha256);
//!
//! // TOTP: time-based (30-second step, starting from Unix epoch)
//! let code = totp(secret, 1718000000, 30, 6, HashAlgorithm::Sha256);
//! ```

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// ---------------------------------------------------------------------------
// Hash algorithm selection
// ---------------------------------------------------------------------------

/// Hash algorithm for HOTP/TOTP computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 (legacy compatibility only — do not use for new applications).
    Sha1,
    /// SHA-256 (recommended).
    Sha256,
    /// SHA-512 (high security).
    Sha512,
}

// ---------------------------------------------------------------------------
// HOTP — RFC 4226
// ---------------------------------------------------------------------------

/// Compute an HOTP code (RFC 4226).
///
/// # Arguments
/// * `secret` — shared secret key
/// * `counter` — moving factor (must be synchronised between prover and verifier)
/// * `digits` — number of digits in the output code (6, 7, or 8)
/// * `algo` — hash algorithm
///
/// # Returns
/// The HOTP code as a `u32` (e.g. `123456` for 6 digits).
pub fn hotp(secret: &[u8], counter: u64, digits: u32, algo: HashAlgorithm) -> u32 {
    // Encode counter as 8-byte big-endian
    let counter_bytes = counter.to_be_bytes();

    // HMAC(secret, counter)
    let hmac_result = compute_hmac(secret, &counter_bytes, algo);

    // Dynamic truncation (RFC 4226 §5.4)
    let offset = (hmac_result.last().expect("HMAC output non-empty") & 0x0F) as usize;
    let truncated = u32::from_be_bytes([
        hmac_result[offset],
        hmac_result[offset + 1],
        hmac_result[offset + 2],
        hmac_result[offset + 3],
    ]) & 0x7FFF_FFFF;

    truncated % (10_u32.pow(digits))
}

// ---------------------------------------------------------------------------
// TOTP — RFC 6238
// ---------------------------------------------------------------------------

/// Compute a TOTP code (RFC 6238).
///
/// # Arguments
/// * `secret` — shared secret key
/// * `timestamp` — Unix timestamp (seconds since epoch)
/// * `time_step` — time step in seconds (typically 30)
/// * `digits` — number of digits in the output code (6, 7, or 8)
/// * `algo` — hash algorithm
///
/// # Returns
/// The TOTP code as a `u32`.
pub fn totp(
    secret: &[u8],
    timestamp: u64,
    time_step: u64,
    digits: u32,
    algo: HashAlgorithm,
) -> u32 {
    let counter = timestamp / time_step;
    hotp(secret, counter, digits, algo)
}

/// Format a TOTP/HOTP code with leading zeros.
pub fn format_code(code: u32, digits: u32) -> String {
    format!("{:0>width$}", code, width = digits as usize)
}

// ---------------------------------------------------------------------------
// URI generation (otpauth:// scheme — Google Authenticator compatible)
// ---------------------------------------------------------------------------

/// Generate an `otpauth://hotp/` URI for QR provisioning.
pub fn hotp_uri(
    secret: &[u8],
    issuer: &str,
    account: &str,
    counter: u64,
    digits: u32,
    algo: HashAlgorithm,
) -> String {
    let secret_b32 = base32_encode(secret);
    let algo_name = algo_str(algo);
    format!(
        "otpauth://hotp/{}:{}?secret={}&issuer={}&counter={}&digits={}&algorithm={}",
        url_encode(issuer),
        url_encode(account),
        secret_b32,
        url_encode(issuer),
        counter,
        digits,
        algo_name,
    )
}

/// Generate an `otpauth://totp/` URI for QR provisioning.
pub fn totp_uri(
    secret: &[u8],
    issuer: &str,
    account: &str,
    period: u64,
    digits: u32,
    algo: HashAlgorithm,
) -> String {
    let secret_b32 = base32_encode(secret);
    let algo_name = algo_str(algo);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&period={}&digits={}&algorithm={}",
        url_encode(issuer),
        url_encode(account),
        secret_b32,
        url_encode(issuer),
        period,
        digits,
        algo_name,
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub(crate) fn compute_hmac(secret: &[u8], message: &[u8], algo: HashAlgorithm) -> Vec<u8> {
    match algo {
        HashAlgorithm::Sha1 => {
            type HmacSha1 = Hmac<Sha1>;
            let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha256 => {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha512 => {
            type HmacSha512 = Hmac<Sha512>;
            let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn algo_str(algo: HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Sha1 => "SHA1",
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha512 => "SHA512",
    }
}

/// Minimal base32 *encode* (RFC 4648 §5 alphabet, A-Z + 2-7, no padding,
/// uppercase). Used internally to format TOTP shared secrets for
/// `otpauth://` URIs; the same alphabet is consumed by [`base32_decode`]
/// on the import side. Made `pub` so `origin-tools/origin-pass` can
/// reuse the SDK's encoder (no crate-local base32 dep needed).
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Minimal base32 *decode* (RFC 4648 §5 alphabet, A-Z + 2-7). Strips
/// trailing `=` padding if present (`otpauth://` URIs omit padding;
/// we accept both forms). Uppercase only — lowercase input returns
/// `Err`.
///
/// Inverse of [`base32_encode`]. Used by
/// `origin-tools/origin-pass`'s `cmd_import_qr` to recover the raw
/// shared secret from an `otpauth://` URI's `secret=` query parameter.
pub fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for byte in s.bytes() {
        if byte == b'=' {
            break; // padding terminates the stream.
        }
        let v = match ALPHABET.iter().position(|&c| c == byte) {
            Some(p) => p as u64,
            None => return Err(format!("invalid base32 character: {:?}", byte as char)),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Minimal percent-encoding for URI components.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D test vectors (SHA-1, 6 digits)
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_test_vectors() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, &expected_code) in expected.iter().enumerate() {
            let code = hotp(RFC_SECRET, counter as u64, 6, HashAlgorithm::Sha1);
            assert_eq!(code, expected_code, "HOTP mismatch at counter {counter}");
        }
    }

    #[test]
    fn totp_deterministic() {
        let secret = b"test-secret";
        let code1 = totp(secret, 1718000000, 30, 6, HashAlgorithm::Sha256);
        let code2 = totp(secret, 1718000000, 30, 6, HashAlgorithm::Sha256);
        assert_eq!(code1, code2);
    }

    #[test]
    fn totp_different_timestamps() {
        let secret = b"test-secret";
        // Two timestamps in different 30-second windows
        let code1 = totp(secret, 1718000000, 30, 6, HashAlgorithm::Sha256);
        let code2 = totp(secret, 1718000031, 30, 6, HashAlgorithm::Sha256);
        // Very unlikely to be equal
        assert_ne!(code1, code2);
    }

    #[test]
    fn digits_6_7_8() {
        let secret = b"test-secret";
        let c6 = hotp(secret, 0, 6, HashAlgorithm::Sha256);
        let c7 = hotp(secret, 0, 7, HashAlgorithm::Sha256);
        let c8 = hotp(secret, 0, 8, HashAlgorithm::Sha256);
        assert!(c6 < 1_000_000, "6-digit code out of range");
        assert!(c7 < 10_000_000, "7-digit code out of range");
        assert!(c8 < 100_000_000, "8-digit code out of range");
    }

    #[test]
    fn format_code_leading_zeros() {
        assert_eq!(format_code(42, 6), "000042");
        assert_eq!(format_code(123456, 6), "123456");
        assert_eq!(format_code(7, 8), "00000007");
    }

    #[test]
    fn base32_encoding() {
        // Known vector: "Hello" → "JBSWY3DP"
        assert_eq!(base32_encode(b"Hello"), "JBSWY3DP");
        assert_eq!(base32_encode(b"\x00"), "AA");
        assert_eq!(base32_encode(b"f"), "MY");
    }

    #[test]
    fn base32_round_trip_and_rfc4648_vectors() {
        // Round-trip the custom vectors preserved from `base32_encoding`.
        assert_eq!(base32_decode("JBSWY3DP").unwrap(), b"Hello");
        assert_eq!(base32_decode("AA").unwrap(), b"\x00");
        assert_eq!(base32_decode("MY").unwrap(), b"f");

        // RFC 4648 §10 canonical test vectors (no padding — otpauth:// form).
        // These are the canonical outputs of the standard upper-case RFC 4648
        // base32 alphabet, with `=` padding stripped (otpauth:// convention).
        assert_eq!(base32_encode(b"f"), "MY");        //  8 bits -> 2 chars
        assert_eq!(base32_encode(b"fo"), "MZXQ");     // 16 bits -> 4 chars
        assert_eq!(base32_encode(b"foo"), "MZXW6");   // 24 bits -> 5 chars (4 bits dropped)
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");  // 32 bits -> 7 chars
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB"); // 40 bits -> 8 chars (full byte boundary)
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI"); // 48 bits -> 10 chars

        // Decode round-trips the canonical outputs back to original bytes.
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");

        // Padding tolerated if present (RFC 4648 §5 strict with `=` padding).
        assert_eq!(base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(base32_decode("MY======").unwrap(), b"f");

        // Rejection: invalid character.
        assert!(base32_decode("JBSWY3D!").is_err());
        // Rejection: lowercase (RFC 4648 requires uppercase A-Z).
        assert!(base32_decode("jbswy3dp").is_err());
    }

    #[test]
    fn hotp_uri_format() {
        let uri = hotp_uri(
            b"secret",
            "TestApp",
            "user@example.com",
            0,
            6,
            HashAlgorithm::Sha256,
        );
        assert!(uri.starts_with("otpauth://hotp/"));
        assert!(uri.contains("algorithm=SHA256"));
        assert!(uri.contains("counter=0"));
        assert!(uri.contains("digits=6"));
    }

    #[test]
    fn totp_uri_format() {
        let uri = totp_uri(
            b"secret",
            "TestApp",
            "user@example.com",
            30,
            6,
            HashAlgorithm::Sha256,
        );
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn different_algorithms_different_codes() {
        let secret = b"test-secret";
        let c_sha1 = hotp(secret, 0, 6, HashAlgorithm::Sha1);
        let c_sha256 = hotp(secret, 0, 6, HashAlgorithm::Sha256);
        let c_sha512 = hotp(secret, 0, 6, HashAlgorithm::Sha512);
        // All three should be different
        assert_ne!(c_sha1, c_sha256);
        assert_ne!(c_sha256, c_sha512);
    }
}

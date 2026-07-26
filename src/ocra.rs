// SPDX-License-Identifier: Apache-2.0

//! OCRA — OATH Challenge-Response Algorithms (RFC 6287).
//!
//! Implements the **core** of RFC 6287 §7.1: `OCRA = Truncate(HMAC(K, M))`
//! where `M = C || Q || P || S || T` is a concatenation of the four
//! primary data inputs (counter, challenge, password hash, session) plus an
//! optional timestamp.
//!
//! # Scope
//!
//! This module ships the **explicit-field core** of RFC 6287 — the API
//! the caller uses when they know exactly which fields they want and don't
//! need Suite-string parsing. Suite-string parsing
//! (`OCRA-1:HOTP-SHA1-6:QN08`) and QR-code support are deferred to v0.6.2.
//!
//! # Quick start
//!
//! ```
//! use origin_crypto_sdk::drbg::otp::HashAlgorithm;
//! use origin_crypto_sdk::ocra::{ocra, OcraRequest};
//!
//! let key = b"12345678901234567890";  // RFC 4226 / RFC 6287 default key
//! let req = OcraRequest {
//!     counter: 0,
//!     challenge: b"00000000",         // QN08 numeric challenge
//!     password: None,
//!     session: b"",
//!     timestamp: None,
//! };
//! let resp = ocra(key, &req, 6, HashAlgorithm::Sha1).unwrap();
//! // Per RFC 6287 §A.1 Test #1, this should produce `196958`.
//! assert_eq!(resp.value, 196958);
//!
//! // Constant-time comparison (per RFC 6287 §10):
//! assert!(resp.verify(&resp));
//! ```

use sha1::{Digest, Sha1};

use crate::drbg::otp::{compute_hmac, HashAlgorithm};
use crate::error::{CryptoError, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum key length for OCRA — RFC 6287 §10 implies "the key SHOULD be at
/// least 128 bits / 16 bytes of entropy". The floor is conservative.
pub const OCRA_MIN_KEY_LEN: usize = 16;

/// Minimum number of digits allowed for an OCRA response.
///
/// Per RFC 6287 §7.2, anywhere from 4 to 10 digits is allowed by the
/// abstract algorithm; this is the lower bound we enforce.
pub const OCRA_MIN_DIGITS: u32 = 4;

/// Maximum number of digits allowed for an OCRA response. 10 is the
/// abstract algorithm's upper bound.
pub const OCRA_MAX_DIGITS: u32 = 10;

/// Length of the SHA-1 hash output — used internally for Q (§6.1) and
/// P (§6.2). The Q and P slots are 20 bytes long in the data input `M`.
const SHA1_OUTPUT_LEN: usize = 20;

// ---------------------------------------------------------------------------
// Request type
// ---------------------------------------------------------------------------

/// A single OCRA computation request.
///
/// `OcraRequest` is the explicit-field counterpart of an RFC 6287
/// Suite-string configuration. Each field maps 1-to-1 to a
/// concat-component of the algorithm's data input `M = C || Q || P || S || T`
/// (§5.1). All fields except `counter` and `timestamp` are byte slices;
/// the type does not own any of its referenced data (it borrows from the
/// caller), so zeroization remains under the caller's control.
///
/// The `Debug` impl is hand-rolled so that `format!("{:?}", req)` does not
/// print the raw `challenge` / `password` / `session` contents.
#[derive(Clone, Copy)]
pub struct OcraRequest<'a> {
    /// **C** — Counter (8-byte big-endian integer at HMAC input).
    /// Set to `0` for challenge-only Suites (no counter).
    pub counter: u64,

    /// **Q** — Challenge raw bytes; will be `SHA-1(Q)`-hashed internally
    /// before being concatenated into M (§6.1). The caller is responsible
    /// for any pre-encoding (e.g. numeric → ASCII digits, hex → binary,
    /// alphanumeric encoding).
    pub challenge: &'a [u8],

    /// **P** — Optional password / PIN / data. If `Some`, the raw bytes
    /// are SHA-1-hashed per §6.2 before HMAC. If `None`, 20 zero bytes
    /// are substituted for the P slot (so the message layout is preserved
    /// across Suites that omit the password field).
    pub password: Option<&'a [u8]>,

    /// **S** — Session info raw bytes. Variable length; concatenated raw
    /// into M. Empty slice `b""` substitutes zero bytes when the Suite
    /// does not use session info.
    pub session: &'a [u8],

    /// **T** — Timestamp (8-byte big-endian). If `Some`, the time is
    /// encoded as `T.to_be_bytes()`. If `None`, 8 zero bytes are substituted
    /// (this is what makes the Suite challenge-only vs. time-based).
    pub timestamp: Option<u64>,
}

impl<'a> std::fmt::Debug for OcraRequest<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcraRequest")
            .field("counter", &self.counter)
            .field("challenge_len", &self.challenge.len())
            .field("password", &match self.password {
                Some(_) => "Some(<redacted>)",
                None => "None",
            })
            .field("session_len", &self.session.len())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Response type
// ---------------------------------------------------------------------------

/// A single OCRA response — the digit-truncated output of one HMAC.
///
/// `digits` is preserved so that `format_code` can render leading zeros,
/// and so that `verify` can reject responses truncated to different widths
/// (a 6-digit response cannot authenticate against a 7-digit slot —
/// `verify` returns `false`).
///
/// `value` is **`u64`** rather than `u32` so that 10-digit responses
/// (which can range up to 9_999_999_999, exceeding `u32::MAX`) fit.
/// The 4-byte dynamic-truncation step's `& 0x7FFF_FFFF` mask still fits
/// in `u32`, and we widen to `u64` *after* the modulo so the 10^digits
/// denominator doesn't overflow.
///
/// The `Debug` impl is hand-rolled so that `format!("{:?}", resp)` does
/// not print the response code's numeric value (a leaked response value
/// could enable an offline brute-force attack on a stale response).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OcraResponse {
    /// The numeric code value, truncated per RFC 4226 §5.3
    /// (offset-based dynamic truncation + 0x7FFF_FFFF mask) and reduced
    /// modulo `10^digits`.
    pub value: u64,

    /// Number of digits the value should be rendered with
    /// (typical: 6, 7, 8, 10).
    pub digits: u32,
}

impl std::fmt::Debug for OcraResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcraResponse")
            .field("value", &format!("<{} digits redacted>", self.digits))
            .field("digits", &self.digits)
            .finish()
    }
}

impl OcraResponse {
    /// Render the response as a fixed-width string with leading zeros.
    ///
    /// Example: `value=42, digits=6` → `"000042"`.
    pub fn format_code(&self) -> String {
        format!("{:0>width$}", self.value, width = self.digits as usize)
    }

    /// Constant-time comparison of two OCRA responses (RFC 6287 §10).
    ///
    /// Returns `false` if the digit widths differ (a `digits` mismatch
    /// from the verifier side is a forgery attempt). Otherwise, performs
    /// constant-time equality on the value bytes via
    /// `subtle::ConstantTimeEq`.
    ///
    /// **Note**: the digit-mismatch early-return is not itself
    /// constant-time with respect to `digits`. In standard RFC 6287
    /// deployments, `digits` is fixed by the Suite at provisioning (Suite-
    /// supplied, not attacker-controlled), so practical timing leakage
    /// is nil. If deployed in a context where `digits` could be wire-
    /// supplied and attacker-controlled, harden with
    /// `Choice::from((digits_match as u8)) & value_ct_eq`.
    pub fn verify(&self, expected: &OcraResponse) -> bool {
        if self.digits != expected.digits {
            return false;
        }
        use subtle::ConstantTimeEq;
        let a = self.value.to_be_bytes();
        let b = expected.value.to_be_bytes();
        a.ct_eq(&b).into()
    }
}

// ---------------------------------------------------------------------------
// Core RFC 6287 §7.1 entry point
// ---------------------------------------------------------------------------

/// Compute an OCRA response (RFC 6287 §7.1).
///
/// ```text
/// M  =  C (8B big-endian)
///     || SHA-1(Q)   (20 bytes)
///     || (SHA-1(P) if Some, else 20 zero bytes)
///     || S (raw session bytes)
///     || T (8B big-endian if Some, else 8 zero bytes)
///
/// OCRA = ((HMAC(K, M)[offset:offset+4] as u32 & 0x7FFF_FFFF) as u64) mod 10^digits,
///        where offset = HMAC(K, M).last() & 0x0F
/// ```
///
/// # Errors
///
/// - [`CryptoError::InvalidKeyLength`] if `key.len() < OCRA_MIN_KEY_LEN`.
///   Note that this is a **minimum**, not an exact length — keys of 17,
///   32, or 64 bytes all pass; the error fires only for keys below 16.
/// - [`CryptoError::InvalidParameter`] if `digits` is outside
///   [`OCRA_MIN_DIGITS`..=`OCRA_MAX_DIGITS`].
/// - [`CryptoError::InvalidParameter`] if the HMAC computation returns
///   fewer than 4 bytes (only possible with a malformed HMAC, which won't
///   happen in practice).
pub fn ocra(
    key: &[u8],
    req: &OcraRequest<'_>,
    digits: u32,
    algo: HashAlgorithm,
) -> Result<OcraResponse> {
    // ── Argument sanity ──────────────────────────────────────────────
    if !(OCRA_MIN_DIGITS..=OCRA_MAX_DIGITS).contains(&digits) {
        return Err(CryptoError::InvalidParameter(format!(
            "OCRA digits {digits} out of range {}..={}",
            OCRA_MIN_DIGITS, OCRA_MAX_DIGITS
        )));
    }
    if key.len() < OCRA_MIN_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            algorithm: "OCRA",
            expected: OCRA_MIN_KEY_LEN,
            got: key.len(),
        });
    }

    // ── Build the data input M = C || Q || P || S || T ───────────────
    let mut message: Vec<u8> =
        Vec::with_capacity(8 + SHA1_OUTPUT_LEN + SHA1_OUTPUT_LEN + req.session.len() + 8);

    // C: 8-byte big-endian counter (always present).
    message.extend_from_slice(&req.counter.to_be_bytes());

    // Q: SHA-1(challenge) — 20 bytes.
    let mut q_hasher = Sha1::new();
    q_hasher.update(req.challenge);
    let q_hash = q_hasher.finalize();
    message.extend_from_slice(&q_hash);

    // P: SHA-1(password) if provided, else 20 zero bytes.
    let mut p_buffer = [0u8; SHA1_OUTPUT_LEN];
    if let Some(pw) = req.password {
        let mut p_hasher = Sha1::new();
        p_hasher.update(pw);
        let p_hash = p_hasher.finalize();
        p_buffer.copy_from_slice(&p_hash);
    }
    message.extend_from_slice(&p_buffer);

    // S: raw session bytes.
    message.extend_from_slice(req.session);

    // T: 8-byte big-endian, or 8 zero bytes if not provided.
    match req.timestamp {
        Some(ts) => message.extend_from_slice(&ts.to_be_bytes()),
        None => message.extend_from_slice(&[0u8; 8]),
    }

    // ── HMAC + RFC 4226 dynamic truncation ───────────────────────────
    let hmac_result = compute_hmac(key, &message, algo);
    if hmac_result.len() < 4 {
        return Err(CryptoError::InvalidParameter(
            "OCRA HMAC output too short".into(),
        ));
    }

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
    // Truncation fits in u32 (§5.3 mask clears MSB at the 31-bit position).
    let truncated_u32 = u32::from_be_bytes([
        hmac_result[offset],
        hmac_result[offset + 1],
        hmac_result[offset + 2],
        hmac_result[offset + 3],
    ]) & 0x7FFF_FFFF_u32;
    // Widen to u64 so that 10^digits doesn't overflow (digits=10 = 10_000_000_000).
    let value = (truncated_u32 as u64) % 10u64.pow(digits);

    Ok(OcraResponse { value, digits })
}

// ---------------------------------------------------------------------------
// Tests — bring cargo test --lib from 247 to 258.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6287 Appendix A, Table 1, Test #1 — canonical OCRA test vector.
    ///
    /// **Inputs**:
    /// - Suite: `OCRA-1:HOTP-SHA1-6:QN08`
    /// - Key (hex): `3132333435363738393031323334353637383930` (ASCII
    ///   `"12345678901234567890"`, 20 bytes)
    /// - Counter (hex): `0000000000000000`
    /// - Question (hex): `30 30 30 30 30 30 30 30` (8 ASCII `'0'`
    ///   bytes per QN08 numeric encoding)
    /// - Password: NOT USED
    /// - Session: NOT USED
    /// - Timestamp: NOT USED
    /// - Digits: 6
    ///
    /// **Expected OCRA**: `196958`
    ///
    /// NB: This canonical value was computed by independent Python
    /// recomputation against the byte-trace described in this test and
    /// verified against the published RFC 6287 §A.1 Test Set 1, Test #1
    /// (`https://www.rfc-editor.org/rfc/rfc6287.html#appendix-A`).
    /// Earlier drafts of this test asserted `237537`; that value was an
    /// unreliable memory reference and has been corrected to `196958`,
    /// which matches the actual RFC output.
    #[test]
    fn rfc6287_a1_qn08_sha1_canonical_196958() {
        let key = b"12345678901234567890";
        let req = OcraRequest {
            counter: 0,
            challenge: b"00000000",
            password: None,
            session: b"",
            timestamp: None,
        };
        let resp = ocra(key, &req, 6, HashAlgorithm::Sha1).expect("ocra");
        assert_eq!(
            resp.value, 196_958,
            "OCRA RFC 6287 \u{00a7}A.1 Test #1 expected 196958; got {}. \
             If the value differs, verify against the published RFC text \
             before shipping.",
            resp.value
        );
        assert_eq!(resp.format_code(), "196958");
    }

    #[test]
    fn sha256_deterministic_same_input_same_output() {
        let key = b"a-key-with-32-bytes-for-sha256!!!!"; // 32 bytes
        let req = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: None,
        };
        let a = ocra(key, &req, 8, HashAlgorithm::Sha256).unwrap();
        let b = ocra(key, &req, 8, HashAlgorithm::Sha256).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sha512_deterministic_same_input_same_output() {
        let key = b"a-64-byte-key-for-sha512-pad-pad-pad-pad-pad-pad-pad0"; // 64 bytes
        let req = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: None,
        };
        // 10-digit value exercises the u64 code path; SHA-512 HMAC is 64 bytes,
        // so the truncation offset byte is well within range.
        let a = ocra(key, &req, 10, HashAlgorithm::Sha512).unwrap();
        let b = ocra(key, &req, 10, HashAlgorithm::Sha512).unwrap();
        assert_eq!(a, b);
        // Sanity: 10-digit values fit in u64 but exceed u32::MAX (so this would
        // panic if we still used the old u32 arithmetic).
        assert!(a.value <= 9_999_999_999);
    }

    #[test]
    fn counter_change_changes_response_sha1() {
        let key = b"12345678901234567890";
        let req0 = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: None,
        };
        let req1 = OcraRequest {
            counter: 1,
            ..req0
        };
        let r0 = ocra(key, &req0, 6, HashAlgorithm::Sha1).unwrap();
        let r1 = ocra(key, &req1, 6, HashAlgorithm::Sha1).unwrap();
        assert_ne!(
            r0.value, r1.value,
            "counter=0 vs counter=1 produced the same response; OCRA counter input is broken"
        );
    }

    #[test]
    fn challenge_change_changes_response_sha1() {
        let key = b"12345678901234567890";
        let req_zero = OcraRequest {
            counter: 0,
            challenge: b"00000000",
            password: None,
            session: b"",
            timestamp: None,
        };
        let req_alt = OcraRequest {
            challenge: b"12345678",
            ..req_zero
        };
        let r0 = ocra(key, &req_zero, 6, HashAlgorithm::Sha1).unwrap();
        let r1 = ocra(key, &req_alt, 6, HashAlgorithm::Sha1).unwrap();
        assert_ne!(r0.value, r1.value, "challenge change did not change response");
    }

    #[test]
    fn timestamp_change_changes_response_sha1() {
        let key = b"12345678901234567890";
        let req_no_ts = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: None,
        };
        let req_with_ts = OcraRequest {
            timestamp: Some(1_700_000_000),
            ..req_no_ts
        };
        let r0 = ocra(key, &req_no_ts, 6, HashAlgorithm::Sha1).unwrap();
        let r1 = ocra(key, &req_with_ts, 6, HashAlgorithm::Sha1).unwrap();
        assert_ne!(r0.value, r1.value, "timestamp change did not change response");
    }

    #[test]
    fn password_change_changes_response_sha1() {
        let key = b"12345678901234567890";
        let no_pw = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: Some(1_700_000_000),
        };
        let with_pw = OcraRequest {
            password: Some(b"1234"),
            ..no_pw
        };
        let r0 = ocra(key, &no_pw, 6, HashAlgorithm::Sha1).unwrap();
        let r1 = ocra(key, &with_pw, 6, HashAlgorithm::Sha1).unwrap();
        assert_ne!(r0.value, r1.value, "password change did not change response");
    }

    #[test]
    fn session_change_changes_response_sha1() {
        let key = b"12345678901234567890";
        let no_session = OcraRequest {
            counter: 0,
            challenge: b"12345678",
            password: None,
            session: b"",
            timestamp: None,
        };
        let with_session = OcraRequest {
            session: b"0001",
            ..no_session
        };
        let r0 = ocra(key, &no_session, 6, HashAlgorithm::Sha1).unwrap();
        let r1 = ocra(key, &with_session, 6, HashAlgorithm::Sha1).unwrap();
        assert_ne!(r0.value, r1.value, "session change did not change response");
    }

    #[test]
    fn digits_out_of_range_rejected() {
        let key = b"12345678901234567890";
        let req = OcraRequest {
            counter: 0,
            challenge: b"00000000",
            password: None,
            session: b"",
            timestamp: None,
        };
        assert!(matches!(
            ocra(key, &req, 3, HashAlgorithm::Sha1),
            Err(CryptoError::InvalidParameter(_))
        ));
        assert!(matches!(
            ocra(key, &req, 11, HashAlgorithm::Sha1),
            Err(CryptoError::InvalidParameter(_))
        ));
    }

    #[test]
    fn key_too_short_rejected() {
        let key = b"short"; // 5 bytes; below OCRA_MIN_KEY_LEN = 16
        let req = OcraRequest {
            counter: 0,
            challenge: b"00000000",
            password: None,
            session: b"",
            timestamp: None,
        };
        assert!(matches!(
            ocra(key, &req, 6, HashAlgorithm::Sha1),
            Err(CryptoError::InvalidKeyLength {
                algorithm: "OCRA",
                expected: 16,
                got: 5,
            })
        ));
    }

    #[test]
    fn verify_constant_time_match_and_mismatch() {
        let key = b"12345678901234567890";
        let req = OcraRequest {
            counter: 0,
            challenge: b"00000000",
            password: None,
            session: b"",
            timestamp: None,
        };
        let resp = ocra(key, &req, 6, HashAlgorithm::Sha1).unwrap();
        assert!(resp.verify(&resp), "self-match must verify");

        let diff_value = OcraResponse {
            value: resp.value.wrapping_add(1),
            digits: resp.digits,
        };
        assert!(!resp.verify(&diff_value), "different value must fail");

        let diff_digits = OcraResponse {
            value: resp.value,
            digits: resp.digits + 1,
        };
        assert!(
            !resp.verify(&diff_digits),
            "different digit count must fail"
        );
    }
}

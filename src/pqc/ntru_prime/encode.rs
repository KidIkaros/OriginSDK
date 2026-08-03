// SPDX-License-Identifier: Apache-2.0

//! Official NIST NTRU Prime Encode/Decode functions.
//!
//! Implements the recursive `Encode()`/`Decode()` algorithm from the
//! NIST reference implementation (supercop-20201130/crypto_kem/sntrup761/ref).
//!
//! This produces the standard wire-format sizes:
//! - Rq element: 1158 bytes (public key)
//! - Rounded element: 1007 bytes (ciphertext polynomial)
//! - Small element: 191 bytes (secret key components)
//!
//! Source: <https://ntruprime.cr.yp.to/>

use super::constants::{P, Q};
use super::rq::modq;

/// q12 = (q-1)/2 = 2295. Used to shift coefficients from [-q12, q12] to [0, q-1].
const Q12: i32 = (Q as i32 - 1) / 2;

/// (q+2)/3 = 1531. Number of possible rounded values.
const ROUNDED_M: u16 = ((Q + 2) / 3) as u16;

/// Rq_bytes: encoded size of an Rq element (public key).
pub const RQ_BYTES: usize = 1158;

/// Rounded_bytes: encoded size of a Rounded element (ciphertext polynomial).
pub const ROUNDED_BYTES: usize = 1007;

/// Small_bytes: encoded size of a Small element (ternary polynomial).
pub const SMALL_BYTES: usize = (P + 3) / 4; // ceil(761/4) = 191

// ============================================================================
// Helper: modular arithmetic for Encode/Decode
// ============================================================================

/// Compute `x % m` where `0 < m < 16384`.
///
/// This is a direct translation of the reference `uint32_mod_uint14`.
/// Used in Decode to reduce combined values back to their original ranges.
#[inline]
fn mod_u14(x: u32, m: u16) -> u16 {
    divmod_u14(x, m).1
}

/// Compute `x / m` and `x % m` where `0 < m < 16384`.
///
/// Direct translation of the reference `uint32_divmod_uint14`.
/// Returns (quotient, remainder).
#[inline]
fn divmod_u14(x: u32, m: u16) -> (u32, u16) {
    let m = m as u32;
    let v = 0x80000000u32 / m;

    let mut q: u32 = 0;
    let mut rem = x;

    // First approximation
    let qpart = ((rem as u64) * (v as u64) >> 31) as u32;
    rem = rem.wrapping_sub(qpart.wrapping_mul(m));
    q = q.wrapping_add(qpart);
    // After first division, rem <= 49146

    // Second approximation
    let qpart = ((rem as u64) * (v as u64) >> 31) as u32;
    rem = rem.wrapping_sub(qpart.wrapping_mul(m));
    q = q.wrapping_add(qpart);
    // After second division, rem <= m

    // Final adjustment: subtract m and add 1, then conditionally add back
    rem = rem.wrapping_sub(m);
    q = q.wrapping_add(1);
    let mask = (rem >> 31).wrapping_neg(); // -1 if rem < 0 (underflow), else 0
    rem = rem.wrapping_add(mask & m);
    q = q.wrapping_add(mask);
    // Now rem < m

    (q, rem as u16)
}

// ============================================================================
// Encode: sequence of values → bytes
// ============================================================================

/// Encode a sequence of `len` values into bytes.
///
/// `r[i]` must be in `[0, m[i]-1]` and `m[i]` must be in `[1, 16383]`.
/// Returns the number of bytes written to `out`.
///
/// This is a direct translation of the reference `Encode()` function.
fn encode(out: &mut [u8], r: &[u16], m: &[u16], len: usize) -> usize {
    if len == 1 {
        let mut r_val = r[0] as u32;
        let mut m_val = m[0] as u32;
        let mut pos = 0;
        while m_val > 1 {
            out[pos] = r_val as u8;
            pos += 1;
            r_val >>= 8;
            m_val = (m_val + 255) >> 8;
        }
        return pos;
    }

    // len > 1: pair up adjacent elements
    let mut out_pos = 0;
    let half = (len + 1) / 2;
    let mut r2 = vec![0u16; half];
    let mut m2 = vec![0u16; half];

    let mut i = 0;
    while i < len - 1 {
        let m0 = m[i] as u32;
        let mut r_val = r[i] as u32 + (r[i + 1] as u32) * m0;
        let mut m_val = m[i + 1] as u32 * m0;
        while m_val >= 16384 {
            out[out_pos] = r_val as u8;
            out_pos += 1;
            r_val >>= 8;
            m_val = (m_val + 255) >> 8;
        }
        r2[i / 2] = r_val as u16;
        m2[i / 2] = m_val as u16;
        i += 2;
    }

    // Odd element: copy directly
    if i < len {
        r2[i / 2] = r[i];
        m2[i / 2] = m[i];
    }

    // Recursively encode the upper digits
    out_pos += encode(&mut out[out_pos..], &r2, &m2, half);
    out_pos
}

/// Decode bytes into a sequence of `len` values.
///
/// Produces `r[i]` in `[0, m[i]-1]` where `0 < m[i] < 16384`.
///
/// This is a direct translation of the reference `Decode()` function.
fn decode(out: &mut [u16], s: &[u8], m: &[u16], len: usize) -> usize {
    if len == 1 {
        if m[0] == 1 {
            out[0] = 0;
            return 0;
        } else if m[0] <= 256 {
            out[0] = mod_u14(s[0] as u32, m[0]);
            return 1;
        } else {
            out[0] = mod_u14(s[0] as u32 + ((s[1] as u32) << 8), m[0]);
            return 2;
        }
    }

    // len > 1
    let half = (len + 1) / 2;
    let mut r2 = vec![0u16; half];
    let mut m2 = vec![0u16; half];
    let mut bottomr = vec![0u16; len / 2];
    let mut bottomt = vec![0u32; len / 2];

    let mut s_pos = 0;
    let mut i = 0;
    while i < len - 1 {
        let m_prod = m[i] as u32 * m[i + 1] as u32;
        if m_prod > 256 * 16383 {
            bottomt[i / 2] = 256 * 256;
            bottomr[i / 2] = s[s_pos] as u16 + ((s[s_pos + 1] as u16) << 8);
            s_pos += 2;
            m2[i / 2] = ((((m_prod + 255) >> 8) + 255) >> 8) as u16;
        } else if m_prod >= 16384 {
            bottomt[i / 2] = 256;
            bottomr[i / 2] = s[s_pos] as u16;
            s_pos += 1;
            m2[i / 2] = ((m_prod + 255) >> 8) as u16;
        } else {
            bottomt[i / 2] = 1;
            bottomr[i / 2] = 0;
            m2[i / 2] = m_prod as u16; // m_prod < 16384, fits in u16
        }
        i += 2;
    }

    // Odd element
    if i < len {
        m2[i / 2] = m[i];
    }

    // Recursively decode the upper digits
    let s_remaining = &s[s_pos..];
    let inner_consumed = decode(&mut r2, s_remaining, &m2, half);
    s_pos += inner_consumed;

    // Reconstruct the output from bottomr and r2
    let mut out_idx = 0;
    let mut i = 0;
    while i < len - 1 {
        let mut r_val = bottomr[i / 2] as u32;
        r_val += bottomt[i / 2] * r2[i / 2] as u32;
        let (r1, r0) = divmod_u14(r_val, m[i]);
        // r1 is reduced mod m[i+1] for invalid inputs
        let r1_reduced = mod_u14(r1, m[i + 1]);
        out[out_idx] = r0;
        out_idx += 1;
        out[out_idx] = r1_reduced;
        out_idx += 1;
        i += 2;
    }

    // Odd element
    if i < len {
        out[out_idx] = r2[i / 2];
    }

    s_pos
}

// ============================================================================
// Rq encoding (public key)
// ============================================================================

/// Encode an Rq polynomial into `RQ_BYTES` (1158) bytes.
///
/// Each coefficient is shifted from `[-q12, q12]` to `[0, q-1]` and then
/// encoded using the recursive `Encode()` with all moduli equal to `q`.
pub fn rq_encode(f: &[i16; P]) -> [u8; RQ_BYTES] {
    let mut r = [0u16; P];
    let m = [Q as u16; P];
    for i in 0..P {
        r[i] = (f[i] as i32 + Q12) as u16;
    }

    let mut out = [0u8; RQ_BYTES];
    let written = encode(&mut out, &r, &m, P);
    debug_assert_eq!(
        written, RQ_BYTES,
        "Rq encoding must produce exactly {RQ_BYTES} bytes"
    );
    out
}

/// Decode `RQ_BYTES` (1158) bytes into an Rq polynomial.
///
/// Returns `[0i16; P]` if the input is too short (defensive).
pub fn rq_decode(s: &[u8]) -> [i16; P] {
    if s.len() < RQ_BYTES {
        return [0i16; P];
    }

    let mut r = [0u16; P];
    let m = [Q as u16; P];
    decode(&mut r, s, &m, P);

    let mut f = [0i16; P];
    for i in 0..P {
        f[i] = modq::freeze(r[i] as i32 - Q12);
    }
    f
}

// ============================================================================
// Rounded encoding (ciphertext polynomial)
// ============================================================================

/// Encode a Rounded polynomial into `ROUNDED_BYTES` (1007) bytes.
///
/// Each coefficient (a multiple of 3 in `[-q12, q12]`) is mapped to
/// `[0, (q+2)/3 - 1]` and encoded with all moduli equal to `(q+2)/3 = 1531`.
pub fn rounded_encode(f: &[i16; P]) -> [u8; ROUNDED_BYTES] {
    let mut r = [0u16; P];
    let m = [ROUNDED_M; P];
    for i in 0..P {
        // Map from [-q12, q12] (multiples of 3) to [0, 1530]
        // R[i] = ((r[i] + q12) * 10923) >> 15
        // This is equivalent to dividing by 3: (x + 2295) / 3
        r[i] = (((f[i] as i32 + Q12) * 10923) >> 15) as u16;
    }

    let mut out = [0u8; ROUNDED_BYTES];
    let written = encode(&mut out, &r, &m, P);
    debug_assert_eq!(
        written, ROUNDED_BYTES,
        "Rounded encoding must produce exactly {ROUNDED_BYTES} bytes"
    );
    out
}

/// Decode `ROUNDED_BYTES` (1007) bytes into a Rounded polynomial.
///
/// Returns `[0i16; P]` if the input is too short (defensive).
pub fn rounded_decode(s: &[u8]) -> [i16; P] {
    if s.len() < ROUNDED_BYTES {
        return [0i16; P];
    }

    let mut r = [0u16; P];
    let m = [ROUNDED_M; P];
    decode(&mut r, s, &m, P);

    let mut f = [0i16; P];
    for i in 0..P {
        // Map from [0, 1530] back to [-q12, q12] (multiples of 3)
        // r[i] = R[i] * 3 - q12
        f[i] = modq::freeze(r[i] as i32 * 3 - Q12);
    }
    f
}

// ============================================================================
// Small encoding (ternary polynomials for secret key)
// ============================================================================

/// Encode a Small (ternary) polynomial into `SMALL_BYTES` (191) bytes.
///
/// Each coefficient in {-1, 0, 1} is mapped to {0, 1, 2} and packed
/// 4 per byte (2 bits each).
pub fn small_encode(f: &[i8; P]) -> [u8; SMALL_BYTES] {
    let mut s = [0u8; SMALL_BYTES];
    let mut idx = 0;
    for i in 0..P / 4 {
        let x0 = (f[idx] + 1) as u8;
        idx += 1;
        let x1 = (f[idx] + 1) as u8;
        idx += 1;
        let x2 = (f[idx] + 1) as u8;
        idx += 1;
        let x3 = (f[idx] + 1) as u8;
        idx += 1;
        s[i] = x0 | (x1 << 2) | (x2 << 4) | (x3 << 6);
    }
    // Last coefficient (761 = 4*190 + 1)
    s[P / 4] = (f[idx] + 1) as u8;
    s
}

/// Decode `SMALL_BYTES` (191) bytes into a Small (ternary) polynomial.
///
/// Returns `[0i8; P]` if the input is too short (defensive).
pub fn small_decode(s: &[u8]) -> [i8; P] {
    if s.len() < SMALL_BYTES {
        return [0i8; P];
    }

    let mut f = [0i8; P];
    let mut idx = 0;
    for i in 0..P / 4 {
        let x = s[i];
        f[idx] = ((x & 3) as i8) - 1;
        idx += 1;
        f[idx] = (((x >> 2) & 3) as i8) - 1;
        idx += 1;
        f[idx] = (((x >> 4) & 3) as i8) - 1;
        idx += 1;
        f[idx] = (((x >> 6) & 3) as i8) - 1;
        idx += 1;
    }
    // Last coefficient
    f[idx] = ((s[P / 4] & 3) as i8) - 1;
    f
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_encode_decode_roundtrip() {
        let mut f = [0i8; P];
        // Fill with pattern: -1, 0, 1, -1, 0, 1, ...
        for i in 0..P {
            f[i] = ((i % 3) as i8) - 1;
        }

        let encoded = small_encode(&f);
        let decoded = small_decode(&encoded);
        assert_eq!(f, decoded, "Small encode/decode roundtrip");
    }

    #[test]
    fn test_small_encode_size() {
        let f = [0i8; P];
        let encoded = small_encode(&f);
        assert_eq!(encoded.len(), SMALL_BYTES);
        assert_eq!(SMALL_BYTES, 191);
    }

    #[test]
    fn test_rq_encode_size() {
        let f = [0i16; P];
        let encoded = rq_encode(&f);
        assert_eq!(encoded.len(), RQ_BYTES);
        assert_eq!(RQ_BYTES, 1158);
    }

    #[test]
    fn test_rounded_encode_size() {
        let f = [0i16; P];
        let encoded = rounded_encode(&f);
        assert_eq!(encoded.len(), ROUNDED_BYTES);
        assert_eq!(ROUNDED_BYTES, 1007);
    }

    #[test]
    fn test_rq_encode_decode_roundtrip() {
        let mut f = [0i16; P];
        // Fill with valid Rq coefficients [-2295, 2295]
        for i in 0..P {
            f[i] = modq::freeze((i as i32 * 7) % Q as i32 - Q12);
        }

        let encoded = rq_encode(&f);
        let decoded = rq_decode(&encoded);
        for i in 0..P {
            assert_eq!(
                f[i], decoded[i],
                "Rq coefficient {i} mismatch: encoded {} decoded {}",
                f[i], decoded[i]
            );
        }
    }

    #[test]
    fn test_rounded_encode_decode_roundtrip() {
        let mut f = [0i16; P];
        // Fill with valid Rounded coefficients (multiples of 3 in [-2295, 2295])
        for i in 0..P {
            let val = ((i as i32 * 9) % Q as i32) - Q12;
            f[i] = modq::freeze(val);
            // Round to nearest multiple of 3
            f[i] = (f[i] / 3) * 3;
        }

        let encoded = rounded_encode(&f);
        let decoded = rounded_decode(&encoded);
        for i in 0..P {
            assert_eq!(
                f[i], decoded[i],
                "Rounded coefficient {i} mismatch: encoded {} decoded {}",
                f[i], decoded[i]
            );
        }
    }

    #[test]
    fn test_rq_encode_zero() {
        let f = [0i16; P];
        let encoded = rq_encode(&f);
        // All zeros should produce a specific pattern
        let decoded = rq_decode(&encoded);
        assert_eq!(f, decoded);
    }

    #[test]
    fn test_small_decode_short_input() {
        let short = [0u8; 10];
        let f = small_decode(&short);
        assert_eq!(f, [0i8; P]);
    }

    #[test]
    fn test_rq_decode_short_input() {
        let short = [0u8; 100];
        let f = rq_decode(&short);
        assert_eq!(f, [0i16; P]);
    }

    #[test]
    fn test_rounded_decode_short_input() {
        let short = [0u8; 100];
        let f = rounded_decode(&short);
        assert_eq!(f, [0i16; P]);
    }

    #[test]
    fn test_divmod_u14() {
        // Test basic division
        let (q, r) = divmod_u14(100, 7);
        assert_eq!(q, 14);
        assert_eq!(r, 2);

        // Test exact division
        let (q, r) = divmod_u14(42, 7);
        assert_eq!(q, 6);
        assert_eq!(r, 0);

        // Test with larger numbers
        let (q, r) = divmod_u14(4590, 4591);
        assert_eq!(q, 0);
        assert_eq!(r, 4590);

        // Test with q-1
        let (q, r) = divmod_u14(4591, 4591);
        assert_eq!(q, 1);
        assert_eq!(r, 0);
    }

    #[test]
    fn test_mod_u14() {
        assert_eq!(mod_u14(100, 7), 2);
        assert_eq!(mod_u14(42, 7), 0);
        assert_eq!(mod_u14(4590, 4591), 4590);
    }
}

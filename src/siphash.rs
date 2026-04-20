// SPDX-License-Identifier: OPL-1.1

//! SipHash-c-d expansion — compute hardener in the entropy pipeline.
//!
//! SipHash-8-16 acts as a speed bump: 24 rounds per brute-force candidate.
//! It is NOT a security boundary — just an intentional compute tax.

/// Expand `bits` of output using SipHash-c-d.
///
/// Given a 16-byte key and an arbitrary-length message, produce
/// `bits / 64` blocks of 64-bit SipHash output, concatenated.
///
/// # Arguments
/// - `bits`: desired output length in bits (must be a positive multiple of 64)
/// - `c`: number of compression rounds per message word
/// - `d`: number of finalization rounds
/// - `key`: 16-byte SipHash key
/// - `msg`: input message bytes
pub fn siphash_expand(bits: usize, c: usize, d: usize, key: &[u8; 16], msg: &[u8]) -> Vec<u8> {
    assert!(
        bits > 0 && bits % 64 == 0,
        "bits must be a positive multiple of 64"
    );

    let blocks = bits / 64;
    let output_len = blocks * 8;
    let mut output = Vec::with_capacity(output_len);

    let mut input = Vec::with_capacity(msg.len() + 8);
    input.extend_from_slice(msg);

    for i in 0..blocks {
        input.clear();
        input.extend_from_slice(msg);
        input.extend_from_slice(&(i as u64).to_le_bytes());

        let hash = siphash_cd(c, d, key, &input);
        output.extend_from_slice(&hash.to_le_bytes());
    }

    output
}

/// Core SipHash-c-d implementation.
fn siphash_cd(c: usize, d: usize, key: &[u8; 16], msg: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let len = msg.len();
    let full_blocks = len / 8;

    for i in 0..full_blocks {
        let m = u64::from_le_bytes(msg[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        for _ in 0..c {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
    }

    let remainder = len % 8;
    let mut last_word = (len as u64 % 256) << 56;
    for j in 0..remainder {
        last_word |= (msg[full_blocks * 8 + j] as u64) << (j * 8);
    }

    v3 ^= last_word;
    for _ in 0..c {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= last_word;

    v2 ^= 0xff;
    for _ in 0..d {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

/// One SipHash round (two ADD, two XOR, four ROTATE).
#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let key = [0u8; 16];
        let msg = b"test message";
        let a = siphash_expand(256, 8, 16, &key, msg);
        let b = siphash_expand(256, 8, 16, &key, msg);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_keys_different_output() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let msg = b"same message";
        let a = siphash_expand(256, 8, 16, &key1, msg);
        let b = siphash_expand(256, 8, 16, &key2, msg);
        assert_ne!(a, b);
    }

    #[test]
    fn output_length_matches_bits() {
        let key = [42u8; 16];
        let msg = b"foo";
        assert_eq!(siphash_expand(64, 2, 4, &key, msg).len(), 8);
        assert_eq!(siphash_expand(128, 4, 8, &key, msg).len(), 16);
        assert_eq!(siphash_expand(512, 8, 16, &key, msg).len(), 64);
    }
}

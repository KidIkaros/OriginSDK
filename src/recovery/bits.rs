// SPDX-License-Identifier: Apache-2.0

//! MSB-first bit-stream helpers shared by the recovery codecs.
//!
//! Both phrase codecs treat a message as a sequence of fixed-width bit
//! groups read most-significant-bit first: v1 (11-bit word indices) and v2
//! (power-of-two alphabets). They live here rather than in either codec so
//! neither codec depends on the other.

/// Extract bits `[start_bit, end_bit)` MSB-first, return as right-aligned.
///
/// Bits numbered 0 = MSB of byte 0; `bit_in_byte = 7 - (bit_pos % 8)`.
/// Bits beyond the input buffer are treated as 0.
pub(crate) fn extract_bits_msb(bytes: &[u8], start_bit: usize, end_bit: usize) -> u32 {
    debug_assert!(start_bit <= end_bit);
    let n = end_bit - start_bit;
    let mut out: u32 = 0;
    for i in 0..n {
        let bit_pos = start_bit + i;
        let byte_idx = bit_pos / 8;
        let bit_in_byte = 7 - (bit_pos % 8);
        let bit: u32 = if byte_idx < bytes.len() {
            ((bytes[byte_idx] >> bit_in_byte) & 1).into()
        } else {
            0
        };
        out = (out << 1) | bit;
    }
    out
}

/// Insert `n_bits` bits of `value` (high bits first) into `bytes` at
/// bit position `start_bit`. Grows `bytes` as required.
pub(crate) fn insert_bits_msb(bytes: &mut Vec<u8>, value: u32, start_bit: usize, n_bits: usize) {
    for i in 0..n_bits {
        let bit_pos = start_bit + i;
        let byte_idx = bit_pos / 8;
        let bit_in_byte = 7 - (bit_pos % 8);
        let bit = ((value >> (n_bits - 1 - i)) & 1) as u8;
        while bytes.len() <= byte_idx {
            bytes.push(0);
        }
        if bit == 1 {
            bytes[byte_idx] |= 1 << bit_in_byte;
        }
    }
}

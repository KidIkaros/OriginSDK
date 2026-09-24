// SPDX-License-Identifier: Apache-2.0

//! Error Correction Codes
//!
//! Provides Reed-Solomon error correction for data recovery.

use crate::error::{CryptoError, Result};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Galois Field GF(2^8) arithmetic for Reed-Solomon
/// Using the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0x11D)
/// Represented as 0x1B after removing the x^8 term
#[derive(Debug)]
struct GaloisField;

impl GaloisField {
    const PRIMITIVE_POLYNOMIAL: u8 = 0x1B;

    /// Multiply two elements in GF(2^8) using polynomial reduction
    // CT-REVIEW(12.1): `while b != 0` terminates early — iteration count
    // depends on `b`'s Hamming weight, and `if (b & 1) != 0` is a
    // data-dependent branch. Acceptable for non-secret shard data; flag
    // if RS is ever applied over secrets.
    pub fn mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;

        while b != 0 {
            if (b & 1) != 0 {
                result ^= a;
            }
            let high_bit = (a & 0x80) != 0;
            a <<= 1;
            if high_bit {
                a ^= Self::PRIMITIVE_POLYNOMIAL;
            }
            b >>= 1;
        }

        result
    }

    /// Exponentiation in GF(2^8)
    // CT-REVIEW(12.1): square-and-multiply with a data-dependent
    // `exp & 1` multiply — same caveat as `mul`.
    pub fn exp(a: u8, n: u8) -> u8 {
        if a == 0 {
            return if n == 0 { 1 } else { 0 };
        }
        let mut result = 1u8;
        let mut base = a;
        let mut exp = n;

        while exp > 0 {
            if exp & 1 != 0 {
                result = Self::mul(result, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }

        result
    }

    /// Multiplicative inverse in GF(2^8): a^(-1) = a^254 for a != 0
    /// (the multiplicative group GF(2^8)* has order 255, so a^255 = 1).
    pub fn inv(a: u8) -> Option<u8> {
        if a == 0 {
            None
        } else {
            Some(Self::exp(a, 254))
        }
    }
}

/// Reed-Solomon error correction with proper Galois field arithmetic
#[derive(Debug)]
pub struct ReedSolomonCodec {
    data_shards: usize,
    parity_shards: usize,
}

impl ReedSolomonCodec {
    /// Create a new Reed-Solomon codec
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
        }
    }

    /// Generate the Vandermonde matrix used to compute parity shards.
    ///
    /// Evaluation points are `1..=data_shards` (never `0`), so every data
    /// shard actually contributes to every parity equation. (A previous
    /// version used points `0..data_shards` with exponent `i+1`, which made
    /// data shard 0's column all-zero — shard 0 was invisible to every
    /// parity check and could never be detected as corrupted or recovered.)
    fn vandermonde_matrix(data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
        let mut matrix = vec![vec![0u8; data_shards]; parity_shards];

        for i in 0..parity_shards {
            for j in 0..data_shards {
                matrix[i][j] = GaloisField::exp((j + 1) as u8, i as u8);
            }
        }

        matrix
    }

    /// Row `idx` of the full systematic generator matrix (size
    /// `(data_shards + parity_shards) x data_shards`): the identity for
    /// `idx < data_shards` (a data shard is just itself), or the
    /// corresponding Vandermonde row for a parity shard.
    fn generator_row(data_shards: usize, parity_shards: usize, idx: usize) -> Vec<u8> {
        if idx < data_shards {
            let mut row = vec![0u8; data_shards];
            row[idx] = 1;
            row
        } else {
            let matrix = Self::vandermonde_matrix(data_shards, parity_shards);
            matrix[idx - data_shards].clone()
        }
    }

    /// Invert a square matrix over GF(2^8) via Gauss-Jordan elimination.
    /// Returns an error if the matrix is singular.
    fn invert_gf256_matrix(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        let n = matrix.len();
        // Augmented matrix [matrix | I]
        let mut aug: Vec<Vec<u8>> = matrix
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let mut r = row.clone();
                r.resize(2 * n, 0);
                r[n + i] = 1;
                r
            })
            .collect();

        for col in 0..n {
            // Find a pivot row with a non-zero entry in this column.
            let pivot_row = (col..n).find(|&r| aug[r][col] != 0).ok_or_else(|| {
                CryptoError::ReedSolomon("Matrix is singular; cannot recover shards".to_string())
            })?;
            aug.swap(col, pivot_row);

            let pivot_inv = GaloisField::inv(aug[col][col]).ok_or_else(|| {
                CryptoError::ReedSolomon("Matrix is singular; cannot recover shards".to_string())
            })?;
            for v in aug[col].iter_mut() {
                *v = GaloisField::mul(*v, pivot_inv);
            }

            for r in 0..n {
                if r != col && aug[r][col] != 0 {
                    let factor = aug[r][col];
                    for c in 0..2 * n {
                        aug[r][c] ^= GaloisField::mul(factor, aug[col][c]);
                    }
                }
            }
        }

        Ok(aug.into_iter().map(|row| row[n..].to_vec()).collect())
    }

    /// Split `data` into `data_shards` shards and compute `parity_shards`
    /// parity shards, returning all shards individually (each the same
    /// length, zero-padded). Unlike [`encode`](Self::encode), the caller
    /// keeps track of each shard's index, which is what makes true erasure
    /// recovery (a shard going missing, not just corrupted) possible via
    /// [`decode_shards`](Self::decode_shards).
    pub fn encode_shards(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards: Vec<Vec<u8>> =
            vec![vec![0u8; shard_size]; self.data_shards + self.parity_shards];

        // Split data into shards
        for (i, chunk) in data.chunks(shard_size).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }

        // Compute parity shards
        let matrix = Self::vandermonde_matrix(self.data_shards, self.parity_shards);
        for i in 0..self.parity_shards {
            for j in 0..shard_size {
                let mut parity = 0u8;
                for k in 0..self.data_shards {
                    parity ^= GaloisField::mul(matrix[i][k], shards[k][j]);
                }
                shards[self.data_shards + i][j] = parity;
            }
        }

        Ok(shards)
    }

    /// Encode data by computing parity shards, flattened into a single byte
    /// buffer (4-byte little-endian original length, then each shard
    /// concatenated in order).
    ///
    /// **Limitation**: this flat format has no way to represent a shard
    /// being *missing* (as opposed to present-but-corrupted) — a genuinely
    /// lost shard shifts every byte after it, which [`decode`](Self::decode)
    /// cannot distinguish from corruption. Callers that need real erasure
    /// tolerance (recovering from a shard that never arrives, e.g. sharded
    /// storage/transport) should use [`encode_shards`](Self::encode_shards)
    /// / [`decode_shards`](Self::decode_shards) instead, which track shard
    /// indices explicitly.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shards = self.encode_shards(data)?;

        let mut encoded = Vec::new();
        // Store original data length at the beginning
        encoded.extend_from_slice(&(data.len() as u32).to_le_bytes());
        for shard in &shards {
            encoded.extend_from_slice(shard);
        }

        Ok(encoded)
    }

    /// Reconstruct the `data_shards` original data shards from any
    /// `data_shards` (or more) of the `data_shards + parity_shards` total
    /// shards, identified by their original index. This is standard
    /// systematic Reed-Solomon erasure decoding: build the square matrix of
    /// generator-matrix rows for the shards we have, invert it over
    /// GF(2^8), and multiply through to recover the missing data shards.
    fn reconstruct_data(
        &self,
        available: &[(usize, Vec<u8>)],
        shard_size: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if available.len() < self.data_shards {
            return Err(CryptoError::ReedSolomon(format!(
                "Not enough shards to reconstruct: have {}, need {}",
                available.len(),
                self.data_shards
            )));
        }

        let chosen = &available[..self.data_shards];
        let rows: Vec<Vec<u8>> = chosen
            .iter()
            .map(|(idx, _)| Self::generator_row(self.data_shards, self.parity_shards, *idx))
            .collect();
        let inv = Self::invert_gf256_matrix(&rows)?;

        let mut data_shards = vec![vec![0u8; shard_size]; self.data_shards];
        for j in 0..shard_size {
            for (row, inv_row) in inv.iter().enumerate() {
                let mut val = 0u8;
                for (col, (_, shard)) in chosen.iter().enumerate() {
                    val ^= GaloisField::mul(inv_row[col], shard[j]);
                }
                data_shards[row][j] = val;
            }
        }

        Ok(data_shards)
    }

    /// Reconstruct original data from a set of shards, some of which may be
    /// genuinely missing (`None`), as produced by
    /// [`encode_shards`](Self::encode_shards). Recovers correctly as long
    /// as at most `parity_shards` shards are missing/`None`.
    pub fn decode_shards(
        &self,
        shards: &[Option<Vec<u8>>],
        original_len: usize,
    ) -> Result<Vec<u8>> {
        let total_shards = self.data_shards + self.parity_shards;
        if shards.len() != total_shards {
            return Err(CryptoError::ReedSolomon(format!(
                "Expected {} shards, got {}",
                total_shards,
                shards.len()
            )));
        }

        let available: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.clone().map(|v| (i, v)))
            .collect();

        if available.len() < self.data_shards {
            return Err(CryptoError::ReedSolomon(format!(
                "Too many shards missing: have {}, need at least {}",
                available.len(),
                self.data_shards
            )));
        }

        let shard_size = available[0].1.len();
        if available.iter().any(|(_, v)| v.len() != shard_size) {
            return Err(CryptoError::ReedSolomon(
                "Inconsistent shard sizes".to_string(),
            ));
        }

        let data_shards = self.reconstruct_data(&available, shard_size)?;

        let mut data = Vec::new();
        for shard in &data_shards {
            data.extend_from_slice(shard);
        }
        data.truncate(original_len);
        Ok(data)
    }

    /// Decode data and reconstruct using parity shards.
    ///
    /// Requires all `data_shards + parity_shards` shards to be physically
    /// present in `encoded` (see the limitation noted on
    /// [`encode`](Self::encode)). Corruption is detected and repaired via
    /// per-byte syndrome decoding, which can correctly locate and correct
    /// **at most one** corrupted shard per byte position.
    ///
    /// **Warning — silent miscorrection beyond one error.** This is a
    /// bounded-distance decoder for a code of minimum distance 3 (it can
    /// correct 1 error *or* detect 2, not both). Two or more shards
    /// corrupted at the *same* byte offset produce a syndrome that is
    /// algebraically indistinguishable from a valid single-error pattern,
    /// so the decoder will apply a plausible-but-wrong correction and may
    /// return incorrect data **without signalling an error**. Do not rely
    /// on this method to detect multi-shard corruption. Callers that know
    /// in advance which shards are missing/bad (up to `parity_shards` of
    /// them, simultaneously) should use
    /// [`encode_shards`](Self::encode_shards)/[`decode_shards`](Self::decode_shards)
    /// instead, which track shard indices and support full
    /// `parity_shards`-way erasure recovery with a hard failure when too
    /// many shards are missing.
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let (mut shards, original_len) = self.parse_encoded(encoded)?;
        self.correct_single_shard_errors(&mut shards)?;
        Ok(self.reassemble(&shards, original_len))
    }

    /// Split `encoded` into its `len(4 LE) ‖ shard_0 ‖ … ‖ shard_n` layout.
    /// Returns `(shards, original_len)`.
    fn parse_encoded(&self, encoded: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
        let total_shards = self.data_shards + self.parity_shards;

        if encoded.len() < 4 {
            return Err(CryptoError::ReedSolomon(
                "Encoded data too short to read length".to_string(),
            ));
        }
        let original_len =
            u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

        let shard_size = (encoded.len() - 4) / total_shards;

        if (encoded.len() - 4) % total_shards != 0 {
            return Err(CryptoError::ReedSolomon(
                "Encoded data length not divisible by total shards".to_string(),
            ));
        }

        let shards: Vec<Vec<u8>> = encoded[4..]
            .chunks(shard_size)
            .map(|s| s.to_vec())
            .collect();

        if shards.len() != total_shards {
            return Err(CryptoError::ReedSolomon(format!(
                "Expected {} shards, got {}",
                total_shards,
                shards.len()
            )));
        }

        Ok((shards, original_len))
    }

    /// Concatenate the data shards and trim to `original_len`.
    fn reassemble(&self, shards: &[Vec<u8>], original_len: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for shard in shards.iter().take(self.data_shards) {
            data.extend_from_slice(shard);
        }
        data.truncate(original_len);
        data
    }

    /// Per-byte-position syndrome decoding over `shards` in place.
    ///
    /// For parity row `i`, the systematic code satisfies
    /// `sum_k matrix[i][k] * data[k][j] XOR parity[i][j] == 0`. The
    /// syndrome `syn[i]` is the (nonzero, if corrupted) left-hand side.
    /// If exactly one shard `m` (data or parity) is corrupted at
    /// position `j` with error value `e`, then `syn[i] == H(i, m) * e`
    /// for every row `i`, where `H(i, m)` is `matrix[i][m]` for a data
    /// shard or `1` for `m`'s own parity row (0 otherwise). Because the
    /// Vandermonde columns are pairwise distinct field elements raised
    /// to distinct powers, at most one `(m, e)` hypothesis is
    /// consistent across *all* `parity_shards` equations when there is
    /// truly only one corrupted shard — so this both locates and
    /// corrects a single-shard error, unlike the previous heuristic
    /// (which was a tautology: it "detected" every data shard as
    /// corrupted on every mismatch, see the regression test below).
    ///
    /// Two or more simultaneously corrupted shards at the same byte
    /// position can't be resolved by this single-error algebra (that
    /// needs a full error-locator-polynomial decoder). For a code of
    /// minimum distance 3 such a pattern is algebraically
    /// indistinguishable from a valid single-error hypothesis, so this
    /// decoder will apply a plausible-but-wrong correction rather than
    /// erroring — see the method-level warning on [`decode`](Self::decode).
    /// Callers needing multi-shard tolerance must use `decode_shards`
    /// with explicit erasure information.
    // CT-REVIEW(12.1): per-position early `continue` on clean syndromes
    // and the hypothesis-search `break` leak "is this byte position
    // corrupted?" via timing — public metadata for transport ECC, but
    // flag for review if carried over secrets.
    fn correct_single_shard_errors(&self, shards: &mut [Vec<u8>]) -> Result<()> {
        let total_shards = self.data_shards + self.parity_shards;
        let shard_size = shards.first().map_or(0, Vec::len);
        let matrix = Self::vandermonde_matrix(self.data_shards, self.parity_shards);

        let h = |m: usize, i: usize| -> u8 {
            if m < self.data_shards {
                matrix[i][m]
            } else if m - self.data_shards == i {
                1
            } else {
                0
            }
        };

        for j in 0..shard_size {
            let syndromes: Vec<u8> = (0..self.parity_shards)
                .map(|i| {
                    let mut calculated = 0u8;
                    for k in 0..self.data_shards {
                        calculated ^= GaloisField::mul(matrix[i][k], shards[k][j]);
                    }
                    calculated ^ shards[self.data_shards + i][j]
                })
                .collect();

            if syndromes.iter().all(|&s| s == 0) {
                continue;
            }

            let mut found: Option<(usize, u8)> = None;
            let mut ambiguous = false;
            for m in 0..total_shards {
                let pivot = match (0..self.parity_shards).find(|&i| h(m, i) != 0) {
                    Some(p) => p,
                    None => continue,
                };
                let e = GaloisField::mul(
                    syndromes[pivot],
                    // SAFETY: pivot was found because h(m, pivot) != 0, so the
                    // inverse exists. This is a proven internal invariant.
                    GaloisField::inv(h(m, pivot)).expect("h(m, pivot) != 0 by construction"),
                );
                if e == 0 {
                    continue;
                }
                let consistent =
                    (0..self.parity_shards).all(|i| GaloisField::mul(h(m, i), e) == syndromes[i]);
                if consistent {
                    if found.is_some() {
                        ambiguous = true;
                        break;
                    }
                    found = Some((m, e));
                }
            }

            match found {
                Some((m, e)) if !ambiguous => {
                    if m < self.data_shards {
                        shards[m][j] ^= e;
                    }
                    // Else: the corruption is in a parity shard, which
                    // doesn't affect the decoded data output.
                }
                _ => {
                    return Err(CryptoError::ReedSolomon(
                        "Parity check failed - data corruption beyond recovery capacity"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Parallel encode using rayon for improved performance on large data
    #[cfg(feature = "parallel")]
    pub fn encode_parallel(&self, data: &[u8]) -> Result<Vec<u8>> {
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards: Vec<Vec<u8>> =
            vec![vec![0u8; shard_size]; self.data_shards + self.parity_shards];

        // Split data into shards
        for (i, chunk) in data.chunks(shard_size).enumerate() {
            shards[i][..chunk.len()].copy_from_slice(chunk);
        }

        // Compute parity shards in parallel
        let matrix = Self::vandermonde_matrix(self.data_shards, self.parity_shards);
        let parity_shards: Vec<Vec<u8>> = (0..self.parity_shards)
            .into_par_iter()
            .map(|i| {
                (0..shard_size)
                    .map(|j| {
                        let mut parity = 0u8;
                        for k in 0..self.data_shards {
                            parity = parity ^ GaloisField::mul(matrix[i][k], shards[k][j]);
                        }
                        parity
                    })
                    .collect()
            })
            .collect();

        // Copy parity shards back
        for (i, parity_shard) in parity_shards.iter().enumerate() {
            shards[self.data_shards + i].copy_from_slice(parity_shard);
        }

        // Flatten shards into encoded data
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(data.len() as u32).to_le_bytes());
        for shard in &shards {
            encoded.extend_from_slice(shard);
        }

        Ok(encoded)
    }
}

/// 128+8 Reed-Solomon encoding for data (128 byte blocks + 8 parity bytes)
#[derive(Debug)]
pub struct DataReedSolomon;

impl DataReedSolomon {
    /// Create a new Reed-Solomon encoder/decoder.
    pub fn new() -> Self {
        Self
    }

    /// Encode a 128-byte block to 136 bytes (128+8)
    pub fn encode_block(&self, block: &[u8]) -> Result<Vec<u8>> {
        if block.len() != 128 {
            return Err(CryptoError::ReedSolomon(
                "Block must be exactly 128 bytes".to_string(),
            ));
        }

        let codec = ReedSolomonCodec::new(128, 8);
        let encoded = codec.encode(block)?;
        Ok(encoded[4..].to_vec())
    }

    /// Decode a 136-byte block back to 128 bytes
    pub fn decode_block(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.len() != 136 {
            return Err(CryptoError::ReedSolomon(
                "Encoded block must be exactly 136 bytes".to_string(),
            ));
        }

        let mut encoded_with_prefix = Vec::with_capacity(140);
        encoded_with_prefix.extend_from_slice(&(128u32).to_le_bytes());
        encoded_with_prefix.extend_from_slice(encoded);

        let codec = ReedSolomonCodec::new(128, 8);
        codec.decode(&encoded_with_prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reed_solomon_encode() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"Hello, World! This is a test.";

        let encoded = codec.encode(data).unwrap();
        assert!(encoded.len() > data.len());
    }

    #[test]
    fn test_reed_solomon_encode_decode_roundtrip() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"Hello, World! This is a test.";

        let encoded = codec.encode(data).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_data_reed_solomon_encode_decode_roundtrip() {
        let codec = DataReedSolomon::new();
        let mut block = [0u8; 128];
        block[..9].copy_from_slice(b"test data");

        let encoded = codec.encode_block(&block).unwrap();
        let decoded = codec.decode_block(&encoded).unwrap();

        assert_eq!(block.to_vec(), decoded);
    }

    /// Regression test for D4: a genuinely *missing* shard (not just
    /// corrupted-in-place) must be recoverable via the shard-aware API.
    #[test]
    fn decode_shards_recovers_one_missing_data_shard() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"Hello, World! This is a test of erasure recovery.";
        let shards = codec.encode_shards(data).unwrap();

        for missing in 0..shards.len() {
            let mut with_gap: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
            with_gap[missing] = None;
            let decoded = codec.decode_shards(&with_gap, data.len()).unwrap();
            assert_eq!(decoded, data, "failed recovering missing shard {missing}");
        }
    }

    /// Losing up to `parity_shards` shards simultaneously must still recover.
    #[test]
    fn decode_shards_recovers_max_simultaneous_erasures() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"some longer test payload for multi-erasure recovery";
        let shards = codec.encode_shards(data).unwrap();

        let mut with_gaps: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        with_gaps[0] = None; // missing data shard 0 (the previously-blind-spot index)
        with_gaps[5] = None; // missing a parity shard too

        let decoded = codec.decode_shards(&with_gaps, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    /// Losing more shards than parity_shards must fail cleanly, not
    /// silently return corrupted data.
    #[test]
    fn decode_shards_fails_when_too_many_missing() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"test data";
        let shards = codec.encode_shards(data).unwrap();

        let mut with_gaps: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        with_gaps[0] = None;
        with_gaps[1] = None;
        with_gaps[2] = None; // 3 missing > parity_shards (2)

        assert!(codec.decode_shards(&with_gaps, data.len()).is_err());
    }

    /// Regression test for D8: `decode()`'s in-place corruption repair was
    /// a mathematical tautology (it "detected" every data shard as
    /// corrupted on any single mismatch), so it always failed with
    /// "beyond recovery capacity" whenever `data_shards > parity_shards`
    /// (the common case) even for a single flipped bit. Verify a single
    /// bit flip in a data shard is actually corrected now.
    #[test]
    fn decode_repairs_single_bit_flip_in_data_shard() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"Hello, World! This is a test of corruption recovery!!";
        let mut encoded = codec.encode(data).unwrap();
        // Flip one bit deep in shard 0 (well after the 4-byte length prefix).
        encoded[4] ^= 0x01;
        let decoded = codec
            .decode(&encoded)
            .expect("single-bit corruption should be repairable");
        assert_eq!(decoded, data);
    }

    /// Same, but the corrupted byte is in a parity shard rather than a
    /// data shard — decoded data must still come back correct.
    #[test]
    fn decode_tolerates_corruption_in_parity_shard() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"parity shard corruption should not affect decoded data";
        let mut encoded = codec.encode(data).unwrap();
        let shard_size = (data.len() + 4 - 1) / 4;
        // Corrupt a byte inside parity shard 0 (shards[4]): offset is
        // 4 (length prefix) + 4 data shards * shard_size.
        let parity_offset = 4 + 4 * shard_size;
        encoded[parity_offset] ^= 0x01;
        let decoded = codec
            .decode(&encoded)
            .expect("parity-shard corruption should be tolerated");
        assert_eq!(decoded, data);
    }

    /// Documents the fundamental limit of the flat `decode` path: a
    /// systematic [k+2, k] Reed-Solomon code has minimum distance 3, so it
    /// can correct one error *or* detect two — never both. Two shards
    /// corrupted at the same byte offset alias to a valid single-error
    /// hypothesis, so `decode` applies a plausible-but-wrong correction and
    /// returns `Ok` with incorrect data rather than signalling an error.
    ///
    /// This is not a bug to fix; it is the code-theoretic bound. The
    /// correct way to tolerate multiple bad/missing shards is
    /// `decode_shards` with explicit erasure indices (covered by
    /// `decode_shards_recovers_max_simultaneous_erasures`).
    #[test]
    fn decode_silently_miscorrects_beyond_one_error() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"Hello, World! This is a test of corruption recovery!!";
        let mut encoded = codec.encode(data).unwrap();
        let shard_size = (data.len() + 4 - 1) / 4;
        // Corrupt byte 0 of both data shard 0 and data shard 1.
        encoded[4] ^= 0x01;
        encoded[4 + shard_size] ^= 0x01;
        // Beyond the code's correction capacity: the decoder cannot tell
        // this apart from a single-shard error, so it returns Ok with
        // silently-wrong data. Callers must not rely on `decode` to detect
        // multi-shard corruption.
        let decoded = codec
            .decode(&encoded)
            .expect("single-error decoder returns Ok");
        assert_ne!(
            decoded, data,
            "two-error pattern aliases to a single-error hypothesis and is miscorrected"
        );
    }

    /// Every data shard (including shard 0) must actually affect the parity
    /// shards. Regression test for the Vandermonde matrix bug where shard 0
    /// had an all-zero column and was invisible to every parity equation.
    #[test]
    fn every_data_shard_affects_parity() {
        let codec = ReedSolomonCodec::new(4, 2);
        let data = b"abcdefgh";
        let baseline = codec.encode_shards(data).unwrap();

        for i in 0..4 {
            let mut mutated = data.to_vec();
            mutated[i * 2] ^= 0xFF;
            let shards = codec.encode_shards(&mutated).unwrap();
            assert_ne!(
                shards[4], baseline[4],
                "data shard {i} did not affect parity shard 0"
            );
        }
    }
}

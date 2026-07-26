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
    pub fn exp(a: u8, n: u8) -> u8 {
        if a == 0 {
            return 0;
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

    /// Generate Vandermonde matrix for encoding
    fn vandermonde_matrix(data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
        let mut matrix = vec![vec![0u8; data_shards]; parity_shards];

        for i in 0..parity_shards {
            for j in 0..data_shards {
                matrix[i][j] = GaloisField::exp(j as u8, i as u8 + 1);
            }
        }

        matrix
    }

    /// Encode data by computing parity shards using matrix multiplication
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>> {
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
                    parity = parity ^ GaloisField::mul(matrix[i][k], shards[k][j]);
                }
                shards[self.data_shards + i][j] = parity;
            }
        }

        // Flatten shards into encoded data
        let mut encoded = Vec::new();
        // Store original data length at the beginning
        encoded.extend_from_slice(&(data.len() as u32).to_le_bytes());
        for shard in &shards {
            encoded.extend_from_slice(shard);
        }

        Ok(encoded)
    }

    /// Decode data and reconstruct using parity shards
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
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

        let mut shards: Vec<Vec<u8>> = encoded[4..]
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

        let matrix = Self::vandermonde_matrix(self.data_shards, self.parity_shards);

        // Try to detect corrupted shards
        let mut corrupted_shards = Vec::new();

        for i in 0..self.parity_shards {
            let parity_shard = self.data_shards + i;
            for j in 0..shard_size {
                let mut calculated = 0u8;
                for k in 0..self.data_shards {
                    calculated = calculated ^ GaloisField::mul(matrix[i][k], shards[k][j]);
                }
                if calculated != shards[parity_shard][j] {
                    for k in 0..self.data_shards {
                        let mut test_calc = 0u8;
                        for m in 0..self.data_shards {
                            if m != k {
                                test_calc =
                                    test_calc ^ GaloisField::mul(matrix[i][m], shards[m][j]);
                            }
                        }
                        if GaloisField::mul(shards[k][j], matrix[i][k]) == (calculated ^ test_calc)
                        {
                            if !corrupted_shards.contains(&k) {
                                corrupted_shards.push(k);
                            }
                        }
                    }
                }
            }
        }

        // Recover corrupted shards
        if !corrupted_shards.is_empty() && corrupted_shards.len() <= self.parity_shards {
            for &corrupted_idx in &corrupted_shards {
                for j in 0..shard_size {
                    let mut recovered = 0u8;
                    for k in 0..self.data_shards {
                        if k != corrupted_idx {
                            recovered = recovered ^ GaloisField::mul(matrix[0][k], shards[k][j]);
                        }
                    }
                    let parity_value = shards[self.data_shards][j];
                    shards[corrupted_idx][j] = parity_value ^ recovered;
                }
            }
        }

        // Verify parity after recovery
        for i in 0..self.parity_shards {
            let parity_shard = self.data_shards + i;
            for j in 0..shard_size {
                let mut calculated = 0u8;
                for k in 0..self.data_shards {
                    calculated = calculated ^ GaloisField::mul(matrix[i][k], shards[k][j]);
                }
                if calculated != shards[parity_shard][j] {
                    return Err(CryptoError::ReedSolomon(
                        "Parity check failed - data corruption beyond recovery capacity"
                            .to_string(),
                    ));
                }
            }
        }

        // Reconstruct original data
        let mut data = Vec::new();
        for i in 0..self.data_shards {
            data.extend_from_slice(&shards[i]);
        }

        // Trim to original length
        if data.len() > original_len {
            data.truncate(original_len);
        }

        Ok(data)
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
}

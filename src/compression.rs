// SPDX-License-Identifier: OPL-1.1

//! Compression module using Deflate algorithm

use crate::error::{CryptoError, Result};
use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;

/// Compress data using Deflate algorithm
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(data, Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CryptoError::Compression(format!("Compression failed: {}", e)))?;
    Ok(compressed)
}

/// Decompress data using Deflate algorithm
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| CryptoError::Compression(format!("Decompression failed: {}", e)))?;
    Ok(decompressed)
}

/// Compress data with custom compression level (0-9)
pub fn compress_with_level(data: &[u8], level: u8) -> Result<Vec<u8>> {
    let compression = Compression::new(level as u32);
    let mut encoder = DeflateEncoder::new(data, compression);
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CryptoError::Compression(format!("Compression failed: {}", e)))?;
    Ok(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let original = b"Hello, World! This is a test message that should compress reasonably well.";
        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(original.to_vec(), decompressed);
        assert!(compressed.len() < original.len());
    }

    #[test]
    fn test_compress_with_level() {
        let original = b"Test data for compression level testing";
        let compressed_fast = compress_with_level(original, 1).unwrap();
        let compressed_best = compress_with_level(original, 9).unwrap();

        // Best compression should be smaller or equal to fast compression
        assert!(compressed_best.len() <= compressed_fast.len());
    }

    #[test]
    fn test_empty_data() {
        let empty = b"";
        let compressed = compress(empty).unwrap();
        let decompressed = decompress(&compressed).unwrap();

        assert_eq!(empty.to_vec(), decompressed);
    }
}

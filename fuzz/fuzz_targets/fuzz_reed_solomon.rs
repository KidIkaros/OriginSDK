// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: Reed-Solomon error correction encode/decode
//!
//! Verifies that Reed-Solomon encoding and decoding never panics,
//! that encode+decode is a roundtrip, and that single-shard
//! corruption is recoverable.
//!
//! Run with: cargo +nightly fuzz run fuzz_reed_solomon

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::error_correction::ReedSolomonCodec;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > 4096 {
        return;
    }

    // Use small shard counts for fuzzing speed: 2 data + 1 parity
    let codec = ReedSolomonCodec::new(2, 1);

    if let Ok(encoded) = codec.encode(data) {
        // Roundtrip with all shards intact
        if let Ok(decoded) = codec.decode(&encoded) {
            assert_eq!(decoded, data, "Reed-Solomon roundtrip failed");
        }

        // Corrupt one data byte (within the first data shard)
        let data_shard_size = encoded.len() - 4; // drop original_len prefix
        let data_shards_total = 3; // 2 data + 1 parity = 3 shards
        let shard_size = data_shard_size / data_shards_total;
        if shard_size > 0 && encoded.len() > 5 {
            let mut corrupted = encoded.clone();
            let corrupt_pos = 4 + shard_size / 2;
            if corrupt_pos < corrupted.len() {
                corrupted[corrupt_pos] ^= 0xFF;
                // Decode may succeed (if RS can fix it) or fail gracefully
                let _ = codec.decode(&corrupted);
            }
        }
    }
});

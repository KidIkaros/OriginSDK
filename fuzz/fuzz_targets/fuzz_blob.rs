// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: seed-blob deserialization
//!
//! Feeds arbitrary bytes into the blob parse/recover path. The decoder
//! must never panic — malformed blobs return Err. Also exercises
//! version detection and tier probing on arbitrary input.
//!
//! `recover_seed` is run at `MemoryTier::Nano` (8 MB Argon2id): the
//! parse/decrypt attack surface is tier-independent, and larger tiers
//! would spend the entire fuzz budget inside the KDF.
//!
//! Run with: cargo +nightly fuzz run fuzz_blob

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::blob;
use origin_crypto_sdk::tier::MemoryTier;

fuzz_target!(|data: &[u8]| {
    // Version detection and tier probing on arbitrary bytes.
    let _ = blob::detect_blob_version(data);
    let _ = blob::blob_tier(data);

    // Full recover path: arbitrary blob + fuzzed passphrase. Malformed
    // blobs bail at parse; well-formed ones reach Argon2 at Nano cost.
    let passphrase: &[u8] = if data.len() > 1 {
        &data[..data.len().min(16)]
    } else {
        b"x"
    };
    let _ = blob::recover_seed(data, passphrase, MemoryTier::Nano);

    // Rotation exercises a second parse + re-encode of the same input.
    let _ = blob::rotate_blob(data, passphrase, b"fuzz-rotate", MemoryTier::Nano);
});

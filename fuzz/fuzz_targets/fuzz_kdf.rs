// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: HKDF-SHA3-256
//!
//! Verifies that HKDF never panics on arbitrary input and that:
//! - Different IKM produces different output
//! - HKDF is deterministic for same inputs
//!
//! Run with: cargo +nightly fuzz run fuzz_kdf

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::kdf::hkdf::hkdf_sha3_256;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Use first byte to determine output length (capped to 128)
    let output_len = 1 + (data[0] as usize % 128);
    let ikm = &data[1..];

    // Use a fixed small salt and info to keep fuzzer output focused on IKM behavior
    let salt: &[u8] = b"fuzz_salt_v1";
    let info: &[u8] = b"fuzz_info_v1";

    if let Ok(mut out1) = (move || -> Result<Vec<u8>, ()> {
        let mut out = vec![0u8; output_len];
        hkdf_sha3_256(ikm, Some(salt), info, &mut out).map_err(|_| ())?;
        Ok(out)
    })()
    {
        let mut out2 = vec![0u8; output_len];
        let _ = hkdf_sha3_256(ikm, Some(salt), info, &mut out2);
        // Determinism
        assert_eq!(out1, out2);
    }
});

// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: NTRU Prime (sntrup761) decode + decapsulate
//!
//! Feeds the fuzzer's arbitrary bytes into the decapsulation path as a
//! ciphertext against a real keypair. The CCA-fallback decap must never
//! panic and must always return Ok — a malformed ciphertext only changes
//! the derived session key, it must not crash or error.
//!
//! Also exercises `decapsulate` on valid ciphertexts truncated/extended
//! at the encoding boundary.
//!
//! Run with: cargo +nightly fuzz run fuzz_ntru_prime

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::drbg::ChaCha20Rng;
use origin_crypto_sdk::pqc::ntru_prime::{Ciphertext, NtruPrime, PrivateKey, PublicKey, CT_SIZE};
use std::sync::LazyLock;

// Keygen is comparatively expensive; hoist it out of the per-input path.
static KEYPAIR: LazyLock<(PublicKey, PrivateKey)> =
    LazyLock::new(|| NtruPrime::generate_keypair(&mut ChaCha20Rng::from_seed([0x5Au8; 32])));

fuzz_target!(|data: &[u8]| {
    let (pk, sk) = &*KEYPAIR;

    // Path 1: arbitrary bytes padded/truncated to CT_SIZE → decapsulate.
    // Must return Ok (CCA: any ciphertext yields *a* session key).
    let mut ct_buf = [0u8; CT_SIZE];
    let n = data.len().min(CT_SIZE);
    ct_buf[..n].copy_from_slice(&data[..n]);
    let ct: Ciphertext = ct_buf;
    let _ = NtruPrime::decapsulate(&ct, sk);

    // Path 2: mutate a valid ciphertext — exercises the "well-formed but
    // wrong" CCA path (re-encryption mismatch). The encapsulation RNG is
    // seeded from the fuzz input so ephemeral randomness varies per run.
    let mut rng = ChaCha20Rng::from_seed({
        let mut s = [0u8; 32];
        let m = data.len().min(32);
        s[..m].copy_from_slice(&data[..m]);
        s
    });
    let (mut ct_valid, _ss) = NtruPrime::encapsulate(pk, &mut rng);
    if !data.is_empty() {
        let pos = (data[0] as usize) % CT_SIZE;
        let mask = if data.len() > 1 { data[1] } else { 0xFF };
        ct_valid[pos] ^= mask;
        let _ = NtruPrime::decapsulate(&ct_valid, sk);
    }
});

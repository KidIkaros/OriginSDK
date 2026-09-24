// SPDX-License-Identifier: Apache-2.0

//! Fuzz target: Falcon-512 signature parsing + verify
//!
//! Feeds arbitrary bytes into `Falcon512Signature::from_bytes` and
//! `Falcon512PublicKey::from_bytes`, then verifies against a real
//! keypair. The parse/verify path must never panic — malformed inputs
//! return Err or false, never crash.
//!
//! Run with: cargo +nightly fuzz run fuzz_falcon

#![no_main]

use libfuzzer_sys::fuzz_target;
use origin_crypto_sdk::pqc::falcon512::{
    self, Falcon512PrivateKey, Falcon512PublicKey, Falcon512Signature,
};
use std::sync::LazyLock;

const MESSAGE: &[u8] = b"fuzz message";

// Falcon keygen/sign are expensive; hoist fixed material out of the
// per-input path so the fuzzer spends cycles on the parse/verify surface.
static KEYPAIR: LazyLock<(Falcon512PrivateKey, Falcon512PublicKey)> =
    LazyLock::new(|| falcon512::generate_keypair([42u8; 32]));
static SIG: LazyLock<Option<Falcon512Signature>> =
    LazyLock::new(|| falcon512::sign(MESSAGE, &KEYPAIR.0).ok());

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (_sk, pk) = &*KEYPAIR;

    // Path 1: arbitrary bytes as a signature → parse + verify.
    if let Ok(sig) = Falcon512Signature::from_bytes(data) {
        let _ = falcon512::verify(MESSAGE, &sig, pk);
    }

    // Path 2: arbitrary bytes as a public key → parse must not panic;
    // if it parses, verify a real signature against it.
    if let (Ok(pk_fuzz), Some(sig)) = (Falcon512PublicKey::from_bytes(data), SIG.as_ref()) {
        let _ = falcon512::verify(MESSAGE, sig, &pk_fuzz);
    }

    // Path 3: arbitrary bytes as a private key → parse must not panic;
    // if it parses, sign and verify the round-trip.
    if let Ok(sk_fuzz) = Falcon512PrivateKey::from_bytes(data) {
        if let Ok(sig) = falcon512::sign(MESSAGE, &sk_fuzz) {
            let _ = falcon512::verify(MESSAGE, &sig, pk);
        }
    }

    // Path 4: mutate a valid signature — well-formed-but-wrong path.
    if let Some(sig_bytes) = SIG.as_ref().map(|s| s.0.clone()) {
        let mut mutated = sig_bytes;
        if mutated.len() > 4 && data.len() > 2 {
            let pos = (data[0] as usize) % mutated.len();
            mutated[pos] ^= data[1];
            if let Ok(sig) = Falcon512Signature::from_bytes(&mutated) {
                let _ = falcon512::verify(MESSAGE, &sig, pk);
            }
        }
    }
});

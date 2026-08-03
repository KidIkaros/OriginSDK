// SPDX-License-Identifier: Apache-2.0

//! Malformed-input robustness tests (parser fuzzing).
//!
//! These tests verify that parser and deserialization functions handle
//! malformed inputs gracefully — returning errors or `None` rather than
//! panicking, truncating, or producing undefined behavior.
//!
//! Classification: misuse-resistance evidence
//! Purpose: ensure no panic on attacker-controlled input.

use origin_crypto_sdk::aead::XChaCha20Poly1305;
use origin_crypto_sdk::blob::{blob_tier, detect_blob_version, recover_seed, BLOB_MAGIC};
use origin_crypto_sdk::tier::MemoryTier;

// ── XChaCha20-Poly1305: malformed ciphertext handling ──────────────────

#[test]
fn malformed_aead_empty_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, b"", b"").is_err(),
        "empty ciphertext must be rejected, not panic"
    );
}

#[test]
fn malformed_aead_one_byte_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &[0x00], b"").is_err(),
        "1-byte ciphertext (less than tag) must be rejected, not panic"
    );
}

#[test]
fn malformed_aead_tag_only_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    // 16-byte tag with no ciphertext — should fail auth, not panic
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &[0u8; 16], b"").is_err(),
        "tag-only ciphertext must fail authentication, not panic"
    );
}

#[test]
fn malformed_aead_15_byte_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    // 15 bytes — less than tag size
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &[0xab; 15], b"").is_err(),
        "15-byte ciphertext (less than tag) must be rejected, not panic"
    );
}

#[test]
fn malformed_aead_17_byte_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    // 17 bytes — 1 byte ciphertext + 16 byte tag, but wrong tag
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &[0xab; 17], b"").is_err(),
        "17-byte ciphertext with wrong tag must fail authentication, not panic"
    );
}

#[test]
fn malformed_aead_very_large_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let large = vec![0xabu8; 1_000_000];
    // Should fail auth (wrong tag), not panic or OOM
    assert!(
        XChaCha20Poly1305::decrypt_aad(&key, &nonce, &large, b"").is_err(),
        "large malformed ciphertext must fail authentication, not panic"
    );
}

// ── Blob parser: malformed input handling ──────────────────────────────

#[test]
fn malformed_blob_empty() {
    assert_eq!(
        detect_blob_version(b""),
        None,
        "empty blob must return None"
    );
    assert_eq!(blob_tier(b""), None, "empty blob tier must return None");
}

#[test]
fn malformed_blob_one_byte() {
    assert_eq!(detect_blob_version(&[0x00]), None);
    assert_eq!(blob_tier(&[0x00]), None);
}

#[test]
fn malformed_blob_three_bytes() {
    assert_eq!(detect_blob_version(&[0x00, 0x01, 0x02]), None);
    assert_eq!(blob_tier(&[0x00, 0x01, 0x02]), None);
}

#[test]
fn malformed_blob_wrong_magic() {
    // 6 bytes with wrong magic — should not be detected as v2
    let blob = [0xff, 0xff, 0xff, 0xff, 0x02, 0x01];
    assert_eq!(
        detect_blob_version(&blob),
        None,
        "wrong magic must not be v2"
    );
    assert_eq!(blob_tier(&blob), None, "wrong magic must not have a tier");
}

#[test]
fn malformed_blob_valid_magic_invalid_tier() {
    // Valid magic but invalid tier byte (0xff)
    let mut blob = BLOB_MAGIC.to_vec();
    blob.push(0x02); // version
    blob.push(0xff); // invalid tier
    assert_eq!(detect_blob_version(&blob), Some(2), "valid magic → v2");
    assert_eq!(blob_tier(&blob), None, "invalid tier byte must return None");
}

#[test]
fn malformed_blob_recover_empty() {
    let result = recover_seed(b"", b"passphrase", MemoryTier::Nano);
    assert!(
        result.is_err(),
        "recover_seed on empty blob must return error"
    );
}

#[test]
fn malformed_blob_recover_garbage() {
    let garbage = vec![0xffu8; 256];
    let result = recover_seed(&garbage, b"passphrase", MemoryTier::Nano);
    assert!(
        result.is_err(),
        "recover_seed on garbage must return error, not panic"
    );
}

#[test]
fn malformed_blob_recover_truncated_v2() {
    // Valid magic + version + tier, but truncated after header
    let mut blob = BLOB_MAGIC.to_vec();
    blob.push(0x02); // version
    blob.push(0x01); // Standard tier
    blob.extend_from_slice(&[0xab; 10]); // truncated payload

    let result = recover_seed(&blob, b"passphrase", MemoryTier::Standard);
    assert!(
        result.is_err(),
        "recover_seed on truncated v2 blob must return error, not panic"
    );
}

#[test]
fn malformed_blob_recover_wrong_passphrase() {
    use origin_crypto_sdk::blob::create_blob;
    let seed = [0x42u8; 32];
    let blob = create_blob(b"correct passphrase", MemoryTier::Nano, Some(&seed))
        .expect("create_blob failed");

    let result = recover_seed(&blob, b"wrong passphrase", MemoryTier::Nano);
    assert!(
        result.is_err(),
        "recover_seed with wrong passphrase must return error"
    );
}

#[test]
fn malformed_blob_recover_wrong_tier() {
    use origin_crypto_sdk::blob::create_blob;
    let seed = [0x42u8; 32];
    // Create a v1 blob (no magic) by creating a v2 blob and stripping the header
    // Actually, create_blob always creates v2. For v2 blobs, the tier is embedded
    // and the passed-in tier to recover_seed is ignored.
    // So we test that a v2 blob with Nano tier can be recovered regardless of
    // the tier parameter (since v2 uses the embedded tier).
    let blob =
        create_blob(b"passphrase", MemoryTier::Nano, Some(&seed)).expect("create_blob failed");

    // v2 blob: tier parameter is ignored, embedded tier is used
    // This should succeed because the embedded tier (Nano) is correct
    let result = recover_seed(&blob, b"passphrase", MemoryTier::Sovereign);
    assert!(
        result.is_ok(),
        "v2 blob recovery should use embedded tier, not the parameter"
    );
    assert_eq!(result.unwrap(), seed, "recovered seed must match original");
}

// ── Blob parser: all-zero and all-0xff inputs ──────────────────────────

#[test]
fn malformed_blob_all_zeros() {
    let zeros = vec![0u8; 1024];
    // 1024 bytes >= BLOB_LEN (88), so detect_blob_version returns Some(1) (v1 fallback)
    // This is expected behavior — the magic check fails, but it's long enough for v1.
    let version = detect_blob_version(&zeros);
    assert!(
        version == None || version == Some(1),
        "all-zeros blob: version should be None or v1 fallback, got {version:?}"
    );
    // recover_seed should fail gracefully (wrong Argon2 output / auth tag)
    assert!(recover_seed(&zeros, b"pass", MemoryTier::Nano).is_err());
}

#[test]
fn malformed_blob_all_0xff() {
    let ffs = vec![0xffu8; 1024];
    let version = detect_blob_version(&ffs);
    assert!(
        version == None || version == Some(1),
        "all-0xff blob: version should be None or v1 fallback, got {version:?}"
    );
    assert!(recover_seed(&ffs, b"pass", MemoryTier::Nano).is_err());
}

// ── AEAD: random-ish malformed inputs (lightweight property fuzz) ──────

#[test]
fn malformed_aead_various_lengths_no_panic() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];

    // Test various ciphertext lengths from 0 to 256
    for len in 0..=256 {
        let ct = vec![0xabu8; len];
        // Must never panic — only return Ok or Err
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, b"");
    }
}

#[test]
fn malformed_aead_various_aad_lengths_no_panic() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 24];
    let plaintext = b"test";

    let ct = XChaCha20Poly1305::encrypt_aad(&key, &nonce, plaintext, b"").unwrap();

    // Test various AAD lengths — all should fail (wrong AAD) but not panic
    for aad_len in 0..=256 {
        let aad = vec![0xcdu8; aad_len];
        let _ = XChaCha20Poly1305::decrypt_aad(&key, &nonce, &ct, &aad);
    }
}

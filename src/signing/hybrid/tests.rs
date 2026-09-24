// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use crate::pqc::ed448::SigningKey as Ed448SigningKey;
use crate::pqc::falcon1024::{
    generate_keypair_from_seed as falcon_keygen, sign as falcon_sign, verify as falcon_verify,
};
use crate::primitives::blake3;

use super::*;

/// Mutex to serialize tests that mutate the process-global bundle cache.
/// Without this, parallel test threads interfere via the shared static.
static CACHE_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether to run expensive cache tests (eviction, TTL, concurrent, lifecycle).
/// Each cache test triggers Falcon-1024 keygen (~5s per call). Set
/// `ORIGIN_FULL_TESTS=1` in CI to enable them. In fast dev mode, only
/// the basic cache hit/clear tests run.
fn run_expensive_cache_tests() -> bool {
    std::env::var("ORIGIN_FULL_TESTS").as_deref() == Ok("1")
}

#[test]
fn test_blake3_hash() {
    let msg = b"test message";
    let hash = blake3::hash(msg);
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_blake3_keyed() {
    let key = [42u8; blake3::KEY_LEN];
    let msg = b"test message";
    let hash = blake3::keyed_hash(&key, msg);
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_shake256_output() {
    let msg = b"test message";
    let out = shake256_output(msg, 64);
    assert_eq!(out.len(), 64);
    let out2 = shake256_output(msg, 64);
    assert_eq!(out, out2);
}

#[test]
fn test_shake128_output() {
    let msg = b"test message";
    let out = shake128_output(msg, 32);
    assert_eq!(out.len(), 32);
}

#[test]
fn test_skein512_basic() {
    let msg = b"test message";
    let h1 = skein512(msg);
    let h2 = skein512(msg);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn test_skein1024_basic() {
    let msg = b"test message";
    let h1 = skein1024(msg);
    let h2 = skein1024(msg);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 128);
}

#[test]
fn test_ed25519_blake3() {
    let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Blake3::sign(&sk, msg);
    Ed25519Blake3::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_blake3_rejects_wrong_msg() {
    let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let sig = Ed25519Blake3::sign(&sk, b"original");
    assert!(Ed25519Blake3::verify(&pk, b"tampered", &sig).is_err());
}

#[test]
fn test_ed25519_shake256() {
    let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Shake256::sign(&sk, msg, 64);
    Ed25519Shake256::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_skein512() {
    let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Skein512::sign(&sk, msg);
    Ed25519Skein512::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_skein512_rejects_wrong_msg() {
    let sk = Ed25519SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let sig = Ed25519Skein512::sign(&sk, b"original");
    assert!(Ed25519Skein512::verify(&pk, b"tampered", &sig).is_err());
}

#[test]
fn test_ed448_sha3_256() {
    let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed448Sha3_256::sign(&sk, msg);
    Ed448Sha3_256::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed448_shake256() {
    let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed448Shake256::sign(&sk, msg, 64);
    Ed448Shake256::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed448_skein512() {
    let sk = Ed448SigningKey::from_bytes(&[42u8; 57]).unwrap();
    let pk = sk.verifying_key();
    let msg = b"hello";
    let sig = Ed448Skein512::sign(&sk, msg);
    Ed448Skein512::verify(&pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_falcon1024() {
    let seed = [42u8; 32];
    let (falcon_pk, falcon_sk) = falcon_keygen(&seed).unwrap();
    let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Falcon1024::sign(&ed_sk, &falcon_sk, msg);
    Ed25519Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_falcon512() {
    let seed = [42u8; 32];
    let (falcon_sk, falcon_pk) = crate::pqc::falcon512::generate_keypair(seed);
    let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Falcon512::sign(&ed_sk, &falcon_sk, msg);
    Ed25519Falcon512::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

#[test]
fn test_ed25519_falcon512_rejects_tampered() {
    let seed = [42u8; 32];
    let (falcon_sk, falcon_pk) = crate::pqc::falcon512::generate_keypair(seed);
    let ed_sk = Ed25519SigningKey::from_bytes(&[1u8; 32]);
    let ed_pk = ed_sk.verifying_key();
    let msg = b"hello";
    let sig = Ed25519Falcon512::sign(&ed_sk, &falcon_sk, msg);
    assert!(Ed25519Falcon512::verify(&ed_pk, &falcon_pk, b"tampered", &sig).is_err());
}

#[test]
fn test_ed448_falcon1024() {
    let seed = [42u8; 32];
    let (falcon_pk, falcon_sk) = falcon_keygen(&seed).unwrap();
    let ed_sk = Ed448SigningKey::from_bytes(&[1u8; 57]).unwrap();
    let ed_pk = ed_sk.verifying_key();
    let msg = b"hello";
    let sig = Ed448Falcon1024::sign(&ed_sk, &falcon_sk, msg);
    Ed448Falcon1024::verify(&ed_pk, &falcon_pk, msg, &sig).unwrap();
}

#[test]
fn test_derive_hybrid_keys() {
    let seed = [42u8; 32];
    let sub = derive_hybrid_keys(&seed, "test").unwrap();
    assert_eq!(sub.ed25519.len(), 32);
    assert_eq!(sub.chacha20.len(), 32);
    assert_eq!(sub.hash.len(), 32);
}

#[test]
fn test_ed25519_chacha20blake3_sha3_256() {
    let seed = [42u8; 32];
    let msg = b"hello hybrid kdf";
    let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain", msg).unwrap();
    Ed25519ChaCha20Blake3Sha3_256::verify(&seed, "domain", msg, &sig).unwrap();
}

#[test]
fn test_ed25519_chacha20blake3_sha3_rejects_wrong() {
    let seed = [42u8; 32];
    let sig = Ed25519ChaCha20Blake3Sha3_256::sign(&seed, "domain", b"orig").unwrap();
    assert!(Ed25519ChaCha20Blake3Sha3_256::verify(&seed, "domain", b"wrong", &sig).is_err());
}

#[test]
fn test_hybrid_signing_key_bundle_basic() {
    let seed = [42u8; 32];
    let bundle = HybridSigningKeyBundle::from_seed(&seed, "test-domain").unwrap();
    assert_eq!(bundle.domain(), "test-domain");

    // Sign a message with the canonical hybrid
    let msg = b"hello bundle";
    let sig = bundle.sign_hybrid(msg);
    Ed25519Falcon1024::verify(bundle.ed25519_pk(), bundle.falcon1024_pk(), msg, &sig).unwrap();
}

#[test]
fn test_hybrid_signing_key_bundle_deterministic() {
    let seed = [42u8; 32];
    let bundle1 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();
    let bundle2 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();

    // Same seed + domain = same Ed25519 key
    assert_eq!(
        bundle1.ed25519_pk().to_bytes(),
        bundle2.ed25519_pk().to_bytes()
    );
    // Same seed + domain = same Falcon-1024 key
    assert_eq!(
        bundle1.falcon1024_pk().as_bytes(),
        bundle2.falcon1024_pk().as_bytes()
    );
}

/// Regression test: Falcon key must also be domain-separated (not just Ed25519).
/// This was a real bug — the original `from_seed` passed the master seed
/// directly to Falcon keygen, ignoring the domain parameter.
#[test]
fn test_hybrid_signing_key_bundle_domain_separates_falcon() {
    let seed = [42u8; 32];
    let bundle1 = HybridSigningKeyBundle::from_seed(&seed, "domain1").unwrap();
    let bundle2 = HybridSigningKeyBundle::from_seed(&seed, "domain2").unwrap();

    // Different domains must yield different Falcon keys
    assert_ne!(
        bundle1.falcon1024_pk().as_bytes(),
        bundle2.falcon1024_pk().as_bytes(),
        "Falcon key should differ between domains"
    );
}

/// The cache must produce the same keys as the non-cached path.
#[test]
fn test_hybrid_signing_key_bundle_cache_consistency() {
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    let seed = [42u8; 32];
    let b1 = HybridSigningKeyBundle::from_seed(&seed, "test-domain").unwrap();
    let b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "test-domain")
        .expect("cached should succeed");

    assert_eq!(b1.ed25519_pk().to_bytes(), b2.ed25519_pk().to_bytes());
    assert_eq!(b1.falcon1024_pk().as_bytes(), b2.falcon1024_pk().as_bytes());
}

/// Cached and non-cached paths must produce functionally identical bundles.
/// Two calls to `from_seed_cached` should return Arc to the same instance.
#[test]
fn test_hybrid_signing_key_bundle_cache_returns_same_arc() {
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    let seed = [42u8; 32];
    let b1 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-test")
        .expect("first cached should succeed");
    let b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-test")
        .expect("second cached should succeed");

    // Both Arcs point to the same allocation
    assert!(Arc::ptr_eq(&b1, &b2));
}

/// The cache must respect a max-entries cap and evict the oldest entry
/// (FIFO) when full, so that key material does not accumulate unbounded.
#[test]
fn test_bundle_cache_evicts_oldest_at_capacity() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    bundle_cache_configure(2, None);
    assert_eq!(bundle_cache_len(), 0);

    let s1 = HybridSigningKeyBundle::from_seed_cached(&[1u8; 32], "evict-a").expect("first insert");
    assert_eq!(bundle_cache_len(), 1);

    let _s2 =
        HybridSigningKeyBundle::from_seed_cached(&[2u8; 32], "evict-b").expect("second insert");
    assert_eq!(bundle_cache_len(), 2);

    // Third insert should evict the oldest (s1's entry).
    let _s3 =
        HybridSigningKeyBundle::from_seed_cached(&[3u8; 32], "evict-c").expect("third insert");
    assert_eq!(bundle_cache_len(), 2);

    // s1's Arc is still alive (we hold it), but re-caching should produce a
    // new Arc because the old entry was evicted.
    let s1_again = HybridSigningKeyBundle::from_seed_cached(&[1u8; 32], "evict-a")
        .expect("re-insert after eviction");
    assert!(!Arc::ptr_eq(&s1, &s1_again));

    // Restore defaults for other tests.
    bundle_cache_clear();
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// The cache must evict expired entries on access when a TTL is configured.
#[test]
fn test_bundle_cache_evicts_expired_entries_on_ttl() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    bundle_cache_configure(8, Some(Duration::from_millis(50)));

    let seed = [99u8; 32];
    let _b = HybridSigningKeyBundle::from_seed_cached(&seed, "ttl-test").expect("insert");
    assert_eq!(bundle_cache_len(), 1);

    // Wait for TTL to elapse.
    std::thread::sleep(Duration::from_millis(60));

    // A new lookup should trigger eviction and re-derivation.
    let b2 =
        HybridSigningKeyBundle::from_seed_cached(&seed, "ttl-test").expect("re-derive after TTL");
    assert_eq!(bundle_cache_len(), 1);

    // The re-derived bundle should have the same public keys.
    let b_ref = HybridSigningKeyBundle::from_seed(&seed, "ttl-test").unwrap();
    assert_eq!(b2.ed25519_pk().to_bytes(), b_ref.ed25519_pk().to_bytes());

    // Restore defaults.
    bundle_cache_clear();
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// `bundle_cache_configure` must clear existing entries on policy change.
#[test]
fn test_bundle_cache_configure_clears_existing_entries() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    let _b = HybridSigningKeyBundle::from_seed_cached(&[5u8; 32], "cfg-clear").expect("insert");
    assert_eq!(bundle_cache_len(), 1);

    bundle_cache_configure(4, None);
    assert_eq!(bundle_cache_len(), 0);

    // Restore defaults.
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// Multiple threads hitting the cache concurrently must all get valid,
/// consistent bundles without panicking or corrupting the cache.
#[test]
fn test_bundle_cache_concurrent_access() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    bundle_cache_configure(4, None);

    let seed = [77u8; 32];
    let domain = "concurrent-test";

    // Pre-populate so threads hit the cache (not the slow keygen path).
    let expected = HybridSigningKeyBundle::from_seed_cached(&seed, domain).expect("pre-populate");
    let expected_ed_pk = expected.ed25519_pk().to_bytes();

    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                let bundle =
                    HybridSigningKeyBundle::from_seed_cached(&seed, domain).expect("thread");
                bundle.ed25519_pk().to_bytes()
            })
        })
        .collect();

    for thread in threads {
        let ed_pk = thread.join().expect("thread panicked");
        assert_eq!(ed_pk, expected_ed_pk);
    }

    // All threads got the same cached Arc.
    assert_eq!(bundle_cache_len(), 1);

    // Restore defaults.
    bundle_cache_clear();
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// Concurrent inserts of different keys must not exceed the configured cap.
#[test]
fn test_bundle_cache_concurrent_inserts_respect_cap() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();
    bundle_cache_configure(3, None);

    let threads: Vec<_> = (0..6)
        .map(|i| {
            let seed = [i as u8 + 1; 32];
            std::thread::spawn(move || {
                HybridSigningKeyBundle::from_seed_cached(&seed, "cap-test")
                    .expect("concurrent insert")
            })
        })
        .collect();

    for thread in threads {
        let _ = thread.join().expect("thread panicked");
    }

    // Cache must not exceed the configured max.
    assert!(bundle_cache_len() <= 3);

    // Restore defaults.
    bundle_cache_clear();
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// Full cache lifecycle: configure → insert → verify → clear → re-insert
/// → verify → restore defaults. Exercises the public management API
/// end-to-end and confirms that clear + re-insert produces a fresh Arc.
#[test]
fn test_bundle_cache_lifecycle() {
    if !run_expensive_cache_tests() {
        return;
    }
    let _guard = CACHE_TEST_GUARD.lock().unwrap();

    // Start clean.
    bundle_cache_clear();
    bundle_cache_configure(4, None);
    assert_eq!(bundle_cache_len(), 0);

    // Insert.
    let seed = [33u8; 32];
    let b1 = HybridSigningKeyBundle::from_seed_cached(&seed, "lifecycle").expect("insert");
    assert_eq!(bundle_cache_len(), 1);

    // Cache hit returns the same Arc.
    let b1_again = HybridSigningKeyBundle::from_seed_cached(&seed, "lifecycle").expect("cache hit");
    assert!(Arc::ptr_eq(&b1, &b1_again));

    // Clear empties the cache.
    bundle_cache_clear();
    assert_eq!(bundle_cache_len(), 0);

    // Re-insert after clear produces a new Arc (not the old one).
    let b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "lifecycle")
        .expect("re-insert after clear");
    assert!(!Arc::ptr_eq(&b1, &b2));

    // Public keys are still deterministic.
    assert_eq!(b1.ed25519_pk().to_bytes(), b2.ed25519_pk().to_bytes());

    // Restore defaults.
    bundle_cache_clear();
    bundle_cache_configure(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES, None);
}

/// An ownable `BundleCache` instance must be independent of the
/// process-global cache: entries in one never appear in the other.
#[test]
fn test_ownable_bundle_cache_is_independent_of_global() {
    let _guard = CACHE_TEST_GUARD.lock().unwrap();
    bundle_cache_clear();

    let local = BundleCache::new();
    local.configure(2, None);
    assert!(local.is_empty());

    let seed = [55u8; 32];
    let b1 = local
        .get_or_insert(&seed, "local-test", || {
            HybridSigningKeyBundle::from_seed(&seed, "local-test")
        })
        .expect("local insert");
    assert_eq!(local.len(), 1);

    // Second lookup on the ownable cache hits the same Arc.
    let b2 = local
        .get_or_insert(&seed, "local-test", || {
            HybridSigningKeyBundle::from_seed(&seed, "local-test")
        })
        .expect("local hit");
    assert!(Arc::ptr_eq(&b1, &b2));

    // The process-global cache was not touched.
    assert_eq!(bundle_cache_len(), 0);
}

#[test]
fn test_falcon1024_keygen_convenience() {
    let seed = [42u8; 32];
    let (pk, sk) = falcon1024_keygen(&seed).unwrap();
    let msg = b"test";
    let sig = falcon_sign(msg, &sk).unwrap();
    assert!(falcon_verify(msg, &sig, &pk).is_ok());
}

#[test]
fn test_xor_combine() {
    let a = [1u8, 2, 3, 4];
    let b = [5u8, 6, 7, 8];
    let out = xor_combine(&a, &b);
    assert_eq!(out, vec![4, 4, 4, 12]);
}

#[test]
fn test_concat_combine() {
    let a = [1u8, 2];
    let b = [3u8, 4, 5];
    let out = concat_combine(&a, &b);
    assert_eq!(out, vec![1, 2, 3, 4, 5]);
}

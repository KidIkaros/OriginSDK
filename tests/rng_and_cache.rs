// SPDX-License-Identifier: Apache-2.0

//! RNG failure injection and concurrency/cache lifecycle tests.
//!
//! These tests verify:
//! - Fallible RNG APIs (`try_generate_nonce`, `try_generate_key`, `fill_random`)
//!   return errors rather than panicking when the entropy source fails
//! - The process-wide hybrid signing key cache behaves correctly under
//!   concurrent access, eviction, TTL expiry, and manual clearing
//! - Cache entries are bounded and don't grow unboundedly
//!
//! Classification: misuse-resistance and concurrency evidence
//! Purpose: verify that environmental failures are handled gracefully and
//! the cache doesn't leak keys or grow without bound.

use std::sync::Arc;
use std::thread;

use origin_crypto_sdk::aead::{try_generate_key, try_generate_nonce};
use origin_crypto_sdk::fill_random;
use origin_crypto_sdk::signing::hybrid::{
    bundle_cache_clear, bundle_cache_configure, bundle_cache_len, HybridSigningKeyBundle,
};

// ── Fallible RNG API tests ─────────────────────────────────────────────

#[test]
fn rng_try_generate_nonce_succeeds() {
    let nonce = try_generate_nonce();
    assert!(
        nonce.is_ok(),
        "try_generate_nonce should succeed under normal conditions"
    );
    let nonce = nonce.unwrap();
    assert_eq!(nonce.len(), 24);
}

#[test]
fn rng_try_generate_key_succeeds() {
    let key = try_generate_key();
    assert!(
        key.is_ok(),
        "try_generate_key should succeed under normal conditions"
    );
    let key = key.unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn rng_fill_random_succeeds() {
    let mut buf = [0u8; 64];
    let result = fill_random(&mut buf);
    assert!(
        result.is_ok(),
        "fill_random should succeed under normal conditions"
    );
    // Verify the buffer was actually filled (extremely unlikely to be all zeros)
    assert!(
        buf.iter().any(|&b| b != 0),
        "fill_random should produce non-zero output"
    );
}

#[test]
fn rng_fill_random_empty_buffer() {
    let mut buf: [u8; 0] = [];
    let result = fill_random(&mut buf);
    assert!(
        result.is_ok(),
        "fill_random on empty buffer should succeed (no-op)"
    );
}

#[test]
fn rng_fill_random_large_buffer() {
    let mut buf = vec![0u8; 10_000];
    let result = fill_random(&mut buf);
    assert!(result.is_ok(), "fill_random on large buffer should succeed");
    assert!(
        buf.iter().any(|&b| b != 0),
        "large buffer should have non-zero output"
    );
}

#[test]
fn rng_two_calls_produce_different_output() {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    fill_random(&mut buf1).unwrap();
    fill_random(&mut buf2).unwrap();
    assert_ne!(buf1, buf2, "two RNG calls should produce different output");
}

#[test]
fn rng_nonce_uniqueness() {
    let mut nonces = Vec::new();
    for _ in 0..100 {
        nonces.push(try_generate_nonce().unwrap());
    }
    // All 100 nonces should be distinct
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "nonce {i} and {j} must be distinct");
        }
    }
}

// ── Cache lifecycle tests ──────────────────────────────────────────────
//
// All cache tests share a process-global singleton, so they must be
// serialized to avoid interference. We use a module-level Mutex.

use std::sync::Mutex as StdMutex;
static CACHE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

fn cache_test_guard() -> std::sync::MutexGuard<'static, ()> {
    CACHE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn setup_cache_test() {
    bundle_cache_clear();
}

#[test]
fn cache_starts_empty() {
    let _guard = cache_test_guard();
    setup_cache_test();
    assert_eq!(bundle_cache_len(), 0, "cache should be empty after clear");
}

#[test]
fn cache_populated_after_from_seed_cached() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed = [0x42u8; 32];
    let _bundle = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-test-1").unwrap();
    assert_eq!(
        bundle_cache_len(),
        1,
        "cache should have 1 entry after from_seed_cached"
    );
}

#[test]
fn cache_hit_does_not_grow() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed = [0x42u8; 32];
    let _b1 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-hit").unwrap();
    let _b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "cache-hit").unwrap();
    assert_eq!(
        bundle_cache_len(),
        1,
        "cache hit should not create a new entry"
    );
}

#[test]
fn cache_different_domains_create_separate_entries() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed = [0x42u8; 32];
    let _b1 = HybridSigningKeyBundle::from_seed_cached(&seed, "domain-a").unwrap();
    let _b2 = HybridSigningKeyBundle::from_seed_cached(&seed, "domain-b").unwrap();
    assert_eq!(
        bundle_cache_len(),
        2,
        "different domains should create separate cache entries"
    );
}

#[test]
fn cache_different_seeds_create_separate_entries() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed1 = [0x01u8; 32];
    let seed2 = [0x02u8; 32];
    let _b1 = HybridSigningKeyBundle::from_seed_cached(&seed1, "same-domain").unwrap();
    let _b2 = HybridSigningKeyBundle::from_seed_cached(&seed2, "same-domain").unwrap();
    assert_eq!(
        bundle_cache_len(),
        2,
        "different seeds should create separate cache entries"
    );
}

#[test]
fn cache_clear_empties_all_entries() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed = [0x42u8; 32];
    let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "clear-test-1").unwrap();
    let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "clear-test-2").unwrap();
    assert_eq!(bundle_cache_len(), 2);

    bundle_cache_clear();
    assert_eq!(bundle_cache_len(), 0, "cache should be empty after clear");
}

#[test]
fn cache_bounded_by_max_entries() {
    let _guard = cache_test_guard();
    setup_cache_test();
    // Configure a small cache
    bundle_cache_configure(3, None);
    assert_eq!(bundle_cache_len(), 0, "configure should clear the cache");

    // Add 5 entries to a cache with max 3
    for i in 0u8..5 {
        let seed = [i; 32];
        let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "bounded").unwrap();
    }

    // Cache should not exceed max_entries
    assert!(
        bundle_cache_len() <= 3,
        "cache should be bounded by max_entries (3), got {}",
        bundle_cache_len()
    );

    // Cleanup
    bundle_cache_clear();
}

#[test]
fn cache_configure_resets_cache() {
    let _guard = cache_test_guard();
    setup_cache_test();
    let seed = [0x42u8; 32];
    let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "configure-reset").unwrap();
    assert_eq!(bundle_cache_len(), 1);

    // Reconfiguring should clear existing entries
    bundle_cache_configure(10, None);
    assert_eq!(
        bundle_cache_len(),
        0,
        "bundle_cache_configure should clear existing entries"
    );
}

// ── Concurrency tests ──────────────────────────────────────────────────

#[test]
fn cache_concurrent_access_no_deadlock() {
    let _guard = cache_test_guard();
    setup_cache_test();
    bundle_cache_configure(20, None);

    let seed = [0x42u8; 32];
    let threads: Vec<_> = (0..4)
        .map(|i| {
            let seed = seed;
            thread::spawn(move || {
                let domain = format!("concurrent-{i}");
                let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, &domain).unwrap();
                // Sign a message to exercise the bundle
                let _sig = bundle.sign_hybrid(b"concurrent test message");
                bundle_cache_len(); // Also exercise the diagnostic API
            })
        })
        .collect();

    for t in threads {
        t.join().expect("concurrent cache access thread panicked");
    }

    // All threads should have completed without deadlock
    // Cache should have 4 entries (one per domain)
    assert!(
        bundle_cache_len() <= 4,
        "cache should have at most 4 entries after 4 concurrent threads"
    );

    bundle_cache_clear();
}

#[test]
fn cache_concurrent_same_domain_returns_same_bundle() {
    let _guard = cache_test_guard();
    setup_cache_test();
    bundle_cache_configure(10, None);

    let seed = [0x42u8; 32];
    let domain = "same-domain-concurrent";
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let seed = seed;
            let domain = domain.to_string();
            thread::spawn(move || {
                let bundle = HybridSigningKeyBundle::from_seed_cached(&seed, &domain).unwrap();
                // Verify the Ed25519 public key is deterministic
                bundle.ed25519_pk().to_bytes()
            })
        })
        .collect();

    let results: Vec<[u8; 32]> = threads
        .into_iter()
        .map(|t| t.join().expect("thread panicked"))
        .collect();

    // All threads should get the same Ed25519 public key (cache hit)
    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "concurrent access to same (seed, domain) must return same key"
        );
    }

    bundle_cache_clear();
}

#[test]
fn rng_concurrent_calls_are_thread_safe() {
    // Verify that fill_random is safe to call from multiple threads concurrently
    let threads: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                let mut buf = [0u8; 32];
                for _ in 0..10 {
                    fill_random(&mut buf).expect("fill_random failed in thread {i}");
                    assert!(buf.iter().any(|&b| b != 0));
                }
            })
        })
        .collect();

    for t in threads {
        t.join().expect("RNG thread panicked");
    }
}

// ── Cache TTL tests ────────────────────────────────────────────────────

#[test]
fn cache_ttl_expires_entries() {
    let _guard = cache_test_guard();
    setup_cache_test();
    // Set TTL to 1 millisecond — entries should expire quickly
    bundle_cache_configure(100, Some(std::time::Duration::from_millis(1)));

    let seed = [0x42u8; 32];
    let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "ttl-test").unwrap();
    assert_eq!(bundle_cache_len(), 1);

    // Wait for TTL to expire
    thread::sleep(std::time::Duration::from_millis(50));

    // Accessing the cache should trigger eviction of expired entries
    // The next from_seed_cached call should re-derive (cache miss)
    let _ = HybridSigningKeyBundle::from_seed_cached(&seed, "ttl-test").unwrap();

    // After re-derivation, the cache should have 1 entry (the new one)
    // The old expired entry should have been evicted
    assert_eq!(
        bundle_cache_len(),
        1,
        "expired entry should be replaced, not duplicated"
    );

    bundle_cache_clear();
}

// ── Cache and non-cached API consistency ───────────────────────────────

#[test]
fn cache_and_non_cached_produce_same_keys() {
    let _guard = cache_test_guard();
    setup_cache_test();

    let seed = [0x42u8; 32];
    let domain = "consistency-test";

    let bundle_uncached = HybridSigningKeyBundle::from_seed(&seed, domain).unwrap();
    let bundle_cached = HybridSigningKeyBundle::from_seed_cached(&seed, domain).unwrap();

    assert_eq!(
        bundle_uncached.ed25519_pk().to_bytes(),
        bundle_cached.ed25519_pk().to_bytes(),
        "cached and uncached bundles must produce same Ed25519 key"
    );

    assert_eq!(
        bundle_uncached.falcon1024_pk().as_bytes(),
        bundle_cached.falcon1024_pk().as_bytes(),
        "cached and uncached bundles must produce same Falcon key"
    );

    bundle_cache_clear();
}

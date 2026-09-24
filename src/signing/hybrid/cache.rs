// SPDX-License-Identifier: Apache-2.0

//! Bounded cache for [`HybridSigningKeyBundle`].
//!
//! Falcon-1024 keygen is expensive (~4s), so the bundle API offers
//! `from_seed_cached`, which memoizes bundles keyed by a domain-separated
//! BLAKE3 digest of `(seed, domain)` — the raw seed is never retained in
//! the index.
//!
//! [`BundleCache`] is an ownable value type — `BundleCache::new()` creates
//! an independent instance for callers that want explicit ownership. For
//! the common case, a process-global instance sits behind `OnceLock` and
//! is reached through the free functions below; that global is the crate's
//! one piece of process-global mutable state, wrapped (never bare) and
//! bounded by entry count and optional TTL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::primitives::blake3;

use super::bundle::HybridSigningKeyBundle;

/// Default maximum number of cached bundles before FIFO eviction kicks in.
pub const DEFAULT_BUNDLE_CACHE_MAX_ENTRIES: usize = 8;

/// A cached bundle with insertion timestamp for TTL and FIFO eviction.
struct CacheEntry {
    bundle: Arc<HybridSigningKeyBundle>,
    inserted_at: Instant,
}

impl CacheEntry {
    fn new(bundle: Arc<HybridSigningKeyBundle>) -> Self {
        Self {
            bundle,
            inserted_at: Instant::now(),
        }
    }
}

/// Bounded cache for [`HybridSigningKeyBundle`], keyed by a
/// domain-separated digest of `(seed, domain)`.
///
/// The digest prevents the cache index from retaining a second raw copy of
/// the caller's master seed. The cache is bounded by a maximum entry count
/// and an optional TTL. When an entry is evicted, the cache drops its `Arc`
/// clone; if no other `Arc` clones exist outside the cache, the bundle's
/// key material is zeroized via the `Drop` implementations of the
/// individual key types (Falcon, Ed25519, Ed448). Callers that retain `Arc`
/// clones past eviction keep the key material alive until their last clone
/// is dropped — this is a documented limitation of reference-counted
/// caching.
///
/// `BundleCache` is an ownable value: `BundleCache::new()` gives an
/// independent instance for callers that want explicit ownership (e.g.
/// per-connection or per-tenant caches). The free functions
/// [`bundle_cache_configure`]/[`bundle_cache_clear`]/[`bundle_cache_len`]
/// and [`HybridSigningKeyBundle::from_seed_cached`] operate on a single
/// process-global instance as a convenience for the common case.
pub struct BundleCache {
    entries: Mutex<HashMap<[u8; 32], CacheEntry>>,
    max_entries: Mutex<usize>,
    ttl: Mutex<Option<Duration>>,
}

fn bundle_cache_key(master_seed: &[u8; 32], domain: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8 + domain.len());
    input.extend_from_slice(master_seed);
    input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    input.extend_from_slice(domain.as_bytes());
    blake3::derive_key("origin-crypto-sdk/bundle-cache/v1", &input)
}

impl std::fmt::Debug for BundleCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Entries hold key material — report only the bound policy.
        f.debug_struct("BundleCache")
            .field("entries", &self.len())
            .field("max_entries", &self.max_entries)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl Default for BundleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleCache {
    /// Create an empty cache with default bounds
    /// ([`DEFAULT_BUNDLE_CACHE_MAX_ENTRIES`], no TTL).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries: Mutex::new(DEFAULT_BUNDLE_CACHE_MAX_ENTRIES),
            ttl: Mutex::new(None),
        }
    }

    /// Fetch the cached bundle for `(seed, domain)`, or run `derive` and
    /// insert its result on a miss. Expired entries are evicted before the
    /// lookup; the oldest entry is evicted when the cache is at capacity.
    ///
    /// `derive` runs while the cache's entry lock is held, so a miss
    /// serializes against other inserts — matching the historical
    /// process-global behavior.
    pub fn get_or_insert(
        &self,
        master_seed: &[u8; 32],
        domain: &str,
        derive: impl FnOnce() -> Result<HybridSigningKeyBundle>,
    ) -> Result<Arc<HybridSigningKeyBundle>> {
        self.get_or_insert_key(bundle_cache_key(master_seed, domain), derive)
    }

    /// Key-addressed variant of [`BundleCache::get_or_insert`].
    fn get_or_insert_key(
        &self,
        key: [u8; 32],
        derive: impl FnOnce() -> Result<HybridSigningKeyBundle>,
    ) -> Result<Arc<HybridSigningKeyBundle>> {
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Evict expired entries before lookup so a stale hit is impossible.
        self.evict_expired_locked(&mut entries);

        if let Some(entry) = entries.get(&key) {
            return Ok(entry.bundle.clone());
        }

        // Evict oldest if at capacity.
        self.evict_oldest_locked(&mut entries);

        let bundle = Arc::new(derive()?);
        entries.insert(key, CacheEntry::new(bundle.clone()));
        Ok(bundle)
    }

    /// Remove entries whose TTL has elapsed. Caller must hold the entries lock.
    fn evict_expired_locked(&self, entries: &mut HashMap<[u8; 32], CacheEntry>) {
        let ttl = match self.ttl.lock() {
            Ok(ttl) => *ttl,
            Err(poisoned) => *poisoned.into_inner(),
        };
        let Some(ttl) = ttl else {
            return;
        };
        let now = Instant::now();
        entries.retain(|_, entry| now.duration_since(entry.inserted_at) < ttl);
    }

    /// Evict the oldest entry if the cache is at or above capacity.
    /// Caller must hold the entries lock.
    fn evict_oldest_locked(&self, entries: &mut HashMap<[u8; 32], CacheEntry>) {
        let max = match self.max_entries.lock() {
            Ok(max) => *max,
            Err(poisoned) => *poisoned.into_inner(),
        };
        if entries.len() < max {
            return;
        }
        // FIFO eviction: find and remove the entry with the earliest insertion time.
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(key, _)| *key)
        {
            entries.remove(&oldest_key);
        }
    }

    /// Clear all entries. Always succeeds; poisoned locks recover.
    pub fn clear(&self) {
        match self.entries.lock() {
            Ok(mut entries) => entries.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(entries) => entries.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// True when the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace the bounding policy and clear existing entries so stale
    /// entries under the old policy do not persist.
    ///
    /// `max_entries` is clamped to a minimum of 1. `ttl` of `None` disables
    /// time-based eviction.
    pub fn configure(&self, max_entries: usize, ttl: Option<Duration>) {
        self.clear();
        match self.max_entries.lock() {
            Ok(mut current) => *current = max_entries.max(1),
            Err(poisoned) => *poisoned.into_inner() = max_entries.max(1),
        }
        match self.ttl.lock() {
            Ok(mut current) => *current = ttl,
            Err(poisoned) => *poisoned.into_inner() = ttl,
        }
    }
}

static BUNDLE_CACHE: OnceLock<BundleCache> = OnceLock::new();

fn bundle_cache() -> &'static BundleCache {
    BUNDLE_CACHE.get_or_init(BundleCache::new)
}

/// Fetch-or-derive against the process-global cache. Called by
/// [`HybridSigningKeyBundle::from_seed_cached`].
pub(crate) fn get_or_insert(
    master_seed: &[u8; 32],
    domain: &str,
    derive: impl FnOnce() -> Result<HybridSigningKeyBundle>,
) -> Result<Arc<HybridSigningKeyBundle>> {
    bundle_cache().get_or_insert(master_seed, domain, derive)
}

/// Configure the process-wide bundle cache bounds.
///
/// Sets the maximum number of cached bundles and an optional time-to-live.
/// Entries that exceed the TTL are evicted on the next cache access. When
/// the cache exceeds `max_entries`, the oldest entry is evicted (FIFO).
///
/// Calling this clears the existing cache so stale entries under the old
/// policy do not persist. Call once at process startup before any
/// `from_seed_cached` call for deterministic behavior.
///
/// # Fork safety
///
/// After a `fork()`, the child process inherits the parent's cache contents
/// including private key material. The child must call [`bundle_cache_clear`]
/// (or [`bundle_cache_configure`]) before using `from_seed_cached` to avoid
/// operating on stale key material from the parent.
///
/// # Panics
/// This function does not panic. If the internal locks are poisoned, the
/// previous values are recovered and overwritten.
pub fn bundle_cache_configure(max_entries: usize, ttl: Option<Duration>) {
    bundle_cache().configure(max_entries, ttl);
}

/// Clear the process-wide bundle cache. Useful for tests or
/// memory-constrained environments.
pub fn bundle_cache_clear() {
    if let Some(cache) = BUNDLE_CACHE.get() {
        cache.clear();
    }
}

/// Return the current number of entries in the process-wide bundle cache.
/// Intended for diagnostics and tests.
pub fn bundle_cache_len() -> usize {
    BUNDLE_CACHE.get().map_or(0, BundleCache::len)
}

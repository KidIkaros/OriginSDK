// SPDX-License-Identifier: Apache-2.0

//! Unix memory-locking primitives (`mlock`/`munlock`) behind safe wrappers.
//!
//! Used by the Sovereign memory tier to request that seed pages are not
//! swapped to disk. Both calls are best-effort: callers ignore the return
//! value because `mlock` limits (`RLIMIT_MEMLOCK`) vary by platform and a
//! failed lock must not break seed handling on constrained systems.
//!
//! The FFI boundary lives here — in the `internal` detail layer — so that
//! domain code (e.g. `seed`) never declares `extern "C"` blocks.

/// Request that `len` bytes starting at `addr` remain resident in RAM.
///
/// Returns `true` if the kernel accepted the request. Returns `false` on
/// non-Unix platforms and on any `mlock` error.
#[cfg(unix)]
pub(crate) fn lock(addr: *const u8, len: usize) -> bool {
    if addr.is_null() || len == 0 {
        return false;
    }
    extern "C" {
        fn mlock(addr: *const u8, len: usize) -> i32;
    }
    unsafe { mlock(addr, len) == 0 }
}

/// Release a previous [`lock`] request on `len` bytes at `addr`.
///
/// Returns `true` if the kernel accepted the request. Returns `false` on
/// non-Unix platforms and on any `munlock` error.
#[cfg(unix)]
pub(crate) fn unlock(addr: *const u8, len: usize) -> bool {
    if addr.is_null() || len == 0 {
        return false;
    }
    extern "C" {
        fn munlock(addr: *const u8, len: usize) -> i32;
    }
    unsafe { munlock(addr, len) == 0 }
}

/// Non-Unix stubs: memory locking is unavailable, report failure.
#[cfg(not(unix))]
pub(crate) fn lock(_addr: *const u8, _len: usize) -> bool {
    false
}

/// Non-Unix stub for [`unlock`].
#[cfg(not(unix))]
pub(crate) fn unlock(_addr: *const u8, _len: usize) -> bool {
    false
}

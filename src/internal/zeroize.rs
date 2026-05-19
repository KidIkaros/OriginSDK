// SPDX-License-Identifier: OPL-1.1

//! Secure memory zeroing — replacement for the `zeroize` crate.
//!
//! Uses `core::ptr::write_volatile` and `core::sync::atomic::compiler_fence`
//! to prevent the compiler from optimizing away the zeroing operation.

use core::sync::atomic::{compiler_fence, Ordering};

/// Securely zero memory using volatile writes and compiler fences.
///
/// This prevents the compiler from optimizing away the zeroing
/// operation, even when the memory is about to be dropped.
pub fn secure_zero_memory(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // Volatile write ensures the compiler cannot elide this store
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    // Prevent reordering of memory operations across this point
    compiler_fence(Ordering::SeqCst);
}

/// Trait for types that can be securely zeroized.
///
/// Replacement for `zeroize::Zeroize`.
pub trait Zeroize {
    /// Zero out all sensitive data in this value.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        secure_zero_memory(self);
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        secure_zero_memory(self.as_mut_slice());
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        secure_zero_memory(self.as_mut_slice());
    }
}

impl<const N: usize> Zeroize for [i64; N] {
    fn zeroize(&mut self) {
        let ptr = self.as_mut_ptr() as *mut u8;
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, N * core::mem::size_of::<i64>()) };
        secure_zero_memory(bytes);
    }
}

impl<const N: usize> Zeroize for [i8; N] {
    fn zeroize(&mut self) {
        let ptr = self.as_mut_ptr() as *mut u8;
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, N * core::mem::size_of::<i8>()) };
        secure_zero_memory(bytes);
    }
}

impl<const N: usize> Zeroize for [u32; N] {
    fn zeroize(&mut self) {
        let ptr = self.as_mut_ptr() as *mut u8;
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, N * core::mem::size_of::<u32>()) };
        secure_zero_memory(bytes);
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        unsafe {
            for byte in self.as_mut_vec().iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// A wrapper that zeroizes its contents on drop.
///
/// Replacement for `zeroize::Zeroizing`.
pub struct Zeroizing<T: Zeroize>(pub T);

impl<T: Zeroize> Zeroizing<T> {
    /// Create a new `Zeroizing` wrapper.
    pub fn new(data: T) -> Self {
        Self(data)
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

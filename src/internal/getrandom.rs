// SPDX-License-Identifier: OPL-1.1

//! OS entropy extraction — replacement for the `getrandom` crate.
//!
//! Uses direct syscalls to avoid pulling in the `getrandom` dependency.

/// Fill `dest` with random bytes from the OS CSPRNG.
///
/// On Linux, this uses `getrandom(2)`.
/// On other Unix platforms, it falls back to `/dev/urandom`.
/// On Windows, it uses `BCryptGenRandom`.
pub fn fill(dest: &mut [u8]) -> Result<(), &'static str> {
    #[cfg(target_os = "linux")]
    {
        // Linux getrandom syscall: syscall(SYS_getrandom, buf, buflen, flags)
        // SYS_getrandom = 318 on x86_64, 278 on aarch64
        #[cfg(target_arch = "x86_64")]
        const SYS_GETRANDOM: i64 = 318;
        #[cfg(target_arch = "aarch64")]
        const SYS_GETRANDOM: i64 = 278;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture for getrandom syscall");

        extern "C" {
            fn syscall(number: i64, ...) -> i64;
            fn __errno_location() -> *mut i32;
        }
        const EINTR: i32 = 4;

        let mut offset = 0;
        while offset < dest.len() {
            let ret = unsafe {
                syscall(SYS_GETRANDOM, dest.as_mut_ptr().add(offset), dest.len() - offset, 0)
            };
            if ret < 0 {
                let errno = unsafe { *__errno_location() };
                if errno == EINTR {
                    continue;
                }
                return Err("getrandom syscall failed");
            }
            offset += ret as usize;
        }
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(|_| "failed to open /dev/urandom")?;
        file.read_exact(dest)
            .map_err(|_| "failed to read from /dev/urandom")?;
        Ok(())
    }

    #[cfg(windows)]
    {
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut u8,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }
        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
        let ret = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                dest.as_mut_ptr(),
                dest.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err("BCryptGenRandom failed")
        }
    }
}

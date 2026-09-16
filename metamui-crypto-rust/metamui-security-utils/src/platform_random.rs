//! Platform-specific secure random number generation
//! 
//! This module provides secure random number generation using
//! platform-specific APIs for maximum security and performance.

/// Error type for platform random operations
#[derive(Debug)]
pub enum PlatformRandomError {
    /// System call failed with the given error code
    SystemCallFailed(i32),
    /// Invalid buffer length provided
    InvalidLength,
    /// Platform not supported for this operation
    NotSupported,
}

impl core::fmt::Display for PlatformRandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SystemCallFailed(code) => write!(f, "System call failed with code: {}", code),
            Self::InvalidLength => write!(f, "Invalid buffer length"),
            Self::NotSupported => write!(f, "Platform not supported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PlatformRandomError {}

/// Fill buffer with cryptographically secure random bytes
pub fn fill_random_bytes(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    if buffer.is_empty() {
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        fill_random_windows(buffer)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        fill_random_linux(buffer)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        fill_random_apple(buffer)
    }

    #[cfg(target_arch = "wasm32")]
    {
        fill_random_wasm(buffer)
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_arch = "wasm32"
    )))]
    {
        Err(PlatformRandomError::NotSupported)
    }
}

/// Windows implementation using BCryptGenRandom
#[cfg(target_os = "windows")]
fn fill_random_windows(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    use winapi::shared::bcrypt::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    use winapi::shared::ntdef::NULL;

    // STATUS_SUCCESS is 0
    const STATUS_SUCCESS: i32 = 0;

    let status = unsafe {
        BCryptGenRandom(
            NULL as *mut _,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(PlatformRandomError::SystemCallFailed(status))
    }
}

/// Linux/Android implementation using getrandom syscall
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_random_linux(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    use libc::{c_void, size_t, ssize_t};

    // getrandom syscall number
    #[cfg(target_arch = "x86_64")]
    const SYS_GETRANDOM: i64 = 318;
    #[cfg(target_arch = "x86")]
    const SYS_GETRANDOM: i32 = 355;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETRANDOM: i64 = 278;
    #[cfg(target_arch = "arm")]
    const SYS_GETRANDOM: i32 = 384;

    const GRND_NONBLOCK: u32 = 0x0001;

    let mut filled = 0;
    while filled < buffer.len() {
        let result = unsafe {
            libc::syscall(
                SYS_GETRANDOM,
                buffer[filled..].as_mut_ptr() as *mut c_void,
                (buffer.len() - filled) as size_t,
                GRND_NONBLOCK,
            ) as ssize_t
        };

        if result < 0 {
            // Bionic (Android) exposes the thread-local errno as `__errno`;
            // glibc/musl (Linux) use `__errno_location`. Both return `*mut c_int`.
            #[cfg(target_os = "android")]
            let errno = unsafe { *libc::__errno() };
            #[cfg(not(target_os = "android"))]
            let errno = unsafe { *libc::__errno_location() };
            
            // EAGAIN means the entropy pool is not initialized yet
            if errno == libc::EAGAIN {
                // Fall back to /dev/urandom
                return fill_random_urandom(&mut buffer[filled..]);
            }
            
            return Err(PlatformRandomError::SystemCallFailed(errno));
        }

        filled += result as usize;
    }

    Ok(())
}

/// Fallback implementation using /dev/urandom
///
/// Through libc rather than `std::fs`: the crate is `no_std`, and this
/// function is compiled on every Linux/Android build, so a `std` import here
/// broke `--no-default-features` on exactly the hosts no macOS check reaches
/// (#215 feature matrix, linux/amd64).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn fill_random_urandom(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    let fd = unsafe { libc::open(b"/dev/urandom\0".as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(PlatformRandomError::SystemCallFailed(-1));
    }
    let mut filled = 0;
    let mut outcome = Ok(());
    while filled < buffer.len() {
        let n = unsafe {
            libc::read(fd, buffer[filled..].as_mut_ptr().cast(), buffer.len() - filled)
        };
        if n > 0 {
            filled += n as usize;
            continue;
        }
        #[cfg(target_os = "android")]
        let errno = unsafe { *libc::__errno() };
        #[cfg(not(target_os = "android"))]
        let errno = unsafe { *libc::__errno_location() };
        // `read_exact` retried EINTR and treated end-of-file as failure; so does this.
        if n < 0 && errno == libc::EINTR {
            continue;
        }
        outcome = Err(PlatformRandomError::SystemCallFailed(-1));
        break;
    }
    unsafe { libc::close(fd) };
    outcome
}

/// macOS/iOS implementation using Security framework
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn fill_random_apple(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    use security_framework::random::SecRandom;
    
    match SecRandom::default().copy_bytes(buffer) {
        Ok(()) => Ok(()),
        Err(_) => Err(PlatformRandomError::SystemCallFailed(-1)),
    }
}

/// WebAssembly implementation, delegating the backend choice to `getrandom`.
///
/// This used to call `crypto.getRandomValues` through `wasm-bindgen`/`web-sys`
/// directly, which hard-wired a browser environment into every wasm32
/// consumer of this crate — the `js` feature and the generated
/// `__wbindgen_placeholder__` imports came along whether or not the consumer
/// was a browser. `getrandom` already abstracts exactly this choice: browser
/// builds enable its `js` feature and get the same Web Crypto call, while a non-browser wasm32 host
/// supplies its own source via `custom`. Chunking is `getrandom`'s
/// responsibility too — its `js` backend already splits at the Web Crypto
/// 65536-byte limit.
#[cfg(target_arch = "wasm32")]
fn fill_random_wasm(buffer: &mut [u8]) -> Result<(), PlatformRandomError> {
    getrandom::getrandom(buffer).map_err(|e| {
        // `getrandom::Error` carries a NonZeroU32 code; keep it rather than
        // flattening every wasm failure to a single sentinel.
        PlatformRandomError::SystemCallFailed(e.code().get() as i32)
    })
}

/// Generate a random u32
pub fn random_u32() -> Result<u32, PlatformRandomError> {
    let mut bytes = [0u8; 4];
    fill_random_bytes(&mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}

/// Generate a random u64
pub fn random_u64() -> Result<u64, PlatformRandomError> {
    let mut bytes = [0u8; 8];
    fill_random_bytes(&mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

/// Generate a random array
pub fn random_array<const N: usize>() -> Result<[u8; N], PlatformRandomError> {
    let mut array = [0u8; N];
    fill_random_bytes(&mut array)?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random_bytes() {
        let mut buffer = [0u8; 32];
        assert!(fill_random_bytes(&mut buffer).is_ok());
        
        // Check that buffer is not all zeros
        assert!(!buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_u32() {
        let val1 = random_u32().unwrap();
        let val2 = random_u32().unwrap();
        
        // Very unlikely to be equal
        assert_ne!(val1, val2);
    }

    #[test]
    fn test_random_array() {
        let arr1: [u8; 16] = random_array().unwrap();
        let arr2: [u8; 16] = random_array().unwrap();
        
        assert_ne!(arr1, arr2);
    }

    #[test]
    fn test_empty_buffer() {
        let mut buffer = [];
        assert!(fill_random_bytes(&mut buffer).is_ok());
    }

    // The /dev/urandom path runs only when getrandom(2) reports EAGAIN, which
    // no test host produces, so it is called directly.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn test_urandom_fallback_fills_the_whole_buffer() {
        let mut a = [0u8; 4096];
        let mut b = [0u8; 4096];
        fill_random_urandom(&mut a).unwrap();
        fill_random_urandom(&mut b).unwrap();
        assert!(a[4064..].iter().any(|&x| x != 0), "tail of the buffer left unfilled");
        assert_ne!(a, b);
        assert!(fill_random_urandom(&mut []).is_ok());
    }
}
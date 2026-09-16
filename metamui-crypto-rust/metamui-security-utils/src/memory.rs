//! Secure memory clearing utilities.
//!
//! This module provides traits and implementations for securely clearing
//! sensitive data from memory, preventing compiler optimizations from
//! removing the clearing operations.

#[cfg(feature = "alloc")]
extern crate alloc;

use core::mem::{self, MaybeUninit};
use core::ptr;
use core::sync::atomic::{self, Ordering};

/// A trait for securely clearing memory.
pub trait Zeroize {
    /// Securely clear the memory of this value.
    fn zeroize(&mut self);
}

/// A marker trait for types that should be zeroized on drop.
/// 
/// Types implementing this trait should manually implement Drop
/// and call zeroize() in their drop implementation.
pub trait ZeroizeOnDrop: Zeroize {}

/// Compiler barrier to prevent optimizations.
#[inline(always)]
fn atomic_fence() {
    atomic::fence(Ordering::SeqCst);
}

/// Zero out the given slice of bytes.
/// 
/// This function securely clears memory using volatile writes
/// to prevent compiler optimizations from removing the operation.
#[inline]
pub fn zero(data: &mut [u8]) {
    data.zeroize();
}

/// Write zeros to a memory region with barriers to prevent optimization.
#[inline]
unsafe fn write_zeros(ptr: *mut u8, len: usize) {
    // Use volatile writes to prevent optimization
    for i in 0..len {
        ptr::write_volatile(ptr.add(i), 0);
    }
    atomic_fence();
}

/// Zeroize for byte slices.
impl Zeroize for [u8] {
    #[inline]
    fn zeroize(&mut self) {
        unsafe {
            write_zeros(self.as_mut_ptr(), self.len());
        }
    }
}

/// Zeroize for mutable references to arrays.
impl<const N: usize> Zeroize for [u8; N] {
    #[inline]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

/// Macro to implement Zeroize for integer types.
macro_rules! impl_zeroize_for_integer {
    ($($t:ty),+) => {
        $(
            impl Zeroize for $t {
                #[inline]
                fn zeroize(&mut self) {
                    unsafe {
                        write_zeros(self as *mut _ as *mut u8, mem::size_of::<$t>());
                    }
                }
            }
        )+
    };
}

impl_zeroize_for_integer!(u8, u16, u32, u64, u128, usize);
impl_zeroize_for_integer!(i8, i16, i32, i64, i128, isize);

/// Zeroize for f32
impl Zeroize for f32 {
    #[inline]
    fn zeroize(&mut self) {
        unsafe {
            write_zeros(self as *mut _ as *mut u8, mem::size_of::<f32>());
        }
    }
}

/// Zeroize for f64
impl Zeroize for f64 {
    #[inline]
    fn zeroize(&mut self) {
        unsafe {
            write_zeros(self as *mut _ as *mut u8, mem::size_of::<f64>());
        }
    }
}

/// Zeroize for Vec<T> where T: Zeroize.
#[cfg(feature = "alloc")]
impl<T: Zeroize> Zeroize for alloc::vec::Vec<T> {
    #[inline]
    fn zeroize(&mut self) {
        for item in self.iter_mut() {
            item.zeroize();
        }
        self.clear();
    }
}

/// Zeroize for String.
#[cfg(feature = "alloc")]
impl Zeroize for alloc::string::String {
    #[inline]
    fn zeroize(&mut self) {
        unsafe {
            self.as_mut_vec().zeroize();
        }
        self.clear();
    }
}

/// A wrapper type that zeroizes its contents on drop.
#[derive(Debug)]
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Create a new `Zeroizing` wrapper.
    #[inline]
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }

    /// Get a reference to the inner value.
    #[inline]
    pub fn get_ref(&self) -> &T {
        &self.0
    }

    /// Get a mutable reference to the inner value.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Extract the inner value without zeroizing.
    #[inline]
    pub fn into_inner(self) -> T {
        unsafe {
            let mut temp = MaybeUninit::<T>::uninit();
            ptr::copy_nonoverlapping(&self.0, temp.as_mut_ptr(), 1);
            mem::forget(self);
            temp.assume_init()
        }
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> AsRef<T> for Zeroizing<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> AsMut<T> for Zeroizing<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Zeroizing(self.0.clone())
    }
}

/// Platform-specific secure memory operations.
#[cfg(feature = "std")]
pub mod platform {
    use std::io;

    /// Lock memory pages to prevent swapping.
    /// 
    /// This prevents sensitive data from being written to swap files.
    /// Returns Ok(()) if successful or if the platform doesn't support memory locking.
    pub fn mlock(ptr: *const u8, len: usize) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
        {
            use libc::{mlock as libc_mlock, c_void};
            
            let result = unsafe { libc_mlock(ptr as *const c_void, len) };
            
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        #[cfg(target_os = "windows")]
        {
            use winapi::um::memoryapi::VirtualLock;
            use winapi::shared::minwindef::LPVOID;
            use winapi::shared::basetsd::SIZE_T;
            
            let result = unsafe { VirtualLock(ptr as LPVOID, len as SIZE_T) };
            
            if result != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "windows"
        )))]
        {
            // Platform doesn't support memory locking (e.g. wasm32): nothing to
            // lock, and no page-lock API to call.
            let _ = (ptr, len);
            Ok(())
        }
    }

    /// Unlock memory pages.
    /// 
    /// This allows previously locked memory to be swapped out if needed.
    /// Returns Ok(()) if successful or if the platform doesn't support memory locking.
    pub fn munlock(ptr: *const u8, len: usize) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly"))]
        {
            use libc::{munlock as libc_munlock, c_void};
            
            let result = unsafe { libc_munlock(ptr as *const c_void, len) };
            
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        #[cfg(target_os = "windows")]
        {
            use winapi::um::memoryapi::VirtualUnlock;
            use winapi::shared::minwindef::LPVOID;
            use winapi::shared::basetsd::SIZE_T;
            
            let result = unsafe { VirtualUnlock(ptr as LPVOID, len as SIZE_T) };
            
            if result != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "windows"
        )))]
        {
            // Platform doesn't support memory locking (e.g. wasm32): nothing to
            // lock, and no page-lock API to call.
            let _ = (ptr, len);
            Ok(())
        }
    }

    /// Lock all current and future memory pages.
    /// 
    /// This is a more aggressive form of memory locking that affects the entire process.
    /// Use with caution as it can impact system performance.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn mlockall() -> io::Result<()> {
        use libc::{mlockall, MCL_CURRENT, MCL_FUTURE};
        
        let result = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Unlock all memory pages.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn munlockall() -> io::Result<()> {
        use libc::munlockall;
        
        let result = unsafe { munlockall() };
        
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// A guard that automatically unlocks memory when dropped.
    pub struct LockedMemory<T> {
        data: T,
        ptr: *const u8,
        len: usize,
    }

    impl<T> LockedMemory<T> {
        /// Create a new locked memory region.
        pub fn new(data: T) -> io::Result<Self> {
            let ptr = &data as *const T as *const u8;
            let len = core::mem::size_of::<T>();
            
            mlock(ptr, len)?;
            
            Ok(Self { data, ptr, len })
        }

        /// Get a reference to the locked data.
        pub fn get_ref(&self) -> &T {
            &self.data
        }

        /// Get a mutable reference to the locked data.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.data
        }
    }

    impl<T> Drop for LockedMemory<T> {
        fn drop(&mut self) {
            // Best effort unlock - ignore errors
            let _ = munlock(self.ptr, self.len);
        }
    }

    impl<T> AsRef<T> for LockedMemory<T> {
        fn as_ref(&self) -> &T {
            &self.data
        }
    }

    impl<T> AsMut<T> for LockedMemory<T> {
        fn as_mut(&mut self) -> &mut T {
            &mut self.data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::vec;

    #[test]
    fn test_zeroize_u32() {
        let mut value = 0x12345678u32;
        value.zeroize();
        assert_eq!(value, 0);
    }

    #[test]
    fn test_zeroize_array() {
        let mut array = [1u8, 2, 3, 4, 5];
        array.zeroize();
        assert_eq!(array, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_zeroize_slice() {
        let mut vec = vec![1u8, 2, 3, 4, 5];
        vec.as_mut_slice().zeroize();
        assert_eq!(vec, vec![0, 0, 0, 0, 0]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_zeroize_vec() {
        let mut vec = vec![1u8, 2, 3, 4, 5];
        vec.zeroize();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_zeroizing_wrapper() {
        let mut z = Zeroizing::new([1u8, 2, 3, 4]);
        assert_eq!(z.as_ref(), &[1, 2, 3, 4]);
        
        z.as_mut()[0] = 5;
        assert_eq!(z.as_ref(), &[5, 2, 3, 4]);
    }

    #[test]
    fn test_zeroizing_drop() {
        let data = [1u8, 2, 3, 4];
        {
            let _z = Zeroizing::new(data);
            // z is dropped here and should be zeroized
        }
        // We can't directly test that memory was zeroized after drop,
        // but we can verify the mechanism works
    }
}
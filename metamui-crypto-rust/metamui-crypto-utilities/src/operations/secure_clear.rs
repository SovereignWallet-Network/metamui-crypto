/// Secure memory clearing utilities

use metamui_security_utils::Zeroize;
use core::sync::atomic::{compiler_fence, Ordering};


/// Secure memory clearing utility
pub struct Clear;

impl Clear {
    /// Clear sensitive data from memory
    pub fn clear<T: Zeroize>(data: &mut T) {
        // Use zeroize which handles compiler optimization barriers
        data.zeroize();
        
        // Additional compiler fence to prevent reordering
        compiler_fence(Ordering::SeqCst);
    }
    
    /// Clear a byte slice
    pub fn clear_bytes(bytes: &mut [u8]) {
        bytes.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
    
    /// Clear on drop wrapper
    pub fn clear_on_drop<T: Zeroize>(data: T) -> ClearOnDrop<T> {
        ClearOnDrop(data)
    }
}

/// Wrapper that clears data on drop
pub struct ClearOnDrop<T: Zeroize>(T);

impl<T: Zeroize> ClearOnDrop<T> {
    /// Get a reference to the inner value
    pub fn inner(&self) -> &T {
        &self.0
    }
    
    /// Get a mutable reference to the inner value
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
    
    /// Consume and return the inner value (without clearing)
    pub fn into_inner(self) -> T {
        let this = core::mem::ManuallyDrop::new(self);
        // Safety: We're moving out of ManuallyDrop which prevents drop from running
        unsafe { core::ptr::read(&this.0) }
    }
}

impl<T: Zeroize> Drop for ClearOnDrop<T> {
    fn drop(&mut self) {
        self.0.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize + Clone> Clone for ClearOnDrop<T> {
    fn clone(&self) -> Self {
        ClearOnDrop(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_clear_bytes() {
        let mut data = vec![1, 2, 3, 4, 5];
        Clear::clear_bytes(&mut data);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }
    
    #[test]
    fn test_clear_on_drop() {
        let secret = vec![1, 2, 3, 4, 5];
        {
            let _wrapped = Clear::clear_on_drop(secret.clone());
            // Data should be cleared when wrapped goes out of scope
        }
        // Can't easily test the clearing happened, but at least test the API
    }
    
    #[test]
    fn test_clear_on_drop_access() {
        let mut wrapped = Clear::clear_on_drop(vec![1, 2, 3]);
        assert_eq!(wrapped.inner(), &vec![1, 2, 3]);
        
        wrapped.inner_mut().push(4);
        assert_eq!(wrapped.inner(), &vec![1, 2, 3, 4]);
    }
    
    #[test]
    fn test_into_inner() {
        let wrapped = Clear::clear_on_drop(vec![1, 2, 3]);
        let inner = wrapped.into_inner();
        assert_eq!(inner, vec![1, 2, 3]);
        // inner won't be cleared since we called into_inner
    }
}
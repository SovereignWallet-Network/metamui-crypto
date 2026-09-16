//! Constant-time operations for cryptographic security

use metamui_security_utils::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time operations utility
pub struct ConstantTime;

impl ConstantTime {
    /// Compare two byte slices in constant time
    pub fn compare(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }
    
    /// Select between two values based on a condition (constant time)
    pub fn select<T: ConditionallySelectable>(condition: bool, a: T, b: T) -> T {
        T::conditional_select(&a, &b, Choice::from(condition as u8))
    }
    
    /// Check if a value is zero in constant time
    pub fn is_zero(bytes: &[u8]) -> bool {
        let mut acc = 0u8;
        for &byte in bytes {
            acc |= byte;
        }
        acc == 0
    }
    
    /// Compare two u32 values in constant time
    pub fn compare_u32(a: u32, b: u32) -> bool {
        a.ct_eq(&b).into()
    }
    
    /// Less than comparison in constant time
    pub fn less_than(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut borrow = 0u16;
        let mut result = 0u8;
        
        // Compare from least significant byte (little-endian)
        for i in 0..a.len() {
            let ai = a[i] as u16;
            let bi = b[i] as u16;
            let diff = ai.wrapping_sub(bi).wrapping_sub(borrow);
            borrow = (diff >> 8) & 1;
            result |= (diff & 0xFF) as u8;
        }
        
        // If there's a borrow at the end, a < b
        borrow == 1 && result != 0
    }
    
    /// Conditional swap in constant time
    pub fn conditional_swap<T: ConditionallySelectable>(condition: bool, a: &mut T, b: &mut T) {
        let choice = Choice::from(condition as u8);
        T::conditional_swap(a, b, choice);
    }
    
    /// XOR two byte arrays in constant time
    pub fn xor(a: &mut [u8], b: &[u8]) {
        assert_eq!(a.len(), b.len(), "Arrays must have the same length");
        for (ai, bi) in a.iter_mut().zip(b.iter()) {
            *ai ^= bi;
        }
    }
    
    /// Increment a counter in constant time (little-endian)
    pub fn increment_counter_le(counter: &mut [u8]) {
        let mut carry = 1u16;
        for byte in counter.iter_mut() {
            let sum = (*byte as u16) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_time_compare() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";
        
        assert!(ConstantTime::compare(a, b));
        assert!(!ConstantTime::compare(a, c));
    }
    
    #[test]
    fn test_constant_time_select() {
        let a = 42u32;
        let b = 84u32;
        
        assert_eq!(ConstantTime::select(true, a, b), a);
        assert_eq!(ConstantTime::select(false, a, b), b);
    }
    
    #[test]
    fn test_is_zero() {
        assert!(ConstantTime::is_zero(&[0, 0, 0, 0]));
        assert!(!ConstantTime::is_zero(&[0, 0, 1, 0]));
        assert!(!ConstantTime::is_zero(&[1, 2, 3, 4]));
    }
    
    #[test]
    fn test_less_than() {
        // Test with same length arrays
        let a = [1, 2, 3, 4]; // 0x04030201 in little-endian
        let b = [1, 2, 3, 5]; // 0x05030201 in little-endian
        assert!(ConstantTime::less_than(&a, &b));
        assert!(!ConstantTime::less_than(&b, &a));
        
        // Test equal values
        let c = [1, 2, 3, 4];
        assert!(!ConstantTime::less_than(&a, &c));
    }
    
    #[test]
    fn test_xor() {
        let mut a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        ConstantTime::xor(&mut a, &b);
        assert_eq!(a, [4, 4, 4, 12]); // 1^5=4, 2^6=4, 3^7=4, 4^8=12
    }
    
    #[test]
    fn test_increment_counter() {
        let mut counter = [255, 0, 0, 0]; // 255 in little-endian
        ConstantTime::increment_counter_le(&mut counter);
        assert_eq!(counter, [0, 1, 0, 0]); // 256 in little-endian
        
        let mut counter2 = [255, 255, 0, 0]; // 65535 in little-endian
        ConstantTime::increment_counter_le(&mut counter2);
        assert_eq!(counter2, [0, 0, 1, 0]); // 65536 in little-endian
    }
}
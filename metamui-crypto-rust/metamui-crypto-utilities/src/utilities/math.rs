/// Mathematical utilities for cryptographic operations

/// Mathematical operations
pub struct Math;

impl Math {
    /// Modular addition with overflow protection
    pub fn mod_add(a: u64, b: u64, modulus: u64) -> u64 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= modulus {
            sum.wrapping_sub(modulus)
        } else {
            sum
        }
    }
    
    /// Modular subtraction
    pub fn mod_sub(a: u64, b: u64, modulus: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            modulus - (b - a)
        }
    }
    
    /// Modular multiplication using Montgomery reduction for large moduli
    pub fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
        ((a as u128 * b as u128) % modulus as u128) as u64
    }
    
    /// Modular exponentiation using square-and-multiply
    pub fn mod_exp(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        if modulus == 1 {
            return 0;
        }
        
        let mut result = 1u64;
        base %= modulus;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = Self::mod_mul(result, base, modulus);
            }
            exp >>= 1;
            base = Self::mod_mul(base, base, modulus);
        }
        
        result
    }
    
    /// Greatest common divisor using Euclidean algorithm
    pub fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let temp = b;
            b = a % b;
            a = temp;
        }
        a
    }
    
    /// Extended Euclidean algorithm
    /// Returns (gcd, x, y) such that a*x + b*y = gcd
    pub fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
        if b == 0 {
            return (a, 1, 0);
        }
        
        let (gcd, x1, y1) = Self::extended_gcd(b, a % b);
        let x = y1;
        let y = x1 - (a / b) * y1;
        
        (gcd, x, y)
    }
    
    /// Modular inverse using extended Euclidean algorithm
    pub fn mod_inverse(a: u64, modulus: u64) -> Option<u64> {
        let (gcd, x, _) = Self::extended_gcd(a as i64, modulus as i64);
        
        if gcd != 1 {
            None
        } else {
            let inv = if x < 0 {
                (x + modulus as i64) as u64
            } else {
                x as u64
            };
            Some(inv)
        }
    }
    
    /// Check if a number is prime (simple trial division)
    pub fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        if n == 2 {
            return true;
        }
        if n % 2 == 0 {
            return false;
        }
        
        let sqrt_n = (n as f64).sqrt() as u64;
        for i in (3..=sqrt_n).step_by(2) {
            if n % i == 0 {
                return false;
            }
        }
        
        true
    }
    
    /// Next prime number
    pub fn next_prime(mut n: u64) -> u64 {
        if n < 2 {
            return 2;
        }
        
        if n % 2 == 0 {
            n += 1;
        } else {
            n += 2;
        }
        
        while !Self::is_prime(n) {
            n += 2;
        }
        
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mod_arithmetic() {
        let modulus = 17;
        
        // Test modular addition
        assert_eq!(Math::mod_add(10, 8, modulus), 1); // 18 % 17 = 1
        assert_eq!(Math::mod_add(15, 15, modulus), 13); // 30 % 17 = 13
        
        // Test modular subtraction
        assert_eq!(Math::mod_sub(10, 5, modulus), 5);
        assert_eq!(Math::mod_sub(5, 10, modulus), 12); // -5 % 17 = 12
        
        // Test modular multiplication
        assert_eq!(Math::mod_mul(5, 7, modulus), 1); // 35 % 17 = 1
        assert_eq!(Math::mod_mul(12, 13, modulus), 3); // 156 % 17 = 3
    }
    
    #[test]
    fn test_mod_exp() {
        assert_eq!(Math::mod_exp(3, 5, 13), 9); // 3^5 % 13 = 243 % 13 = 9
        assert_eq!(Math::mod_exp(2, 10, 1000), 24); // 2^10 % 1000 = 1024 % 1000 = 24
        assert_eq!(Math::mod_exp(5, 0, 13), 1); // 5^0 = 1
    }
    
    #[test]
    fn test_gcd() {
        assert_eq!(Math::gcd(48, 18), 6);
        assert_eq!(Math::gcd(100, 35), 5);
        assert_eq!(Math::gcd(17, 13), 1);
        assert_eq!(Math::gcd(0, 5), 5);
    }
    
    #[test]
    fn test_extended_gcd() {
        let (gcd, x, y) = Math::extended_gcd(35, 15);
        assert_eq!(gcd, 5);
        assert_eq!(35 * x + 15 * y, 5);
        
        let (gcd2, x2, y2) = Math::extended_gcd(17, 13);
        assert_eq!(gcd2, 1);
        assert_eq!(17 * x2 + 13 * y2, 1);
    }
    
    #[test]
    fn test_mod_inverse() {
        assert_eq!(Math::mod_inverse(3, 11), Some(4)); // 3 * 4 % 11 = 1
        assert_eq!(Math::mod_inverse(5, 17), Some(7)); // 5 * 7 % 17 = 1
        assert_eq!(Math::mod_inverse(6, 12), None); // gcd(6, 12) = 6 != 1
    }
    
    #[test]
    fn test_is_prime() {
        assert!(!Math::is_prime(0));
        assert!(!Math::is_prime(1));
        assert!(Math::is_prime(2));
        assert!(Math::is_prime(3));
        assert!(!Math::is_prime(4));
        assert!(Math::is_prime(5));
        assert!(Math::is_prime(17));
        assert!(!Math::is_prime(100));
        assert!(Math::is_prime(101));
    }
    
    #[test]
    fn test_next_prime() {
        assert_eq!(Math::next_prime(0), 2);
        assert_eq!(Math::next_prime(2), 3);
        assert_eq!(Math::next_prime(3), 5);
        assert_eq!(Math::next_prime(4), 5);
        assert_eq!(Math::next_prime(14), 17);
        assert_eq!(Math::next_prime(100), 101);
    }
}
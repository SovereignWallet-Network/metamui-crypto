use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};


/// Mathematical utilities for cryptographic operations
pub struct MathUtil;

impl MathUtil {
    /// Modular exponentiation: (base^exp) mod modulus
    pub fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        base.modpow(exp, modulus)
    }

    /// Modular multiplication: (a * b) mod modulus
    pub fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
        (a * b) % modulus
    }

    /// Modular addition: (a + b) mod modulus
    pub fn mod_add(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
        (a + b) % modulus
    }

    /// Modular subtraction: (a - b) mod modulus
    pub fn mod_sub(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
        if a >= b {
            (a - b) % modulus
        } else {
            // Handle negative result by adding modulus
            let diff = b - a;
            modulus - (diff % modulus)
        }
    }

    /// Modular inverse using extended Euclidean algorithm
    pub fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
        let a_signed = a.to_bigint().unwrap();
        let m_signed = modulus.to_bigint().unwrap();
        
        let (gcd, x, _) = Self::extended_gcd(&a_signed, &m_signed);
        
        if gcd != BigInt::one() {
            // No inverse exists if gcd != 1
            return None;
        }
        
        // Ensure positive result
        let result = if x < BigInt::zero() {
            x + &m_signed
        } else {
            x
        };
        
        Some(result.to_biguint().unwrap())
    }

    /// Extended Euclidean algorithm
    /// Returns (gcd, x, y) such that ax + by = gcd(a, b)
    pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a.clone(), BigInt::one(), BigInt::zero());
        }
        
        let (gcd, x1, y1) = Self::extended_gcd(b, &(a % b));
        let x = y1.clone();
        let y = x1 - (a / b) * y1;
        
        (gcd, x, y)
    }

    /// Greatest common divisor
    pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
        let mut a = a.clone();
        let mut b = b.clone();
        
        while !b.is_zero() {
            let temp = b.clone();
            b = a % &b;
            a = temp;
        }
        
        a
    }

    /// Least common multiple
    pub fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
        if a.is_zero() || b.is_zero() {
            return BigUint::zero();
        }
        (a * b) / Self::gcd(a, b)
    }

    /// Miller-Rabin primality test
    pub fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
        if n <= &BigUint::from(1u32) {
            return false;
        }
        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return true;
        }
        if n.bit(0) == false {  // Even number
            return false;
        }

        // Write n-1 as 2^r * d
        let n_minus_1 = n - BigUint::one();
        let mut r = 0;
        let mut d = n_minus_1.clone();
        
        while d.bit(0) == false {
            d >>= 1;
            r += 1;
        }

        let _counter = 42u64;
        
        'witness: for _ in 0..rounds {
            // Pick a random witness
            let a = Self::random_biguint_range(&BigUint::from(2u32), &n_minus_1);
            
            let mut x = Self::mod_pow(&a, &d, n);
            
            if x == BigUint::one() || x == n_minus_1 {
                continue 'witness;
            }
            
            for _ in 0..r - 1 {
                x = Self::mod_mul(&x, &x, n);
                if x == n_minus_1 {
                    continue 'witness;
                }
            }
            
            return false;
        }
        
        true
    }

    /// Generate random BigUint in range [min, max)
    pub fn random_biguint_range(min: &BigUint, max: &BigUint) -> BigUint {
        if min >= max {
            return min.clone();
        }
        
        let range = max - min;
        let bits = range.bits();
        let _counter = 42u64;
        
        loop {
            let mut bytes = vec![0u8; ((bits + 7) / 8) as usize];
            getrandom::getrandom(&mut bytes[..]).expect("OS random source unavailable");
            
            let candidate = BigUint::from_bytes_be(&bytes);
            let result = min + (candidate % &range);
            
            if &result < max {
                return result;
            }
        }
    }

    /// Generate random BigUint with specified number of bits
    pub fn random_biguint(bits: usize) -> BigUint {
        let bytes = (bits + 7) / 8;
        let mut data = vec![0u8; bytes];
        getrandom::getrandom(&mut data[..]).expect("OS random source unavailable");
        
        // Clear excess bits
        if bits % 8 != 0 {
            let mask = (1u8 << (bits % 8)) - 1;
            data[0] &= mask;
        }
        
        // Set the high bit to ensure the number has the desired bit length
        if bits > 0 {
            let byte_index = (bits - 1) / 8;
            let bit_index = (bits - 1) % 8;
            data[bytes - 1 - byte_index] |= 1u8 << bit_index;
        }
        
        BigUint::from_bytes_be(&data)
    }

    /// Integer square root
    pub fn isqrt(n: &BigUint) -> BigUint {
        if n.is_zero() {
            return BigUint::zero();
        }
        
        // Newton's method
        let mut x = n.clone();
        let mut y: BigUint = (x.clone() + BigUint::one()) >> 1;
        
        while y < x {
            x = y.clone();
            y = (&x + n / &x) >> 1;
        }
        
        x
    }

    /// Factorial
    pub fn factorial(n: u32) -> BigUint {
        if n == 0 || n == 1 {
            return BigUint::one();
        }
        
        let mut result = BigUint::one();
        for i in 2..=n {
            result *= i;
        }
        result
    }

    /// Binomial coefficient (n choose k)
    pub fn binomial(n: u32, k: u32) -> BigUint {
        if k > n {
            return BigUint::zero();
        }
        if k == 0 || k == n {
            return BigUint::one();
        }
        
        let k = k.min(n - k); // Take advantage of symmetry
        
        let mut result = BigUint::one();
        for i in 0..k {
            result = result * (n - i) / (i + 1);
        }
        result
    }

    /// Check if a number is a perfect square
    pub fn is_perfect_square(n: &BigUint) -> bool {
        let sqrt = Self::isqrt(n);
        &sqrt * &sqrt == *n
    }

    /// Compute Euler's totient function φ(n)
    pub fn euler_totient(n: &BigUint) -> BigUint {
        if n.is_zero() || n == &BigUint::one() {
            return n.clone();
        }
        
        let mut result = n.clone();
        let mut temp = n.clone();
        let two = BigUint::from(2u32);
        
        // Check for factor 2
        if (&temp & &BigUint::one()).is_zero() {
            result -= &result / &two;
            while (&temp & &BigUint::one()).is_zero() {
                temp >>= 1;
            }
        }
        
        // Check odd factors
        let mut i = BigUint::from(3u32);
        while &i * &i <= temp {
            if (&temp % &i).is_zero() {
                result -= &result / &i;
                while (&temp % &i).is_zero() {
                    temp /= &i;
                }
            }
            i += &two;
        }
        
        // If temp > 1, then it's a prime factor
        if temp > BigUint::one() {
            result -= &result / &temp;
        }
        
        result
    }

    /// Chinese Remainder Theorem
    /// Solves the system of congruences: x ≡ remainders[i] (mod moduli[i])
    pub fn chinese_remainder_theorem(
        remainders: &[BigUint], 
        moduli: &[BigUint]
    ) -> Option<BigUint> {
        if remainders.len() != moduli.len() || remainders.is_empty() {
            return None;
        }
        
        // Check that all moduli are pairwise coprime
        for i in 0..moduli.len() {
            for j in i + 1..moduli.len() {
                if Self::gcd(&moduli[i], &moduli[j]) != BigUint::one() {
                    return None;
                }
            }
        }
        
        let big_m: BigUint = moduli.iter().product();
        let mut result = BigUint::zero();
        
        for i in 0..remainders.len() {
            let mi = &big_m / &moduli[i];
            let mi_inv = Self::mod_inverse(&mi, &moduli[i])?;
            result = Self::mod_add(
                &result,
                &Self::mod_mul(&Self::mod_mul(&remainders[i], &mi, &big_m), &mi_inv, &big_m),
                &big_m
            );
        }
        
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_pow() {
        let base = BigUint::from(2u32);
        let exp = BigUint::from(10u32);
        let modulus = BigUint::from(1000u32);
        let result = MathUtil::mod_pow(&base, &exp, &modulus);
        assert_eq!(result, BigUint::from(24u32)); // 2^10 % 1000 = 1024 % 1000 = 24
    }

    #[test]
    fn test_gcd() {
        let a = BigUint::from(48u32);
        let b = BigUint::from(18u32);
        assert_eq!(MathUtil::gcd(&a, &b), BigUint::from(6u32));
    }

    #[test]
    fn test_lcm() {
        let a = BigUint::from(12u32);
        let b = BigUint::from(18u32);
        assert_eq!(MathUtil::lcm(&a, &b), BigUint::from(36u32));
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(7u32);
        let m = BigUint::from(26u32);
        let inv = MathUtil::mod_inverse(&a, &m).unwrap();
        assert_eq!(MathUtil::mod_mul(&a, &inv, &m), BigUint::one());
    }

    #[test]
    fn test_is_probably_prime() {
        assert!(MathUtil::is_probably_prime(&BigUint::from(2u32), 10));
        assert!(MathUtil::is_probably_prime(&BigUint::from(17u32), 10));
        assert!(MathUtil::is_probably_prime(&BigUint::from(97u32), 10));
        assert!(!MathUtil::is_probably_prime(&BigUint::from(4u32), 10));
        assert!(!MathUtil::is_probably_prime(&BigUint::from(91u32), 10)); // 7 * 13
    }

    #[test]
    fn test_factorial() {
        assert_eq!(MathUtil::factorial(0), BigUint::one());
        assert_eq!(MathUtil::factorial(5), BigUint::from(120u32));
        assert_eq!(MathUtil::factorial(10), BigUint::from(3628800u32));
    }

    #[test]
    fn test_binomial() {
        assert_eq!(MathUtil::binomial(5, 2), BigUint::from(10u32));
        assert_eq!(MathUtil::binomial(10, 3), BigUint::from(120u32));
        assert_eq!(MathUtil::binomial(6, 0), BigUint::one());
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(MathUtil::isqrt(&BigUint::from(16u32)), BigUint::from(4u32));
        assert_eq!(MathUtil::isqrt(&BigUint::from(17u32)), BigUint::from(4u32));
        assert_eq!(MathUtil::isqrt(&BigUint::from(25u32)), BigUint::from(5u32));
    }
}
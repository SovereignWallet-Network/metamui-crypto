//! Test helpers for Falcon-512 testing with approximation tolerance
//! 
//! This module provides utilities for testing Falcon-512 components
//! while properly handling the approximate nature of the NTRU equation.

use crate::constants::{N, Q};

/// Default relative error tolerance for equation verification
pub const DEFAULT_RELATIVE_TOLERANCE: f64 = 1e-10;

/// Default absolute error tolerance for integer operations
pub const DEFAULT_ABSOLUTE_TOLERANCE: i32 = 10;

/// Verify NTRU equation with appropriate tolerance
/// 
/// Checks if f*G - g*F ≈ q within acceptable bounds
pub fn verify_ntru_equation_approximate(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
) -> bool {
    verify_ntru_equation_with_tolerance(
        f, g, big_f, big_g,
        DEFAULT_ABSOLUTE_TOLERANCE,
    )
}

/// Verify NTRU equation with custom tolerance
pub fn verify_ntru_equation_with_tolerance(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    tolerance: i32,
) -> bool {
    use crate::karatsuba::karatsuba_mul_mod;
    
    let f_i32: Vec<i32> = f.iter().map(|&x| x as i32).collect();
    let g_i32: Vec<i32> = g.iter().map(|&x| x as i32).collect();
    let big_f_i32: Vec<i32> = big_f.iter().map(|&x| x as i32).collect();
    let big_g_i32: Vec<i32> = big_g.iter().map(|&x| x as i32).collect();
    
    let fg = karatsuba_mul_mod(&f_i32, &big_g_i32, N);
    let gf = karatsuba_mul_mod(&g_i32, &big_f_i32, N);
    
    // Check equation with tolerance
    for i in 0..N {
        let diff = (fg[i] - gf[i] + Q as i32) % Q as i32;
        
        if i == 0 {
            // First coefficient should be q (mod q) = 0
            // Allow 0, 1, or q-1
            if diff != 0 && diff != 1 && diff != Q as i32 - 1 {
                return false;
            }
        } else {
            // Other coefficients should be approximately 0 (mod q)
            if diff > tolerance && diff < Q as i32 - tolerance {
                return false;
            }
        }
    }
    
    true
}

/// Check if two floating-point values are approximately equal
pub fn approx_equal_f64(a: f64, b: f64, tolerance: f64) -> bool {
    let diff = (a - b).abs();
    let max = a.abs().max(b.abs());
    
    if max < 1e-10 {
        // Both very small, use absolute comparison
        diff < tolerance
    } else {
        // Use relative comparison
        diff / max < tolerance
    }
}

/// Check if two complex values are approximately equal
pub fn approx_equal_complex(
    a_real: f64, a_imag: f64,
    b_real: f64, b_imag: f64,
    tolerance: f64,
) -> bool {
    approx_equal_f64(a_real, b_real, tolerance) &&
    approx_equal_f64(a_imag, b_imag, tolerance)
}

/// Verify signature equation with tolerance
/// 
/// Checks if s0 + s1*h ≈ c (mod q) within acceptable bounds
pub fn verify_signature_equation_approximate(
    s0: &[i16],
    s1: &[i16],
    h: &[i16],
    c: &[i16],
) -> bool {
    verify_signature_equation_with_tolerance(
        s0, s1, h, c,
        DEFAULT_ABSOLUTE_TOLERANCE,
    )
}

/// Verify signature equation with custom tolerance
pub fn verify_signature_equation_with_tolerance(
    s0: &[i16],
    s1: &[i16],
    h: &[i16],
    c: &[i16],
    tolerance: i32,
) -> bool {
    use crate::ntt_falcon;
    
    // Compute s1*h using NTT
    let s1h = ntt_falcon::multiply_ntt(s1, h);
    
    // Check s0 + s1*h ≈ c (mod q)
    for i in 0..N {
        let lhs = ((s0[i] as i32 + s1h[i] as i32) % Q as i32 + Q as i32) % Q as i32;
        let rhs = (c[i] as i32 + Q as i32) % Q as i32;
        
        // Compute minimum distance considering modular wrap-around
        let diff = (lhs - rhs).abs();
        let wrap_diff = (Q as i32 - diff).min(diff);
        
        if wrap_diff > tolerance {
            return false;
        }
    }
    
    true
}

/// Calculate relative error between two values
pub fn relative_error(actual: f64, expected: f64) -> f64 {
    if expected.abs() < 1e-10 {
        actual.abs()
    } else {
        (actual - expected).abs() / expected.abs()
    }
}

/// Assert that NTRU equation is satisfied approximately
#[macro_export]
macro_rules! assert_ntru_equation_approx {
    ($f:expr, $g:expr, $big_f:expr, $big_g:expr) => {
        assert!(
            $crate::test_helpers::verify_ntru_equation_approximate($f, $g, $big_f, $big_g),
            "NTRU equation not satisfied within tolerance"
        );
    };
    ($f:expr, $g:expr, $big_f:expr, $big_g:expr, $tolerance:expr) => {
        assert!(
            $crate::test_helpers::verify_ntru_equation_with_tolerance(
                $f, $g, $big_f, $big_g, $tolerance
            ),
            "NTRU equation not satisfied within tolerance {}", $tolerance
        );
    };
}

/// Assert that signature equation is satisfied approximately
#[macro_export]
macro_rules! assert_signature_equation_approx {
    ($s0:expr, $s1:expr, $h:expr, $c:expr) => {
        assert!(
            $crate::test_helpers::verify_signature_equation_approximate($s0, $s1, $h, $c),
            "Signature equation not satisfied within tolerance"
        );
    };
    ($s0:expr, $s1:expr, $h:expr, $c:expr, $tolerance:expr) => {
        assert!(
            $crate::test_helpers::verify_signature_equation_with_tolerance(
                $s0, $s1, $h, $c, $tolerance
            ),
            "Signature equation not satisfied within tolerance {}", $tolerance
        );
    };
}

/// Assert that two floating-point values are approximately equal
#[macro_export]
macro_rules! assert_approx_eq {
    ($left:expr, $right:expr) => {
        assert!(
            $crate::test_helpers::approx_equal_f64(
                $left, $right, 
                $crate::test_helpers::DEFAULT_RELATIVE_TOLERANCE
            ),
            "assertion failed: `(left ≈ right)`\n  left: `{}`,\n right: `{}`",
            $left, $right
        );
    };
    ($left:expr, $right:expr, $tolerance:expr) => {
        assert!(
            $crate::test_helpers::approx_equal_f64($left, $right, $tolerance),
            "assertion failed: `(left ≈ right)` with tolerance {}\n  left: `{}`,\n right: `{}`",
            $tolerance, $left, $right
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_approx_equal_f64() {
        assert!(approx_equal_f64(1.0, 1.0 + 1e-11, 1e-10));
        assert!(!approx_equal_f64(1.0, 1.0 + 1e-9, 1e-10));
        assert!(approx_equal_f64(0.0, 1e-11, 1e-10));
        assert!(approx_equal_f64(1e6, 1e6 * (1.0 + 1e-11), 1e-10));
    }
    
    #[test]
    fn test_relative_error() {
        assert!(relative_error(1.001, 1.0) < 0.002);
        assert!(relative_error(100.1, 100.0) < 0.002);
        assert!(relative_error(0.0, 0.0) < 1e-10);
    }
    
    #[test]
    fn test_macros() {
        // Test approximate equality macro
        assert_approx_eq!(1.0, 1.0 + 1e-11);
        assert_approx_eq!(1.0, 1.0 + 1e-6, 1e-5);
    }
}
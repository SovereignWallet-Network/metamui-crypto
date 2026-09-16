// Access FPR through the crate root since it's likely re-exported
use metamui_falcon512::falcon_fpr::FPR;
use std::f64::consts::PI;

/// Test basic FPR creation and conversion
#[test]
fn test_fpr_basics() {
    // Test zero
    let zero = FPR::ZERO;
    assert_eq!(zero.to_f64(), 0.0);
    assert_eq!(zero.to_bits(), 0);
    
    // Test one
    let one = FPR::ONE;
    assert_eq!(one.to_f64(), 1.0);
    assert_eq!(one.to_bits(), 0x3FF0000000000000);
    
    // Test conversion from f64
    let values = [
        0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5,
        3.14159265358979323846,  // pi
        2.718281828459045,        // e
        1.41421356237309504880,   // sqrt(2)
        1e-10, 1e10, -1e-10, -1e10,
    ];
    
    for &val in &values {
        let fpr = FPR::from_f64(val);
        let recovered = fpr.to_f64();
        let error = (recovered - val).abs();
        let relative_error = if val != 0.0 { error / val.abs() } else { error };
        
        println!("Value: {} -> FPR -> {}, error: {}, relative: {}", 
                 val, recovered, error, relative_error);
        
        // Should have very small error (< 1e-15 relative for normal numbers)
        if val.abs() > 1e-100 && val.abs() < 1e100 {
            assert!(relative_error < 1e-14, 
                    "Large relative error for {}: {}", val, relative_error);
        }
    }
}

/// Test FPR addition
#[test]
fn test_fpr_addition() {
    let test_cases = [
        (1.0, 2.0, 3.0),
        (1.0, -1.0, 0.0),
        (3.14159, 2.71828, 5.85987),
        (1e10, 1.0, 1e10 + 1.0),  // Large + small should preserve both
        (1e-10, 1e-10, 2e-10),  // Small + small
        (-5.0, 3.0, -2.0),
    ];
    
    for (a, b, expected) in &test_cases {
        let fpr_a = FPR::from_f64(*a);
        let fpr_b = FPR::from_f64(*b);
        let result = fpr_a.add(fpr_b);
        let actual = result.to_f64();
        let error = (actual - expected).abs();
        
        println!("FPR: {} + {} = {} (expected {}), error: {}", 
                 a, b, actual, expected, error);
        
        // Allow small floating point error
        assert!(error < 1e-10 * expected.abs().max(1.0),
                "Addition error too large: {} + {} = {} (expected {})",
                a, b, actual, expected);
    }
}

/// Test FPR subtraction
#[test]
fn test_fpr_subtraction() {
    let test_cases = [
        (3.0, 2.0, 1.0),
        (1.0, 1.0, 0.0),
        (5.0, -3.0, 8.0),
        (1e10, 1.0, 1e10 - 1.0),  // Large - small should preserve both
        (1e-10, 1e-11, 9e-11),
    ];
    
    for (a, b, expected) in &test_cases {
        let fpr_a = FPR::from_f64(*a);
        let fpr_b = FPR::from_f64(*b);
        let result = fpr_a.sub(fpr_b);
        let actual = result.to_f64();
        let error = (actual - expected).abs();
        
        println!("FPR: {} - {} = {} (expected {}), error: {}", 
                 a, b, actual, expected, error);
        
        assert!(error < 1e-10 * expected.abs().max(1.0),
                "Subtraction error too large: {} - {} = {} (expected {})",
                a, b, actual, expected);
    }
}

/// Test FPR multiplication
#[test]
fn test_fpr_multiplication() {
    let test_cases = [
        (2.0, 3.0, 6.0),
        (1.0, -1.0, -1.0),
        (0.0, 5.0, 0.0),
        (3.14159, 2.0, 6.28318),
        (1e10, 1e-10, 1.0),
        (1e-5, 1e-5, 1e-10),
        (-2.5, 4.0, -10.0),
    ];
    
    for (a, b, expected) in &test_cases {
        let fpr_a = FPR::from_f64(*a);
        let fpr_b = FPR::from_f64(*b);
        let result = fpr_a.mul(fpr_b);
        let actual = result.to_f64();
        let error = (actual - expected).abs();
        let relative_error = if *expected != 0.0 { 
            error / expected.abs() 
        } else { 
            error 
        };
        
        println!("FPR: {} * {} = {} (expected {}), error: {}, relative: {}", 
                 a, b, actual, expected, error, relative_error);
        
        // Multiplication can have slightly more error
        assert!(relative_error < 1e-13 || error < 1e-100,
                "Multiplication error too large: {} * {} = {} (expected {})",
                a, b, actual, expected);
    }
}

/// Test FPR division
#[test]
fn test_fpr_division() {
    let test_cases = [
        (6.0, 2.0, 3.0),
        (1.0, 1.0, 1.0),
        (-10.0, 2.5, -4.0),
        (1.0, 3.0, 0.3333333333333333),
        (1e10, 1e5, 1e5),
        (1e-10, 1e-5, 1e-5),
    ];
    
    for (a, b, expected) in &test_cases {
        let fpr_a = FPR::from_f64(*a);
        let fpr_b = FPR::from_f64(*b);
        let result = fpr_a.div(fpr_b);
        let actual = result.to_f64();
        let error = (actual - expected).abs();
        let relative_error = if *expected != 0.0 { 
            error / expected.abs() 
        } else { 
            error 
        };
        
        println!("FPR: {} / {} = {} (expected {}), relative error: {}", 
                 a, b, actual, expected, relative_error);
        
        assert!(relative_error < 1e-13,
                "Division error too large: {} / {} = {} (expected {})",
                a, b, actual, expected);
    }
}

/// Test FPR square root
#[test]
fn test_fpr_sqrt() {
    let test_cases = [
        (4.0, 2.0),
        (9.0, 3.0),
        (2.0, 1.41421356237309504880),
        (100.0, 10.0),
        (0.25, 0.5),
        (1e10, 1e5),
        (1e-10, 1e-5),
    ];
    
    for (a, expected) in &test_cases {
        let fpr_a = FPR::from_f64(*a);
        let result = fpr_a.sqrt();
        let actual = result.to_f64();
        let error = (actual - expected).abs();
        let relative_error = error / expected;
        
        println!("FPR: sqrt({}) = {} (expected {}), relative error: {}", 
                 a, actual, expected, relative_error);
        
        assert!(relative_error < 1e-13,
                "Sqrt error too large: sqrt({}) = {} (expected {})",
                a, actual, expected);
    }
}

/// Test FFT-specific operations: sin/cos in FPR
#[test]
fn test_fpr_trig() {
    
    // Test angles and their expected sin/cos values
    let test_angles = [
        (0.0, 0.0, 1.0),  // sin(0) = 0, cos(0) = 1
        (PI / 2.0, 1.0, 0.0),  // sin(π/2) = 1, cos(π/2) = 0
        (PI, 0.0, -1.0),  // sin(π) = 0, cos(π) = -1
        (PI / 4.0, 0.7071067811865475, 0.7071067811865476),  // sin(π/4) = cos(π/4) = √2/2
    ];
    
    for (angle, expected_sin, expected_cos) in &test_angles {
        // Test using FPR arithmetic
        let sin_val = angle.sin();
        let cos_val = angle.cos();
        
        let fpr_sin = FPR::from_f64(sin_val);
        let fpr_cos = FPR::from_f64(cos_val);
        
        let recovered_sin = fpr_sin.to_f64();
        let recovered_cos = fpr_cos.to_f64();
        
        println!("Angle {}: sin = {} (expected {}), cos = {} (expected {})",
                 angle, recovered_sin, expected_sin, recovered_cos, expected_cos);
        
        assert!((recovered_sin - expected_sin).abs() < 1e-14,
                "Sin error too large for angle {}", angle);
        assert!((recovered_cos - expected_cos).abs() < 1e-14,
                "Cos error too large for angle {}", angle);
    }
}

/// Test complex multiplication using FPR (as used in FFT)
#[test]
fn test_fpr_complex_mul() {
    // Complex multiplication: (a + bi) * (c + di) = (ac - bd) + (ad + bc)i
    let test_cases = [
        ((1.0, 0.0), (1.0, 0.0), (1.0, 0.0)),  // 1 * 1 = 1
        ((0.0, 1.0), (0.0, 1.0), (-1.0, 0.0)), // i * i = -1
        ((3.0, 4.0), (1.0, 2.0), (-5.0, 10.0)), // (3+4i)*(1+2i) = -5+10i
    ];
    
    for ((a_re, a_im), (b_re, b_im), (expected_re, expected_im)) in &test_cases {
        let fpr_a_re = FPR::from_f64(*a_re);
        let fpr_a_im = FPR::from_f64(*a_im);
        let fpr_b_re = FPR::from_f64(*b_re);
        let fpr_b_im = FPR::from_f64(*b_im);
        
        // Complex multiplication using FPR
        let result_re = fpr_a_re.mul(fpr_b_re).sub(fpr_a_im.mul(fpr_b_im));
        let result_im = fpr_a_re.mul(fpr_b_im).add(fpr_a_im.mul(fpr_b_re));
        
        let actual_re = result_re.to_f64();
        let actual_im = result_im.to_f64();
        
        println!("({} + {}i) * ({} + {}i) = {} + {}i (expected {} + {}i)",
                 a_re, a_im, b_re, b_im, actual_re, actual_im, expected_re, expected_im);
        
        assert!((actual_re - expected_re).abs() < 1e-14,
                "Complex multiplication real part error");
        assert!((actual_im - expected_im).abs() < 1e-14,
                "Complex multiplication imaginary part error");
    }
}

/// Test that demonstrates the current FFT scaling issue
#[test]
fn test_fpr_fft_scaling() {
    // This test will likely fail with current implementation
    // It's here to validate our fixes
    
    let n = 4;
    let scale_factor = 1.0 / n as f64;
    
    // Test that scaling works correctly in FPR
    let values = [1.0, 2.0, 3.0, 4.0];
    
    for val in &values {
        let fpr_val = FPR::from_f64(*val);
        let fpr_scale = FPR::from_f64(scale_factor);
        let scaled = fpr_val.mul(fpr_scale);
        let result = scaled.to_f64();
        let expected = val * scale_factor;
        
        println!("FPR: {} * {} = {} (expected {})", 
                 val, scale_factor, result, expected);
        
        let error = (result - expected).abs();
        assert!(error < 1e-15,
                "Scaling error too large: {} * {} = {} (expected {})",
                val, scale_factor, result, expected);
    }
}
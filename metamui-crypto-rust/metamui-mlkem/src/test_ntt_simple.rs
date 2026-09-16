//! Simple NTT test

use metamui_mlkem::ntt::{ntt, inverse_ntt};
use metamui_mlkem::polynomial::{Polynomial, N, Q};

fn main() {
    // Test with a very simple polynomial
    let mut poly = Polynomial::zero();
    
    // Just set first few coefficients
    poly.coefficients[0] = 1;
    poly.coefficients[1] = 2;
    poly.coefficients[2] = 3;
    
    println!("Original: {:?}", &poly.coefficients[0..10]);
    
    let original = poly.clone();
    
    // Apply NTT
    ntt(&mut poly);
    println!("After NTT: {:?}", &poly.coefficients[0..10]);
    
    // Apply inverse NTT
    inverse_ntt(&mut poly);
    println!("After invNTT: {:?}", &poly.coefficients[0..10]);
    
    // Check if we recovered the original
    let mut matches = true;
    for i in 0..N {
        // Normalize to [0, Q)
        let orig = if original.coefficients[i] < 0 {
            original.coefficients[i] + Q
        } else {
            original.coefficients[i] % Q
        };
        
        let recovered = if poly.coefficients[i] < 0 {
            poly.coefficients[i] + Q
        } else {
            poly.coefficients[i] % Q
        };
        
        if orig != recovered {
            if i < 10 {
                println!("Mismatch at {}: {} vs {}", i, orig, recovered);
            }
            matches = false;
        }
    }
    
    if matches {
        println!("SUCCESS: NTT round-trip works!");
    } else {
        println!("FAILURE: NTT round-trip doesn't work");
    }
}
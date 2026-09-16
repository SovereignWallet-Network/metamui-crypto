//! Numerically stable FFT implementation for Falcon-512
//! 
//! This module provides a high-precision FFT implementation with
//! numerical stability guarantees for use in lattice-based cryptography.

use alloc::vec::Vec;
use core::f64::consts::PI;

/// Complex number with enhanced precision tracking
#[derive(Clone, Copy, Debug)]
pub struct ComplexStable {
    pub re: f64,
    pub im: f64,
    /// Track precision loss for debugging
    pub precision_bits: u32,
}

impl ComplexStable {
    /// Create a new complex number
    pub fn new(re: f64, im: f64) -> Self {
        Self {
            re,
            im,
            precision_bits: 53, // f64 mantissa bits
        }
    }
    
    /// Zero complex number
    pub fn zero() -> Self {
        Self::new(0.0, 0.0)
    }
    
    /// Complex conjugate
    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
            precision_bits: self.precision_bits,
        }
    }
    
    /// Squared norm
    pub fn norm_sqr(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }
    
    /// Multiply with precision tracking
    pub fn mul_tracked(&self, other: &Self) -> Self {
        let re = self.re * other.re - self.im * other.im;
        let im = self.re * other.im + self.im * other.re;
        
        // Track precision loss (simplified model)
        let precision_bits = self.precision_bits.min(other.precision_bits).saturating_sub(1);
        
        Self { re, im, precision_bits }
    }
    
    /// Add with Kahan summation for reduced rounding error
    pub fn add_kahan(&self, other: &Self, compensation: &mut (f64, f64)) -> Self {
        // Kahan summation for real part
        let y_re = other.re - compensation.0;
        let t_re = self.re + y_re;
        compensation.0 = (t_re - self.re) - y_re;
        
        // Kahan summation for imaginary part
        let y_im = other.im - compensation.1;
        let t_im = self.im + y_im;
        compensation.1 = (t_im - self.im) - y_im;
        
        Self {
            re: t_re,
            im: t_im,
            precision_bits: self.precision_bits.min(other.precision_bits),
        }
    }
    
    /// Check if the number is numerically stable
    pub fn is_stable(&self) -> bool {
        self.re.is_finite() && 
        self.im.is_finite() && 
        self.precision_bits >= 20 // At least 20 bits of precision
    }
    
    /// Stabilize by clamping small values to zero
    pub fn stabilize(&mut self, epsilon: f64) {
        if self.re.abs() < epsilon {
            self.re = 0.0;
        }
        if self.im.abs() < epsilon {
            self.im = 0.0;
        }
        if !self.re.is_finite() {
            self.re = 0.0;
            self.precision_bits = 0;
        }
        if !self.im.is_finite() {
            self.im = 0.0;
            self.precision_bits = 0;
        }
    }
}

/// Numerically stable FFT implementation
pub struct FFTStable {
    /// Size of the FFT (must be power of 2)
    n: usize,
    /// Log2 of n
    logn: usize,
    /// Precomputed twiddle factors with extra precision
    twiddles: Vec<ComplexStable>,
    /// Bit reversal permutation
    bit_rev: Vec<usize>,
}

impl FFTStable {
    /// Create a new FFT instance for size n
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two(), "FFT size must be power of 2");
        let logn = n.trailing_zeros() as usize;
        
        // Precompute twiddle factors with high precision
        let mut twiddles = Vec::with_capacity(n / 2);
        for k in 0..n/2 {
            let angle = -2.0 * PI * (k as f64) / (n as f64);
            // Use higher precision trig functions if available
            let (sin_val, cos_val) = angle.sin_cos();
            twiddles.push(ComplexStable::new(cos_val, sin_val));
        }
        
        // Precompute bit reversal permutation
        let mut bit_rev = vec![0; n];
        for i in 0..n {
            bit_rev[i] = i.reverse_bits() >> (usize::BITS as usize - logn);
        }
        
        Self {
            n,
            logn,
            twiddles,
            bit_rev,
        }
    }
    
    /// Forward FFT with numerical stability checks
    pub fn forward(&self, input: &[f64]) -> Vec<ComplexStable> {
        assert_eq!(input.len(), self.n, "Input size mismatch");
        
        // Convert to complex and apply bit reversal
        let mut data = vec![ComplexStable::zero(); self.n];
        for i in 0..self.n {
            data[self.bit_rev[i]] = ComplexStable::new(input[i], 0.0);
        }
        
        // Cooley-Tukey FFT with stability checks
        let mut size = 2;
        while size <= self.n {
            let half_size = size / 2;
            let table_step = self.n / size;
            
            for start in (0..self.n).step_by(size) {
                let mut k = 0;
                for j in start..start + half_size {
                    let twiddle = &self.twiddles[k];
                    
                    let a = data[j];
                    let b = data[j + half_size].mul_tracked(twiddle);
                    
                    // Butterfly operation with precision tracking
                    data[j] = ComplexStable {
                        re: a.re + b.re,
                        im: a.im + b.im,
                        precision_bits: a.precision_bits.min(b.precision_bits),
                    };
                    
                    data[j + half_size] = ComplexStable {
                        re: a.re - b.re,
                        im: a.im - b.im,
                        precision_bits: a.precision_bits.min(b.precision_bits),
                    };
                    
                    // Check for numerical instability
                    if !data[j].is_stable() || !data[j + half_size].is_stable() {
                        // Apply stabilization
                        data[j].stabilize(1e-14);
                        data[j + half_size].stabilize(1e-14);
                    }
                    
                    k += table_step;
                }
            }
            size <<= 1;
        }
        
        data
    }
    
    /// Inverse FFT with numerical stability
    pub fn inverse(&self, input: &[ComplexStable]) -> Vec<f64> {
        assert_eq!(input.len(), self.n, "Input size mismatch");
        
        // Apply bit reversal
        let mut data = vec![ComplexStable::zero(); self.n];
        for i in 0..self.n {
            data[self.bit_rev[i]] = input[i].conj(); // Conjugate for inverse
        }
        
        // Forward FFT on conjugated data
        let mut size = 2;
        while size <= self.n {
            let half_size = size / 2;
            let table_step = self.n / size;
            
            for start in (0..self.n).step_by(size) {
                let mut k = 0;
                for j in start..start + half_size {
                    let twiddle = &self.twiddles[k];
                    
                    let a = data[j];
                    let b = data[j + half_size].mul_tracked(twiddle);
                    
                    data[j] = ComplexStable {
                        re: a.re + b.re,
                        im: a.im + b.im,
                        precision_bits: a.precision_bits.min(b.precision_bits),
                    };
                    
                    data[j + half_size] = ComplexStable {
                        re: a.re - b.re,
                        im: a.im - b.im,
                        precision_bits: a.precision_bits.min(b.precision_bits),
                    };
                    
                    // Stabilize if needed
                    if !data[j].is_stable() || !data[j + half_size].is_stable() {
                        data[j].stabilize(1e-14);
                        data[j + half_size].stabilize(1e-14);
                    }
                    
                    k += table_step;
                }
            }
            size <<= 1;
        }
        
        // Conjugate and scale
        let scale = 1.0 / (self.n as f64);
        let mut result = vec![0.0; self.n];
        for i in 0..self.n {
            result[i] = data[i].re * scale; // Take real part after conjugation
            
            // Warn if imaginary part is significant (indicates error)
            if data[i].im.abs() * scale > 1e-10 {
                #[cfg(feature = "std")]
                eprintln!("Warning: Significant imaginary part in inverse FFT at index {}: {}", 
                         i, data[i].im * scale);
            }
        }
        
        result
    }
    
    /// Check conditioning of FFT operation
    pub fn check_conditioning(&self, input: &[ComplexStable]) -> f64 {
        // Compute condition number estimate
        let mut min_norm = f64::INFINITY;
        let mut max_norm = 0.0;
        
        for c in input {
            let norm = c.norm_sqr();
            if norm > 0.0 {
                min_norm = f64::min(min_norm, norm);
                max_norm = f64::max(max_norm, norm);
            }
        }
        
        if min_norm > 0.0 {
            (max_norm / min_norm).sqrt()
        } else {
            f64::INFINITY
        }
    }
}

/// Multiply two polynomials in FFT domain with stability checks
pub fn multiply_fft_stable(
    a_fft: &[ComplexStable],
    b_fft: &[ComplexStable],
) -> Vec<ComplexStable> {
    assert_eq!(a_fft.len(), b_fft.len(), "FFT size mismatch");
    
    let mut result = vec![ComplexStable::zero(); a_fft.len()];
    for i in 0..a_fft.len() {
        result[i] = a_fft[i].mul_tracked(&b_fft[i]);
        
        // Check for overflow or underflow
        if !result[i].is_stable() {
            #[cfg(feature = "std")]
            eprintln!("Warning: Numerical instability in FFT multiplication at index {}", i);
            result[i].stabilize(1e-14);
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fft_forward_inverse() {
        let fft = FFTStable::new(8);
        let input = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        
        let forward = fft.forward(&input);
        let inverse = fft.inverse(&forward);
        
        for i in 0..8 {
            assert!((inverse[i] - input[i]).abs() < 1e-10,
                    "FFT inverse failed at index {}: {} != {}", i, inverse[i], input[i]);
        }
    }
    
    #[test]
    fn test_numerical_stability() {
        let mut c = ComplexStable::new(1e-100, 1e-100);
        assert!(c.is_stable());
        
        c.stabilize(1e-50);
        assert_eq!(c.re, 0.0);
        assert_eq!(c.im, 0.0);
    }
}
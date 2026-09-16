/// FFT and NTT operations for Falcon-512

use crate::constants::{N, Q, LOGN};
use crate::poly::{Poly, PolyF64};

use alloc::vec::Vec;
use core::f64::consts::PI;

/// Number-Theoretic Transform (NTT) for polynomial multiplication modulo q
pub struct NTT;

impl NTT {
    /// Primitive root of unity modulo q
    /// For q = 12289, we use g = 11 which has order 12288 = q-1
    const PRIMITIVE_ROOT: u16 = 11;
    
    /// Compute w^n mod q using fast exponentiation
    fn pow_mod(base: u16, exp: u32) -> u16 {
        let mut result = 1u32;
        let mut base = base as u32;
        let mut exp = exp;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * base) % (Q as u32);
            }
            base = (base * base) % (Q as u32);
            exp >>= 1;
        }
        
        result as u16
    }
    
    /// Generate the n-th root of unity for NTT
    fn get_root_of_unity() -> u16 {
        // For standard NTT, we need an n-th root of unity
        // omega = g^((q-1)/n) where g is primitive root
        let exp = ((Q as u32 - 1) / N as u32) as u32;
        Self::pow_mod(Self::PRIMITIVE_ROOT, exp)
    }
    
    /// Forward NTT transform
    pub fn forward(poly: &Poly) -> Vec<u16> {
        let mut a: Vec<u16> = poly.coeffs.iter()
            .map(|&c| {
                let c = c as i32;
                if c < 0 {
                    (c + Q as i32) as u16
                } else {
                    c as u16
                }
            })
            .collect();
        
        let omega = Self::get_root_of_unity();
        
        // Cooley-Tukey NTT
        let mut m = 1;
        for _ in 0..LOGN {
            let omega_m = Self::pow_mod(omega, (N / (2 * m)) as u32);
            let mut k = 0;
            while k < N {
                let mut omega_power = 1u16;
                for j in 0..m {
                    let t = ((omega_power as u32 * a[k + j + m] as u32) % (Q as u32)) as u16;
                    let u = a[k + j];
                    
                    a[k + j] = ((u as u32 + t as u32) % (Q as u32)) as u16;
                    a[k + j + m] = ((u as u32 + Q as u32 - t as u32) % (Q as u32)) as u16;
                    
                    omega_power = ((omega_power as u32 * omega_m as u32) % (Q as u32)) as u16;
                }
                k += 2 * m;
            }
            m *= 2;
        }
        
        // Bit reversal
        let mut result = vec![0u16; N];
        for i in 0..N {
            result[Self::bit_reverse(i, LOGN)] = a[i];
        }
        
        result
    }
    
    /// Inverse NTT transform
    pub fn inverse(a: &[u16]) -> Poly {
        let mut a = a.to_vec();
        
        // Bit reversal
        let mut temp = vec![0u16; N];
        for i in 0..N {
            temp[i] = a[Self::bit_reverse(i, LOGN)];
        }
        a = temp;
        
        let omega = Self::get_root_of_unity();
        let omega_inv = Self::pow_mod(omega, (2 * N - 1) as u32);
        
        // Cooley-Tukey inverse NTT
        let mut m = N / 2;
        while m >= 1 {
            let omega_m = Self::pow_mod(omega_inv, (N / (2 * m)) as u32);
            let mut k = 0;
            while k < N {
                let mut omega_power = 1u16;
                for j in 0..m {
                    let u = a[k + j];
                    let t = a[k + j + m];
                    
                    a[k + j] = ((u as u32 + t as u32) % (Q as u32)) as u16;
                    let diff = if u >= t {
                        u - t
                    } else {
                        (u as u32 + Q as u32 - t as u32) as u16
                    };
                    a[k + j + m] = ((omega_power as u32 * diff as u32) % (Q as u32)) as u16;
                    
                    omega_power = ((omega_power as u32 * omega_m as u32) % (Q as u32)) as u16;
                }
                k += 2 * m;
            }
            m /= 2;
        }
        
        // Multiply by N^(-1) mod q
        let n_inv = Self::pow_mod(N as u16, (Q as u32 - 2) as u32);
        let coeffs: Vec<i16> = a.iter()
            .map(|&c| {
                let c = ((c as u32 * n_inv as u32) % (Q as u32)) as u16;
                if c > Q / 2 {
                    c as i16 - Q as i16
                } else {
                    c as i16
                }
            })
            .collect();
        
        Poly { coeffs }
    }
    
    /// Multiply two polynomials using NTT
    pub fn multiply(a: &Poly, b: &Poly) -> Poly {
        // Use negacyclic NTT for polynomial multiplication in ring X^n + 1
        use crate::ntt_negacyclic::NegacyclicNTT;
        
        // Forward NTT transform
        let a_ntt = NegacyclicNTT::forward(a);
        let b_ntt = NegacyclicNTT::forward(b);
        
        // Pointwise multiplication in NTT domain
        let mut c_ntt = vec![0u16; N];
        for i in 0..N {
            c_ntt[i] = ((a_ntt[i] as u32 * b_ntt[i] as u32) % (Q as u32)) as u16;
        }
        
        // Inverse NTT transform
        NegacyclicNTT::inverse(&c_ntt)
    }
    
    /// Bit reversal for FFT
    fn bit_reverse(x: usize, log_n: usize) -> usize {
        let mut result = 0;
        let mut x = x;
        for _ in 0..log_n {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }
}

/// Complex FFT for floating-point polynomials
pub struct FFT;

/// FFT Context for Falcon operations
pub struct FFTContext {
    // Precomputed twiddle factors could be stored here for optimization
}

impl FFT {
    /// Convert FFT back to floating point polynomial coefficients
    pub fn inverse_to_f64(fft: &[Complex]) -> Vec<f64> {
        let n = fft.len();
        let mut result: Vec<Complex> = fft.to_vec();
        
        // Use fft_internal instead of fft_recursive for consistency with forward()
        // This fixes the FFT round-trip mismatch issue where forward() uses fft_internal
        // but inverse_to_f64() was using fft_recursive, causing incompatibility
        Self::fft_internal(&mut result, true);
        
        // Scale by 1/n and extract real parts
        let scale = 1.0 / n as f64;
        result.iter().map(|c| c.re * scale).collect()
    }
    
    /// Forward FFT
    pub fn forward(poly: &PolyF64) -> Vec<Complex> {
        let mut a: Vec<Complex> = poly.coeffs.iter()
            .map(|&c| Complex::new(c, 0.0))
            .collect();
        
        Self::fft_internal(&mut a, false);
        a
    }
    
    /// Inverse FFT
    pub fn inverse(a: &[Complex]) -> PolyF64 {
        let mut a = a.to_vec();
        Self::fft_internal(&mut a, true);
        
        let n = a.len() as f64;
        PolyF64 {
            coeffs: a.iter().map(|c| c.re / n).collect(),
        }
    }
    
    /// Internal FFT implementation (Cooley-Tukey)
    fn fft_internal(a: &mut [Complex], inverse: bool) {
        let n = a.len();
        if n <= 1 {
            return;
        }
        
        // Bit reversal
        for i in 0..n {
            let j = Self::bit_reverse(i, (n as f64).log2() as usize);
            if i < j {
                a.swap(i, j);
            }
        }
        
        // Cooley-Tukey FFT
        let mut len = 2;
        while len <= n {
            let angle = 2.0 * PI / len as f64 * if inverse { -1.0 } else { 1.0 };
            let wlen = Complex::from_polar(1.0, angle);
            
            for i in (0..n).step_by(len) {
                let mut w = Complex::new(1.0, 0.0);
                for j in 0..len / 2 {
                    let u = a[i + j];
                    let v = a[i + j + len / 2] * w;
                    a[i + j] = u + v;
                    a[i + j + len / 2] = u - v;
                    w = w * wlen;
                }
            }
            len *= 2;
        }
    }
    
    /// Bit reversal
    fn bit_reverse(x: usize, bits: usize) -> usize {
        let mut result = 0;
        let mut x = x;
        for _ in 0..bits {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        result
    }
}

/// Complex number for FFT
#[derive(Clone, Copy, Debug)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }
    
    pub fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }
    
    pub fn from_polar(r: f64, theta: f64) -> Self {
        Self {
            re: r * theta.cos(),
            im: r * theta.sin(),
        }
    }
    
    pub fn norm_squared(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }
    
    /// Alias for norm_squared to match enhanced solver usage
    pub fn norm_sqr(&self) -> f64 {
        self.norm_squared()
    }
    
    pub fn conj(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }
    
    pub fn add(&self, other: &Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }
    
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }
    
    pub fn mul(&self, other: &Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }
    
    pub fn div(&self, other: &Self) -> Self {
        let denom = other.norm_sqr();
        if denom == 0.0 {
            panic!("Division by zero complex number");
        }
        Self {
            re: (self.re * other.re + self.im * other.im) / denom,
            im: (self.im * other.re - self.re * other.im) / denom,
        }
    }
    
    pub fn neg(&self) -> Self {
        Self {
            re: -self.re,
            im: -self.im,
        }
    }
}

impl core::ops::Add for Complex {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }
}

impl core::ops::Sub for Complex {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }
}

impl core::ops::Mul for Complex {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }
}

impl core::ops::Mul<Complex> for f64 {
    type Output = Complex;
    
    fn mul(self, other: Complex) -> Complex {
        Complex {
            re: self * other.re,
            im: self * other.im,
        }
    }
}

impl core::ops::Div for Complex {
    type Output = Self;
    
    fn div(self, other: Self) -> Self {
        let denom = other.re * other.re + other.im * other.im;
        Self {
            re: (self.re * other.re + self.im * other.im) / denom,
            im: (self.im * other.re - self.re * other.im) / denom,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_forward_inverse() {
    let mut poly = Poly::zero(N);        poly.coeffs[0] = 1;
        poly.coeffs[1] = 2;
        poly.coeffs[2] = 3;
        
        let ntt = NTT::forward(&poly);
        let recovered = NTT::inverse(&ntt);
        
        assert_eq!(poly.coeffs[0], recovered.coeffs[0]);
        assert_eq!(poly.coeffs[1], recovered.coeffs[1]);
        assert_eq!(poly.coeffs[2], recovered.coeffs[2]);
    }

    #[test]
    fn test_ntt_multiply() {
        let mut a = Poly::zero(N);
        let mut b = Poly::zero(N);
        
        a.coeffs[0] = 1;
        a.coeffs[1] = 2;
        b.coeffs[0] = 3;
        b.coeffs[1] = 4;
        
        let c_ntt = NTT::multiply(&a, &b);
        let c_direct = a.mul(&b);
        
        for i in 0..N {
            assert_eq!(c_ntt.coeffs[i], c_direct.coeffs[i]);
        }
    }
}

impl FFTContext {
    /// Create a new FFT context
    pub fn new() -> Self {
        Self {}
    }
    
    /// Forward FFT transform for polynomials
    pub fn forward(&self, poly: &Poly) -> crate::error::Result<Vec<Complex>> {
        let poly_f64 = PolyF64::from_poly(poly);
        Ok(FFT::forward(&poly_f64))
    }
    
    /// Inverse FFT transform
    pub fn inverse(&self, coeffs: &[Complex]) -> crate::error::Result<PolyF64> {
        Ok(FFT::inverse(coeffs))
    }
}

/// FFT Complex type alias for compatibility
pub type FFTComplex = Complex;

// We don't need trait implementations since we're using methods

/// Forward FFT transform
pub fn fft_forward(poly: &Poly) -> Vec<Complex> {
    let n = poly.coeffs.len();
    let mut result = vec![Complex::zero(); n];
    
    for i in 0..n {
        result[i] = Complex::new(poly.coeffs[i] as f64, 0.0);
    }
    
    fft_recursive(&mut result, false);
    result
}

/// Inverse FFT transform
pub fn fft_inverse(fft: &[Complex]) -> Poly {
    let n = fft.len();
    let mut result: Vec<Complex> = fft.to_vec();
    
    fft_recursive(&mut result, true);
    
    // Scale by 1/n and convert to polynomial
    let scale = 1.0 / n as f64;
    let mut poly = Poly::zero(N);
    for i in 0..n.min(N) {
        poly.coeffs[i] = (result[i].re * scale).round() as i16;
    }
    
    poly
}

/// Recursive FFT implementation
fn fft_recursive(a: &mut [Complex], inverse: bool) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    
    let mut even = vec![Complex::zero(); n/2];
    let mut odd = vec![Complex::zero(); n/2];
    
    for i in 0..n/2 {
        even[i] = a[2*i];
        odd[i] = a[2*i + 1];
    }
    
    fft_recursive(&mut even, inverse);
    fft_recursive(&mut odd, inverse);
    
    let angle = if inverse { 2.0 * PI / n as f64 } else { -2.0 * PI / n as f64 };
    let w = Complex::from_polar(1.0, angle);
    let mut wn = Complex::new(1.0, 0.0);
    
    for i in 0..n/2 {
        let t = wn * odd[i];
        a[i] = even[i] + t;
        a[i + n/2] = even[i] - t;
        wn = wn * w;
    }
}

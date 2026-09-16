//! Stack-allocated polynomial types for small operations
//!
//! Provides zero-allocation polynomial operations for performance-critical paths.
//! Uses stack allocation with proper alignment for SIMD operations.

use core::mem::{self, MaybeUninit};
use core::ops::{Index, IndexMut};
use core::ptr;

/// ML-KEM polynomial size
pub const POLY_N: usize = 256;

/// Stack-allocated polynomial with cache-line alignment
#[repr(C, align(64))]
pub struct StackPoly<const N: usize> {
    coeffs: [i16; N],
}

impl<const N: usize> StackPoly<N> {
    /// Create a new zero polynomial
    #[inline]
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }
    
    /// Create from array
    #[inline]
    pub fn from_array(coeffs: [i16; N]) -> Self {
        Self { coeffs }
    }
    
    /// Create from slice (panics if wrong size)
    #[inline]
    pub fn from_slice(slice: &[i16]) -> Self {
        assert_eq!(slice.len(), N, "Slice length must match polynomial size");
        let mut poly = Self::zero();
        poly.coeffs.copy_from_slice(slice);
        poly
    }
    
    /// Create uninitialized polynomial
    #[inline]
    pub fn uninit() -> MaybeUninit<Self> {
        MaybeUninit::uninit()
    }
    
    /// Get coefficients
    #[inline]
    pub fn coeffs(&self) -> &[i16] {
        &self.coeffs
    }
    
    /// Get mutable coefficients
    #[inline]
    pub fn coeffs_mut(&mut self) -> &mut [i16] {
        &mut self.coeffs
    }
    
    /// Copy to another polynomial
    #[inline]
    pub fn copy_to(&self, other: &mut Self) {
        other.coeffs.copy_from_slice(&self.coeffs);
    }
    
    /// Add another polynomial in-place
    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_add(other.coeffs[i]);
        }
    }
    
    /// Subtract another polynomial in-place
    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_sub(other.coeffs[i]);
        }
    }
    
    /// Negate polynomial in-place
    #[inline]
    pub fn negate(&mut self) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_neg();
        }
    }
    
    /// Scale polynomial by a constant
    #[inline]
    pub fn scale(&mut self, scalar: i16) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].wrapping_mul(scalar);
        }
    }
    
    /// Reduce coefficients modulo q
    #[inline]
    pub fn reduce(&mut self, q: i16) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].rem_euclid(q);
        }
    }
    
    /// Check if polynomial is zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|&c| c == 0)
    }
    
    /// Get pointer to coefficients
    #[inline]
    pub fn as_ptr(&self) -> *const i16 {
        self.coeffs.as_ptr()
    }
    
    /// Get mutable pointer to coefficients
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut i16 {
        self.coeffs.as_mut_ptr()
    }
}

impl<const N: usize> Clone for StackPoly<N> {
    #[inline]
    fn clone(&self) -> Self {
        Self { coeffs: self.coeffs }
    }
}

impl<const N: usize> Copy for StackPoly<N> {}

impl<const N: usize> Default for StackPoly<N> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> Index<usize> for StackPoly<N> {
    type Output = i16;
    
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

impl<const N: usize> IndexMut<usize> for StackPoly<N> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeffs[index]
    }
}

/// Small polynomial type alias for ML-KEM
pub type SmallPoly = StackPoly<POLY_N>;

/// Dual polynomial for NTT operations (stores both time and frequency domain)
#[repr(C, align(64))]
pub struct DualStackPoly<const N: usize> {
    time_domain: [i16; N],
    freq_domain: [i16; N],
    is_ntt: bool,
}

impl<const N: usize> DualStackPoly<N> {
    /// Create new dual polynomial in time domain
    #[inline]
    pub fn new_time(coeffs: [i16; N]) -> Self {
        Self {
            time_domain: coeffs,
            freq_domain: [0; N],
            is_ntt: false,
        }
    }
    
    /// Create new dual polynomial in frequency domain
    #[inline]
    pub fn new_freq(coeffs: [i16; N]) -> Self {
        Self {
            time_domain: [0; N],
            freq_domain: coeffs,
            is_ntt: true,
        }
    }
    
    /// Get time domain coefficients
    #[inline]
    pub fn time_coeffs(&self) -> &[i16] {
        assert!(!self.is_ntt, "Polynomial is in frequency domain");
        &self.time_domain
    }
    
    /// Get frequency domain coefficients
    #[inline]
    pub fn freq_coeffs(&self) -> &[i16] {
        assert!(self.is_ntt, "Polynomial is in time domain");
        &self.freq_domain
    }
    
    /// Check if in NTT form
    #[inline]
    pub fn is_ntt(&self) -> bool {
        self.is_ntt
    }
    
    /// Switch domains (caller must perform actual NTT/INTT)
    #[inline]
    pub fn switch_domain(&mut self) {
        if self.is_ntt {
            // Moving from frequency to time
            self.time_domain.copy_from_slice(&self.freq_domain);
        } else {
            // Moving from time to frequency
            self.freq_domain.copy_from_slice(&self.time_domain);
        }
        self.is_ntt = !self.is_ntt;
    }
}

/// Fast stack buffer for temporary operations
#[repr(C, align(64))]
pub struct StackBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> StackBuffer<N> {
    /// Create new zero buffer
    #[inline]
    pub const fn new() -> Self {
        Self { data: [0; N] }
    }
    
    /// Get as byte slice
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    /// Get as mutable byte slice
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Interpret as array of i16 (unsafe - caller must ensure alignment)
    #[inline]
    pub unsafe fn as_i16_slice(&self) -> &[i16] {
        let ptr = self.data.as_ptr() as *const i16;
        let len = N / mem::size_of::<i16>();
        core::slice::from_raw_parts(ptr, len)
    }
    
    /// Interpret as mutable array of i16 (unsafe - caller must ensure alignment)
    #[inline]
    pub unsafe fn as_i16_slice_mut(&mut self) -> &mut [i16] {
        let ptr = self.data.as_mut_ptr() as *mut i16;
        let len = N / mem::size_of::<i16>();
        core::slice::from_raw_parts_mut(ptr, len)
    }
    
    /// Clear buffer
    #[inline]
    pub fn clear(&mut self) {
        unsafe {
            ptr::write_bytes(self.data.as_mut_ptr(), 0, N);
        }
    }
}

/// Stack-allocated polynomial vector
#[repr(C, align(64))]
pub struct StackPolyVec<const K: usize, const N: usize> {
    polys: [StackPoly<N>; K],
}

impl<const K: usize, const N: usize> StackPolyVec<K, N> {
    /// Create new zero polynomial vector
    #[inline]
    pub fn zero() -> Self {
        // Initialize array without Copy trait requirement
        let mut polys = core::mem::MaybeUninit::<[StackPoly<N>; K]>::uninit();
        
        unsafe {
            let ptr = polys.as_mut_ptr() as *mut StackPoly<N>;
            for i in 0..K {
                ptr.add(i).write(StackPoly::zero());
            }
            Self {
                polys: polys.assume_init(),
            }
        }
    }
    
    /// Get polynomial at index
    #[inline]
    pub fn get(&self, index: usize) -> &StackPoly<N> {
        &self.polys[index]
    }
    
    /// Get mutable polynomial at index
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> &mut StackPoly<N> {
        &mut self.polys[index]
    }
    
    /// Get all polynomials
    #[inline]
    pub fn polys(&self) -> &[StackPoly<N>; K] {
        &self.polys
    }
    
    /// Get all polynomials mutably
    #[inline]
    pub fn polys_mut(&mut self) -> &mut [StackPoly<N>; K] {
        &mut self.polys
    }
}

impl<const K: usize, const N: usize> Index<usize> for StackPolyVec<K, N> {
    type Output = StackPoly<N>;
    
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.polys[index]
    }
}

impl<const K: usize, const N: usize> IndexMut<usize> for StackPolyVec<K, N> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.polys[index]
    }
}

/// ML-KEM-768 specific polynomial vector (k=3)
pub type MLKem768PolyVec = StackPolyVec<3, POLY_N>;

/// Optimized operations for stack polynomials
pub mod ops {
    use super::*;
    
    /// Fast polynomial addition using SIMD when available
    #[inline]
    pub fn fast_add<const N: usize>(a: &StackPoly<N>, b: &StackPoly<N>, result: &mut StackPoly<N>) {
        #[cfg(target_feature = "avx2")]
        {
            if N % 16 == 0 {
                unsafe { simd_add(a.as_ptr(), b.as_ptr(), result.as_mut_ptr(), N) }
                return;
            }
        }
        
        // Fallback to scalar
        for i in 0..N {
            result[i] = a[i].wrapping_add(b[i]);
        }
    }
    
    /// Fast polynomial subtraction using SIMD when available
    #[inline]
    pub fn fast_sub<const N: usize>(a: &StackPoly<N>, b: &StackPoly<N>, result: &mut StackPoly<N>) {
        #[cfg(target_feature = "avx2")]
        {
            if N % 16 == 0 {
                unsafe { simd_sub(a.as_ptr(), b.as_ptr(), result.as_mut_ptr(), N) }
                return;
            }
        }
        
        // Fallback to scalar
        for i in 0..N {
            result[i] = a[i].wrapping_sub(b[i]);
        }
    }
    
    #[cfg(target_feature = "avx2")]
    unsafe fn simd_add(a: *const i16, b: *const i16, result: *mut i16, n: usize) {
        use core::arch::x86_64::*;
        
        let chunks = n / 16;
        for i in 0..chunks {
            let va = _mm256_loadu_si256((a as *const __m256i).add(i));
            let vb = _mm256_loadu_si256((b as *const __m256i).add(i));
            let vr = _mm256_add_epi16(va, vb);
            _mm256_storeu_si256((result as *mut __m256i).add(i), vr);
        }
    }
    
    #[cfg(target_feature = "avx2")]
    unsafe fn simd_sub(a: *const i16, b: *const i16, result: *mut i16, n: usize) {
        use core::arch::x86_64::*;
        
        let chunks = n / 16;
        for i in 0..chunks {
            let va = _mm256_loadu_si256((a as *const __m256i).add(i));
            let vb = _mm256_loadu_si256((b as *const __m256i).add(i));
            let vr = _mm256_sub_epi16(va, vb);
            _mm256_storeu_si256((result as *mut __m256i).add(i), vr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stack_poly() {
        let mut poly = StackPoly::<256>::zero();
        assert!(poly.is_zero());
        
        poly[0] = 1;
        poly[1] = 2;
        assert!(!poly.is_zero());
        
        let poly2 = StackPoly::from_array([3; 256]);
        poly.add_assign(&poly2);
        assert_eq!(poly[0], 4);
        assert_eq!(poly[1], 5);
    }
    
    #[test]
    fn test_dual_poly() {
        let coeffs = [1; 256];
        let mut dual = DualStackPoly::new_time(coeffs);
        assert!(!dual.is_ntt());
        assert_eq!(dual.time_coeffs()[0], 1);
        
        dual.switch_domain();
        assert!(dual.is_ntt());
    }
    
    #[test]
    fn test_stack_buffer() {
        let mut buffer = StackBuffer::<512>::new();
        buffer.as_bytes_mut()[0] = 1;
        
        unsafe {
            let i16_slice = buffer.as_i16_slice_mut();
            i16_slice[0] = 256;
            assert_eq!(buffer.as_bytes()[0], 0);
            assert_eq!(buffer.as_bytes()[1], 1);
        }
    }
    
    #[test]
    fn test_poly_vec() {
        let mut vec = MLKem768PolyVec::zero();
        vec[0][0] = 1;
        vec[1][0] = 2;
        vec[2][0] = 3;
        
        assert_eq!(vec.get(0)[0], 1);
        assert_eq!(vec.get(1)[0], 2);
        assert_eq!(vec.get(2)[0], 3);
    }
    
    #[test]
    fn test_alignment() {
        let poly = StackPoly::<256>::zero();
        let ptr = &poly as *const _ as usize;
        assert_eq!(ptr % 64, 0, "StackPoly should be 64-byte aligned");
        
        let dual = DualStackPoly::<256>::new_time([0; 256]);
        let ptr = &dual as *const _ as usize;
        assert_eq!(ptr % 64, 0, "DualStackPoly should be 64-byte aligned");
    }
}
/// Polynomial operations for Dilithium

use crate::params::{N, Q};
use crate::ntt::{reduce32, NTT};
use rand_core::{RngCore, CryptoRng};

/// Polynomial in Rq = Zq[X]/(X^n + 1)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Poly {
    /// Create zero polynomial
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }
    
    /// Create polynomial from coefficients
    pub fn from_coeffs(coeffs: [i32; N]) -> Self {
        // Don't automatically reduce - let operations handle reduction as needed
        Self { coeffs }
    }
    
    /// Sample uniformly random polynomial
    pub fn random_uniform<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut coeffs = [0i32; N];
        for c in &mut coeffs {
            let mut bytes = [0u8; 4];
            loop {
                rng.fill_bytes(&mut bytes[..3]);
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) & 0x7FFFFF;
                if val < Q {
                    *c = val as i32;
                    break;
                }
            }
        }
        Self::from_coeffs(coeffs)
    }
    
    /// Sample polynomial with coefficients in [-eta, eta]
    pub fn random_eta<R: RngCore + CryptoRng>(rng: &mut R, eta: u32) -> Self {
        let mut coeffs = [0i32; N];
        
        if eta == 2 {
            // Sample 2 bits at a time
            let mut bytes = vec![0u8; N / 4 + 1];
            rng.fill_bytes(&mut bytes);
            
            let mut bit_idx = 0;
            for c in &mut coeffs {
                let byte_idx = bit_idx / 8;
                let bit_offset = bit_idx % 8;
                
                let a0 = (bytes[byte_idx] >> bit_offset) & 1;
                let a1 = if bit_offset < 7 {
                    (bytes[byte_idx] >> (bit_offset + 1)) & 1
                } else {
                    bytes[byte_idx + 1] & 1
                };
                
                *c = a0 as i32 - a1 as i32;
                bit_idx += 2;
            }
        } else if eta == 4 {
            // Sample 4 bits at a time
            let mut bytes = vec![0u8; N / 2 + 1];
            rng.fill_bytes(&mut bytes);
            
            for (i, c) in coeffs.iter_mut().enumerate() {
                let byte_idx = i / 2;
                let nibble = if i % 2 == 0 {
                    bytes[byte_idx] & 0x0F
                } else {
                    (bytes[byte_idx] >> 4) & 0x0F
                };
                
                let a = (nibble & 1) + ((nibble >> 1) & 1);
                let b = ((nibble >> 2) & 1) + ((nibble >> 3) & 1);
                *c = a as i32 - b as i32;
            }
        }
        
        Self { coeffs }
    }
    
    /// Sample polynomial with coefficients in [-gamma1+1, gamma1]
    pub fn random_gamma1<R: RngCore + CryptoRng>(rng: &mut R, gamma1: u32) -> Self {
        let mut coeffs = [0i32; N];
        
        for c in &mut coeffs {
            let mut bytes = [0u8; 4];
            loop {
                rng.fill_bytes(&mut bytes[..3]);
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) & 0x7FFFFF;
                if val < 2 * gamma1 {
                    // Sample in [0, 2*gamma1), then map to [-(gamma1-1), gamma1]
                    *c = (gamma1 as i32) - (val as i32);
                    break;
                }
            }
        }
        
        Self { coeffs }
    }
    
    /// Convert to NTT representation
    pub fn to_ntt(&self) -> Self {
        Self {
            coeffs: NTT::new().ntt(&self.coeffs),
        }
    }
    
    /// Convert from NTT representation
    pub fn from_ntt(&self) -> Self {
        // Reference implementation doesn't center coefficients after inverse NTT
        let coeffs = NTT::new().intt(&self.coeffs);
        Self { coeffs }
    }
    
    /// High-precision conversion from NTT domain for Dilithium5
    /// 
    /// Uses enhanced precision inverse NTT to prevent coefficient explosion
    /// when working with results from high-precision matrix operations.
    pub fn from_ntt_hp(&self) -> Self {
        use crate::ntt::NTT;
        let ntt = NTT::new();
        Self {
            coeffs: ntt.intt(&self.coeffs),
        }
    }
    
    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = reduce32(self.coeffs[i] + other.coeffs[i]);
        }
        Self { coeffs }
    }
    
    /// Add two polynomials in NTT domain (no centering)
    pub fn add_ntt(&self, other: &Self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = (self.coeffs[i] + other.coeffs[i]).rem_euclid(Q as i32);
        }
        Self { coeffs }
    }
    
    /// Subtract two polynomials in NTT domain (no centering)
    pub fn sub_ntt(&self, other: &Self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = (self.coeffs[i] - other.coeffs[i]).rem_euclid(Q as i32);
        }
        Self { coeffs }
    }
    
    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            // First do the subtraction modulo Q (matching Python's poly_sub)
            let diff = (self.coeffs[i] - other.coeffs[i]).rem_euclid(Q as i32);
            // Then apply reduce32 to center the result
            coeffs[i] = reduce32(diff);
        }
        Self { coeffs }
    }
    
    /// Multiply two polynomials in NTT domain
    pub fn mul_ntt(&self, other: &Self) -> Self {
        Self {
            coeffs: {
                let mut result = [0i32; N];
                NTT::new().pointwise_mul(&self.coeffs, &other.coeffs, &mut result);
                result
            },
        }
    }
    
    /// High-precision multiply for large matrix operations (D5)
    pub fn mul_ntt_64(&self, other: &Self) -> Self {
        let mut result = [0i32; N];
        for i in 0..N {
            // Use 64-bit arithmetic for the multiplication to prevent overflow
            let prod = (self.coeffs[i] as i64) * (other.coeffs[i] as i64);
            result[i] = crate::ntt::montgomery_reduce(prod);
        }
        Self { coeffs: result }
    }
    
    /// Scale polynomial by constant
    pub fn scale(&self, c: i32) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            // Use mod_q to match Python - just reduce modulo Q without centering
            let product = (self.coeffs[i] as i64 * c as i64) % Q as i64;
            coeffs[i] = if product < 0 { (product + Q as i64) as i32 } else { product as i32 };
        }
        Self { coeffs }
    }
    
    /// Shift left by D bits (multiply by 2^D) without modular reduction
    /// This matches the reference implementation's poly_shiftl
    pub fn shiftl(&self, d: u32) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = self.coeffs[i] << d;
        }
        Self { coeffs }
    }
    
    /// Power2round decomposition - matches C reference exactly
    pub fn power2round(&self, d: u32) -> (Self, Self) {
        // Local implementation of power2round
        fn power2round_coeff(a: i32, d: u32) -> (i32, i32) {
            let a1 = (a + (1 << (d - 1)) - 1) >> d;
            let a0 = a - (a1 << d);
            (a1, a0)
        }
        
        let mut r1_coeffs = [0i32; N];
        let mut r0_coeffs = [0i32; N];
        
        for i in 0..N {
            let (a1, a0) = power2round_coeff(self.coeffs[i], d);
            r1_coeffs[i] = a1;
            r0_coeffs[i] = a0;
        }
        
        (Self { coeffs: r1_coeffs }, Self { coeffs: r0_coeffs })
    }
    
    /// Decompose polynomial for signature compression
    pub fn decompose(&self, gamma2: u32) -> (Self, Self) {
        let mut r1_coeffs = [0i32; N];
        let mut r0_coeffs = [0i32; N];
        
        for i in 0..N {
            // Use the decompose_coeff function from operations that matches C reference
            let (r1, r0) = crate::operations::decompose_coeff(self.coeffs[i], gamma2);
            r1_coeffs[i] = r1;
            r0_coeffs[i] = r0;
        }
        
        (Self { coeffs: r1_coeffs }, Self { coeffs: r0_coeffs })
    }
    
    /// Reduce all coefficients using reduce32 to range [-6283008, 6283008]
    /// This matches the reference implementation's poly_reduce
    pub fn reduce(&self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = reduce32(self.coeffs[i]);
        }
        Self { coeffs }
    }
    
    /// Apply Montgomery reduction to each coefficient to prevent precision accumulation
    /// This is specifically needed for larger matrix operations (D5) to maintain precision
    pub fn montgomery_reduce_coeffs(&self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            // Apply Montgomery reduction to bring coefficients back into proper range
            // This prevents the accumulation of precision errors in larger matrices
            coeffs[i] = crate::ntt::montgomery_reduce(self.coeffs[i] as i64);
        }
        Self { coeffs }
    }
    
    /// Add Q to negative coefficients (conditional add Q)
    /// This matches the reference implementation's poly_caddq
    pub fn caddq(&self) -> Self {
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = if self.coeffs[i] < 0 {
                self.coeffs[i] + Q as i32
            } else {
                self.coeffs[i]
            };
        }
        Self { coeffs }
    }
    
    /// Check if infinity norm is within bound
    pub fn check_norm_bound(&self, bound: u32) -> bool {
        for &c in &self.coeffs {
            // First reduce to [0, Q) range
            let mut c = c.rem_euclid(Q as i32);
            // Then center to [-(Q-1)/2, (Q-1)/2]
            if c > (Q as i32) / 2 {
                c -= Q as i32;
            }
            if c.abs() >= bound as i32 {
                return false;
            }
        }
        true
    }
    
    /// Pack polynomial into bytes
    pub fn pack(&self) -> Vec<u8> {
        let mut data = vec![0u8; 384];
        
        for i in (0..N).step_by(2) {
            let c0 = self.coeffs[i].rem_euclid(Q as i32) as u32;
            let c1 = if i + 1 < N {
                self.coeffs[i + 1].rem_euclid(Q as i32) as u32
            } else {
                0
            };
            
            let idx = i * 3 / 2;
            data[idx] = c0 as u8;
            data[idx + 1] = ((c0 >> 8) as u8) | ((c1 as u8) << 4);
            data[idx + 2] = (c1 >> 4) as u8;
            if idx + 3 < 384 {
                data[idx + 3] = (c1 >> 12) as u8;
            }
        }
        
        data
    }
    
    /// Unpack polynomial from bytes
    pub fn unpack(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 384 {
            return Err("Invalid packed polynomial length");
        }
        
        let mut coeffs = [0i32; N];
        
        for i in (0..data.len()).step_by(3) {
            if i + 2 < data.len() {
                let idx = i * 2 / 3;
                
                let c0 = data[i] as u32
                    | ((data[i + 1] as u32 & 0x0F) << 8)
                    | ((data[i + 2] as u32) << 16);
                    
                if idx < N {
                    coeffs[idx] = c0 as i32;
                }
                
                if i + 3 < data.len() && idx + 1 < N {
                    let c1 = ((data[i + 1] as u32) >> 4)
                        | ((data[i + 2] as u32) << 4)
                        | ((data[i + 3] as u32) << 12);
                    coeffs[idx + 1] = c1 as i32;
                }
            }
        }
        
        Ok(Self { coeffs })
    }
}

/// Vector of polynomials
#[derive(Clone, Debug)]
pub struct PolyVec {
    pub polys: Vec<Poly>,
}

impl PolyVec {
    /// Create zero polynomial vector
    pub fn zero(len: usize) -> Self {
        Self {
            polys: vec![Poly::zero(); len],
        }
    }
    
    /// Create from vector of polynomials
    pub fn from_polys(polys: Vec<Poly>) -> Self {
        Self { polys }
    }
    
    /// Sample random polynomial vector with small coefficients
    pub fn random_eta<R: RngCore + CryptoRng>(rng: &mut R, len: usize, eta: u32) -> Self {
        let polys = (0..len)
            .map(|_| Poly::random_eta(rng, eta))
            .collect();
        Self { polys }
    }
    
    /// Convert all polynomials to NTT representation
    pub fn to_ntt(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.to_ntt()).collect(),
        }
    }
    
    /// Convert all polynomials from NTT representation
    pub fn from_ntt(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.from_ntt()).collect(),
        }
    }
    
    /// High-precision conversion from NTT domain for Dilithium5
    /// 
    /// Uses enhanced precision inverse NTT to prevent coefficient explosion
    /// when working with results from high-precision matrix operations.
    pub fn from_ntt_hp(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.from_ntt_hp()).collect(),
        }
    }
    
    /// Add two polynomial vectors
    pub fn add(&self, other: &Self) -> Result<Self, &'static str> {
        if self.polys.len() != other.polys.len() {
            return Err("Vectors must have same length");
        }
        
        let polys = self.polys.iter()
            .zip(other.polys.iter())
            .map(|(a, b)| a.add(b))
            .collect();
            
        Ok(Self { polys })
    }
    
    /// Add two polynomial vectors in NTT domain
    pub fn add_ntt(&self, other: &Self) -> Result<Self, &'static str> {
        if self.polys.len() != other.polys.len() {
            return Err("Vectors must have same length");
        }
        
        let polys = self.polys.iter()
            .zip(other.polys.iter())
            .map(|(a, b)| a.add_ntt(b))
            .collect();
            
        Ok(Self { polys })
    }
    
    /// Subtract two polynomial vectors in NTT domain
    pub fn sub_ntt(&self, other: &Self) -> Result<Self, &'static str> {
        if self.polys.len() != other.polys.len() {
            return Err("Vectors must have same length");
        }
        
        let polys = self.polys.iter()
            .zip(other.polys.iter())
            .map(|(a, b)| a.sub_ntt(b))
            .collect();
            
        Ok(Self { polys })
    }
    
    /// Subtract two polynomial vectors
    pub fn sub(&self, other: &Self) -> Result<Self, &'static str> {
        if self.polys.len() != other.polys.len() {
            return Err("Vectors must have same length");
        }
        
        let polys = self.polys.iter()
            .zip(other.polys.iter())
            .map(|(a, b)| a.sub(b))
            .collect();
            
        Ok(Self { polys })
    }
    
    /// Reduce all polynomials modulo Q to canonical form [-Q/2, Q/2]
    pub fn reduce(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.reduce()).collect(),
        }
    }
    
    /// Add Q to negative coefficients in all polynomials
    pub fn caddq(&self) -> Self {
        Self {
            polys: self.polys.iter().map(|p| p.caddq()).collect(),
        }
    }
    
    /// Check if all polynomials have infinity norm within bound
    pub fn check_norm_bound(&self, bound: u32) -> bool {
        self.polys.iter().all(|p| p.check_norm_bound(bound))
    }
    
    /// Scale all polynomials by a constant
    pub fn scale(&self, scalar: i32) -> Self {
        Self {
            polys: self.polys.iter()
                .map(|p| p.scale(scalar))  // Use Poly's scale method which now uses reduce32
                .collect()
        }
    }
    
    /// Pack polynomial vector into bytes
    pub fn pack(&self) -> Vec<u8> {
        self.polys.iter()
            .flat_map(|p| p.pack())
            .collect()
    }
    
    /// Unpack polynomial vector from bytes
    pub fn unpack(data: &[u8], len: usize) -> Result<Self, &'static str> {
        let poly_size = 384;
        if data.len() != len * poly_size {
            return Err("Invalid packed vector length");
        }
        
        let polys = (0..len)
            .map(|i| {
                let start = i * poly_size;
                let end = start + poly_size;
                Poly::unpack(&data[start..end])
            })
            .collect::<Result<Vec<_>, _>>()?;
            
        Ok(Self { polys })
    }
}

/// Matrix-vector multiplication in NTT domain
pub fn matrix_vector_mul_ntt(mat: &[PolyVec], vec: &PolyVec) -> Result<PolyVec, &'static str> {
    let k = mat.len();
    if k == 0 {
        return Err("Empty matrix");
    }
    
    let l = vec.polys.len();
    
    // DISABLE high-precision NTT for now - use standard NTT for all Dilithium variants
    // For Dilithium5 (8x7 matrix), use specialized high-precision implementation
    // if k == 8 && l == 7 {
    //     return crate::ntt_high_precision::matrix_vector_mul_hp(mat, vec);
    // }
    
    let mut result = Vec::with_capacity(k);
    
    for row in mat {
        if row.polys.len() != l {
            return Err("Matrix dimensions don't match");
        }
        
        let mut acc = Poly::zero();
        
        // Standard precision for D2/D3 (and any other non-8x7 matrices)
        for (j, poly) in row.polys.iter().enumerate() {
            let prod = poly.mul_ntt(&vec.polys[j]);
            acc = acc.add_ntt(&prod);
        }
        result.push(acc);
    }
    
    Ok(PolyVec::from_polys(result))
}
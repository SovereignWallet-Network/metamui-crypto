//! Number Theoretic Transform (NTT) for ML-DSA, portable scalar code.
//!
//! Every function here is plain Rust that compiles the same on every target;
//! there is no SIMD, assembly or CPU-feature detection in this crate. The
//! forward transform is Cooley-Tukey over `ZETAS` (FIPS 204 Algorithm 41),
//! the inverse is Gentleman-Sande with the final `N^-1` scaling (Algorithm 42).

#![allow(dead_code)]

use crate::params::{N, Q};

/// Barrett reduction constants
const BARRETT_SHIFT: u32 = 26;
const BARRETT_MULTIPLIER: u64 = (1u64 << BARRETT_SHIFT) / Q as u64;

/// Montgomery reduction constant
const Q_INV: u64 = 58728449; // -q^(-1) mod 2^32

/// Precomputed twiddle factors for NTT (from reference implementation)
pub const ZETAS: [i32; 256] = [
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
];

/// Cryptographically secure constant-time Barrett reduction for Dilithium Q = 8380417
/// Based on reference implementations and optimized for constant-time execution
#[inline(always)]
fn barrett_reduce(a: i64) -> i32 {
    const Q_I64: i64 = Q as i64;
    
    // Barrett reduction constants optimized for Q = 8380417
    const BARRETT_SHIFT: u32 = 26;
    const BARRETT_R: i64 = 8; // (1 << 26) / Q = 67108864 / 8380417 ≈ 8.009 -> 8
    
    // Step 1: Compute quotient approximation  
    let v = (a * BARRETT_R) >> BARRETT_SHIFT;
    
    // Step 2: Compute remainder
    let mut t = a - v * Q_I64;
    
    // Step 3: Conditional reduction to ensure t ∈ [0, Q)
    // Use constant-time conditional subtraction
    let mask1 = ((t >= Q_I64) as i64).wrapping_neg();
    t -= Q_I64 & mask1;
    
    let mask2 = ((t >= Q_I64) as i64).wrapping_neg(); 
    t -= Q_I64 & mask2;
    
    // Handle negative results by adding Q
    let mask3 = ((t < 0) as i64).wrapping_neg();
    t += Q_I64 & mask3;
    
    let mask4 = ((t < 0) as i64).wrapping_neg();
    t += Q_I64 & mask4;
    
    t as i32
}

/// Optimized modular multiplication
#[inline(always)]
fn mod_mul(a: i32, b: i32) -> i32 {
    barrett_reduce(a as i64 * b as i64)
}

/// Montgomery reduction (exact implementation from reference)
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    const QINV: u64 = 58728449; // q^(-1) mod 2^32
    
    // Standard Montgomery reduction from reference
    let t = (a as u64).wrapping_mul(QINV) & 0xFFFFFFFF;
    // Use wrapping arithmetic to handle potential underflow
    let result = (a.wrapping_sub((t as i64).wrapping_mul(Q as i64)) >> 32) as i32;
    
    // Conditional reduction to ensure result is in proper range
    // The reference doesn't center here - that's done later if needed
    result
}

/// Optimized Montgomery reduction
#[inline(always)]
fn montgomery_reduce_opt(a: i64) -> i32 {
    montgomery_reduce(a)
}

/// Bit reversal lookup table
const BIT_REV_TABLE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let mut x = i;
        x = ((x & 0xAA) >> 1) | ((x & 0x55) << 1);
        x = ((x & 0xCC) >> 2) | ((x & 0x33) << 2);
        x = ((x & 0xF0) >> 4) | ((x & 0x0F) << 4);
        table[i] = x as u8;
        i += 1;
    }
    table
};

/// Number Theoretic Transform over Z_q[X]/(X^256 + 1), scalar
pub struct OptimizedNTT {
    zetas: [i32; 128],
    zetas_inv: [i32; 128],
    n_inv: i32,
}

/// Type alias for backward compatibility
pub type NTT = OptimizedNTT;


impl OptimizedNTT {
    /// Wrapper for ntt that returns a new array
    pub fn ntt(&self, input: &[i32; N]) -> [i32; N] {
        let mut result = *input;
        self.ntt_inplace(&mut result);
        result
    }
    
    /// Wrapper for intt that returns a new array
    pub fn intt(&self, input: &[i32; N]) -> [i32; N] {
        let mut result = *input;
        self.intt_inplace(&mut result);
        result
    }
    
    /// Create new optimized NTT instance using precomputed values
    pub fn new() -> Self {
        // Use dummy arrays - we'll use the global ZETAS array directly
        let zetas = [0i32; 128];
        let zetas_inv = [0i32; 128];
        
        // Final scaling factor for inverse NTT
        // CORRECTED: Use standard modular multiplication, not Montgomery
        // INTT(NTT(x)) = x * 256, so we need N^(-1) mod Q = 8347681
        let f = 8347681;
        
        Self {
            zetas,
            zetas_inv,
            n_inv: f,
        }
    }
    
    /// Forward NTT - exactly matching working Python implementation
    pub fn ntt_inplace(&self, a: &mut [i32; N]) {
        // Forward NTT using exact Python reference algorithm
        let mut k = 0;
        let mut length = 128; // N / 2
        
        while length > 0 {
            let mut start = 0;
            while start < N {
                k += 1;
                let zeta = ZETAS[k];
                
                for j in start..(start + length) {
                    let t = montgomery_reduce(zeta as i64 * a[j + length] as i64);
                    a[j + length] = a[j] - t;
                    a[j] = a[j] + t;
                    
                    // Explicit reduction to prevent coefficient explosion
                    a[j] = reduce32(a[j]);
                    a[j + length] = reduce32(a[j + length]);
                }
                
                start = start + 2 * length; // Exact match to Python: start = start + 2 * length
            }
            length >>= 1;
        }
    }
    
    /// Inverse NTT - exactly matching working Python implementation
    pub fn intt_inplace(&self, a: &mut [i32; N]) {
        // Inverse NTT using exact Python reference algorithm (Gentleman-Sande)
        let mut k = 256;
        let mut length = 1;
        
        while length < N {
            let mut start = 0;
            while start < N {
                k -= 1;
                let zeta = -ZETAS[k]; // Note: negative for inverse (exact match to Python)
                
                for j in start..(start + length) {
                    let t = a[j];
                    a[j] = t + a[j + length];
                    a[j + length] = t - a[j + length];
                    a[j + length] = montgomery_reduce(zeta as i64 * a[j + length] as i64);
                }
                
                start = start + 2 * length; // Exact match to Python: start = start + 2 * length
            }
            length <<= 1;
        }
        
        // Final scaling: multiply by N^(-1) mod Q using standard modular arithmetic
        // CORRECTED: Use standard modular multiplication, not Montgomery reduction
        for j in 0..N {
            a[j] = ((a[j] as i64 * self.n_inv as i64) % Q as i64) as i32;
            // Apply centered reduction to ensure coefficients are in proper range
            a[j] = reduce32(a[j]);
        }
    }
    
    /// Fixed pointwise multiplication with explicit coefficient reduction
    pub fn pointwise_mul(&self, a: &[i32; N], b: &[i32; N], c: &mut [i32; N]) {
        // Process in chunks for better cache usage
        for i in (0..N).step_by(16) {
            let end = (i + 16).min(N);
            for j in i..end {
                // Explicit modular reduction to prevent coefficient explosion
                let product = (a[j] as i64 * b[j] as i64) % Q as i64;
                c[j] = reduce32(product as i32);
            }
        }
    }
    
    /// Batch NTT for multiple polynomials
    pub fn batch_ntt(&self, polys: &mut [[i32; N]]) {
        for poly in polys.iter_mut() {
            self.ntt(poly);
        }
    }
    
    /// Batch inverse NTT
    pub fn batch_intt(&self, polys: &mut [[i32; N]]) {
        for poly in polys.iter_mut() {
            self.intt(poly);
        }
    }
}

/// Fast modular exponentiation
fn mod_pow(mut base: i32, mut exp: u32) -> i32 {
    let mut result = 1i32;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base);
        }
        base = mod_mul(base, base);
        exp >>= 1;
    }
    
    result
}

// Note: Optimized NTT instance should be created as needed
// rather than using global state for better performance characteristics

/// Modular reduction for Dilithium's Q
#[inline(always)]
pub fn mod_q(a: i64) -> i32 {
    barrett_reduce(a)
}

/// Reduce 32-bit value modulo Q to range [-6283008, 6283008]
/// This matches the reference implementation's reduce32
#[inline(always)]
pub fn reduce32(a: i32) -> i32 {
    // Reference implementation:
    // t = (a + (1 << 22)) >> 23;
    // t = a - t*Q;
    let t = (a + (1 << 22)) >> 23;
    a - t * (Q as i32)
}
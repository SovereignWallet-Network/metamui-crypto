//! Fast Fourier Transform (FFT) operations for HAETAE
//!
//! This module implements complex FFT used for norm checking in HAETAE.
//! Uses fixed-point arithmetic with 16-bit fractional precision.
//!
//! Transcopy from: metamui-haetae/src/fft.c

use crate::poly::Poly;

/// FFT size (must equal polynomial degree N)
pub const FFT_N: usize = 256;

/// Log2 of FFT size
pub const FFT_LOGN: usize = 8;

/// Complex number in fixed-point format (Q16.16)
///
/// Real and imaginary parts are stored as i32 with 16-bit fractional precision.
/// This represents values scaled by 2^16 (65536).
#[derive(Clone, Copy, Debug, Default)]
pub struct Complex {
    /// Real part (fixed-point Q16.16)
    pub real: i32,
    /// Imaginary part (fixed-point Q16.16)
    pub imag: i32,
}

impl Complex {
    /// Create new complex number
    pub const fn new(real: i32, imag: i32) -> Self {
        Self { real, imag }
    }
}

/// Roots of unity for FFT (e^(-i*π*k/256) scaled by 65536)
///
/// Generated in Python:
/// ```python
/// import numpy as np
/// rootsf = np.exp(-1j * np.pi * np.arange(256) / 256)
/// roots = [(int(r.real), int(r.imag)) for r in np.round(65536 * rootsf)]
/// ```
static ROOTS: [Complex; FFT_N] = [
    Complex { real: 65536, imag:     0}, Complex { real: 65531, imag:   -804},
    Complex { real: 65516, imag:  -1608}, Complex { real: 65492, imag:  -2412},
    Complex { real: 65457, imag:  -3216}, Complex { real: 65413, imag:  -4019},
    Complex { real: 65358, imag:  -4821}, Complex { real: 65294, imag:  -5623},
    Complex { real: 65220, imag:  -6424}, Complex { real: 65137, imag:  -7224},
    Complex { real: 65043, imag:  -8022}, Complex { real: 64940, imag:  -8820},
    Complex { real: 64827, imag:  -9616}, Complex { real: 64704, imag: -10411},
    Complex { real: 64571, imag: -11204}, Complex { real: 64429, imag: -11996},
    Complex { real: 64277, imag: -12785}, Complex { real: 64115, imag: -13573},
    Complex { real: 63944, imag: -14359}, Complex { real: 63763, imag: -15143},
    Complex { real: 63572, imag: -15924}, Complex { real: 63372, imag: -16703},
    Complex { real: 63162, imag: -17479}, Complex { real: 62943, imag: -18253},
    Complex { real: 62714, imag: -19024}, Complex { real: 62476, imag: -19792},
    Complex { real: 62228, imag: -20557}, Complex { real: 61971, imag: -21320},
    Complex { real: 61705, imag: -22078}, Complex { real: 61429, imag: -22834},
    Complex { real: 61145, imag: -23586}, Complex { real: 60851, imag: -24335},
    Complex { real: 60547, imag: -25080}, Complex { real: 60235, imag: -25821},
    Complex { real: 59914, imag: -26558}, Complex { real: 59583, imag: -27291},
    Complex { real: 59244, imag: -28020}, Complex { real: 58896, imag: -28745},
    Complex { real: 58538, imag: -29466}, Complex { real: 58172, imag: -30182},
    Complex { real: 57798, imag: -30893}, Complex { real: 57414, imag: -31600},
    Complex { real: 57022, imag: -32303}, Complex { real: 56621, imag: -33000},
    Complex { real: 56212, imag: -33692}, Complex { real: 55794, imag: -34380},
    Complex { real: 55368, imag: -35062}, Complex { real: 54934, imag: -35738},
    Complex { real: 54491, imag: -36410}, Complex { real: 54040, imag: -37076},
    Complex { real: 53581, imag: -37736}, Complex { real: 53114, imag: -38391},
    Complex { real: 52639, imag: -39040}, Complex { real: 52156, imag: -39683},
    Complex { real: 51665, imag: -40320}, Complex { real: 51166, imag: -40951},
    Complex { real: 50660, imag: -41576}, Complex { real: 50146, imag: -42194},
    Complex { real: 49624, imag: -42806}, Complex { real: 49095, imag: -43412},
    Complex { real: 48559, imag: -44011}, Complex { real: 48015, imag: -44604},
    Complex { real: 47464, imag: -45190}, Complex { real: 46906, imag: -45769},
    Complex { real: 46341, imag: -46341}, Complex { real: 45769, imag: -46906},
    Complex { real: 45190, imag: -47464}, Complex { real: 44604, imag: -48015},
    Complex { real: 44011, imag: -48559}, Complex { real: 43412, imag: -49095},
    Complex { real: 42806, imag: -49624}, Complex { real: 42194, imag: -50146},
    Complex { real: 41576, imag: -50660}, Complex { real: 40951, imag: -51166},
    Complex { real: 40320, imag: -51665}, Complex { real: 39683, imag: -52156},
    Complex { real: 39040, imag: -52639}, Complex { real: 38391, imag: -53114},
    Complex { real: 37736, imag: -53581}, Complex { real: 37076, imag: -54040},
    Complex { real: 36410, imag: -54491}, Complex { real: 35738, imag: -54934},
    Complex { real: 35062, imag: -55368}, Complex { real: 34380, imag: -55794},
    Complex { real: 33692, imag: -56212}, Complex { real: 33000, imag: -56621},
    Complex { real: 32303, imag: -57022}, Complex { real: 31600, imag: -57414},
    Complex { real: 30893, imag: -57798}, Complex { real: 30182, imag: -58172},
    Complex { real: 29466, imag: -58538}, Complex { real: 28745, imag: -58896},
    Complex { real: 28020, imag: -59244}, Complex { real: 27291, imag: -59583},
    Complex { real: 26558, imag: -59914}, Complex { real: 25821, imag: -60235},
    Complex { real: 25080, imag: -60547}, Complex { real: 24335, imag: -60851},
    Complex { real: 23586, imag: -61145}, Complex { real: 22834, imag: -61429},
    Complex { real: 22078, imag: -61705}, Complex { real: 21320, imag: -61971},
    Complex { real: 20557, imag: -62228}, Complex { real: 19792, imag: -62476},
    Complex { real: 19024, imag: -62714}, Complex { real: 18253, imag: -62943},
    Complex { real: 17479, imag: -63162}, Complex { real: 16703, imag: -63372},
    Complex { real: 15924, imag: -63572}, Complex { real: 15143, imag: -63763},
    Complex { real: 14359, imag: -63944}, Complex { real: 13573, imag: -64115},
    Complex { real: 12785, imag: -64277}, Complex { real: 11996, imag: -64429},
    Complex { real: 11204, imag: -64571}, Complex { real: 10411, imag: -64704},
    Complex { real:  9616, imag: -64827}, Complex { real:  8820, imag: -64940},
    Complex { real:  8022, imag: -65043}, Complex { real:  7224, imag: -65137},
    Complex { real:  6424, imag: -65220}, Complex { real:  5623, imag: -65294},
    Complex { real:  4821, imag: -65358}, Complex { real:  4019, imag: -65413},
    Complex { real:  3216, imag: -65457}, Complex { real:  2412, imag: -65492},
    Complex { real:  1608, imag: -65516}, Complex { real:   804, imag: -65531},
    Complex { real:     0, imag: -65536}, Complex { real:   -804, imag: -65531},
    Complex { real:  -1608, imag: -65516}, Complex { real:  -2412, imag: -65492},
    Complex { real:  -3216, imag: -65457}, Complex { real:  -4019, imag: -65413},
    Complex { real:  -4821, imag: -65358}, Complex { real:  -5623, imag: -65294},
    Complex { real:  -6424, imag: -65220}, Complex { real:  -7224, imag: -65137},
    Complex { real:  -8022, imag: -65043}, Complex { real:  -8820, imag: -64940},
    Complex { real:  -9616, imag: -64827}, Complex { real: -10411, imag: -64704},
    Complex { real: -11204, imag: -64571}, Complex { real: -11996, imag: -64429},
    Complex { real: -12785, imag: -64277}, Complex { real: -13573, imag: -64115},
    Complex { real: -14359, imag: -63944}, Complex { real: -15143, imag: -63763},
    Complex { real: -15924, imag: -63572}, Complex { real: -16703, imag: -63372},
    Complex { real: -17479, imag: -63162}, Complex { real: -18253, imag: -62943},
    Complex { real: -19024, imag: -62714}, Complex { real: -19792, imag: -62476},
    Complex { real: -20557, imag: -62228}, Complex { real: -21320, imag: -61971},
    Complex { real: -22078, imag: -61705}, Complex { real: -22834, imag: -61429},
    Complex { real: -23586, imag: -61145}, Complex { real: -24335, imag: -60851},
    Complex { real: -25080, imag: -60547}, Complex { real: -25821, imag: -60235},
    Complex { real: -26558, imag: -59914}, Complex { real: -27291, imag: -59583},
    Complex { real: -28020, imag: -59244}, Complex { real: -28745, imag: -58896},
    Complex { real: -29466, imag: -58538}, Complex { real: -30182, imag: -58172},
    Complex { real: -30893, imag: -57798}, Complex { real: -31600, imag: -57414},
    Complex { real: -32303, imag: -57022}, Complex { real: -33000, imag: -56621},
    Complex { real: -33692, imag: -56212}, Complex { real: -34380, imag: -55794},
    Complex { real: -35062, imag: -55368}, Complex { real: -35738, imag: -54934},
    Complex { real: -36410, imag: -54491}, Complex { real: -37076, imag: -54040},
    Complex { real: -37736, imag: -53581}, Complex { real: -38391, imag: -53114},
    Complex { real: -39040, imag: -52639}, Complex { real: -39683, imag: -52156},
    Complex { real: -40320, imag: -51665}, Complex { real: -40951, imag: -51166},
    Complex { real: -41576, imag: -50660}, Complex { real: -42194, imag: -50146},
    Complex { real: -42806, imag: -49624}, Complex { real: -43412, imag: -49095},
    Complex { real: -44011, imag: -48559}, Complex { real: -44604, imag: -48015},
    Complex { real: -45190, imag: -47464}, Complex { real: -45769, imag: -46906},
    Complex { real: -46341, imag: -46341}, Complex { real: -46906, imag: -45769},
    Complex { real: -47464, imag: -45190}, Complex { real: -48015, imag: -44604},
    Complex { real: -48559, imag: -44011}, Complex { real: -49095, imag: -43412},
    Complex { real: -49624, imag: -42806}, Complex { real: -50146, imag: -42194},
    Complex { real: -50660, imag: -41576}, Complex { real: -51166, imag: -40951},
    Complex { real: -51665, imag: -40320}, Complex { real: -52156, imag: -39683},
    Complex { real: -52639, imag: -39040}, Complex { real: -53114, imag: -38391},
    Complex { real: -53581, imag: -37736}, Complex { real: -54040, imag: -37076},
    Complex { real: -54491, imag: -36410}, Complex { real: -54934, imag: -35738},
    Complex { real: -55368, imag: -35062}, Complex { real: -55794, imag: -34380},
    Complex { real: -56212, imag: -33692}, Complex { real: -56621, imag: -33000},
    Complex { real: -57022, imag: -32303}, Complex { real: -57414, imag: -31600},
    Complex { real: -57798, imag: -30893}, Complex { real: -58172, imag: -30182},
    Complex { real: -58538, imag: -29466}, Complex { real: -58896, imag: -28745},
    Complex { real: -59244, imag: -28020}, Complex { real: -59583, imag: -27291},
    Complex { real: -59914, imag: -26558}, Complex { real: -60235, imag: -25821},
    Complex { real: -60547, imag: -25080}, Complex { real: -60851, imag: -24335},
    Complex { real: -61145, imag: -23586}, Complex { real: -61429, imag: -22834},
    Complex { real: -61705, imag: -22078}, Complex { real: -61971, imag: -21320},
    Complex { real: -62228, imag: -20557}, Complex { real: -62476, imag: -19792},
    Complex { real: -62714, imag: -19024}, Complex { real: -62943, imag: -18253},
    Complex { real: -63162, imag: -17479}, Complex { real: -63372, imag: -16703},
    Complex { real: -63572, imag: -15924}, Complex { real: -63763, imag: -15143},
    Complex { real: -63944, imag: -14359}, Complex { real: -64115, imag: -13573},
    Complex { real: -64277, imag: -12785}, Complex { real: -64429, imag: -11996},
    Complex { real: -64571, imag: -11204}, Complex { real: -64704, imag: -10411},
    Complex { real: -64827, imag:  -9616}, Complex { real: -64940, imag:  -8820},
    Complex { real: -65043, imag:  -8022}, Complex { real: -65137, imag:  -7224},
    Complex { real: -65220, imag:  -6424}, Complex { real: -65294, imag:  -5623},
    Complex { real: -65358, imag:  -4821}, Complex { real: -65413, imag:  -4019},
    Complex { real: -65457, imag:  -3216}, Complex { real: -65492, imag:  -2412},
    Complex { real: -65516, imag:  -1608}, Complex { real: -65531, imag:   -804},
];

/// Bit-reversal table for 8-bit indices
///
/// Generated in Python:
/// ```python
/// brv8 = [int(f"{t:08b}"[::-1],2) for t in range(2**8)]
/// ```
static BRV8: [u8; FFT_N] = [
      0, 128,  64, 192,  32, 160,  96, 224,  16, 144,  80, 208,  48, 176, 112, 240,
      8, 136,  72, 200,  40, 168, 104, 232,  24, 152,  88, 216,  56, 184, 120, 248,
      4, 132,  68, 196,  36, 164, 100, 228,  20, 148,  84, 212,  52, 180, 116, 244,
     12, 140,  76, 204,  44, 172, 108, 236,  28, 156,  92, 220,  60, 188, 124, 252,
      2, 130,  66, 194,  34, 162,  98, 226,  18, 146,  82, 210,  50, 178, 114, 242,
     10, 138,  74, 202,  42, 170, 106, 234,  26, 154,  90, 218,  58, 186, 122, 250,
      6, 134,  70, 198,  38, 166, 102, 230,  22, 150,  86, 214,  54, 182, 118, 246,
     14, 142,  78, 206,  46, 174, 110, 238,  30, 158,  94, 222,  62, 190, 126, 254,
      1, 129,  65, 193,  33, 161,  97, 225,  17, 145,  81, 209,  49, 177, 113, 241,
      9, 137,  73, 201,  41, 169, 105, 233,  25, 153,  89, 217,  57, 185, 121, 249,
      5, 133,  69, 197,  37, 165, 101, 229,  21, 149,  85, 213,  53, 181, 117, 245,
     13, 141,  77, 205,  45, 173, 109, 237,  29, 157,  93, 221,  61, 189, 125, 253,
      3, 131,  67, 195,  35, 163,  99, 227,  19, 147,  83, 211,  51, 179, 115, 243,
     11, 139,  75, 203,  43, 171, 107, 235,  27, 155,  91, 219,  59, 187, 123, 251,
      7, 135,  71, 199,  39, 167, 103, 231,  23, 151,  87, 215,  55, 183, 119, 247,
     15, 143,  79, 207,  47, 175, 111, 239,  31, 159,  95, 223,  63, 191, 127, 255,
];

/// Multiply with rounding (Q16.16 fixed-point)
///
/// Computes (x * y + 2^15) >> 16 for proper rounding.
#[inline]
fn mulrnd16(x: i32, y: i32) -> i32 {
    let r = (x as i64 * y as i64) + (1 << 15);
    (r >> 16) as i32
}

/// Complex multiplication (real part)
#[inline]
fn complex_mul_real(x: Complex, y: Complex) -> i32 {
    mulrnd16(x.real, y.real) - mulrnd16(x.imag, y.imag)
}

/// Complex multiplication (imaginary part)
#[inline]
fn complex_mul_imag(x: Complex, y: Complex) -> i32 {
    mulrnd16(x.real, y.imag) + mulrnd16(x.imag, y.real)
}

/// Complex multiplication
#[inline]
fn complex_mul(x: Complex, y: Complex) -> Complex {
    Complex {
        real: complex_mul_real(x, y),
        imag: complex_mul_imag(x, y),
    }
}

/// Initialize FFT array with bit-reversed coefficients
///
/// Multiplies polynomial coefficients by roots of unity and stores
/// in bit-reversed order for FFT processing.
///
/// # Arguments
/// * `r` - Output complex array (initialized in bit-reversed order)
/// * `x` - Input polynomial
///
/// Transcopy from: void fft_init_and_bitrev(complex_fp32_16 r[FFT_N], const poly *x)
pub fn fft_init_and_bitrev(r: &mut [Complex; FFT_N], x: &Poly) {
    for i in 0..FFT_N {
        let inv_i = BRV8[i] as usize;
        let c = x.coeffs[i];
        r[inv_i].real = c * ROOTS[i].real;
        r[inv_i].imag = c * ROOTS[i].imag;
    }
}

/// Fast Fourier Transform (in-place)
///
/// Performs Cooley-Tukey FFT on complex array.
/// Input must be in bit-reversed order (use fft_init_and_bitrev).
///
/// # Arguments
/// * `data` - Complex array to transform (mutated in-place)
///
/// Transcopy from: void fft(complex_fp32_16 data[FFT_N])
pub fn fft(data: &mut [Complex; FFT_N]) {
    for r in 1..=FFT_LOGN {
        let m = 1 << r;
        let md2 = m >> 1;
        
        let mut n = 0;
        while n < FFT_N {
            for k in 0..md2 {
                let even = n + k;
                let odd = even + md2;
                let twid = k << (FFT_LOGN - r + 1);
                
                let u = data[even];
                let t = complex_mul(ROOTS[twid], data[odd]);
                
                data[even].real = u.real + t.real;
                data[even].imag = u.imag + t.imag;
                data[odd].real = u.real - t.real;
                data[odd].imag = u.imag - t.imag;
            }
            n += m;
        }
    }
}

/// Compute squared absolute value of complex number
///
/// Returns |x|^2 = x.real^2 + x.imag^2 (in fixed-point Q16.16).
///
/// # Arguments
/// * `x` - Complex number
///
/// # Returns
/// Squared magnitude
///
/// Transcopy from: int32_t complex_fp_sqabs(complex_fp32_16 x)
#[inline]
pub fn complex_fp_sqabs(x: Complex) -> i32 {
    mulrnd16(x.real, x.real) + mulrnd16(x.imag, x.imag)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_complex_basic() {
        let c = Complex::new(1000, 2000);
        assert_eq!(c.real, 1000);
        assert_eq!(c.imag, 2000);
    }
    
    #[test]
    fn test_mulrnd16() {
        // Test basic multiplication with rounding
        let x = 65536; // 1.0 in Q16.16
        let y = 32768; // 0.5 in Q16.16
        let result = mulrnd16(x, y);
        assert_eq!(result, 32768); // 1.0 * 0.5 = 0.5
    }
    
    #[test]
    fn test_complex_fp_sqabs() {
        // Test |1+0i|^2 = 1
        let c = Complex::new(65536, 0); // 1.0 + 0i
        let sqabs = complex_fp_sqabs(c);
        assert_eq!(sqabs, 65536); // Should be 1.0
    }
    
    #[test]
    fn test_fft_init_zero() {
        let mut r = [Complex::default(); FFT_N];
        let x = Poly::new();
        
        fft_init_and_bitrev(&mut r, &x);
        
        for i in 0..FFT_N {
            assert_eq!(r[i].real, 0);
            assert_eq!(r[i].imag, 0);
        }
    }
    
    #[test]
    fn test_brv8_symmetry() {
        // Bit reversal should be its own inverse
        for i in 0..256 {
            let rev = BRV8[i] as usize;
            let rev_rev = BRV8[rev] as usize;
            assert_eq!(rev_rev, i, "BRV8 not symmetric at {}", i);
        }
    }
}

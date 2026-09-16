//! Generic (portable) SIMD backend implementation

use crate::{Result, Error};
use super::SimdBackend;

/// Generic backend for ML-KEM operations (no SIMD)
pub struct GenericBackend;

impl GenericBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SimdBackend for GenericBackend {
    fn name(&self) -> &'static str {
        "generic"
    }
    
    fn is_available(&self) -> bool {
        true // Always available
    }
    
    fn ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        // Basic NTT implementation
        const ZETAS: [i16; 128] = [
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
            3158, 622, 1577, 182, 962, 2127, 1855, 1468,
            573, 2004, 264, 383, 2500, 1458, 1727, 3199,
            2648, 1017, 732, 608, 1787, 411, 3124, 1758,
            1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
            516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
            2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
            2931, 961, 1821, 2604, 448, 2264, 677, 2054,
            2226, 430, 555, 843, 2078, 871, 1550, 105,
            422, 587, 177, 3094, 3038, 2869, 1574, 1653,
            3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
            1739, 644, 2457, 349, 418, 329, 3173, 3254,
            817, 1097, 603, 610, 1322, 2044, 1864, 384,
            2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
            2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
            3221, 3021, 996, 991, 958, 1869, 1522, 1628,
        ];

        let mut k = 1;
        let mut len = 128;
        
        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k += 1;
                
                let mut j = start;
                while j < start + len {
                    let t = montgomery_multiply(zeta as i32, poly[j + len] as i32);
                    poly[j + len] = poly[j] - t as i16;
                    poly[j] = poly[j] + t as i16;
                    j += 1;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        
        Ok(())
    }
    
    fn inv_ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        // Basic inverse NTT implementation
        const INV_ZETAS: [i16; 128] = [
            1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
            2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
            1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
            2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
            75, 156, 3000, 2911, 2980, 872, 2685, 1590,
            2210, 602, 1846, 777, 147, 2170, 2551, 246,
            1676, 1755, 460, 291, 235, 3152, 2742, 2907,
            3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
            1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
            951, 247, 1421, 3222, 2499, 271, 90, 853,
            1860, 3203, 1162, 1618, 666, 320, 8, 2813,
            1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
            1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
            130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
            1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
            3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
        ];

        let mut k = 127;
        let mut len = 2;
        
        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = INV_ZETAS[k];
                k = k.wrapping_sub(1);
                
                let mut j = start;
                while j < start + len {
                    let t = poly[j];
                    poly[j] = barrett_reduce((t + poly[j + len]) as i32) as i16;
                    poly[j + len] = poly[j + len] - t;
                    poly[j + len] = montgomery_multiply(zeta as i32, poly[j + len] as i32) as i16;
                    j += 1;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        
        // Final multiplication by n^{-1}
        const F: i16 = 1441; // n^{-1} mod q
        for i in 0..256 {
            poly[i] = montgomery_multiply(poly[i] as i32, F as i32) as i16;
        }
        
        Ok(())
    }
    
    fn poly_basemul(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        // Pointwise multiplication in NTT domain
        for i in 0..128 {
            let (r0, r1) = basemul(
                a[2*i], a[2*i+1],
                b[2*i], b[2*i+1],
                ZETAS_BASEMUL[i]
            );
            r[2*i] = r0;
            r[2*i+1] = r1;
        }
        Ok(())
    }
    
    fn poly_add(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        for i in 0..256 {
            r[i] = a[i].wrapping_add(b[i]);
        }
        Ok(())
    }
    
    fn poly_sub(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        for i in 0..256 {
            r[i] = a[i].wrapping_sub(b[i]);
        }
        Ok(())
    }
    
    fn poly_barrett_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        for i in 0..256 {
            poly[i] = barrett_reduce(poly[i] as i32) as i16;
        }
        Ok(())
    }
    
    fn poly_montgomery_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        for i in 0..256 {
            poly[i] = montgomery_reduce(poly[i] as i32) as i16;
        }
        Ok(())
    }
    
    fn cbd_eta2(&self, poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
        if buf.len() < 512 {
            return Err(Error::InvalidInput);
        }
        
        for i in 0..256 {
            let t = load_32(&buf[4*i..]);
            let d = t & 0x55555555;
            let d = d.wrapping_add((t >> 1) & 0x55555555);
            
            let a = (d & 0x3) as i16;
            let b = ((d >> 2) & 0x3) as i16;
            poly[i] = a - b;
        }
        
        Ok(())
    }
    
    fn uniform_sample(&self, poly: &mut [i16; 256], seed: &[u8], nonce: u8) -> Result<()> {
        use sha3::{Shake128, digest::{ExtendableOutput, Update, XofReader}};
        
        let mut hasher = Shake128::default();
        hasher.update(seed);
        hasher.update(&[nonce]);
        
        let mut reader = hasher.finalize_xof();
        let mut buf = [0u8; 3];
        let mut ctr = 0;
        
        while ctr < 256 {
            reader.read(&mut buf);
            let val = ((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16)) & 0xfff;
            
            if val < 3329 {
                poly[ctr] = val as i16;
                ctr += 1;
            }
        }
        
        Ok(())
    }
    
    fn poly_compress(&self, r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()> {
        match bits {
            4 => {
                for i in 0..128 {
                    let t0 = compress_q(poly[2*i], 4);
                    let t1 = compress_q(poly[2*i+1], 4);
                    r[i] = (t0 | (t1 << 4)) as u8;
                }
            },
            10 => {
                let mut idx = 0;
                for i in 0..64 {
                    let t0 = compress_q(poly[4*i], 10);
                    let t1 = compress_q(poly[4*i+1], 10);
                    let t2 = compress_q(poly[4*i+2], 10);
                    let t3 = compress_q(poly[4*i+3], 10);
                    
                    r[idx] = t0 as u8;
                    r[idx+1] = ((t0 >> 8) | (t1 << 2)) as u8;
                    r[idx+2] = ((t1 >> 6) | (t2 << 4)) as u8;
                    r[idx+3] = ((t2 >> 4) | (t3 << 6)) as u8;
                    r[idx+4] = (t3 >> 2) as u8;
                    idx += 5;
                }
            },
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }
    
    fn poly_decompress(&self, poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()> {
        match bits {
            4 => {
                for i in 0..128 {
                    poly[2*i] = decompress_q((a[i] & 0x0F) as u16, 4);
                    poly[2*i+1] = decompress_q((a[i] >> 4) as u16, 4);
                }
            },
            10 => {
                let mut idx = 0;
                for i in 0..64 {
                    let t0 = a[idx] as u16 | ((a[idx+1] as u16 & 0x03) << 8);
                    let t1 = (a[idx+1] >> 2) as u16 | ((a[idx+2] as u16 & 0x0F) << 6);
                    let t2 = (a[idx+2] >> 4) as u16 | ((a[idx+3] as u16 & 0x3F) << 4);
                    let t3 = (a[idx+3] >> 6) as u16 | ((a[idx+4] as u16) << 2);
                    
                    poly[4*i] = decompress_q(t0, 10);
                    poly[4*i+1] = decompress_q(t1, 10);
                    poly[4*i+2] = decompress_q(t2, 10);
                    poly[4*i+3] = decompress_q(t3, 10);
                    idx += 5;
                }
            },
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }
}

// Helper functions
#[inline]
fn montgomery_multiply(a: i32, b: i32) -> i32 {
    const QINV: i32 = 62209; // q^{-1} mod 2^16
    const Q: i32 = 3329;
    
    let t = a * b;
    let u = ((t as i64 * QINV as i64) & 0xFFFF) as i32;
    ((t - u * Q) >> 16) as i32
}

#[inline]
fn montgomery_reduce(a: i32) -> i32 {
    montgomery_multiply(a, 1353) // R^2 mod q
}

#[inline]
fn barrett_reduce(a: i32) -> i32 {
    const V: i32 = 20159; // floor(2^26/q + 1/2)
    const Q: i32 = 3329;
    
    let t = ((a as i64 * V as i64) >> 26) as i32;
    a - t * Q
}

#[inline]
fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let r0 = montgomery_multiply(a1 as i32, b1 as i32);
    let r0 = montgomery_multiply(r0, zeta as i32);
    let r0 = r0 + montgomery_multiply(a0 as i32, b0 as i32);
    
    let r1 = montgomery_multiply(a0 as i32, b1 as i32);
    let r1 = r1 + montgomery_multiply(a1 as i32, b0 as i32);
    
    (r0 as i16, r1 as i16)
}

#[inline]
fn compress_q(x: i16, bits: usize) -> u16 {
    let d = 1u32 << bits;
    (((((x as u32) << bits) + 1664) / 3329) & (d - 1)) as u16
}

#[inline]
fn decompress_q(x: u16, bits: usize) -> i16 {
    ((x as u32 * 3329 + (1 << (bits - 1))) >> bits) as i16
}

#[inline]
fn load_32(x: &[u8]) -> u32 {
    u32::from_le_bytes([x[0], x[1], x[2], x[3]])
}

const ZETAS_BASEMUL: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
    3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
    516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
    2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

impl Default for GenericBackend {
    fn default() -> Self {
        Self::new()
    }
}
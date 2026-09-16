//! Compression and decompression functions for ML-KEM

use crate::polynomial::{Polynomial, N, Q};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

/// Compress polynomial coefficients
pub fn compress(poly: &Polynomial, d: usize) -> Vec<u8> {
    // Calculate output size: N coefficients * d bits / 8 bits per byte
    let output_size = (N * d + 7) / 8;  // Round up
    let mut output = vec![0u8; output_size];
    
    if d == 4 {
        // Compress to 4 bits per coefficient
        for i in 0..N/2 {
            let t0 = compress_coefficient(poly.coefficients[2*i], 4);
            let t1 = compress_coefficient(poly.coefficients[2*i+1], 4);
            output[i] = (t0 | (t1 << 4)) as u8;
        }
    } else if d == 5 {
        // Compress to 5 bits per coefficient
        let mut j = 0;
        for i in 0..N/8 {
            for k in 0..8 {
                let t = compress_coefficient(poly.coefficients[8*i+k], 5);
                output[j] |= (t << (5 * (k % 8) % 8)) as u8;
                if (5 * (k % 8) % 8) > 3 {
                    j += 1;
                    if j < output.len() {
                        output[j] = (t >> (8 - (5 * (k % 8) % 8))) as u8;
                    }
                }
            }
            j += 1;
        }
    } else if d == 10 {
        // Compress to 10 bits per coefficient
        let mut j = 0;
        for i in 0..N/4 {
            let t0 = compress_coefficient(poly.coefficients[4*i], 10);
            let t1 = compress_coefficient(poly.coefficients[4*i+1], 10);
            let t2 = compress_coefficient(poly.coefficients[4*i+2], 10);
            let t3 = compress_coefficient(poly.coefficients[4*i+3], 10);
            
            output[j] = (t0 & 0xff) as u8;
            output[j+1] = ((t0 >> 8) | ((t1 & 0x3f) << 2)) as u8;
            output[j+2] = ((t1 >> 6) | ((t2 & 0x0f) << 4)) as u8;
            output[j+3] = ((t2 >> 4) | ((t3 & 0x03) << 6)) as u8;
            output[j+4] = (t3 >> 2) as u8;
            j += 5;
        }
    } else if d == 11 {
        // Compress to 11 bits per coefficient
        // 256 coefficients * 11 bits = 2816 bits = 352 bytes
        let mut bit_idx = 0;
        for i in 0..N {
            let t = compress_coefficient(poly.coefficients[i], 11) as u32;
            
            // Pack 11 bits into the output array
            for bit in 0..11 {
                if (t >> bit) & 1 == 1 {
                    let byte_idx = bit_idx / 8;
                    let bit_offset = bit_idx % 8;
                    if byte_idx < output.len() {
                        output[byte_idx] |= 1 << bit_offset;
                    }
                }
                bit_idx += 1;
            }
        }
    }
    
    output
}

/// Decompress polynomial coefficients
pub fn decompress(input: &[u8], d: usize) -> Polynomial {
    let mut poly = Polynomial::zero();
    
    if d == 4 {
        // Decompress from 4 bits per coefficient
        for i in 0..N/2 {
            poly.coefficients[2*i] = decompress_coefficient((input[i] & 0x0f) as u16, 4);
            poly.coefficients[2*i+1] = decompress_coefficient((input[i] >> 4) as u16, 4);
        }
    } else if d == 5 {
        // Decompress from 5 bits per coefficient
        let mut j = 0;
        for i in 0..N/8 {
            for k in 0..8 {
                let mut t = (input[j] >> (5 * k % 8)) as u16;
                if (5 * k % 8) > 3 {
                    j += 1;
                    if j < input.len() {
                        t |= (input[j] << (8 - (5 * k % 8))) as u16;
                    }
                }
                poly.coefficients[8*i+k] = decompress_coefficient(t & 0x1f, 5);
            }
            j += 1;
        }
    } else if d == 10 {
        // Decompress from 10 bits per coefficient
        let mut j = 0;
        for i in 0..N/4 {
            let t0 = (input[j] as u16) | ((input[j+1] as u16 & 0x03) << 8);
            let t1 = ((input[j+1] as u16) >> 2) | ((input[j+2] as u16 & 0x0f) << 6);
            let t2 = ((input[j+2] as u16) >> 4) | ((input[j+3] as u16 & 0x3f) << 4);
            let t3 = ((input[j+3] as u16) >> 6) | ((input[j+4] as u16) << 2);
            
            poly.coefficients[4*i] = decompress_coefficient(t0, 10);
            poly.coefficients[4*i+1] = decompress_coefficient(t1, 10);
            poly.coefficients[4*i+2] = decompress_coefficient(t2, 10);
            poly.coefficients[4*i+3] = decompress_coefficient(t3, 10);
            j += 5;
        }
    } else if d == 11 {
        // Decompress from 11 bits per coefficient
        let mut bit_idx = 0;
        for i in 0..N {
            let mut t = 0u16;
            
            // Extract 11 bits from the input array
            for bit in 0..11 {
                let byte_idx = bit_idx / 8;
                let bit_offset = bit_idx % 8;
                if byte_idx < input.len() {
                    if (input[byte_idx] >> bit_offset) & 1 == 1 {
                        t |= 1 << bit;
                    }
                }
                bit_idx += 1;
            }
            
            poly.coefficients[i] = decompress_coefficient(t, 11);
        }
    }
    
    poly
}

/// Compress a single coefficient
fn compress_coefficient(x: i16, d: usize) -> u16 {
    // Normalize to [0, Q) using Kyber's method
    let mut t = x;
    t += (t >> 15) & Q;  // Add Q if negative
    let x = t as u32;
    // Round and compress
    let t = (x << d) + (Q as u32 / 2);
    ((t / Q as u32) & ((1 << d) - 1)) as u16
}

/// Decompress a single coefficient
fn decompress_coefficient(x: u16, d: usize) -> i16 {
    ((x as u32 * Q as u32 + (1 << (d - 1))) >> d) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compress_decompress() {
        let mut poly = Polynomial::zero();
        for i in 0..N {
            poly.coefficients[i] = ((i * 17) % Q as usize) as i16;
        }
        
        // Test different compression levels
        for d in &[4, 5, 10, 11] {
            let compressed = compress(&poly, *d);
            let decompressed = decompress(&compressed, *d);
            
            // Check that decompression is approximately correct
            for i in 0..N {
                // Normalize both values to [0, Q) for comparison
                let orig = if poly.coefficients[i] < 0 {
                    poly.coefficients[i] + Q
                } else {
                    poly.coefficients[i] % Q
                };
                let decomp = if decompressed.coefficients[i] < 0 {
                    decompressed.coefficients[i] + Q
                } else {
                    decompressed.coefficients[i] % Q
                };
                
                let diff = (orig - decomp).abs();
                // Allow for compression loss - the error should be at most Q/(2^d)
                let max_error = Q / (1 << d) + 1;  // Add 1 for rounding
                assert!(diff <= max_error || diff >= Q - max_error, 
                        "Compression error too large at index {}: orig={}, decomp={}, diff={}, max_error={}", 
                        i, orig, decomp, diff, max_error);
            }
        }
    }
}
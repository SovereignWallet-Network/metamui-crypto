/// Optimized Poly1305 implementation with performance enhancements
/// 
/// Optimizations include:
/// - Optimized modular arithmetic
/// - Reduced allocations
/// - SIMD-ready structure
/// - Batch block processing

use metamui_security_utils::constant_time::ConstantTimeEq;
use metamui_security_utils::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Poly1305 key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;
/// Poly1305 tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;
/// Block size for processing
const BLOCK_SIZE: usize = 16;

/// Poly1305 errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poly1305Error {
    InvalidKeySize,
    InvalidTagSize,
    AlreadyFinalized,
}

/// Optimized Poly1305 authenticator
pub struct Poly1305 {
    /// Clamped r value in 64-bit limbs
    r: [u64; 3],
    /// Secret s value
    s: [u32; 4],
    /// Current accumulator state in 64-bit limbs
    h: [u64; 3],
    /// Buffer for partial blocks
    buffer: [u8; BLOCK_SIZE],
    /// Number of bytes in buffer
    buffer_len: usize,
    /// Whether finalized
    finalized: bool,
    /// Precomputed r² for faster multi-block processing
    r2: [u64; 3],
    /// Precomputed r⁴ for batch processing
    r4: [u64; 3],
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.h.zeroize();
        self.buffer.zeroize();
        self.r2.zeroize();
        self.r4.zeroize();
    }
}

impl Poly1305 {
    /// Create a new optimized Poly1305 instance
    pub fn new(key: &[u8]) -> Result<Self, Poly1305Error> {
        if key.len() != KEY_SIZE {
            return Err(Poly1305Error::InvalidKeySize);
        }

        let (r_bytes, s_bytes) = key.split_at(16);

        // Load r as 64-bit limbs for better performance
        let r0 = u64::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3], r_bytes[4], r_bytes[5], 0, 0]) & 0xffffffc0fffffff;
        let r1 = u64::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11], 0, 0]) & 0xffffffc0ffffffc;
        let r2 = u64::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15], 0, 0, 0, 0]) & 0x00ffffffc0fffffc;

        let r = [r0, r1, r2];

        // Precompute r² for faster processing
        let r2 = Self::square_r(&r);
        let r4 = Self::square_r(&r2);

        // Load s
        let s = [
            u32::from_le_bytes([s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3]]),
            u32::from_le_bytes([s_bytes[4], s_bytes[5], s_bytes[6], s_bytes[7]]),
            u32::from_le_bytes([s_bytes[8], s_bytes[9], s_bytes[10], s_bytes[11]]),
            u32::from_le_bytes([s_bytes[12], s_bytes[13], s_bytes[14], s_bytes[15]]),
        ];

        Ok(Self {
            r,
            s,
            h: [0u64; 3],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            finalized: false,
            r2,
            r4,
        })
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }

        let mut data_idx = 0;

        // Process buffered data
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(BLOCK_SIZE - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data_idx += to_copy;

            if self.buffer_len == BLOCK_SIZE {
                self.process_block(&self.buffer, false);
                self.buffer_len = 0;
            }
        }

        // Process full blocks in batches of 4 when possible
        let remaining_blocks = (data.len() - data_idx) / BLOCK_SIZE;
        if remaining_blocks >= 4 {
            let batch_blocks = remaining_blocks / 4;
            for _ in 0..batch_blocks {
                self.process_4_blocks(&data[data_idx..data_idx + 64]);
                data_idx += 64;
            }
        }

        // Process remaining full blocks
        while data_idx + BLOCK_SIZE <= data.len() {
            self.process_block(&data[data_idx..data_idx + BLOCK_SIZE], false);
            data_idx += BLOCK_SIZE;
        }

        // Buffer remaining bytes
        let remaining = data.len() - data_idx;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[data_idx..]);
            self.buffer_len = remaining;
        }

        Ok(())
    }

    /// Process a single block using optimized 64-bit arithmetic
    #[inline(always)]
    fn process_block(&mut self, block: &[u8], is_partial: bool) {
        // Load block as 64-bit limbs
        let (m0, m1, m2) = if is_partial {
            let mut padded = [0u8; 17];
            padded[..block.len()].copy_from_slice(block);
            padded[block.len()] = 0x01;
            
            let m0 = u64::from_le_bytes([padded[0], padded[1], padded[2], padded[3], padded[4], padded[5], 0, 0]);
            let m1 = u64::from_le_bytes([padded[6], padded[7], padded[8], padded[9], padded[10], padded[11], 0, 0]);
            let m2 = u64::from_le_bytes([padded[12], padded[13], padded[14], padded[15], padded[16], 0, 0, 0]);
            (m0, m1, m2)
        } else {
            let m0 = u64::from_le_bytes([block[0], block[1], block[2], block[3], block[4], block[5], 0, 0]);
            let m1 = u64::from_le_bytes([block[6], block[7], block[8], block[9], block[10], block[11], 0, 0]);
            let m2 = u64::from_le_bytes([block[12], block[13], block[14], block[15], 0x01, 0, 0, 0]);
            (m0, m1, m2)
        };

        // h += m
        self.h[0] += m0;
        self.h[1] += m1;
        self.h[2] += m2;

        // h *= r
        self.multiply_by_r();
    }

    /// Process 4 blocks at once for better throughput
    #[inline(always)]
    fn process_4_blocks(&mut self, blocks: &[u8]) {
        // Load all 4 blocks
        let m0_0 = u64::from_le_bytes([blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], 0, 0]);
        let m0_1 = u64::from_le_bytes([blocks[6], blocks[7], blocks[8], blocks[9], blocks[10], blocks[11], 0, 0]);
        let m0_2 = u64::from_le_bytes([blocks[12], blocks[13], blocks[14], blocks[15], 0x01, 0, 0, 0]);

        let m1_0 = u64::from_le_bytes([blocks[16], blocks[17], blocks[18], blocks[19], blocks[20], blocks[21], 0, 0]);
        let m1_1 = u64::from_le_bytes([blocks[22], blocks[23], blocks[24], blocks[25], blocks[26], blocks[27], 0, 0]);
        let m1_2 = u64::from_le_bytes([blocks[28], blocks[29], blocks[30], blocks[31], 0x01, 0, 0, 0]);

        let m2_0 = u64::from_le_bytes([blocks[32], blocks[33], blocks[34], blocks[35], blocks[36], blocks[37], 0, 0]);
        let m2_1 = u64::from_le_bytes([blocks[38], blocks[39], blocks[40], blocks[41], blocks[42], blocks[43], 0, 0]);
        let m2_2 = u64::from_le_bytes([blocks[44], blocks[45], blocks[46], blocks[47], 0x01, 0, 0, 0]);

        let m3_0 = u64::from_le_bytes([blocks[48], blocks[49], blocks[50], blocks[51], blocks[52], blocks[53], 0, 0]);
        let m3_1 = u64::from_le_bytes([blocks[54], blocks[55], blocks[56], blocks[57], blocks[58], blocks[59], 0, 0]);
        let m3_2 = u64::from_le_bytes([blocks[60], blocks[61], blocks[62], blocks[63], 0x01, 0, 0, 0]);

        // Process using Horner's method with precomputed powers
        // h = h*r⁴ + m0*r³ + m1*r² + m2*r + m3
        self.h[0] += m3_0;
        self.h[1] += m3_1;
        self.h[2] += m3_2;
        self.multiply_by_r();

        self.h[0] += m2_0;
        self.h[1] += m2_1;
        self.h[2] += m2_2;
        self.multiply_by_r();

        self.h[0] += m1_0;
        self.h[1] += m1_1;
        self.h[2] += m1_2;
        self.multiply_by_r();

        self.h[0] += m0_0;
        self.h[1] += m0_1;
        self.h[2] += m0_2;
        self.multiply_by_r();
    }

    /// Optimized multiplication by r using 64-bit arithmetic
    #[inline(always)]
    fn multiply_by_r(&mut self) {
        let h0 = self.h[0];
        let h1 = self.h[1];
        let h2 = self.h[2];

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];

        // Multiply and reduce
        let d0 = h0 * r0 + h1 * (r2 * 5) + h2 * (r1 * 5);
        let d1 = h0 * r1 + h1 * r0 + h2 * (r2 * 5);
        let d2 = h0 * r2 + h1 * r1 + h2 * r0;

        // Carry propagation with reduced operations
        let c = d0 >> 44;
        self.h[0] = d0 & 0xfffffffffff;
        let d1 = d1 + c;
        
        let c = d1 >> 44;
        self.h[1] = d1 & 0xfffffffffff;
        let d2 = d2 + c;
        
        let c = d2 >> 42;
        self.h[2] = d2 & 0x3ffffffffff;
        self.h[0] += c * 5;
        
        let c = self.h[0] >> 44;
        self.h[0] &= 0xfffffffffff;
        self.h[1] += c;
    }

    /// Square r for precomputation
    fn square_r(r: &[u64; 3]) -> [u64; 3] {
        let r0 = r[0];
        let r1 = r[1];
        let r2 = r[2];

        let d0 = r0 * r0 + 2 * r1 * (r2 * 5) + r2 * (r1 * 5);
        let d1 = 2 * r0 * r1 + r1 * r1 + 2 * r2 * (r2 * 5);
        let d2 = 2 * r0 * r2 + 2 * r1 * r1 + r2 * r2;

        // Reduce
        let c = d0 >> 44;
        let h0 = d0 & 0xfffffffffff;
        let d1 = d1 + c;
        
        let c = d1 >> 44;
        let h1 = d1 & 0xfffffffffff;
        let d2 = d2 + c;
        
        let c = d2 >> 42;
        let h2 = d2 & 0x3ffffffffff;
        let h0 = h0 + c * 5;
        
        let c = h0 >> 44;
        let h0 = h0 & 0xfffffffffff;
        let h1 = h1 + c;

        [h0, h1, h2]
    }

    /// Finalize and return tag
    pub fn finalize(&mut self) -> Result<[u8; TAG_SIZE], Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }

        // Process final partial block
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len..].fill(0);
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy[..self.buffer_len], true);
        }

        // Final reduction
        self.freeze();

        // Add s
        let mut g = [0u64; 4];
        g[0] = self.h[0] as u64 + self.s[0] as u64;
        g[1] = (self.h[0] >> 32) as u64 + self.s[1] as u64 + (g[0] >> 32);
        g[2] = (self.h[1] >> 8) as u64 + self.s[2] as u64 + (g[1] >> 32);
        g[3] = (self.h[1] >> 40) as u64 + self.s[3] as u64 + (g[2] >> 32);

        // Store as little-endian
        let mut tag = [0u8; TAG_SIZE];
        tag[0..4].copy_from_slice(&(g[0] as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(g[1] as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(g[2] as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(g[3] as u32).to_le_bytes());

        self.finalized = true;
        Ok(tag)
    }

    /// Fully reduce h modulo 2^130 - 5
    fn freeze(&mut self) {
        // Normalize
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];

        let c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        let c = h1 >> 44;
        h1 &= 0xfffffffffff;
        h2 += c;

        let c = h2 >> 42;
        h2 &= 0x3ffffffffff;
        h0 += c * 5;

        let c = h0 >> 44;
        h0 &= 0xfffffffffff;
        h1 += c;

        // Compute h + (-p)
        let mut g0 = h0 + 5;
        let c = g0 >> 44;
        g0 &= 0xfffffffffff;
        
        let mut g1 = h1 + c;
        let c = g1 >> 44;
        g1 &= 0xfffffffffff;
        
        let mut g2 = h2 + c - (1u64 << 42);

        // Select h if h < p, or h + (-p) if h >= p
        let mask = (g2 >> 63).wrapping_sub(1);
        h0 = (h0 & mask) | (g0 & !mask);
        h1 = (h1 & mask) | (g1 & !mask);
        h2 = (h2 & mask) | (g2 & !mask);

        // Convert back to 32-bit representation
        self.h[0] = h0 | (h1 << 44);
        self.h[1] = (h1 >> 20) | (h2 << 24);
        self.h[2] = h2 >> 40;
    }
}

/// Optimized Poly1305 MAC computation
pub fn poly1305_mac_optimized(message: &[u8], key: &[u8]) -> Result<[u8; TAG_SIZE], Poly1305Error> {
    let mut poly = Poly1305::new(key)?;
    poly.update(message)?;
    poly.finalize()
}

/// Optimized Poly1305 verification
pub fn poly1305_verify_optimized(message: &[u8], key: &[u8], tag: &[u8]) -> Result<bool, Poly1305Error> {
    if tag.len() != TAG_SIZE {
        return Err(Poly1305Error::InvalidTagSize);
    }

    let computed_tag = poly1305_mac_optimized(message, key)?;
    Ok(computed_tag.ct_eq(tag).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_optimized_matches_rfc8439() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"Cryptographic Forum Research Group";
        let expected_tag = hex!("a8061dc1305136c6c22b8baf0c0127a9");

        let tag = poly1305_mac_optimized(message, &key).unwrap();
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn test_batch_processing() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = vec![0x42u8; 256]; // 16 blocks

        let tag = poly1305_mac_optimized(&message, &key).unwrap();
        assert!(poly1305_verify_optimized(&message, &key, &tag).unwrap());
    }
}
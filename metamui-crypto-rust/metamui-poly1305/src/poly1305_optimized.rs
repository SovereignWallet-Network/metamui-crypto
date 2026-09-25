//! Optimized Poly1305 implementation using 64-bit arithmetic
//!
//! This implementation uses five 26-bit limbs for efficient computation
//! on 64-bit platforms.

use crate::{Poly1305Error, KEY_SIZE, TAG_SIZE};
use metamui_security_utils::{Zeroize, ZeroizeOnDrop};

/// Optimized Poly1305 using 64-bit limb arithmetic
#[derive(Debug)]
pub struct Poly1305Optimized {
    /// R value as 5 26-bit limbs
    r: [u64; 5],
    /// S value as bytes
    s: [u8; 16],
    /// Accumulator as 5 26-bit limbs
    h: [u64; 5],
    /// Buffered data
    buffer: [u8; 16],
    /// Buffer length
    buffer_len: usize,
    /// Whether finalized
    finalized: bool,
}

impl Drop for Poly1305Optimized {
    fn drop(&mut self) {
        self.r = [0u64; 5];
        self.s.zeroize();
        self.h = [0u64; 5];
        self.buffer.zeroize();
    }
}

impl Zeroize for Poly1305Optimized {
    fn zeroize(&mut self) {
        self.r = [0u64; 5];
        self.s.zeroize();
        self.h = [0u64; 5];
        self.buffer.zeroize();
        self.buffer_len = 0;
        self.finalized = false;
    }
}

impl ZeroizeOnDrop for Poly1305Optimized {}

impl Poly1305Optimized {
    /// Create a new optimized Poly1305 instance
    pub fn new(key: &[u8]) -> Result<Self, Poly1305Error> {
        if key.len() != KEY_SIZE {
            return Err(Poly1305Error::InvalidKeySize);
        }

        let mut r_bytes = [0u8; 16];
        let mut s = [0u8; 16];
        
        r_bytes.copy_from_slice(&key[0..16]);
        s.copy_from_slice(&key[16..32]);
        
        // Clamp r according to RFC 8439
        r_bytes[3] &= 0x0f;
        r_bytes[7] &= 0x0f;
        r_bytes[11] &= 0x0f;
        r_bytes[15] &= 0x0f;
        r_bytes[4] &= 0xfc;
        r_bytes[8] &= 0xfc;
        r_bytes[12] &= 0xfc;

        // Convert r to 26-bit limbs
        let r = bytes_to_limbs(&r_bytes);

        Ok(Self {
            r,
            s,
            h: [0; 5],
            buffer: [0; 16],
            buffer_len: 0,
            finalized: false,
        })
    }

    /// Update with message data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }

        let mut offset = 0;
        
        // Process buffered data if we can make a full block
        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..].copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block, false);
                offset = needed;
                self.buffer_len = 0;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()]
                    .copy_from_slice(data);
                self.buffer_len += data.len();
                return Ok(());
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            let block = &data[offset..offset + 16];
            self.process_block(block, false);
            offset += 16;
        }

        // Buffer remaining data
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }

        Ok(())
    }

    /// Process a single block
    fn process_block(&mut self, block: &[u8], is_last: bool) {
        // Convert block to limbs and add high bit
        let mut n = bytes_to_limbs(block);
        if !is_last {
            n[4] += 1 << 24; // Add 2^128
        }

        // h = (h + n) * r mod (2^130 - 5)
        add_limbs(&mut self.h, &n);
        mul_limbs(&mut self.h, &self.r);
        reduce(&mut self.h);
    }

    /// Finalize and return the authentication tag
    pub fn finalize(mut self) -> Result<[u8; TAG_SIZE], Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }

        // Process final partial block if any
        if self.buffer_len > 0 {
            self.buffer[self.buffer_len] = 0x01;
            for i in self.buffer_len + 1..16 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.process_block(&block, true);
        }

        // Final reduction
        freeze(&mut self.h);

        // Convert h to bytes and add s
        let mut tag = limbs_to_bytes(&self.h);
        add_bytes(&mut tag, &self.s);

        self.finalized = true;
        Ok(tag)
    }
}

/// Convert bytes to 26-bit limbs (little-endian)
fn bytes_to_limbs(bytes: &[u8]) -> [u64; 5] {
    let mut limbs = [0u64; 5];
    
    limbs[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64 & 0x3ffffff;
    limbs[1] = (u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as u64 >> 2) & 0x3ffffff;
    limbs[2] = (u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as u64 >> 4) & 0x3ffffff;
    limbs[3] = (u32::from_le_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]) as u64 >> 6) & 0x3ffffff;
    limbs[4] = (u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as u64 >> 8) & 0x3ffffff;
    
    limbs
}

/// Convert 26-bit limbs to bytes (little-endian)
///
/// Reconstructs the 130-bit value from 5 limbs into 4 non-overlapping 32-bit words.
fn limbs_to_bytes(limbs: &[u64; 5]) -> [u8; 16] {
    let h0 = limbs[0];
    let h1 = limbs[1];
    let h2 = limbs[2];
    let h3 = limbs[3];
    let h4 = limbs[4];

    // Combine limbs into 32-bit words (non-overlapping writes)
    let f0 = (h0 | (h1 << 26)) as u32;
    let f1 = ((h1 >> 6) | (h2 << 20)) as u32;
    let f2 = ((h2 >> 12) | (h3 << 14)) as u32;
    let f3 = ((h3 >> 18) | (h4 << 8)) as u32;

    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&f0.to_le_bytes());
    bytes[4..8].copy_from_slice(&f1.to_le_bytes());
    bytes[8..12].copy_from_slice(&f2.to_le_bytes());
    bytes[12..16].copy_from_slice(&f3.to_le_bytes());

    bytes
}

/// Add limbs
fn add_limbs(h: &mut [u64; 5], n: &[u64; 5]) {
    h[0] += n[0];
    h[1] += n[1];
    h[2] += n[2];
    h[3] += n[3];
    h[4] += n[4];
}

/// Multiply limbs (h *= r)
fn mul_limbs(h: &mut [u64; 5], r: &[u64; 5]) {
    let h0 = h[0];
    let h1 = h[1];
    let h2 = h[2];
    let h3 = h[3];
    let h4 = h[4];
    
    let r0 = r[0];
    let r1 = r[1];
    let r2 = r[2];
    let r3 = r[3];
    let r4 = r[4];
    
    // Multiply and accumulate
    let mut d0 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1);
    let mut d1 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2);
    let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3);
    let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4);
    let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    
    // Carry propagation
    let mut c: u64;
    c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;
    c = d1 >> 26; d1 &= 0x3ffffff; d2 += c;
    c = d2 >> 26; d2 &= 0x3ffffff; d3 += c;
    c = d3 >> 26; d3 &= 0x3ffffff; d4 += c;
    c = d4 >> 26; d4 &= 0x3ffffff; d0 += c * 5;
    c = d0 >> 26; d0 &= 0x3ffffff; d1 += c;
    
    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
}

/// Reduce modulo 2^130 - 5
fn reduce(h: &mut [u64; 5]) {
    let mut c: u64;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
}

/// Final reduction (freeze)
fn freeze(h: &mut [u64; 5]) {
    reduce(h);
    reduce(h);
    
    // Check if h >= 2^130 - 5
    let mut g = [0u64; 5];
    g[0] = h[0] + 5;
    let mut c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + c;
    c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c;
    c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + c;
    c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = (h[4] + c).wrapping_sub(1 << 26);

    // Select h or g based on whether g[4] has the high bit set
    // If h >= p: g didn't underflow, bit 63 clear, mask = all-ones → select g (reduced value)
    // If h < p:  g underflowed, bit 63 set, mask = 0 → keep h unchanged
    let mask = (g[4] >> 63).wrapping_sub(1);
    h[0] = (h[0] & !mask) | (g[0] & mask);
    h[1] = (h[1] & !mask) | (g[1] & mask);
    h[2] = (h[2] & !mask) | (g[2] & mask);
    h[3] = (h[3] & !mask) | (g[3] & mask);
    h[4] = (h[4] & !mask) | (g[4] & mask);
}

/// Add bytes (for adding s to the tag)
fn add_bytes(tag: &mut [u8; 16], s: &[u8; 16]) {
    let mut carry = 0u32;
    for i in 0..16 {
        carry += tag[i] as u32 + s[i] as u32;
        tag[i] = carry as u8;
        carry >>= 8;
    }
}

/// Compute optimized Poly1305 MAC
pub fn poly1305_mac_optimized(message: &[u8], key: &[u8]) -> Result<[u8; TAG_SIZE], Poly1305Error> {
    let mut poly = Poly1305Optimized::new(key)?;
    poly.update(message)?;
    poly.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_optimized_rfc8439_vector() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"Cryptographic Forum Research Group";
        let expected_tag = hex!("a8061dc1305136c6c22b8baf0c0127a9");

        let tag = poly1305_mac_optimized(message, &key).unwrap();
        assert_eq!(tag, expected_tag);
    }
}
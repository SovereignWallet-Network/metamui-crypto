//! Blake2b permutation for Argon2
//!
//! This module implements the Blake2b-based permutation used in Argon2,
//! specifically the BlaMka variant used for the compression function.
//!
//! Several constants (BLAKE2B_KEYBYTES / SALTBYTES / PERSONALBYTES) and
//! helper functions (rotr64, g, g_blake2) are kept as spec-documented
//! primitives even though the current compression hot path inlines
//! equivalent logic through the `blake2b_long` routine.

#![allow(dead_code)]

extern crate alloc;
use alloc::string::String;

use crate::types::Block;

const BLAKE2B_BLOCKBYTES: usize = 128;
const BLAKE2B_OUTBYTES: usize = 64;
const BLAKE2B_KEYBYTES: usize = 64;
const BLAKE2B_SALTBYTES: usize = 16;
const BLAKE2B_PERSONALBYTES: usize = 16;

/// Rotate right for u64
// ============================================================================
// SECTION 1: BlaMka Functions (Argon2-specific modifications to Blake2b)
// Used for Argon2's block compression function
// ============================================================================

#[inline(always)]
fn rotr64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

/// BlaMka multiplication function
/// Designed by the Lyra PHC team for improved diffusion
#[inline(always)]
fn f_blamka(x: u64, y: u64) -> u64 {
    let m = 0xFFFFFFFFu64;
    let xy = (x & m).wrapping_mul(y & m);
    x.wrapping_add(y).wrapping_add(xy.wrapping_mul(2))
}

/// G function for Blake2b round (BlaMka variant)
#[inline(always)]
fn g(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64) {
    *a = f_blamka(*a, *b);
    *d = rotr64(*d ^ *a, 32);
    *c = f_blamka(*c, *d);
    *b = rotr64(*b ^ *c, 24);
    *a = f_blamka(*a, *b);
    *d = rotr64(*d ^ *a, 16);
    *c = f_blamka(*c, *d);
    *b = rotr64(*b ^ *c, 63);
}

/// Blake2b round function without message (for Argon2)
/// This applies the G function to all columns and diagonals
pub fn blake2b_round_nomsg(v: &mut [u64; 16]) {
    // Column step
    g_indexed(v, 0, 4, 8, 12);
    g_indexed(v, 1, 5, 9, 13);
    g_indexed(v, 2, 6, 10, 14);
    g_indexed(v, 3, 7, 11, 15);
    
    // Diagonal step
    g_indexed(v, 0, 5, 10, 15);
    g_indexed(v, 1, 6, 11, 12);
    g_indexed(v, 2, 7, 8, 13);
    g_indexed(v, 3, 4, 9, 14);
}

/// Helper for G function that works with array indices
/// This uses f_blamka for the additions (Argon2 variant)
fn g_indexed(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = f_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = f_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = f_blamka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = f_blamka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Apply Blake2b permutation to a block
/// This is the core of the Argon2 compression function
pub fn permute_block(block: &mut Block) {
    // Apply Blake2 rounds on columns (0,1,...,15), (16,17,...,31), etc.
    for i in 0..8 {
        let offset = i * 16;
        // Create a temporary array to work with
        let mut v = [0u64; 16];
        for j in 0..16 {
            v[j] = block.v[offset + j];
        }
        
        // Apply the round function
        blake2b_round_nomsg(&mut v);
        
        // Copy back
        for j in 0..16 {
            block.v[offset + j] = v[j];
        }
    }
    
    // Apply Blake2 rounds on rows (0,1,16,17,...,112,113), (2,3,18,19,...,114,115), etc.
    for i in 0..8 {
        let idx = i * 2;
        // Create a temporary array to work with
        let mut v = [0u64; 16];
        v[0] = block.v[idx + 0];
        v[1] = block.v[idx + 1];
        v[2] = block.v[idx + 16];
        v[3] = block.v[idx + 17];
        v[4] = block.v[idx + 32];
        v[5] = block.v[idx + 33];
        v[6] = block.v[idx + 48];
        v[7] = block.v[idx + 49];
        v[8] = block.v[idx + 64];
        v[9] = block.v[idx + 65];
        v[10] = block.v[idx + 80];
        v[11] = block.v[idx + 81];
        v[12] = block.v[idx + 96];
        v[13] = block.v[idx + 97];
        v[14] = block.v[idx + 112];
        v[15] = block.v[idx + 113];
        
        blake2b_round_nomsg(&mut v);
        
        // Copy back
        block.v[idx + 0] = v[0];
        block.v[idx + 1] = v[1];
        block.v[idx + 16] = v[2];
        block.v[idx + 17] = v[3];
        block.v[idx + 32] = v[4];
        block.v[idx + 33] = v[5];
        block.v[idx + 48] = v[6];
        block.v[idx + 49] = v[7];
        block.v[idx + 64] = v[8];
        block.v[idx + 65] = v[9];
        block.v[idx + 80] = v[10];
        block.v[idx + 81] = v[11];
        block.v[idx + 96] = v[12];
        block.v[idx + 97] = v[13];
        block.v[idx + 112] = v[14];
        block.v[idx + 113] = v[15];
    }
}

/// Blake2b IV constants
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Blake2b sigma permutation for mixing
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Blake2b state
struct Blake2bState {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    buf: [u8; BLAKE2B_BLOCKBYTES],
    buflen: usize,
    outlen: usize,
}

impl Blake2bState {
    fn new(outlen: usize) -> Self {
        let mut h = BLAKE2B_IV;
        h[0] ^= 0x01010000 ^ (0 << 8) ^ outlen as u64;
        
        Blake2bState {
            h,
            t: [0, 0],
            f: [0, 0],
            buf: [0; BLAKE2B_BLOCKBYTES],
            buflen: 0,
            outlen,
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut offset = 0;
        let left = BLAKE2B_BLOCKBYTES - self.buflen;

        // If we have buffered data and new data overflows the buffer
        if self.buflen > 0 && data.len() > left {
            self.buf[self.buflen..BLAKE2B_BLOCKBYTES].copy_from_slice(&data[..left]);
            self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
            self.compress();
            self.buflen = 0;
            offset = left;
        }

        // Process full blocks, but always keep at least one byte for finalize
        while offset + BLAKE2B_BLOCKBYTES < data.len() {
            self.buf.copy_from_slice(&data[offset..offset + BLAKE2B_BLOCKBYTES]);
            self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
            self.compress();
            offset += BLAKE2B_BLOCKBYTES;
        }

        // Buffer remaining data (always non-empty if we still have input)
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buf[self.buflen..self.buflen + remaining].copy_from_slice(&data[offset..]);
            self.buflen += remaining;
        }
    }
    
    fn finalize(&mut self, out: &mut [u8]) {
        // Set last block flag
        self.f[0] = !0;
        
        // Pad final block with zeros
        for i in self.buflen..BLAKE2B_BLOCKBYTES {
            self.buf[i] = 0;
        }
        
        self.increment_counter(self.buflen as u64);
        self.compress();
        
        // Output - proper little-endian extraction
        let out_bytes = core::cmp::min(self.outlen, out.len());
        for i in 0..out_bytes {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            if word_idx < self.h.len() {
                out[i] = (self.h[word_idx] >> (byte_idx * 8)) as u8;
            }
        }
    }
    
    fn increment_counter(&mut self, inc: u64) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }
    
    fn compress(&mut self) {
        let mut m = [0u64; 16];
        let mut v = [0u64; 16];
        
        // Load message block into m
        for i in 0..16 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.buf[i * 8..(i + 1) * 8]);
            m[i] = u64::from_le_bytes(bytes);
        }
        
        // Initialize working variables
        for i in 0..8 {
            v[i] = self.h[i];
        }
        for i in 0..8 {
            v[i + 8] = BLAKE2B_IV[i];
        }
        
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        v[14] ^= self.f[0];
        v[15] ^= self.f[1];
        
        // Cryptographic mixing
        for round in 0..12 {
            // Apply G function using manual indexing to avoid borrow issues
            let sigma = &SIGMA[round];
            
            // Mix columns
            g_blake2_indexed(&mut v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]]);
            g_blake2_indexed(&mut v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]]);
            g_blake2_indexed(&mut v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]]);
            g_blake2_indexed(&mut v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]]);
            
            // Mix diagonals
            g_blake2_indexed(&mut v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]]);
            g_blake2_indexed(&mut v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]]);
            g_blake2_indexed(&mut v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]]);
            g_blake2_indexed(&mut v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]]);
        }
        
        // Update hash
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

// ============================================================================  
// SECTION 2: Standard Blake2b Functions (RFC 7693 compliant)
// Used for Blake2b-long hash function and variable-length output
// ============================================================================

/// Original Blake2b G function for the hash
fn g_blake2(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, x: u64, y: u64) {
    *a = a.wrapping_add(*b).wrapping_add(x);
    *d = (*d ^ *a).rotate_right(32);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(24);
    *a = a.wrapping_add(*b).wrapping_add(y);
    *d = (*d ^ *a).rotate_right(16);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_right(63);
}

/// Helper function for g_blake2 that works with array indices
fn g_blake2_indexed(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Blake2b-long (H') for arbitrary length output per RFC 9106 Section 3.2
/// Uses standard Blake2b compression (RFC 7693), not BlaMka variant.
///
/// H'^T(A) = Blake2b-T(LE32(T) || A)                      if T <= 64
/// H'^T(A) = A1[0..32] || ... || Ar[0..32] || A_{r+1}     if T > 64
///   where A1 = Blake2b-64(LE32(T) || A), Ai = Blake2b-64(A_{i-1}),
///   r = ceil(T/32) - 2, A_{r+1} = Blake2b-(T-32*r)(Ar)
pub fn blake2b_long(out: &mut [u8], input: &[u8]) -> Result<(), String> {
    let outlen = out.len();

    if outlen <= BLAKE2B_OUTBYTES {
        // Simple case: output fits in one Blake2b call
        // H'^T(A) = Blake2b-T(LE32(T) || A)
        let mut state = Blake2bState::new(outlen);
        state.update(&(outlen as u32).to_le_bytes());
        state.update(input);
        state.finalize(out);
    } else {
        // Long output case per RFC 9106 Section 3.2
        // r = ceil(T/32) - 2
        // A1 = Blake2b-64(LE32(T) || A)
        // Ai = Blake2b-64(A_{i-1})  for i = 2..r
        // A_{r+1} = Blake2b-(T - 32*r)(Ar)
        // Output = A1[0..32] || A2[0..32] || ... || Ar[0..32] || A_{r+1}

        let r = (outlen + 31) / 32 - 2; // ceil(T/32) - 2

        // A1 = Blake2b-64(LE32(T) || A)
        let mut out_buffer = [0u8; BLAKE2B_OUTBYTES];
        let mut state = Blake2bState::new(BLAKE2B_OUTBYTES);
        state.update(&(outlen as u32).to_le_bytes());
        state.update(input);
        state.finalize(&mut out_buffer);

        // Copy first 32 bytes of A1
        out[..32].copy_from_slice(&out_buffer[..32]);
        let mut out_pos = 32;

        let mut prev_hash = out_buffer;

        // Ai = Blake2b-64(A_{i-1}) for i = 2..r, output first 32 bytes each
        for _ in 1..r {
            let mut state = Blake2bState::new(BLAKE2B_OUTBYTES);
            state.update(&prev_hash);
            state.finalize(&mut out_buffer);

            out[out_pos..out_pos + 32].copy_from_slice(&out_buffer[..32]);
            out_pos += 32;
            prev_hash = out_buffer;
        }

        // A_{r+1} = Blake2b-(T - 32*r)(Ar) -- final block, full output
        let last_len = outlen - 32 * r;
        let mut state = Blake2bState::new(last_len);
        state.update(&prev_hash);
        state.finalize(&mut out[out_pos..out_pos + last_len]);
    }

    Ok(())
}

/// Bare Blake2b hash (no length prefix). Used for the initial pre-hash (H0).
/// This is standard Blake2b per RFC 7693, NOT the Argon2 H' function.
pub fn blake2b(out: &mut [u8], input: &[u8]) -> Result<(), String> {
    let outlen = out.len();
    if outlen == 0 || outlen > BLAKE2B_OUTBYTES {
        return Err("blake2b: invalid output length".into());
    }
    let mut state = Blake2bState::new(outlen);
    state.update(input);
    state.finalize(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::QWORDS_IN_BLOCK;

    #[test]
    fn test_rotr64() {
        assert_eq!(rotr64(0x0123456789ABCDEF, 4), 0xF0123456789ABCDE);
        assert_eq!(rotr64(0x0123456789ABCDEF, 32), 0x89ABCDEF01234567);
        assert_eq!(rotr64(0xFFFFFFFFFFFFFFFF, 1), 0xFFFFFFFFFFFFFFFF);
    }

    #[test]
    fn test_f_blamka() {
        // Test with simple values
        assert_eq!(f_blamka(1, 1), 1 + 1 + 2);
        assert_eq!(f_blamka(0, 0), 0);
        
        // Test with larger values
        let x: u64 = 0x0123456789ABCDEF;
        let y: u64 = 0xFEDCBA9876543210;
        let m: u64 = 0xFFFFFFFF;
        let expected = x.wrapping_add(y).wrapping_add(2u64.wrapping_mul((x & m).wrapping_mul(y & m)));
        assert_eq!(f_blamka(x, y), expected);
    }

    #[test]
    fn test_g_function() {
        let mut a = 0x0123456789ABCDEF;
        let mut b = 0xFEDCBA9876543210;
        let mut c = 0x1111111111111111;
        let mut d = 0x2222222222222222;
        
        let orig_a = a;
        let orig_b = b;
        let orig_c = c;
        let orig_d = d;
        
        g(&mut a, &mut b, &mut c, &mut d);
        
        // Values should have changed
        assert_ne!(a, orig_a);
        assert_ne!(b, orig_b);
        assert_ne!(c, orig_c);
        assert_ne!(d, orig_d);
    }

    #[test]
    fn test_permute_block() {
        let mut block = Block::new();
        
        // Set some initial values
        for i in 0..QWORDS_IN_BLOCK {
            block.v[i] = i as u64;
        }
        
        // Store original for comparison
        let original = block.clone();
        
        // Apply permutation
        permute_block(&mut block);
        
        // Block should be different
        assert_ne!(block.v[0], original.v[0]);
        assert_ne!(block.v[QWORDS_IN_BLOCK - 1], original.v[QWORDS_IN_BLOCK - 1]);
    }
}
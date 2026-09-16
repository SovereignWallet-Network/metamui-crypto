/// Optimized HMAC implementation with performance enhancements
///
/// Optimizations include:
/// - Stack-allocated buffers for small messages
/// - Precomputed key schedules
/// - Reduced allocations
/// - Streaming interface for large data

use crate::operations::secure_clear::Clear;

#[cfg(feature = "std")]
use std::vec::Vec;

/// HMAC state for streaming operations
pub struct HmacState {
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
    inner_hash_state: Sha256State,
    is_sha512: bool,
}

/// SHA-256 state for incremental hashing
struct Sha256State {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256State {
    const H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    fn new() -> Self {
        Self {
            state: Self::H,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut data_idx = 0;
        self.total_len += data.len() as u64;

        // Process any buffered data
        if self.buffer_len > 0 {
            let to_copy = core::cmp::min(64 - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data_idx += to_copy;

            if self.buffer_len == 64 {
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while data_idx + 64 <= data.len() {
            self.process_block(&data[data_idx..data_idx + 64]);
            data_idx += 64;
        }

        // Buffer remaining data
        let remaining = data.len() - data_idx;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[data_idx..]);
            self.buffer_len = remaining;
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        // Padding
        let msg_len_bits = self.total_len * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy);
            self.buffer.fill(0);
            self.buffer_len = 0;
        }

        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&msg_len_bits.to_be_bytes());
        let buffer_copy = self.buffer;
        self.process_block(&buffer_copy);

        // Convert state to bytes
        let mut result = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    #[inline(always)]
    fn process_block(&mut self, block: &[u8]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        let mut w = [0u32; 64];
        
        // Load message schedule
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        
        // Extend message schedule
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Optimized HMAC implementation
pub struct Hmac;

impl Hmac {
    /// Optimized HMAC-SHA256 for small messages (stack-allocated)
    pub fn hmac_sha256_small(key: &[u8], message: &[u8]) -> [u8; 32] {
        const BLOCK_SIZE: usize = 64;
        
        // Prepare key
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let mut hasher = Sha256State::new();
            hasher.update(key);
            let hashed_key = hasher.finalize();
            key_block[..32].copy_from_slice(&hashed_key);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        
        // Create pads
        let mut inner_pad = [0u8; BLOCK_SIZE];
        let mut outer_pad = [0u8; BLOCK_SIZE];
        
        for i in 0..BLOCK_SIZE {
            inner_pad[i] = key_block[i] ^ 0x36;
            outer_pad[i] = key_block[i] ^ 0x5C;
        }
        
        // Inner hash
        let mut inner_hasher = Sha256State::new();
        inner_hasher.update(&inner_pad);
        inner_hasher.update(message);
        let inner_hash = inner_hasher.finalize();
        
        // Outer hash
        let mut outer_hasher = Sha256State::new();
        outer_hasher.update(&outer_pad);
        outer_hasher.update(&inner_hash);
        let result = outer_hasher.finalize();
        
        // Clear sensitive data
        Clear::clear(&mut key_block);
        Clear::clear(&mut inner_pad);
        Clear::clear(&mut outer_pad);
        
        result
    }
    
    /// Create HMAC state for streaming operations
    pub fn new_sha256(key: &[u8]) -> HmacState {
        const BLOCK_SIZE: usize = 64;
        
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let mut hasher = Sha256State::new();
            hasher.update(key);
            let hashed_key = hasher.finalize();
            key_block[..32].copy_from_slice(&hashed_key);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        
        let mut inner_pad = [0u8; BLOCK_SIZE];
        let mut outer_pad = [0u8; BLOCK_SIZE];
        
        for i in 0..BLOCK_SIZE {
            inner_pad[i] = key_block[i] ^ 0x36;
            outer_pad[i] = key_block[i] ^ 0x5C;
        }
        
        let mut inner_hash_state = Sha256State::new();
        inner_hash_state.update(&inner_pad);
        
        Clear::clear(&mut key_block);
        
        HmacState {
            inner_pad,
            outer_pad,
            inner_hash_state,
            is_sha512: false,
        }
    }
}

impl HmacState {
    /// Update HMAC with more data
    pub fn update(&mut self, data: &[u8]) {
        self.inner_hash_state.update(data);
    }
    
    /// Finalize HMAC and return result
    pub fn finalize(mut self) -> Vec<u8> {
        let inner_hash = self.inner_hash_state.finalize();
        
        let mut outer_hasher = Sha256State::new();
        outer_hasher.update(&self.outer_pad);
        outer_hasher.update(&inner_hash);
        let result = outer_hasher.finalize();
        
        // Clear sensitive data
        Clear::clear(&mut self.inner_pad);
        Clear::clear(&mut self.outer_pad);
        
        result.to_vec()
    }
    
    /// Clone the state for parallel operations
    pub fn fork(&self) -> Self {
        Self {
            inner_pad: self.inner_pad,
            outer_pad: self.outer_pad,
            inner_hash_state: Sha256State {
                state: self.inner_hash_state.state,
                buffer: self.inner_hash_state.buffer,
                buffer_len: self.inner_hash_state.buffer_len,
                total_len: self.inner_hash_state.total_len,
            },
            is_sha512: self.is_sha512,
        }
    }
}

/// Batch HMAC operations with the same key
pub struct BatchHmac {
    inner_pad: [u8; 64],
    outer_pad: [u8; 64],
}

impl BatchHmac {
    /// Create a new batch HMAC processor
    pub fn new_sha256(key: &[u8]) -> Self {
        const BLOCK_SIZE: usize = 64;
        
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let mut hasher = Sha256State::new();
            hasher.update(key);
            let hashed_key = hasher.finalize();
            key_block[..32].copy_from_slice(&hashed_key);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        
        let mut inner_pad = [0u8; BLOCK_SIZE];
        let mut outer_pad = [0u8; BLOCK_SIZE];
        
        for i in 0..BLOCK_SIZE {
            inner_pad[i] = key_block[i] ^ 0x36;
            outer_pad[i] = key_block[i] ^ 0x5C;
        }
        
        Clear::clear(&mut key_block);
        
        Self { inner_pad, outer_pad }
    }
    
    /// Compute HMAC for a message
    #[inline]
    pub fn hmac(&self, message: &[u8]) -> [u8; 32] {
        let mut inner_hasher = Sha256State::new();
        inner_hasher.update(&self.inner_pad);
        inner_hasher.update(message);
        let inner_hash = inner_hasher.finalize();
        
        let mut outer_hasher = Sha256State::new();
        outer_hasher.update(&self.outer_pad);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize()
    }
    
    /// Process multiple messages
    pub fn hmac_batch(&self, messages: &[&[u8]]) -> Vec<[u8; 32]> {
        messages.iter().map(|msg| self.hmac(msg)).collect()
    }
}

impl Drop for BatchHmac {
    fn drop(&mut self) {
        Clear::clear(&mut self.inner_pad);
        Clear::clear(&mut self.outer_pad);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hmac_sha256_small() {
        let key = b"test key";
        let message = b"test message";
        
        let result = Hmac::hmac_sha256_small(key, message);
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_streaming_hmac() {
        let key = b"test key";
        let mut hmac = Hmac::new_sha256(key);
        
        hmac.update(b"test ");
        hmac.update(b"message");
        
        let result = hmac.finalize();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_batch_hmac() {
        let key = b"test key";
        let batch = BatchHmac::new_sha256(key);
        
        let messages = vec![
            b"message1".as_slice(),
            b"message2".as_slice(),
            b"message3".as_slice(),
        ];
        
        let results = batch.hmac_batch(&messages);
        assert_eq!(results.len(), 3);
        
        // Verify each result
        for (msg, result) in messages.iter().zip(results.iter()) {
            let individual = Hmac::hmac_sha256_small(key, msg);
            assert_eq!(&individual, result);
        }
    }
}
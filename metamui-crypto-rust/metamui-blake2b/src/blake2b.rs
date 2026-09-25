/// Pure native Rust implementation of BLAKE2b
///
/// This is a complete implementation of BLAKE2b with configurable output size
/// (1-64 bytes), following the BLAKE2 specification (RFC 7693).

use crate::{Blake2b256Hash, Blake2b512Hash, BLAKE2B_256_SIZE, BLAKE2B_512_OUTPUT_SIZE};

/// BLAKE2b initialization vector (same as SHA-512 IV)
const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// BLAKE2b sigma values for message word selection
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

/// BLAKE2b rotation constants
const R1: u32 = 32;
const R2: u32 = 24;
const R3: u32 = 16;
const R4: u32 = 63;

/// BLAKE2b block size
const BLOCK_SIZE: usize = 128;

/// BLAKE2b hasher with configurable output size (1-64 bytes)
pub struct Blake2bHasher {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    buffer: Vec<u8>,
    buffer_len: usize,
    outlen: usize,
}

impl Blake2bHasher {
    /// Create a new BLAKE2b-512 hasher (64-byte output)
    pub fn new() -> Self {
        Self::new_with_output_size(64)
    }

    /// Create a new BLAKE2b hasher with custom output size (1-64 bytes)
    pub fn new_with_output_size(outlen: usize) -> Self {
        assert!(outlen > 0 && outlen <= 64, "Output length must be between 1 and 64 bytes");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ (outlen as u64);

        Self {
            h,
            t: [0, 0],
            f: [0, 0],
            buffer: vec![0u8; BLOCK_SIZE],
            buffer_len: 0,
            outlen,
        }
    }

    /// Create a new keyed BLAKE2b hasher with default 64-byte output
    #[allow(dead_code)]
    pub fn new_keyed(key: &[u8]) -> Self {
        Self::new_keyed_with_output_size(key, 64)
    }

    /// Create a new keyed BLAKE2b hasher with custom output size
    pub fn new_keyed_with_output_size(key: &[u8], outlen: usize) -> Self {
        assert!(key.len() <= 64, "BLAKE2b key must be at most 64 bytes");
        assert!(outlen > 0 && outlen <= 64, "Output length must be between 1 and 64 bytes");

        let mut h = IV;
        h[0] ^= 0x01010000 ^ ((key.len() as u64) << 8) ^ (outlen as u64);

        let mut hasher = Self {
            h,
            t: [0, 0],
            f: [0, 0],
            buffer: vec![0u8; BLOCK_SIZE],
            buffer_len: 0,
            outlen,
        };

        if !key.is_empty() {
            let mut block = [0u8; BLOCK_SIZE];
            block[..key.len()].copy_from_slice(key);
            hasher.update(&block);
        }

        hasher
    }

    /// Update the hasher with new data
    pub fn update(&mut self, data: &[u8]) {
        let mut input = data;
        if input.is_empty() {
            return;
        }

        if self.buffer_len > 0 {
            let fill = BLOCK_SIZE.saturating_sub(self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + fill].copy_from_slice(&input[..fill]);
            self.buffer_len += fill;
            input = &input[fill..];

            // RFC 7693 lazy finalization: the last block — full or partial —
            // must be compressed by finalize() with the final flag. Only
            // compress the (necessarily full) buffer when MORE input
            // follows. The old code compressed the moment the buffer
            // filled, which corrupted (a) keyed hashing of the empty
            // message (the padded key block IS the final block) and
            // (b) any streamed input whose update() boundaries landed on
            // exact 128-byte multiples. Ground truth:
            // test-vectors/blake2/blake2-boundary-vectors.json (hashlib).
            if input.is_empty() {
                return;
            }
            self.increment_counter(BLOCK_SIZE as u64);
            self.compress(false);
            self.buffer_len = 0;
        }

        while input.len() > BLOCK_SIZE {
            self.buffer[..BLOCK_SIZE].copy_from_slice(&input[..BLOCK_SIZE]);
            self.increment_counter(BLOCK_SIZE as u64);
            self.compress(false);
            input = &input[BLOCK_SIZE..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    /// Finalize and return a 256-bit hash
    pub fn finalize_256(mut self) -> Blake2b256Hash {
        assert_eq!(self.outlen, 32, "Use finalize_variable for non-32-byte outputs");
        let bytes = self.finalize_inner();
        let mut result = [0u8; BLAKE2B_256_SIZE];
        result.copy_from_slice(&bytes[..BLAKE2B_256_SIZE]);
        result
    }

    /// Finalize and return a 512-bit hash
    pub fn finalize_512(mut self) -> Blake2b512Hash {
        assert_eq!(self.outlen, 64, "Use finalize_variable for non-64-byte outputs");
        let bytes = self.finalize_inner();
        let mut result = [0u8; BLAKE2B_512_OUTPUT_SIZE];
        result.copy_from_slice(&bytes);
        Blake2b512Hash(result)
    }

    /// Finalize and return variable-length result
    pub fn finalize_variable(mut self) -> Vec<u8> {
        self.finalize_inner()
    }

    /// Internal finalize — returns Vec<u8> of self.outlen bytes
    fn finalize_inner(&mut self) -> Vec<u8> {
        self.f[0] = !0;
        self.buffer[self.buffer_len..].fill(0);
        self.increment_counter(self.buffer_len as u64);
        self.compress(true);

        let mut result = vec![0u8; self.outlen];
        let full_words = self.outlen / 8;
        let remaining = self.outlen % 8;

        for i in 0..full_words {
            result[i * 8..(i + 1) * 8].copy_from_slice(&self.h[i].to_le_bytes());
        }
        if remaining > 0 {
            let bytes = self.h[full_words].to_le_bytes();
            result[full_words * 8..].copy_from_slice(&bytes[..remaining]);
        }

        self.clear();
        result
    }

    fn clear(&mut self) {
        self.h.fill(0);
        self.t.fill(0);
        self.f.fill(0);
        self.buffer.fill(0);
        self.buffer_len = 0;
    }

    fn increment_counter(&mut self, inc: u64) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, last: bool) {
        let mut v = [0u64; 16];

        v[..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&IV);

        v[12] ^= self.t[0];
        v[13] ^= self.t[1];

        if last {
            v[14] ^= !0;
        }

        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes([
                self.buffer[i * 8],
                self.buffer[i * 8 + 1],
                self.buffer[i * 8 + 2],
                self.buffer[i * 8 + 3],
                self.buffer[i * 8 + 4],
                self.buffer[i * 8 + 5],
                self.buffer[i * 8 + 6],
                self.buffer[i * 8 + 7],
            ]);
        }

        for round in 0..12 {
            Self::g(&mut v, 0, 4, 8, 12, m[SIGMA[round][0]], m[SIGMA[round][1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[SIGMA[round][2]], m[SIGMA[round][3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[SIGMA[round][4]], m[SIGMA[round][5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[SIGMA[round][6]], m[SIGMA[round][7]]);

            Self::g(&mut v, 0, 5, 10, 15, m[SIGMA[round][8]], m[SIGMA[round][9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[SIGMA[round][10]], m[SIGMA[round][11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[SIGMA[round][12]], m[SIGMA[round][13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[SIGMA[round][14]], m[SIGMA[round][15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    #[inline]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(R1);

        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(R2);

        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(R3);

        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(R4);
    }
}

impl Drop for Blake2bHasher {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Compute BLAKE2b-256 hash using native implementation
#[allow(dead_code)]
pub fn native_blake2b256(data: &[u8]) -> Blake2b256Hash {
    let mut hasher = Blake2bHasher::new_with_output_size(32);
    hasher.update(data);
    hasher.finalize_256()
}

/// Compute BLAKE2b-512 hash using native implementation
pub fn native_blake2b512(data: &[u8]) -> Blake2b512Hash {
    let mut hasher = Blake2bHasher::new();
    hasher.update(data);
    hasher.finalize_512()
}

/// Compute keyed BLAKE2b-256 hash using native implementation
#[allow(dead_code)]
pub fn native_blake2b256_keyed(key: &[u8], data: &[u8]) -> Blake2b256Hash {
    let mut hasher = Blake2bHasher::new_keyed_with_output_size(key, 32);
    hasher.update(data);
    hasher.finalize_256()
}

/// Compute keyed BLAKE2b-512 hash using native implementation
#[allow(dead_code)]
pub fn native_blake2b512_keyed(key: &[u8], data: &[u8]) -> Blake2b512Hash {
    let mut hasher = Blake2bHasher::new_keyed_with_output_size(key, 64);
    hasher.update(data);
    hasher.finalize_512()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_blake2b256_empty() {
        let hash = native_blake2b256(b"");
        let expected = hex::decode("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_native_blake2b256_abc() {
        let hash = native_blake2b256(b"abc");
        let expected = hex::decode("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319").unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_native_blake2b512_empty() {
        let hash = native_blake2b512(b"");
        let expected = hex::decode("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce").unwrap();
        assert_eq!(&hash.0[..], &expected[..]);
    }

    #[test]
    fn test_native_blake2b512_abc() {
        let hash = native_blake2b512(b"abc");
        let expected = hex::decode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923").unwrap();
        assert_eq!(&hash.0[..], &expected[..]);
    }

    #[test]
    fn test_native_blake2b256_keyed() {
        let key = b"test key";
        let hash = native_blake2b256_keyed(key, b"message");
        let hash2 = native_blake2b256_keyed(key, b"message");
        assert_eq!(hash, hash2);
        let hash3 = native_blake2b256_keyed(b"different key", b"message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_incremental() {
        let mut hasher = Blake2bHasher::new_with_output_size(32);
        hasher.update(b"ab");
        hasher.update(b"c");
        let hash = hasher.finalize_256();
        let expected = native_blake2b256(b"abc");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_incremental_512() {
        let mut hasher = Blake2bHasher::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        let hash = hasher.finalize_512();
        let expected = native_blake2b512(b"abc");
        assert_eq!(hash, expected);
    }
}

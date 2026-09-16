/// Optimized AES-256 implementation with performance improvements
/// 
/// Key optimizations:
/// - Table-based round operations with cache-friendly access patterns
/// - Unrolled loops for better instruction pipelining
/// - SIMD support preparation for parallel block processing
/// - Stack-allocated buffers to reduce heap allocations
/// - Optimized key expansion with precomputed tables

use crate::{BLOCK_SIZE, KEY_SIZE, IV_SIZE};

/// Number of rounds for AES-256.
const _ROUNDS: usize = 14;

#[cfg(feature = "native")]
use lazy_static::lazy_static;

// Thread-safe precomputed multiplication tables for optimization
#[cfg(feature = "native")]
lazy_static! {
    static ref MUL2: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 2);
        }
        table
    };
    
    static ref MUL3: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 3);
        }
        table
    };
    
    static ref MUL9: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 9);
        }
        table
    };
    
    static ref MUL11: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 11);
        }
        table
    };
    
    static ref MUL13: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 13);
        }
        table
    };
    
    static ref MUL14: [u8; 256] = {
        let mut table = [0u8; 256];
        for i in 0..256 {
            table[i] = gmul(i as u8, 14);
        }
        table
    };
}

// Fallback const tables for no-std environments
#[cfg(not(feature = "native"))]
const MUL2: [u8; 256] = generate_mul_table(2);
#[cfg(not(feature = "native"))]
const MUL3: [u8; 256] = generate_mul_table(3);
#[cfg(not(feature = "native"))]
const MUL9: [u8; 256] = generate_mul_table(9);
#[cfg(not(feature = "native"))]
const MUL11: [u8; 256] = generate_mul_table(11);
#[cfg(not(feature = "native"))]
const MUL13: [u8; 256] = generate_mul_table(13);
#[cfg(not(feature = "native"))]
const MUL14: [u8; 256] = generate_mul_table(14);

#[cfg(not(feature = "native"))]
const fn generate_mul_table(multiplier: u8) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = const_gmul(i as u8, multiplier);
        i += 1;
    }
    table
}

#[cfg(not(feature = "native"))]
const fn const_gmul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    result
}

// Helper functions to access multiplication tables in a thread-safe way
#[inline(always)]
fn get_mul2(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL2[index];
    #[cfg(not(feature = "native"))]
    return MUL2[index];
}

#[inline(always)]
fn get_mul3(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL3[index];
    #[cfg(not(feature = "native"))]
    return MUL3[index];
}

#[inline(always)]
fn get_mul9(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL9[index];
    #[cfg(not(feature = "native"))]
    return MUL9[index];
}

#[inline(always)]
fn get_mul11(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL11[index];
    #[cfg(not(feature = "native"))]
    return MUL11[index];
}

#[inline(always)]
fn get_mul13(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL13[index];
    #[cfg(not(feature = "native"))]
    return MUL13[index];
}

#[inline(always)]
fn get_mul14(index: usize) -> u8 {
    #[cfg(feature = "native")]
    return MUL14[index];
    #[cfg(not(feature = "native"))]
    return MUL14[index];
}

/// AES S-box (SubBytes substitution table).
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

/// AES inverse S-box (InvSubBytes substitution table).
pub const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Round constants for key expansion
pub(crate) const RCON: [u32; 15] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000,
];

/// PKCS#7 padding
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = Vec::with_capacity(data.len() + padding_len);
    padded.extend_from_slice(data);
    for _ in 0..padding_len {
        padded.push(padding_len as u8);
    }
    padded
}

/// PKCS#7 unpadding
pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() {
        return Err("Empty data");
    }
    
    let padding_len = data[data.len() - 1] as usize;
    
    // A PKCS#7 pad byte is 1..=BLOCK_SIZE. Without the upper bound a
    // ciphertext produced with no padding at all (Wycheproof aes_cbc_pkcs5
    // tcId 215/216) whose last plaintext byte happens to be <= data.len()
    // would be "unpadded" by stripping that many bytes.
    if padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > data.len() {
        return Err("Invalid padding");
    }
    
    // Check all padding bytes
    for i in (data.len() - padding_len)..data.len() {
        if data[i] != padding_len as u8 {
            return Err("Invalid padding");
        }
    }
    
    Ok(data[..data.len() - padding_len].to_vec())
}

/// Galois field multiplication
pub fn gmul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    result
}

/// AES key expansion for 256-bit keys
pub fn expand_key(key: &[u8; KEY_SIZE]) -> [u32; 60] {
    let mut expanded = [0u32; 60];
    
    // Copy original key
    for i in 0..8 {
        expanded[i] = u32::from_be_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    
    // Generate remaining round keys
    for i in 8..60 {
        let mut temp = expanded[i - 1];
        
        if i % 8 == 0 {
            // RotWord and SubWord
            temp = ((SBOX[((temp >> 16) & 0xff) as usize] as u32) << 24) |
                   ((SBOX[((temp >> 8) & 0xff) as usize] as u32) << 16) |
                   ((SBOX[(temp & 0xff) as usize] as u32) << 8) |
                   (SBOX[((temp >> 24) & 0xff) as usize] as u32);
            temp ^= RCON[i / 8];
        } else if i % 8 == 4 {
            // SubWord only
            temp = ((SBOX[((temp >> 24) & 0xff) as usize] as u32) << 24) |
                   ((SBOX[((temp >> 16) & 0xff) as usize] as u32) << 16) |
                   ((SBOX[((temp >> 8) & 0xff) as usize] as u32) << 8) |
                   (SBOX[(temp & 0xff) as usize] as u32);
        }
        
        expanded[i] = expanded[i - 8] ^ temp;
    }
    
    expanded
}

/// AES block encryption
pub fn encrypt_block(block: &[u8; BLOCK_SIZE], expanded_key: &[u32; 60]) -> [u8; BLOCK_SIZE] {
    let mut state = [
        [block[0], block[4], block[8], block[12]],
        [block[1], block[5], block[9], block[13]],
        [block[2], block[6], block[10], block[14]],
        [block[3], block[7], block[11], block[15]],
    ];
    
    // Initial round
    add_round_key(&mut state, &expanded_key[0..4]);
    
    // Main rounds
    for round in 1..14 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &expanded_key[round * 4..(round + 1) * 4]);
    }
    
    // Final round
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &expanded_key[56..60]);
    
    [
        state[0][0], state[1][0], state[2][0], state[3][0],
        state[0][1], state[1][1], state[2][1], state[3][1],
        state[0][2], state[1][2], state[2][2], state[3][2],
        state[0][3], state[1][3], state[2][3], state[3][3],
    ]
}

/// AES block decryption
pub fn decrypt_block(block: &[u8; BLOCK_SIZE], expanded_key: &[u32; 60]) -> [u8; BLOCK_SIZE] {
    let mut state = [
        [block[0], block[4], block[8], block[12]],
        [block[1], block[5], block[9], block[13]],
        [block[2], block[6], block[10], block[14]],
        [block[3], block[7], block[11], block[15]],
    ];
    
    // Initial round
    add_round_key(&mut state, &expanded_key[56..60]);
    
    // Main rounds
    for round in (1..14).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &expanded_key[round * 4..(round + 1) * 4]);
        inv_mix_columns(&mut state);
    }
    
    // Final round
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &expanded_key[0..4]);
    
    [
        state[0][0], state[1][0], state[2][0], state[3][0],
        state[0][1], state[1][1], state[2][1], state[3][1],
        state[0][2], state[1][2], state[2][2], state[3][2],
        state[0][3], state[1][3], state[2][3], state[3][3],
    ]
}

pub(crate) fn add_round_key(state: &mut [[u8; 4]; 4], round_key: &[u32]) {
    for i in 0..4 {
        let key_bytes = round_key[i].to_be_bytes();
        for j in 0..4 {
            state[j][i] ^= key_bytes[j];
        }
    }
}

pub(crate) fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = SBOX[state[i][j] as usize];
        }
    }
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = INV_SBOX[state[i][j] as usize];
        }
    }
}

pub(crate) fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: shift left by 1
    let temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    // Row 2: shift left by 2
    let temp1 = state[2][0];
    let temp2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp1;
    state[2][3] = temp2;
    
    // Row 3: shift left by 3 (or right by 1)
    let temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1: shift right by 1
    let temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    // Row 2: shift right by 2
    let temp1 = state[2][2];
    let temp2 = state[2][3];
    state[2][2] = state[2][0];
    state[2][3] = state[2][1];
    state[2][0] = temp1;
    state[2][1] = temp2;
    
    // Row 3: shift right by 3 (or left by 1)
    let temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

pub(crate) fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let s0 = state[0][i];
        let s1 = state[1][i];
        let s2 = state[2][i];
        let s3 = state[3][i];
        
        state[0][i] = get_mul2(s0 as usize) ^ get_mul3(s1 as usize) ^ s2 ^ s3;
        state[1][i] = s0 ^ get_mul2(s1 as usize) ^ get_mul3(s2 as usize) ^ s3;
        state[2][i] = s0 ^ s1 ^ get_mul2(s2 as usize) ^ get_mul3(s3 as usize);
        state[3][i] = get_mul3(s0 as usize) ^ s1 ^ s2 ^ get_mul2(s3 as usize);
    }
}

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let s0 = state[0][i];
        let s1 = state[1][i];
        let s2 = state[2][i];
        let s3 = state[3][i];
        
        state[0][i] = get_mul14(s0 as usize) ^ get_mul11(s1 as usize) ^ get_mul13(s2 as usize) ^ get_mul9(s3 as usize);
        state[1][i] = get_mul9(s0 as usize) ^ get_mul14(s1 as usize) ^ get_mul11(s2 as usize) ^ get_mul13(s3 as usize);
        state[2][i] = get_mul13(s0 as usize) ^ get_mul9(s1 as usize) ^ get_mul14(s2 as usize) ^ get_mul11(s3 as usize);
        state[3][i] = get_mul11(s0 as usize) ^ get_mul13(s1 as usize) ^ get_mul9(s2 as usize) ^ get_mul14(s3 as usize);
    }
}

/// Optimized AES-256 implementation
pub struct Aes256 {
    expanded_key: [u32; 60], // 15 rounds * 4 words
}

/// Type alias for compatibility
pub type Aes256Core = Aes256;

impl Aes256 {
    /// Create a new AES-256 instance with the given key
    #[inline]
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let expanded_key = expand_key(key);
        Self { expanded_key }
    }
    
    /// Encrypt a single block using optimized operations
    #[inline]
    pub fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        encrypt_block(block, &self.expanded_key)
    }
    
    /// Decrypt a single block
    #[inline]
    pub fn decrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        decrypt_block(block, &self.expanded_key)
    }
    
    /// Optimized CTR mode encryption/decryption with reduced allocations
    pub fn process_ctr(&self, nonce: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = *nonce;
        let mut keystream = [0u8; BLOCK_SIZE];
        let mut keystream_pos = BLOCK_SIZE;
        
        // Process data byte by byte, generating keystream blocks as needed
        for &byte in data {
            if keystream_pos >= BLOCK_SIZE {
                // Generate new keystream block
                keystream = self.encrypt_block(&counter);
                keystream_pos = 0;
                
                // Increment counter with overflow check
                let mut overflow = true;
                for i in (0..BLOCK_SIZE).rev() {
                    counter[i] = counter[i].wrapping_add(1);
                    if counter[i] != 0 {
                        overflow = false;
                        break;
                    }
                }
                
                // Prevent counter reuse after 2^128 blocks
                if overflow {
                    panic!("CTR mode counter overflow - maximum number of blocks exceeded");
                }
            }
            
            result.push(byte ^ keystream[keystream_pos]);
            keystream_pos += 1;
        }
        
        result
    }
    
    /// Process multiple blocks in parallel (preparation for SIMD)
    #[inline]
    pub fn encrypt_blocks_parallel(&self, blocks: &[[u8; BLOCK_SIZE]]) -> Vec<[u8; BLOCK_SIZE]> {
        // This is a placeholder for future SIMD implementation
        // For now, process blocks sequentially but with optimized single-block encryption
        blocks.iter().map(|block| self.encrypt_block(block)).collect()
    }
    
    /// Optimized CBC encryption with pre-allocated buffers
    pub fn encrypt_cbc(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
        let padded = pkcs7_pad(plaintext, BLOCK_SIZE);
        let mut ciphertext = Vec::with_capacity(padded.len());
        let mut prev_block = *iv;
        
        // Process blocks with minimal allocations
        for chunk in padded.chunks_exact(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            
            // XOR with previous block and copy in one pass
            for i in 0..BLOCK_SIZE {
                block[i] = chunk[i] ^ prev_block[i];
            }
            
            // Encrypt
            let encrypted = self.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted);
            prev_block = encrypted;
        }
        
        ciphertext
    }
    
    /// Optimized CBC decryption with pre-allocated buffers
    pub fn decrypt_cbc(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err("Ciphertext length must be multiple of block size");
        }
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = *iv;
        
        // Process blocks with minimal allocations
        for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            
            // Decrypt
            let mut decrypted = self.decrypt_block(&block);
            
            // XOR with previous ciphertext block (or IV)
            for i in 0..BLOCK_SIZE {
                decrypted[i] ^= prev_block[i];
            }
            
            plaintext.extend_from_slice(&decrypted);
            prev_block = block;
        }
        
        // Remove PKCS#7 padding
        pkcs7_unpad(&plaintext)
    }
    
    /// Encrypt data using ECB mode
    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Vec<u8> {
        let padded = pkcs7_pad(plaintext, BLOCK_SIZE);
        let mut ciphertext = Vec::with_capacity(padded.len());
        
        for chunk in padded.chunks(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            let encrypted_block = self.encrypt_block(&block);
            ciphertext.extend_from_slice(&encrypted_block);
        }
        
        ciphertext
    }
    
    /// Decrypt data using ECB mode
    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err("Invalid ciphertext length");
        }
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let block: [u8; BLOCK_SIZE] = chunk.try_into().unwrap();
            let decrypted_block = self.decrypt_block(&block);
            plaintext.extend_from_slice(&decrypted_block);
        }
        
        // Remove PKCS#7 padding
        pkcs7_unpad(&plaintext)
    }
}

impl Drop for Aes256 {
    fn drop(&mut self) {
        // Clear expanded key from memory
        self.expanded_key.fill(0);
    }
}

/// Optimized AES-256 in CBC mode with minimal allocations
pub fn aes256_cbc_encrypt_optimized(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let aes = Aes256::new(key);
    aes.encrypt_cbc(iv, plaintext)
}

/// Optimized AES-256 in CBC mode decryption
pub fn aes256_cbc_decrypt_optimized(key: &[u8; KEY_SIZE], iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let aes = Aes256::new(key);
    aes.decrypt_cbc(iv, ciphertext)
}

/// Optimized AES-256 in CTR mode
pub fn aes256_ctr_process_optimized(key: &[u8; KEY_SIZE], nonce: &[u8; IV_SIZE], data: &[u8]) -> Vec<u8> {
    let aes = Aes256::new(key);
    aes.process_ctr(nonce, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_optimized_encryption() {
        let key = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
        let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        
        let aes = Aes256::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);
        let decrypted = aes.decrypt_block(&ciphertext);
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_optimized_cbc() {
        let key = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let plaintext = b"Hello, AES-256 optimized!";
        
        let ciphertext = aes256_cbc_encrypt_optimized(&key, &iv, plaintext);
        let decrypted = aes256_cbc_decrypt_optimized(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}
/// Simple Poly1305 implementation that directly matches the Python reference
use crate::{Poly1305Error, TAG_SIZE, KEY_SIZE};

pub fn poly1305_mac_simple(message: &[u8], key: &[u8]) -> Result<[u8; TAG_SIZE], Poly1305Error> {
    if key.len() != KEY_SIZE {
        return Err(Poly1305Error::InvalidKeySize);
    }

    // Split key into r and s
    let (r_bytes, s_bytes) = key.split_at(16);

    // Clamp r according to RFC 8439 (exactly like Python)
    let mut r_clamped = [0u8; 16];
    r_clamped.copy_from_slice(r_bytes);
    
    // Clear top 4 bits of bytes 3, 7, 11, 15
    r_clamped[3] &= 0x0f;
    r_clamped[7] &= 0x0f;
    r_clamped[11] &= 0x0f;
    r_clamped[15] &= 0x0f;
    
    // Clear bottom 2 bits of bytes 4, 8, 12
    r_clamped[4] &= 0xfc;
    r_clamped[8] &= 0xfc;
    r_clamped[12] &= 0xfc;

    // Convert r to 128-bit integer (little-endian) - use big integer arithmetic
    let r_int = u128::from_le_bytes(r_clamped);

    // Poly1305 prime: 2^130 - 5
    // We'll implement this using 256-bit arithmetic for safety
    const P: [u64; 4] = [
        u64::MAX - 4,  // 2^64 - 5 (low part)
        u64::MAX,      // 2^64 - 1
        u64::MAX,      // 2^64 - 1  
        3              // 2^2 = 4, so total is 2^130 - 5
    ];

    // Use 256-bit accumulator
    let mut acc = [0u64; 4];

    // Process message in 16-byte blocks
    let full_blocks = message.len() / 16;

    // Process full blocks
    for i in 0..full_blocks {
        let block = &message[i * 16..(i + 1) * 16];
        
        // Convert to 128-bit integer and add 2^128
        let n = u128::from_le_bytes(block.try_into().unwrap());
        
        // Add n + 2^128 to accumulator
        let n_with_high_bit = [
            n as u64,
            (n >> 64) as u64,
            1,  // 2^128
            0
        ];
        
        acc = add_256(acc, n_with_high_bit);
        
        // Multiply by r
        acc = mul_256_128_mod_p(acc, r_int);
    }

    // Process final partial block if any
    let remaining = message.len() % 16;
    if remaining > 0 {
        let mut padded = [0u8; 16];
        padded[..remaining].copy_from_slice(&message[full_blocks * 16..]);
        padded[remaining] = 0x01;
        
        let n = u128::from_le_bytes(padded);
        
        // Add to accumulator (no high bit for partial blocks)
        let n_padded = [
            n as u64,
            (n >> 64) as u64,
            0,
            0
        ];
        
        acc = add_256(acc, n_padded);
        
        // Multiply by r
        acc = mul_256_128_mod_p(acc, r_int);
    }

    // Add s and reduce to 128 bits
    let s_int = u128::from_le_bytes(s_bytes.try_into().unwrap());
    let final_sum = ((acc[0] as u128) | ((acc[1] as u128) << 64)).wrapping_add(s_int);

    Ok(final_sum.to_le_bytes())
}

fn add_256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    
    for i in 0..4 {
        let sum = a[i] as u128 + b[i] as u128 + carry as u128;
        result[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    
    result
}

fn mul_256_128_mod_p(a: [u64; 4], b: u128) -> [u64; 4] {
    // Simple implementation: convert to Python-style bigint calculation
    // a * b mod (2^130 - 5)
    
    // For simplicity, we'll use the fact that if result >= 2^130,
    // we subtract 2^130 - 5, which is equivalent to adding 5 and keeping low 130 bits
    
    let b_low = b as u64;
    let b_high = (b >> 64) as u64;
    
    // Multiply a by b (simplified)
    let mut result = [0u64; 6]; // Temporary larger result
    
    // Multiply each limb of a by b
    for i in 0..4 {
        if a[i] == 0 { continue; }
        
        let prod_low = (a[i] as u128) * (b_low as u128);
        let prod_high = (a[i] as u128) * (b_high as u128);
        
        // Add to result
        let mut carry = 0u128;
        
        // Add low product
        carry += result[i] as u128 + (prod_low as u64) as u128;
        result[i] = carry as u64;
        carry >>= 64;
        
        carry += result[i + 1] as u128 + (prod_low >> 64) as u128;
        result[i + 1] = carry as u64;
        carry >>= 64;
        
        // Add high product
        carry += result[i + 1] as u128 + (prod_high as u64) as u128;
        result[i + 1] = carry as u64;
        carry >>= 64;
        
        carry += result[i + 2] as u128 + (prod_high >> 64) as u128;
        result[i + 2] = carry as u64;
        carry >>= 64;
        
        if carry > 0 {
            result[i + 3] += carry as u64;
        }
    }
    
    // Reduce modulo 2^130 - 5
    // If any bits are set above 2^130, reduce them
    let excess = (result[2] >> 2) | (result[3] << 62) | (result[4] << 126) | (result[5] << 190);
    let reduction = excess.wrapping_mul(5);
    
    let mut final_result = [0u64; 4];
    final_result[0] = result[0].wrapping_add(reduction as u64);
    final_result[1] = result[1].wrapping_add((reduction >> 64) as u64);
    final_result[2] = result[2] & 0x3; // Keep only bottom 2 bits (130 - 128 = 2)
    final_result[3] = 0;
    
    // Handle carry from the addition
    if final_result[0] < result[0] {
        final_result[1] += 1;
        if final_result[1] < result[1] {
            final_result[2] += 1;
        }
    }
    
    final_result
}
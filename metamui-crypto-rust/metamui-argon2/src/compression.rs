//! Argon2 compression function
//! 
//! This module implements the core compression function used to fill memory blocks.
//! Based on the PHC winner implementation and RFC 9106.

use crate::block::{copy_block, xor_block_into, xor_blocks};
use crate::blake2b::permute_block;
use crate::types::Block;

/// The Argon2 compression function (fill_block in C reference)
/// 
/// This is the core of Argon2, combining two blocks using the Blake2b permutation.
/// 
/// # Algorithm
/// 1. R = prev_block XOR ref_block
/// 2. If with_xor: T = R XOR next_block, else: T = R
/// 3. Apply Blake2b permutation to R
/// 4. next_block = T XOR R (after permutation)
/// 
/// # Arguments
/// * `prev_block` - The previous block in the chain
/// * `ref_block` - The reference block
/// * `next_block` - The block to be filled (modified in place)
/// * `with_xor` - Whether to XOR with existing next_block content (for passes > 0)
pub fn fill_block(
    prev_block: &Block,
    ref_block: &Block,
    next_block: &mut Block,
    with_xor: bool,
) {
    // R = prev_block XOR ref_block
    let mut block_r = xor_blocks(prev_block, ref_block);
    
    // T = R (will be modified if with_xor)
    let mut block_tmp = block_r.clone();
    
    if with_xor {
        // T = R XOR next_block (saving next_block for XOR after permutation)
        xor_block_into(next_block, &mut block_tmp);
    }
    
    // Apply Blake2b permutation to R
    permute_block(&mut block_r);
    
    // next_block = T XOR R (after permutation)
    copy_block(&block_tmp, next_block);
    xor_block_into(&block_r, next_block);
}

/// Alternative compression function interface matching RustCrypto style
/// Returns a new block instead of modifying in place
pub fn compress(x: &Block, y: &Block) -> Block {
    // R = X XOR Y
    let mut r = xor_blocks(x, y);
    let q = r.clone();
    
    // Apply permutation to R
    permute_block(&mut r);
    
    // Return Q XOR R
    xor_blocks(&q, &r)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fill_block_without_xor() {
        let mut prev = Block::new();
        let mut reference = Block::new();
        let mut next = Block::new();
        
        // Set some test values
        prev.v[0] = 0x0123456789ABCDEF;
        reference.v[0] = 0xFEDCBA9876543210;
        
        // Fill without XOR (first pass)
        fill_block(&prev, &reference, &mut next, false);
        
        // Result should be non-zero
        assert_ne!(next.v[0], 0);
        
        // Result should be deterministic
        let mut next2 = Block::new();
        fill_block(&prev, &reference, &mut next2, false);
        assert_eq!(next.v[0], next2.v[0]);
    }
    
    #[test]
    fn test_fill_block_with_xor() {
        let mut prev = Block::new();
        let mut reference = Block::new();
        let mut next = Block::new();
        
        // Set test values
        prev.v[0] = 0x1111111111111111;
        reference.v[0] = 0x2222222222222222;
        next.v[0] = 0x3333333333333333;
        
        let original_next = next.v[0];
        
        // Fill with XOR (subsequent passes)
        fill_block(&prev, &reference, &mut next, true);
        
        // Result should be different from original
        assert_ne!(next.v[0], original_next);
        
        // Result should incorporate original value
        let mut next_without_xor = Block::new();
        fill_block(&prev, &reference, &mut next_without_xor, false);
        assert_ne!(next.v[0], next_without_xor.v[0]);
    }
    
    #[test]
    fn test_compress_function() {
        let mut x = Block::new();
        let mut y = Block::new();
        
        x.v[0] = 0xAAAAAAAAAAAAAAAA;
        y.v[0] = 0x5555555555555555;
        
        let result = compress(&x, &y);
        
        // Should produce consistent results
        let result2 = compress(&x, &y);
        assert_eq!(result.v[0], result2.v[0]);
        
        // Should be non-zero
        assert_ne!(result.v[0], 0);
    }
    
    #[test]
    fn test_compression_symmetry() {
        // Compression should be different for different input orders
        let mut x = Block::new();
        let mut y = Block::new();
        
        x.v[0] = 0x1234567890ABCDEF;
        y.v[0] = 0xFEDCBA0987654321;
        
        let result_xy = compress(&x, &y);
        let result_yx = compress(&y, &x);
        
        // Results should be the same (XOR is commutative)
        // But permutation makes the final result different due to different input
        // Actually, since initial XOR is commutative, results will be the same
        assert_eq!(result_xy.v[0], result_yx.v[0]);
    }
}
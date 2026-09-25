//! Block operations for Argon2
//! 
//! This module provides operations on 1024-byte blocks as per RFC 9106

use crate::types::{Block, QWORDS_IN_BLOCK};

/// XOR two blocks and store result in output block
pub fn xor_block(left: &Block, right: &Block, out: &mut Block) {
    for i in 0..QWORDS_IN_BLOCK {
        out.v[i] = left.v[i] ^ right.v[i];
    }
}

/// XOR two blocks and return a new block
pub fn xor_blocks(left: &Block, right: &Block) -> Block {
    let mut result = Block::new();
    xor_block(left, right, &mut result);
    result
}

/// Copy block from source to destination
pub fn copy_block(src: &Block, dst: &mut Block) {
    dst.v.copy_from_slice(&src.v);
}

/// XOR src block into dst block (dst = dst XOR src)
pub fn xor_block_into(src: &Block, dst: &mut Block) {
    for i in 0..QWORDS_IN_BLOCK {
        dst.v[i] ^= src.v[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_blocks() {
        let mut block1 = Block::new();
        let mut block2 = Block::new();
        
        // Set some test values
        block1.v[0] = 0xDEADBEEF;
        block1.v[1] = 0xCAFEBABE;
        block2.v[0] = 0x12345678;
        block2.v[1] = 0x9ABCDEF0;
        
        let result = xor_blocks(&block1, &block2);
        
        assert_eq!(result.v[0], 0xDEADBEEF ^ 0x12345678);
        assert_eq!(result.v[1], 0xCAFEBABE ^ 0x9ABCDEF0);
        assert_eq!(result.v[2], 0); // Should remain zero
    }

    #[test]
    fn test_copy_block() {
        let mut src = Block::new();
        let mut dst = Block::new();
        
        // Set test values in source
        src.v[0] = 0x123456789ABCDEF0;
        src.v[127] = 0xFEDCBA9876543210;
        
        copy_block(&src, &mut dst);
        
        assert_eq!(dst.v[0], src.v[0]);
        assert_eq!(dst.v[127], src.v[127]);
    }

    #[test]
    fn test_xor_block_into() {
        let mut dst = Block::new();
        let src = Block::new();
        
        dst.v[0] = 0xFF00FF00;
        let src_val = 0x00FF00FF;
        let mut src = src;
        src.v[0] = src_val;
        
        xor_block_into(&src, &mut dst);
        
        assert_eq!(dst.v[0], 0xFFFFFFFF);
    }

    #[test]
    fn test_block_from_bytes() {
        let mut bytes = [0u8; 1024];
        // Set first 8 bytes to create first u64
        bytes[0..8].copy_from_slice(&0x0123456789ABCDEFu64.to_le_bytes());
        
        let block = Block::from_bytes(&bytes);
        assert_eq!(block.v[0], 0x0123456789ABCDEF);
        assert_eq!(block.v[1], 0);
    }

    #[test]
    fn test_block_to_bytes() {
        let mut block = Block::new();
        block.v[0] = 0x0123456789ABCDEF;
        block.v[1] = 0xFEDCBA9876543210;
        
        let mut bytes = [0u8; 1024];
        block.store_to_bytes(&mut bytes);
        
        assert_eq!(&bytes[0..8], &0x0123456789ABCDEFu64.to_le_bytes());
        assert_eq!(&bytes[8..16], &0xFEDCBA9876543210u64.to_le_bytes());
    }
}
//! Argon2d, Argon2i and Argon2id (RFC 9106), written after the PHC reference
//! implementation and verified against the RFC 9106 vectors, the argon2-cffi
//! known answers and the MetaMUI parameter-edge and version-0x10 oracles.
//!
//! Every code path is portable scalar Rust; memory is filled lane by lane in
//! one thread whatever the parallelism value, with the same result as the
//! reference's threaded fill.
//!
//! # Example
//!
//! ```
//! use metamui_argon2::{argon2_hash, Argon2Type, ARGON2_VERSION_13};
//!
//! let tag = argon2_hash(b"password", b"somesalt", 2, 64, 1, 32,
//!                       Argon2Type::Argon2id, ARGON2_VERSION_13).unwrap();
//! assert_eq!(tag.len(), 32);
//! ```

#![no_std]
// Argon2 is an internal KDF crate with many spec-defined constants
// (RFC 9106 Table 1) and algorithm-specific fields whose names match
// the spec directly. Leave rust_2018_idioms enforced; relax
// missing_docs until the public-facing API is fully annotated.
#![allow(missing_docs)]
#![warn(rust_2018_idioms)]


#[cfg(feature = "std")]
extern crate std;

// Core modules
pub mod types;
pub mod block;
pub mod blake2b;
pub mod compression;
pub mod core;

// Re-export main types
pub use types::{
    Argon2Type, Block, Context, Instance, Params, Position,
    ARGON2_VERSION_10, ARGON2_VERSION_13, BLOCK_SIZE, DEFAULT_VERSION,
    QWORDS_IN_BLOCK, SYNC_POINTS,
};

// Re-export main functions
pub use crate::core::{argon2_hash, initialize, fill_memory_blocks, finalize};

// Re-export compression function
pub use compression::{compress, fill_block};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::xor_blocks;
    
    #[test]
    fn test_basic_block_operations() {
        let mut block1 = Block::new();
        let mut block2 = Block::new();
        
        block1.v[0] = 0x123456789ABCDEF0;
        block2.v[0] = 0x0FEDCBA987654321;
        
        let result = xor_blocks(&block1, &block2);
        assert_eq!(result.v[0], block1.v[0] ^ block2.v[0]);
    }
    
    #[test]
    fn test_compression() {
        let mut x = Block::new();
        let mut y = Block::new();
        
        x.v[0] = 1;
        y.v[0] = 2;
        
        let result = compress(&x, &y);
        
        // Result should be deterministic
        let result2 = compress(&x, &y);
        assert_eq!(result.v[0], result2.v[0]);
    }
}
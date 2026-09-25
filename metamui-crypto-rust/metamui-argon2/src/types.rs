//! Type definitions for Argon2
//! 
//! Based on PHC winner implementation and RFC 9106

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;
use core::fmt;

/// Number of 64-bit words in a block
pub const QWORDS_IN_BLOCK: usize = 128;
pub const ARGON2_QWORDS_IN_BLOCK: usize = QWORDS_IN_BLOCK;

/// Block size in bytes
pub const BLOCK_SIZE: usize = QWORDS_IN_BLOCK * 8; // 1024 bytes
pub const ARGON2_BLOCK_SIZE: usize = BLOCK_SIZE;

/// Number of sync points (for parallel processing)
pub const SYNC_POINTS: u32 = 4;
pub const ARGON2_SYNC_POINTS: u32 = SYNC_POINTS;

/// Argon2 versions
pub const ARGON2_VERSION_10: u32 = 0x10;
pub const ARGON2_VERSION_13: u32 = 0x13;

/// Default version (1.3)
pub const DEFAULT_VERSION: u32 = ARGON2_VERSION_13;

/// Argon2 algorithm variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Argon2Type {
    /// Argon2d - data-dependent memory access (faster, for cryptocurrencies)
    Argon2d = 0,
    /// Argon2i - data-independent memory access (slower, resistant to side-channel attacks)
    Argon2i = 1,
    /// Argon2id - hybrid (first half Argon2i, second half Argon2d)
    Argon2id = 2,
}

impl Argon2Type {
    /// Convert from u32
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Argon2Type::Argon2d),
            1 => Some(Argon2Type::Argon2i),
            2 => Some(Argon2Type::Argon2id),
            _ => None,
        }
    }
}

impl fmt::Display for Argon2Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Argon2Type::Argon2d => write!(f, "Argon2d"),
            Argon2Type::Argon2i => write!(f, "Argon2i"),
            Argon2Type::Argon2id => write!(f, "Argon2id"),
        }
    }
}

/// A 1024-byte memory block
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Block {
    /// 128 64-bit words
    pub v: [u64; QWORDS_IN_BLOCK],
}

impl Default for Block {
    fn default() -> Self {
        Self {
            v: [0u64; QWORDS_IN_BLOCK],
        }
    }
}

impl Block {
    /// Create a new zeroed block
    pub fn new() -> Self {
        Self::default()
    }

    /// Load block from byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut block = Self::new();
        block.load_from_bytes(bytes);
        block
    }

    /// Load block data from bytes
    pub fn load_from_bytes(&mut self, bytes: &[u8]) {
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            if i < QWORDS_IN_BLOCK {
                self.v[i] = u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3],
                    chunk[4], chunk[5], chunk[6], chunk[7],
                ]);
            }
        }
    }

    /// Store block data to bytes
    pub fn store_to_bytes(&self, bytes: &mut [u8]) {
        for (i, &word) in self.v.iter().enumerate() {
            let offset = i * 8;
            if offset + 8 <= bytes.len() {
                bytes[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
            }
        }
    }

    /// XOR with another block
    pub fn xor_with(&mut self, other: &Block) {
        for i in 0..QWORDS_IN_BLOCK {
            self.v[i] ^= other.v[i];
        }
    }

    /// Copy from another block
    pub fn copy_from(&mut self, other: &Block) {
        self.v.copy_from_slice(&other.v);
    }
}

/// Position in the memory matrix
#[derive(Debug, Clone, Copy)]
pub struct Position {
    /// Pass number (0-indexed)
    pub pass: u32,
    /// Lane number (0-indexed)
    pub lane: u32,
    /// Slice number (0-indexed)
    pub slice: u32,
    /// Index within the slice
    pub index: u32,
}

/// Argon2 instance (memory and parameters)
pub struct Instance {
    pub memory: Vec<Block>,
    pub version: u32,
    pub pass_number: u32,
    pub slice_blocks: u32,
    pub segment_length: u32,
    pub index_seed: u64,
    pub lanes: u32,
    pub threads: u32,
    pub argon2_type: Argon2Type,
    pub memory_blocks: u32,
    pub context: Context,
}

impl Instance {
    /// Create a new Argon2 instance
    pub fn new(context: &Context) -> Result<Self, &'static str> {
        // RFC 9106 §3.1 bounds, checked here because every entry point —
        // argon2_hash and the Context pipeline (initialize / fill /
        // finalize) — builds an Instance. The pipeline checked none of them:
        // t = 0 skipped every pass, so the tag no longer depended on the
        // password, and lanes = 0 divided by zero below.
        if context.t_cost < 1 {
            return Err("Time cost must be at least 1");
        }
        if context.lanes < 1 || context.lanes > 0x00FF_FFFF {
            return Err("Parallelism must be between 1 and 2^24 - 1");
        }
        if context.m_cost < 8 * context.lanes {
            return Err("Memory cost must be at least 8 * parallelism KiB");
        }
        if context.outlen < 4 {
            return Err("Output length must be at least 4 bytes");
        }
        if context.salt.len() < 8 {
            return Err("Salt must be at least 8 bytes");
        }

        // Calculate memory blocks (m_cost is in KB, each block is 1024 bytes = 1KB)
        // Ensure minimum of 8 blocks per lane as per Argon2 spec
        let min_blocks = core::cmp::max(8 * context.lanes, context.lanes * SYNC_POINTS);
        let memory_blocks = core::cmp::max(context.m_cost, min_blocks);
        
        // Calculate segment length
        let segment_length = memory_blocks / (context.lanes * SYNC_POINTS);
        let slice_blocks = segment_length * context.lanes;
        
        // Allocate memory
        let memory = vec![Block::default(); memory_blocks as usize];
        Ok(Self {
            memory,
            version: context.version,
            pass_number: 0,
            slice_blocks,
            segment_length,
            index_seed: 0,
            lanes: context.lanes,
            threads: context.threads,
            argon2_type: context.argon2_type,
            memory_blocks,
            context: context.clone(),
        })
    }
}



/// Argon2 context (input parameters)
#[derive(Clone)]
pub struct Context {
    /// Password/message
    pub password: Vec<u8>,
    /// Salt
    pub salt: Vec<u8>,
    /// Secret key (optional)
    pub secret: Vec<u8>,
    /// Associated data (optional)
    pub ad: Vec<u8>,
    /// Output length in bytes
    pub outlen: u32,
    /// Time cost (number of passes)
    pub t_cost: u32,
    /// Memory cost in KB
    pub m_cost: u32,
    /// Parallelism (number of lanes)
    pub lanes: u32,
    /// Number of threads (usually same as lanes)
    pub threads: u32,
    /// Argon2 version
    pub version: u32,
    /// Algorithm variant
    pub argon2_type: Argon2Type,
}

impl Context {
    /// Create a new context with required parameters
    pub fn new(
        password: &[u8],
        salt: &[u8],
        outlen: u32,
        t_cost: u32,
        m_cost: u32,
        lanes: u32,
        argon2_type: Argon2Type,
    ) -> Self {
        Self {
            password: password.to_vec(),
            salt: salt.to_vec(),
            secret: vec![],
            ad: vec![],
            outlen,
            t_cost,
            m_cost,
            lanes,
            threads: lanes,
            version: DEFAULT_VERSION,
            argon2_type,
        }
    }

    /// Set secret key
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = secret.to_vec();
        self
    }

    /// Set associated data
    pub fn with_ad(mut self, ad: &[u8]) -> Self {
        self.ad = ad.to_vec();
        self
    }

    /// Set version
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

/// Parameters for Argon2
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Memory cost in KB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
    /// Output length in bytes
    pub output_len: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            m_cost: 4096,  // 4 MB
            t_cost: 3,     // 3 iterations
            p_cost: 1,     // 1 lane
            output_len: 32, // 32 bytes
        }
    }
}
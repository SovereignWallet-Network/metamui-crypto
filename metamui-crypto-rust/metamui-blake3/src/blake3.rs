// MetaMUI BLAKE3 Implementation
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// See LICENSE for full terms.
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


//! Portable BLAKE3 core: the compression function, the chunk/tree state and
//! the XOF. Every digest this crate produces is computed here, by the same
//! scalar arithmetic on every target.

use crate::{HASH_SIZE, KEY_SIZE};
use metamui_security_utils::Zeroize;

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Bytes per chunk (the leaf of the tree).
#[doc(hidden)]
pub const CHUNK_LEN: usize = 1024;
/// Bytes per compression block.
#[doc(hidden)]
pub const BLOCK_LEN: usize = 64;

/// BLAKE3 IV (same as BLAKE2s)
#[doc(hidden)]
pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// BLAKE3 message permutation (from official reference implementation)
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// BLAKE3 flags. These, the IV and `compress`/`chunk_cv`/`parent_cv` are
// `pub` but hidden: they are the oracle a backend (see `crate::backend`) is
// measured against, not API.
#[doc(hidden)]
pub const CHUNK_START: u32 = 1 << 0;
#[doc(hidden)]
pub const CHUNK_END: u32 = 1 << 1;
#[doc(hidden)]
pub const PARENT: u32 = 1 << 2;
#[doc(hidden)]
pub const ROOT: u32 = 1 << 3;
#[doc(hidden)]
pub const KEYED_HASH: u32 = 1 << 4;
#[doc(hidden)]
pub const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
#[doc(hidden)]
pub const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// Blake3State (optimized for O(log N) memory usage)
#[derive(Clone)]
struct Blake3State {
    cv: [u32; 8],  // Chaining value (for current chunk)
    key: [u32; 8], // Key (IV or actual key)
    chunk: Vec<u8>,
    chunk_counter: u64,
    flags: u32,
    // Stack of right-side CVs for tree construction
    cv_stack: Vec<[u32; 8]>,
}

/// The root node's compression inputs, kept un-collapsed so the XOF can
/// re-compress the same block with successive output-block counters
/// (BLAKE3 spec §2.6). Collapsing the root to a single compression result
/// makes any output beyond 64 bytes impossible to produce correctly.
struct RootOutput {
    input_cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    block_len: u32,
    flags: u32,
}

impl Drop for Blake3State {
    fn drop(&mut self) {
        for i in 0..8 {
            self.cv[i] = 0;
            self.key[i] = 0;
        }
        self.chunk.zeroize();
        for cv in &mut self.cv_stack {
            for j in 0..8 {
                cv[j] = 0;
            }
        }
    }
}

impl Blake3State {
    fn new() -> Self {
        Self::initialize(&IV, 0)
    }
    
    fn new_keyed(key: &[u32; 8]) -> Self {
        Self::initialize(key, KEYED_HASH)
    }
    
    fn initialize(key: &[u32; 8], flags: u32) -> Self {
        Self {
            cv: *key,
            key: *key,
            chunk: Vec::with_capacity(CHUNK_LEN),
            chunk_counter: 0,
            flags: CHUNK_START | flags,
            cv_stack: Vec::with_capacity(54), // Max tree height for 2^64 chunks
        }
    }
    
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        
        // If we have a full chunk from previous update, process it now because we have more data
        if self.chunk.len() == CHUNK_LEN {
            // Process the chunk before adding more data
            self.process_chunk();
        }
        
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_remaining = CHUNK_LEN - self.chunk.len();
            
            if remaining <= chunk_remaining {
                self.chunk.extend_from_slice(&data[offset..]);
                return;
            }
            
            self.chunk.extend_from_slice(&data[offset..offset + chunk_remaining]);
            self.process_chunk();
            offset += chunk_remaining;
        }
    }
    
    fn finalize(&mut self, output_length: usize) -> Vec<u8> {
        // Single chunk (root): empty input, or one buffered chunk with an
        // empty CV stack.
        if self.chunk_counter == 0 {
            let root = self.chunk_root_output();
            return Self::root_output_bytes(&root, output_length);
        }

        // Multi-chunk case:
        // 1. Process the last chunk (in buffer) to get its CV.
        // 2. Merge with stack; the FINAL merge keeps its parent block as
        //    the root output block instead of collapsing to a CV.
        let mut current_cv = self.compress_chunk_cv(self.flags | CHUNK_END);
        self.chunk_counter += 1;

        // Merge with stack
        while let Some(left_cv) = self.cv_stack.pop() {
            if self.cv_stack.is_empty() {
                // Final merge - produces ROOT output
                let root = self.parent_root_output(&left_cv, &current_cv);
                return Self::root_output_bytes(&root, output_length);
            } else {
                // Intermediate merge - produces CV
                current_cv = self.parent_output_cv(&left_cv, &current_cv);
            }
        }

        panic!("Invalid state in finalize");
    }

    /// Build the root output descriptor for the single-chunk case: process
    /// every non-final block, then capture (input CV, final block, len,
    /// flags) so output blocks can be re-compressed per the XOF rules.
    fn chunk_root_output(&mut self) -> RootOutput {
        let chunk_len = self.chunk.len();
        let last_block_start = if chunk_len == 0 {
            0
        } else {
            ((chunk_len - 1) / BLOCK_LEN) * BLOCK_LEN
        };

        let mut block_flags = self.flags;
        let mut block_offset = 0;
        while block_offset < last_block_start {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&self.chunk[block_offset..block_offset + BLOCK_LEN]);
            let result = compress(&self.cv, &block, self.chunk_counter,
                                  BLOCK_LEN as u32, block_flags);
            self.cv.copy_from_slice(&result[..8]);
            block_offset += BLOCK_LEN;
            block_flags = self.flags & (KEYED_HASH | DERIVE_KEY_CONTEXT | DERIVE_KEY_MATERIAL);
        }

        let mut block = [0u8; BLOCK_LEN];
        let last_len = chunk_len - last_block_start;
        block[..last_len].copy_from_slice(&self.chunk[last_block_start..]);

        RootOutput {
            input_cv: self.cv,
            block,
            block_len: last_len as u32,
            flags: block_flags | CHUNK_END | ROOT,
        }
    }

    /// Root output descriptor for the final parent merge.
    fn parent_root_output(&self, left: &[u32; 8], right: &[u32; 8]) -> RootOutput {
        let mut parent_block = [0u8; BLOCK_LEN];
        parent_block[..32].copy_from_slice(&words_to_bytes(left));
        parent_block[32..64].copy_from_slice(&words_to_bytes(right));
        RootOutput {
            input_cv: self.key,
            block: parent_block,
            block_len: BLOCK_LEN as u32,
            flags: PARENT | ROOT | self.mode_flags(),
        }
    }

    /// Persistent mode flags that must reach every parent/root compression.
    fn mode_flags(&self) -> u32 {
        self.flags & (KEYED_HASH | DERIVE_KEY_CONTEXT | DERIVE_KEY_MATERIAL)
    }

    /// BLAKE3 XOF: output block i = compress(input_cv, root_block, i,
    /// block_len, flags), 64 bytes per block. The previous implementation
    /// chained a homemade hash(base||counter) construction, which produced
    /// output incompatible with BLAKE3 for every length > 32 (and never
    /// matched the official vectors' 131-byte expansions). Ground truth:
    /// test-vectors/blake3/blake3-official-vectors.json.
    fn root_output_bytes(root: &RootOutput, output_length: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(output_length);
        let mut counter = 0u64;
        while out.len() < output_length {
            let words = compress(&root.input_cv, &root.block, counter,
                                 root.block_len, root.flags);
            let bytes = words_to_bytes_16(&words);
            let needed = output_length - out.len();
            out.extend_from_slice(&bytes[..core::cmp::min(needed, BLOCK_LEN)]);
            counter += 1;
        }
        out
    }
    
    fn process_chunk(&mut self) {
        // Calculate CV for current chunk
        let cv = self.compress_chunk_cv(self.flags | CHUNK_END);
        self.chunk_counter += 1;
        
        // Add to stack and merge if needed
        self.add_cv_to_stack(cv);
        
        // Reset for next chunk
        self.chunk.clear();
        // Preserve persistent flags (KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL)
        let persistent_flags = self.flags & (KEYED_HASH | DERIVE_KEY_CONTEXT | DERIVE_KEY_MATERIAL);
        self.flags = CHUNK_START | persistent_flags;
        // Reset CV to key/IV for next chunk
        self.cv = self.key;
    }
    
    fn add_cv_to_stack(&mut self, mut new_cv: [u32; 8]) {
        // Merge with stack based on chunk counter
        // We merge trailing_zeros(chunk_counter) times
        let merges = self.chunk_counter.trailing_zeros();
        
        for _ in 0..merges {
            let left_cv = self.cv_stack.pop().expect("Stack empty during merge");
            new_cv = self.parent_output_cv(&left_cv, &new_cv);
        }
        
        self.cv_stack.push(new_cv);
    }
    
    fn compress_chunk_cv(&mut self, final_flags: u32) -> [u32; 8] {
        let result = self.compress_chunk_internal(final_flags);
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&result[..8]);
        cv
    }
    
    fn compress_chunk_internal(&mut self, final_flags: u32) -> [u32; 16] {
        let mut block_flags = self.flags;
        let mut block_offset = 0;
        
        // If chunk is empty (and it's the only chunk), we process one empty block
        if self.chunk.is_empty() {
             return compress(&self.cv, &[0u8; BLOCK_LEN], self.chunk_counter, 0, final_flags);
        }
        
        let mut last_result = [0u32; 16];
        
        while block_offset < self.chunk.len() {
            let block_size = core::cmp::min(BLOCK_LEN, self.chunk.len() - block_offset);
            let mut block = [0u8; BLOCK_LEN];
            block[..block_size].copy_from_slice(&self.chunk[block_offset..block_offset + block_size]);
            
            let is_final_block = block_offset + block_size >= self.chunk.len();
            let mut current_flags = block_flags;
            if is_final_block {
                // Only keep CHUNK_START if this is the first block of the chunk
                current_flags = if block_offset == 0 {
                    final_flags
                } else {
                    final_flags & !CHUNK_START
                };
            }
            
            // For intermediate blocks, use BLOCK_LEN; for final block, use actual size
            let block_len = if is_final_block {
                block_size as u32
            } else {
                BLOCK_LEN as u32
            };
            
            
            last_result = compress(&self.cv, &block, self.chunk_counter, block_len, current_flags);
            
            self.cv.copy_from_slice(&last_result[..8]);
            block_offset += block_size;
            
            // Preserve persistent flags for next blocks
            block_flags = self.flags & (KEYED_HASH | DERIVE_KEY_CONTEXT | DERIVE_KEY_MATERIAL);
        }
        
        last_result
    }
    
    
    fn parent_output_cv(&self, left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
        let output = self.parent_compress(left, right, 0);  // no ROOT for intermediate nodes
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&output[..8]);
        cv
    }
    
    fn parent_compress(&self, left: &[u32; 8], right: &[u32; 8], extra_flags: u32) -> [u32; 16] {
        let mut parent_block = [0u8; BLOCK_LEN];
        let left_bytes = words_to_bytes(left);
        let right_bytes = words_to_bytes(right);
        parent_block[..32].copy_from_slice(&left_bytes);
        parent_block[32..64].copy_from_slice(&right_bytes);

        // Mode flags (KEYED_HASH / DERIVE_KEY_*) must reach every parent
        // compression — dropping them here made keyed and derive_key wrong
        // for every input over one chunk (any parent merge).
        compress(&self.key, &parent_block, 0, BLOCK_LEN as u32,
                 PARENT | extra_flags | self.mode_flags())
    }
    
}

/// Native BLAKE3 hasher
#[derive(Clone)]
pub struct Blake3Hasher {
    state: Blake3State,
}

impl Drop for Blake3Hasher {
    fn drop(&mut self) {
        // State will be zeroized through its own Drop impl
    }
}

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self {
            state: Blake3State::new(),
        }
    }

    /// Create a new keyed BLAKE3 hasher
    pub fn new_keyed(key: &[u8; KEY_SIZE]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
        }
        Self {
            state: Blake3State::new_keyed(&key_words),
        }
    }

    /// Create a new derive key hasher.
    ///
    /// Per the BLAKE3 spec: the context string is hashed in its own
    /// DERIVE_KEY_CONTEXT pass, and its 32-byte digest keys the
    /// DERIVE_KEY_MATERIAL pass that the returned hasher performs. (The
    /// old "simplified" single-state version was not BLAKE3 derive_key.)
    pub fn new_derive_key(context: &str) -> Self {
        let mut context_state = Blake3State::initialize(&IV, DERIVE_KEY_CONTEXT);
        context_state.update(context.as_bytes());
        let context_output = context_state.finalize(KEY_SIZE);

        let mut context_key_words = [0u32; 8];
        for i in 0..8 {
            context_key_words[i] = u32::from_le_bytes([
                context_output[i * 4],
                context_output[i * 4 + 1],
                context_output[i * 4 + 2],
                context_output[i * 4 + 3],
            ]);
        }

        Self {
            state: Blake3State::initialize(&context_key_words, DERIVE_KEY_MATERIAL),
        }
    }

    /// Update the hasher with new data
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Batch update for multiple chunks (optimized for throughput)
    pub fn update_batch(&mut self, chunks: &[&[u8]]) {
        for chunk in chunks {
            self.state.update(chunk);
        }
    }

    /// Finalize the hash
    pub fn finalize(&self) -> [u8; HASH_SIZE] {
        let mut state_copy = self.state.clone();
        let output = state_copy.finalize(32);
        let mut result = [0u8; HASH_SIZE];
        result.copy_from_slice(&output[..HASH_SIZE]);
        result
    }

    /// Finalize with arbitrary output length (BLAKE3 XOF).
    pub fn finalize_len(&self, output_length: usize) -> Vec<u8> {
        let mut state_copy = self.state.clone();
        state_copy.finalize(output_length)
    }
}

/// Permute the message block according to MSG_PERMUTATION
#[inline(always)]
fn permute(block: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = block[MSG_PERMUTATION[i]];
    }
    *block = permuted;
}

/// Perform one round of BLAKE3 mixing
#[inline(always)]
fn round_function(state: &mut [u32; 16], block: &[u32; 16]) {
    // Mix the columns
    g(state, 0, 4, 8, 12, block[0], block[1]);
    g(state, 1, 5, 9, 13, block[2], block[3]);
    g(state, 2, 6, 10, 14, block[4], block[5]);
    g(state, 3, 7, 11, 15, block[6], block[7]);
    // Mix the diagonals
    g(state, 0, 5, 10, 15, block[8], block[9]);
    g(state, 1, 6, 11, 12, block[10], block[11]);
    g(state, 2, 7, 8, 13, block[12], block[13]);
    g(state, 3, 4, 9, 14, block[14], block[15]);
}

/// BLAKE3 compression function (portable; the only one in this crate).
#[doc(hidden)]
#[inline]
pub fn compress(cv: &[u32; 8], block: &[u8], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    compress_portable(cv, block, counter, block_len, flags)
}

/// Chaining value of one chunk of the tree: `chunk` (at most [`CHUNK_LEN`]
/// bytes; empty only for the empty message) at position `counter`, keyed by
/// `key`, with the mode `flags` (0, [`KEYED_HASH`] or a `DERIVE_KEY_*`
/// flag) on every block and never [`ROOT`]. The oracle of a backend's
/// `chunk_cvs` (see [`crate::backend`]).
#[doc(hidden)]
pub fn chunk_cv(chunk: &[u8], key: &[u32; 8], counter: u64, flags: u32) -> [u32; 8] {
    debug_assert!(chunk.len() <= CHUNK_LEN);
    let mut cv = *key;
    let mut block_flags = flags | CHUNK_START;
    let mut offset = 0;
    loop {
        let block_len = core::cmp::min(BLOCK_LEN, chunk.len() - offset);
        let mut block = [0u8; BLOCK_LEN];
        block[..block_len].copy_from_slice(&chunk[offset..offset + block_len]);
        if offset + BLOCK_LEN >= chunk.len() {
            block_flags |= CHUNK_END;
        }
        let out = compress(&cv, &block, counter, block_len as u32, block_flags);
        cv.copy_from_slice(&out[..8]);
        block_flags = flags;
        offset += BLOCK_LEN;
        if offset >= chunk.len() {
            return cv;
        }
    }
}

/// Chaining value (or, with [`ROOT`] in `flags`, the root words) of the
/// parent of two subtrees: `compress(key, left ‖ right, 0, 64, PARENT | flags)`.
#[doc(hidden)]
pub fn parent_cv(left: &[u32; 8], right: &[u32; 8], key: &[u32; 8], flags: u32) -> [u32; 8] {
    let mut block = [0u8; BLOCK_LEN];
    for i in 0..8 {
        block[i * 4..i * 4 + 4].copy_from_slice(&left[i].to_le_bytes());
        block[32 + i * 4..32 + i * 4 + 4].copy_from_slice(&right[i].to_le_bytes());
    }
    let out = compress(key, &block, 0, BLOCK_LEN as u32, PARENT | flags);
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[..8]);
    cv
}

/// Portable BLAKE3 compression function
fn compress_portable(cv: &[u32; 8], block: &[u8], counter: u64, block_len: u32, flags: u32) -> [u32; 16] {
    // Initialize state
    let counter_low = counter as u32;
    let counter_high = (counter >> 32) as u32;
    let mut state = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ];
    
    
    // Convert block bytes to words
    let mut block_words = words_from_bytes(block);
    
    
    // Perform 7 rounds with permutation between each
    round_function(&mut state, &block_words); // round 1
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 2
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 3
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 4
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 5
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 6
    permute(&mut block_words);
    round_function(&mut state, &block_words); // round 7
    
    
    // Final XOR step
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    
    
    state
}

/// BLAKE3 G function (exactly translated from Kotlin)
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    if d == 15 {
    }
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = rotr(state[d] ^ state[a], 16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotr(state[b] ^ state[c], 12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = rotr(state[d] ^ state[a], 8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotr(state[b] ^ state[c], 7);
    if d == 15 {
    }
}

/// Rotate right (exactly from Kotlin implementation)
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Convert bytes to 32-bit words
fn words_from_bytes(bytes: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    
    for (i, chunk) in bytes.chunks(4).enumerate().take(16) {
        if chunk.len() == 4 {
            words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        } else {
            // Handle partial chunks by padding with zeros
            let mut padded = [0u8; 4];
            padded[..chunk.len()].copy_from_slice(chunk);
            words[i] = u32::from_le_bytes(padded);
        }
    }
    
    words
}

/// Convert 32-bit words to bytes (exactly from Kotlin)
fn words_to_bytes(words: &[u32; 8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    
    bytes
}

/// Convert 16 words to bytes (exactly from Kotlin wordsToBytes)
fn words_to_bytes_16(words: &[u32; 16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    
    for &word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    
    bytes
}

/// Compute BLAKE3 hash using native implementation
pub fn native_blake3(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute keyed BLAKE3 hash using native implementation
pub fn native_blake3_keyed(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(data);
    hasher.finalize()
}

/// Derive key using BLAKE3
pub fn native_blake3_derive_key(context: &str, material: &[u8]) -> [u8; HASH_SIZE] {
    // Step 1: Hash context string with DERIVE_KEY_CONTEXT flag
    let mut context_state = Blake3State::initialize(&IV, DERIVE_KEY_CONTEXT);
    context_state.update(context.as_bytes());
    let context_output = context_state.finalize(KEY_SIZE);
    
    // Convert to key
    let mut context_key_bytes = [0u8; KEY_SIZE];
    context_key_bytes.copy_from_slice(&context_output[..KEY_SIZE]);
    
    
    // Convert key bytes to words
    let mut context_key_words = [0u32; 8];
    for i in 0..8 {
        context_key_words[i] = u32::from_le_bytes([
            context_key_bytes[i * 4],
            context_key_bytes[i * 4 + 1],
            context_key_bytes[i * 4 + 2],
            context_key_bytes[i * 4 + 3],
        ]);
    }
    
    // Step 2: Hash material with context key and DERIVE_KEY_MATERIAL flag (NOT KEYED_HASH)
    let mut material_state = Blake3State::initialize(&context_key_words, DERIVE_KEY_MATERIAL);
    material_state.update(material);
    let output = material_state.finalize(HASH_SIZE);
    
    let mut result = [0u8; HASH_SIZE];
    result.copy_from_slice(&output[..HASH_SIZE]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_context_hash() {
        // Test that context hashing with DERIVE_KEY_CONTEXT flag works
        let mut context_state = Blake3State::initialize(&IV, DERIVE_KEY_CONTEXT);
        context_state.update(b"metamui-context");
        let context_output = context_state.finalize(KEY_SIZE);
        
        // Convert to key
        let mut context_key_bytes = [0u8; KEY_SIZE];
        context_key_bytes.copy_from_slice(&context_output[..KEY_SIZE]);
        
        let hex_result = hex::encode(&context_key_bytes);
        println!("Context key: {}", hex_result);
        // This should match the debug output: 777daa7a42e90f11caec2a4ada6697f2760d56904d4f2eb339e66db4c2547b4b
    }
}

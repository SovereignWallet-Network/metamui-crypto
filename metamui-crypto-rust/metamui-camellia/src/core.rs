//! Core Camellia implementation.
//!
//! This module contains the main Camellia cipher implementation.
//! Utility helpers (constant_time_eq, generate_key, generate_iv) are
//! kept here as part of the documented API surface even when the
//! runtime dispatch goes through the top-level entry points.

#![allow(dead_code)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::constants::{ROUNDS_128, ROUNDS_256, SBOX1, SBOX2, SBOX3, SBOX4, SIGMA};
use crate::error::CamelliaError;
use crate::types::{Block, Key128, Key192, Key256};
use core::convert::TryInto;
use metamui_security_utils::ConstantTimeEq;
use metamui_security_utils::Zeroize;
#[cfg(all(feature = "random", feature = "getrandom"))]
use getrandom::getrandom;

/// Trait for block cipher operations
pub trait BlockCipher {
    /// Encrypt a block in place
    fn encrypt_block(&self, block: &mut Block);
    
    /// Decrypt a block in place
    fn decrypt_block(&self, block: &mut Block);
}

/// Generic Camellia cipher implementation
#[derive(Clone)]
pub struct Camellia {
    /// Subkeys for encryption/decryption
    subkeys: Vec<u64>,
    /// Number of rounds
    rounds: usize,
}

impl Drop for Camellia {
    fn drop(&mut self) {
        self.subkeys.zeroize();
    }
}

impl Camellia {
    /// Create a new Camellia cipher with the given key
    pub fn new(key: &[u8]) -> Result<Self, CamelliaError> {
        let (subkeys, rounds) = match key.len() {
            16 => {
                let mut k = Key128([0u8; 16]);
                k.0.copy_from_slice(key);
                let subkeys = Self::key_schedule_128(&k);
                k.zeroize();
                (subkeys, ROUNDS_128)
            }
            24 => {
                let mut k = Key192([0u8; 24]);
                k.0.copy_from_slice(key);
                let subkeys = Self::key_schedule_192(&k);
                k.zeroize();
                (subkeys, ROUNDS_256)
            }
            32 => {
                let mut k = Key256([0u8; 32]);
                k.0.copy_from_slice(key);
                let subkeys = Self::key_schedule_256(&k);
                k.zeroize();
                (subkeys, ROUNDS_256)
            }
            size => return Err(CamelliaError::InvalidKeySize { size }),
        };
        
        Ok(Camellia { subkeys, rounds })
    }
    
    /// F-function
    #[inline(always)]
    fn f_function(x: u64, k: u64) -> u64 {
        let x = x ^ k;
        
        // Split into bytes
        let t1 = ((x >> 56) & 0xFF) as usize;
        let t2 = ((x >> 48) & 0xFF) as usize;
        let t3 = ((x >> 40) & 0xFF) as usize;
        let t4 = ((x >> 32) & 0xFF) as usize;
        let t5 = ((x >> 24) & 0xFF) as usize;
        let t6 = ((x >> 16) & 0xFF) as usize;
        let t7 = ((x >> 8) & 0xFF) as usize;
        let t8 = (x & 0xFF) as usize;
        
        // Apply S-boxes
        let t1 = SBOX1[t1];
        let t2 = SBOX2[t2];
        let t3 = SBOX3[t3];
        let t4 = SBOX4[t4];
        let t5 = SBOX2[t5];
        let t6 = SBOX3[t6];
        let t7 = SBOX4[t7];
        let t8 = SBOX1[t8];
        
        // P-function (linear transformation)
        let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
        let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
        let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
        let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
        let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
        let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
        let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
        let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
        
        // Combine result
        ((y1 as u64) << 56) | ((y2 as u64) << 48) | ((y3 as u64) << 40) | ((y4 as u64) << 32) |
        ((y5 as u64) << 24) | ((y6 as u64) << 16) | ((y7 as u64) << 8) | (y8 as u64)
    }
    
    /// FL-function
    #[inline(always)]
    fn fl_function(x: u64, k: u64) -> u64 {
        let x1 = x >> 32;
        let x2 = x & 0xFFFFFFFF;
        let k1 = k >> 32;
        let k2 = k & 0xFFFFFFFF;
        
        let x2_new = x2 ^ Self::rotate_left_32((x1 & k1) as u32, 1) as u64;
        let x1_new = x1 ^ (x2_new | k2);
        
        (x1_new << 32) | x2_new
    }
    
    /// Inverse FL-function
    #[inline(always)]
    fn fl_inv_function(y: u64, k: u64) -> u64 {
        let y1 = y >> 32;
        let y2 = y & 0xFFFFFFFF;
        let k1 = k >> 32;
        let k2 = k & 0xFFFFFFFF;
        
        let x1 = y1 ^ (y2 | k2);
        let x2 = y2 ^ Self::rotate_left_32((x1 & k1) as u32, 1) as u64;
        
        (x1 << 32) | x2
    }
    
    /// Rotate 32-bit value left
    #[inline(always)]
    fn rotate_left_32(x: u32, n: u32) -> u32 {
        x.rotate_left(n)
    }
    
    /// Rotate 128-bit value left
    fn rotate_left_128(x: (u64, u64), n: u32) -> (u64, u64) {
        let n = n % 128;
        if n == 0 {
            x
        } else if n < 64 {
            (
                (x.0 << n) | (x.1 >> (64 - n)),
                (x.1 << n) | (x.0 >> (64 - n))
            )
        } else {
            let n = n - 64;
            (
                (x.1 << n) | (x.0 >> (64 - n)),
                (x.0 << n) | (x.1 >> (64 - n))
            )
        }
    }
    
    /// Generate subkeys for 128-bit key
    fn key_schedule_128(key: &Key128) -> Vec<u64> {
        // Load key
        let kl = (
            u64::from_be_bytes(key.0[0..8].try_into().unwrap()),
            u64::from_be_bytes(key.0[8..16].try_into().unwrap())
        );
        let kr = (0u64, 0u64);
        
        // Generate KA and KB
        let mut d1 = kl.0 ^ kr.0;
        let mut d2 = kl.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[0]);
        d1 ^= Self::f_function(d2, SIGMA[1]);
        d1 ^= kl.0;
        d2 ^= kl.1;
        d2 ^= Self::f_function(d1, SIGMA[2]);
        d1 ^= Self::f_function(d2, SIGMA[3]);
        let ka = (d1, d2);
        
        d1 = ka.0 ^ kr.0;
        d2 = ka.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[4]);
        d1 ^= Self::f_function(d2, SIGMA[5]);
        let _kb = (d1, d2);
        
        // Generate subkeys
        let mut subkeys = Vec::with_capacity(26);
        
        // kw1, kw2
        subkeys.push(kl.0);
        subkeys.push(kl.1);
        
        // k1..k6
        subkeys.push(ka.0);
        subkeys.push(ka.1);
        let kl_15 = Self::rotate_left_128(kl, 15);
        subkeys.push(kl_15.0);
        subkeys.push(kl_15.1);
        let ka_15 = Self::rotate_left_128(ka, 15);
        subkeys.push(ka_15.0);
        subkeys.push(ka_15.1);
        
        // kl1, kl2
        let ka_30 = Self::rotate_left_128(ka, 30);
        subkeys.push(ka_30.0);
        subkeys.push(ka_30.1);
        
        // k7..k12
        let kl_45 = Self::rotate_left_128(kl, 45);
        subkeys.push(kl_45.0);  // k7
        subkeys.push(kl_45.1);  // k8
        let ka_45 = Self::rotate_left_128(ka, 45);
        subkeys.push(ka_45.0);  // k9
        let kl_60 = Self::rotate_left_128(kl, 60);
        subkeys.push(kl_60.1);  // k10
        let ka_60 = Self::rotate_left_128(ka, 60);
        subkeys.push(ka_60.0);  // k11
        subkeys.push(ka_60.1);  // k12
        
        // kl3, kl4
        let kl_77 = Self::rotate_left_128(kl, 77);
        subkeys.push(kl_77.0);
        subkeys.push(kl_77.1);
        
        // k13..k18
        let kl_94 = Self::rotate_left_128(kl, 94);
        subkeys.push(kl_94.0);
        subkeys.push(kl_94.1);
        let ka_94 = Self::rotate_left_128(ka, 94);
        subkeys.push(ka_94.0);
        subkeys.push(ka_94.1);
        let kl_111 = Self::rotate_left_128(kl, 111);
        subkeys.push(kl_111.0);
        subkeys.push(kl_111.1);
        
        // kw3, kw4
        let ka_111 = Self::rotate_left_128(ka, 111);
        subkeys.push(ka_111.0);
        subkeys.push(ka_111.1);
        
        subkeys
    }
    
    /// Generate subkeys for 192-bit key
    fn key_schedule_192(key: &Key192) -> Vec<u64> {
        // Load key
        let kl = (
            u64::from_be_bytes(key.0[0..8].try_into().unwrap()),
            u64::from_be_bytes(key.0[8..16].try_into().unwrap())
        );
        let kr_temp = u64::from_be_bytes([key.0[16], key.0[17], key.0[18], key.0[19], 
                                          key.0[20], key.0[21], key.0[22], key.0[23]]);
        let kr = (kr_temp, !kr_temp);
        
        // Generate KA and KB  
        let mut d1 = kl.0 ^ kr.0;
        let mut d2 = kl.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[0]);
        d1 ^= Self::f_function(d2, SIGMA[1]);
        d1 ^= kl.0;
        d2 ^= kl.1;
        d2 ^= Self::f_function(d1, SIGMA[2]);
        d1 ^= Self::f_function(d2, SIGMA[3]);
        let ka = (d1, d2);
        
        d1 = ka.0 ^ kr.0;
        d2 = ka.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[4]);
        d1 ^= Self::f_function(d2, SIGMA[5]);
        let kb = (d1, d2);
        
        // Generate subkeys (24 rounds)
        let mut subkeys = Vec::with_capacity(34);
        
        // kw1, kw2
        subkeys.push(kl.0);
        subkeys.push(kl.1);
        
        // k1..k6
        subkeys.push(kb.0);
        subkeys.push(kb.1);
        let kr_15 = Self::rotate_left_128(kr, 15);
        subkeys.push(kr_15.0);
        subkeys.push(kr_15.1);
        let ka_15 = Self::rotate_left_128(ka, 15);
        subkeys.push(ka_15.0);
        subkeys.push(ka_15.1);
        
        // kl1, kl2
        let kr_30 = Self::rotate_left_128(kr, 30);
        subkeys.push(kr_30.0);
        subkeys.push(kr_30.1);
        
        // k7..k12
        let kb_30 = Self::rotate_left_128(kb, 30);
        subkeys.push(kb_30.0);
        subkeys.push(kb_30.1);
        let kl_45 = Self::rotate_left_128(kl, 45);
        subkeys.push(kl_45.0);
        subkeys.push(kl_45.1);
        let ka_45 = Self::rotate_left_128(ka, 45);
        subkeys.push(ka_45.0);
        subkeys.push(ka_45.1);
        
        // kl3, kl4
        let kl_60 = Self::rotate_left_128(kl, 60);
        subkeys.push(kl_60.0);
        subkeys.push(kl_60.1);
        
        // k13..k18
        let kr_60 = Self::rotate_left_128(kr, 60);
        subkeys.push(kr_60.0);
        subkeys.push(kr_60.1);
        let kb_60 = Self::rotate_left_128(kb, 60);
        subkeys.push(kb_60.0);
        subkeys.push(kb_60.1);
        let kl_77 = Self::rotate_left_128(kl, 77);
        subkeys.push(kl_77.0);
        subkeys.push(kl_77.1);
        
        // kl5, kl6
        let ka_77 = Self::rotate_left_128(ka, 77);
        subkeys.push(ka_77.0);
        subkeys.push(ka_77.1);
        
        // k19..k24
        let kr_94 = Self::rotate_left_128(kr, 94);
        subkeys.push(kr_94.0);
        subkeys.push(kr_94.1);
        let ka_94 = Self::rotate_left_128(ka, 94);
        subkeys.push(ka_94.0);
        subkeys.push(ka_94.1);
        let kl_111 = Self::rotate_left_128(kl, 111);
        subkeys.push(kl_111.0);
        subkeys.push(kl_111.1);
        
        // kw3, kw4
        let kb_111 = Self::rotate_left_128(kb, 111);
        subkeys.push(kb_111.0);
        subkeys.push(kb_111.1);
        
        subkeys
    }
    
    /// Generate subkeys for 256-bit key
    fn key_schedule_256(key: &Key256) -> Vec<u64> {
        // Load key
        let kl = (
            u64::from_be_bytes(key.0[0..8].try_into().unwrap()),
            u64::from_be_bytes(key.0[8..16].try_into().unwrap())
        );
        let kr = (
            u64::from_be_bytes(key.0[16..24].try_into().unwrap()),
            u64::from_be_bytes(key.0[24..32].try_into().unwrap())
        );
        
        // Generate KA and KB
        let mut d1 = kl.0 ^ kr.0;
        let mut d2 = kl.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[0]);
        d1 ^= Self::f_function(d2, SIGMA[1]);
        d1 ^= kl.0;
        d2 ^= kl.1;
        d2 ^= Self::f_function(d1, SIGMA[2]);
        d1 ^= Self::f_function(d2, SIGMA[3]);
        let ka = (d1, d2);
        
        d1 = ka.0 ^ kr.0;
        d2 = ka.1 ^ kr.1;
        d2 ^= Self::f_function(d1, SIGMA[4]);
        d1 ^= Self::f_function(d2, SIGMA[5]);
        let kb = (d1, d2);
        
        // Generate subkeys for 256-bit (24 rounds, uses kb)
        let mut subkeys = Vec::with_capacity(34);
        
        // kw1, kw2
        subkeys.push(kl.0);
        subkeys.push(kl.1);
        
        // k1..k6
        subkeys.push(kb.0);
        subkeys.push(kb.1);
        let kr_15 = Self::rotate_left_128(kr, 15);
        subkeys.push(kr_15.0);
        subkeys.push(kr_15.1);
        let ka_15 = Self::rotate_left_128(ka, 15);
        subkeys.push(ka_15.0);
        subkeys.push(ka_15.1);
        
        // kl1, kl2
        let kr_30 = Self::rotate_left_128(kr, 30);
        subkeys.push(kr_30.0);
        subkeys.push(kr_30.1);
        
        // k7..k12
        let kb_30 = Self::rotate_left_128(kb, 30);
        subkeys.push(kb_30.0);
        subkeys.push(kb_30.1);
        let kl_45 = Self::rotate_left_128(kl, 45);
        subkeys.push(kl_45.0);
        subkeys.push(kl_45.1);
        let ka_45 = Self::rotate_left_128(ka, 45);
        subkeys.push(ka_45.0);
        subkeys.push(ka_45.1);
        
        // kl3, kl4
        let kl_60 = Self::rotate_left_128(kl, 60);
        subkeys.push(kl_60.0);
        subkeys.push(kl_60.1);
        
        // k13..k18
        let kr_60 = Self::rotate_left_128(kr, 60);
        subkeys.push(kr_60.0);
        subkeys.push(kr_60.1);
        let kb_60 = Self::rotate_left_128(kb, 60);
        subkeys.push(kb_60.0);
        subkeys.push(kb_60.1);
        let kl_77 = Self::rotate_left_128(kl, 77);
        subkeys.push(kl_77.0);
        subkeys.push(kl_77.1);
        
        // kl5, kl6
        let ka_77 = Self::rotate_left_128(ka, 77);
        subkeys.push(ka_77.0);
        subkeys.push(ka_77.1);
        
        // k19..k24
        let kr_94 = Self::rotate_left_128(kr, 94);
        subkeys.push(kr_94.0);
        subkeys.push(kr_94.1);
        let ka_94 = Self::rotate_left_128(ka, 94);
        subkeys.push(ka_94.0);
        subkeys.push(ka_94.1);
        let kl_111 = Self::rotate_left_128(kl, 111);
        subkeys.push(kl_111.0);
        subkeys.push(kl_111.1);
        
        // kw3, kw4
        let kb_111 = Self::rotate_left_128(kb, 111);
        subkeys.push(kb_111.0);
        subkeys.push(kb_111.1);
        
        subkeys
    }
    
    /// Encrypt a block
    pub fn encrypt(&self, block: &mut Block) {
        // Convert block to two 64-bit integers
        let mut d1 = u64::from_be_bytes(block[0..8].try_into().unwrap());
        let mut d2 = u64::from_be_bytes(block[8..16].try_into().unwrap());
        
        // Pre-whitening
        d1 ^= self.subkeys[0];
        d2 ^= self.subkeys[1];
        
        if self.rounds == ROUNDS_128 {
            // 128-bit key encryption
            self.encrypt_rounds_128(&mut d1, &mut d2);
        } else {
            // 192/256-bit key encryption
            self.encrypt_rounds_256(&mut d1, &mut d2);
        }
        
        // Convert back to bytes
        // RFC 3713: C = (D2 << 64) | D1
        // So D2 goes first (high bytes), then D1 (low bytes)
        block[0..8].copy_from_slice(&d2.to_be_bytes());
        block[8..16].copy_from_slice(&d1.to_be_bytes());
    }
    
    /// Decrypt a block
    pub fn decrypt(&self, block: &mut Block) {
        // According to RFC 3713: "The decryption procedure of Camellia can be done 
        // in the same way as the encryption procedure by reversing the order of the subkeys."
        
        // Create a new Camellia instance with reversed subkeys
        let mut reversed_subkeys = self.subkeys.clone();
        
        if self.rounds == ROUNDS_128 {
            // For 128-bit keys, swap according to RFC
            // In our array for 128-bit:
            // 0,1: kw1, kw2
            // 2-7: k1-k6
            // 8,9: ke1, ke2
            // 10-15: k7-k12
            // 16,17: ke3, ke4
            // 18-23: k13-k18
            // 24,25: kw3, kw4
            
            // kw1 <-> kw3, kw2 <-> kw4
            reversed_subkeys.swap(0, 24);
            reversed_subkeys.swap(1, 25);
            
            // k1 <-> k18, k2 <-> k17, ..., k9 <-> k10
            // k1-k6 at indices 2-7
            reversed_subkeys.swap(2, 23);  // k1 <-> k18
            reversed_subkeys.swap(3, 22);  // k2 <-> k17
            reversed_subkeys.swap(4, 21);  // k3 <-> k16
            reversed_subkeys.swap(5, 20);  // k4 <-> k15
            reversed_subkeys.swap(6, 19);  // k5 <-> k14
            reversed_subkeys.swap(7, 18);  // k6 <-> k13
            
            // k7-k12 at indices 10-15
            reversed_subkeys.swap(10, 15); // k7 <-> k12
            reversed_subkeys.swap(11, 14); // k8 <-> k11
            reversed_subkeys.swap(12, 13); // k9 <-> k10
            
            // ke1 <-> ke4, ke2 <-> ke3
            reversed_subkeys.swap(8, 17);  // ke1 <-> ke4
            reversed_subkeys.swap(9, 16);  // ke2 <-> ke3
        } else {
            // For 192/256-bit keys, swap according to RFC
            // kw1 <-> kw3, kw2 <-> kw4
            reversed_subkeys.swap(0, 32);
            reversed_subkeys.swap(1, 33);
            
            // Map round keys: k1-k24 are at indices 2-7, 10-15, 18-23, 26-31
            // k1 <-> k24 (2 <-> 31)
            // k2 <-> k23 (3 <-> 30)
            // ...
            // k12 <-> k13 (15 <-> 18)
            
            // First 6 keys (k1-k6 at indices 2-7)
            reversed_subkeys.swap(2, 31);  // k1 <-> k24
            reversed_subkeys.swap(3, 30);  // k2 <-> k23
            reversed_subkeys.swap(4, 29);  // k3 <-> k22
            reversed_subkeys.swap(5, 28);  // k4 <-> k21
            reversed_subkeys.swap(6, 27);  // k5 <-> k20
            reversed_subkeys.swap(7, 26);  // k6 <-> k19
            
            // Next 6 keys (k7-k12 at indices 10-15)
            reversed_subkeys.swap(10, 23); // k7 <-> k18
            reversed_subkeys.swap(11, 22); // k8 <-> k17
            reversed_subkeys.swap(12, 21); // k9 <-> k16
            reversed_subkeys.swap(13, 20); // k10 <-> k15
            reversed_subkeys.swap(14, 19); // k11 <-> k14
            reversed_subkeys.swap(15, 18); // k12 <-> k13
            
            // FL keys: ke1 <-> ke6, ke2 <-> ke5, ke3 <-> ke4
            reversed_subkeys.swap(8, 25);  // ke1 <-> ke6
            reversed_subkeys.swap(9, 24);  // ke2 <-> ke5
            reversed_subkeys.swap(16, 17); // ke3 <-> ke4
        }
        
        // Create temporary Camellia with reversed keys
        let decrypt_camellia = Camellia {
            subkeys: reversed_subkeys,
            rounds: self.rounds,
        };
        
        // Use encryption with reversed keys for decryption
        decrypt_camellia.encrypt(block);
    }
    
    /// Encryption rounds for 128-bit key
    #[inline]
    fn encrypt_rounds_128(&self, d1: &mut u64, d2: &mut u64) {
        // Rounds 1-6
        *d2 ^= Self::f_function(*d1, self.subkeys[2]);
        *d1 ^= Self::f_function(*d2, self.subkeys[3]);
        *d2 ^= Self::f_function(*d1, self.subkeys[4]);
        *d1 ^= Self::f_function(*d2, self.subkeys[5]);
        *d2 ^= Self::f_function(*d1, self.subkeys[6]);
        *d1 ^= Self::f_function(*d2, self.subkeys[7]);
        
        // FL/FL^-1
        *d1 = Self::fl_function(*d1, self.subkeys[8]);
        *d2 = Self::fl_inv_function(*d2, self.subkeys[9]);
        
        // Rounds 7-12
        *d2 ^= Self::f_function(*d1, self.subkeys[10]);
        *d1 ^= Self::f_function(*d2, self.subkeys[11]);
        *d2 ^= Self::f_function(*d1, self.subkeys[12]);
        *d1 ^= Self::f_function(*d2, self.subkeys[13]);
        *d2 ^= Self::f_function(*d1, self.subkeys[14]);
        *d1 ^= Self::f_function(*d2, self.subkeys[15]);
        
        // FL/FL^-1
        *d1 = Self::fl_function(*d1, self.subkeys[16]);
        *d2 = Self::fl_inv_function(*d2, self.subkeys[17]);
        
        // Rounds 13-18
        *d2 ^= Self::f_function(*d1, self.subkeys[18]);
        *d1 ^= Self::f_function(*d2, self.subkeys[19]);
        *d2 ^= Self::f_function(*d1, self.subkeys[20]);
        *d1 ^= Self::f_function(*d2, self.subkeys[21]);
        *d2 ^= Self::f_function(*d1, self.subkeys[22]);
        *d1 ^= Self::f_function(*d2, self.subkeys[23]);
        
        // Post-whitening
        // RFC 3713: D2 = D2 ^ kw3; D1 = D1 ^ kw4;
        *d2 ^= self.subkeys[24];  // kw3
        *d1 ^= self.subkeys[25];  // kw4
    }
    
    /* Removed - decryption now uses encryption with reversed keys per RFC 3713
    /// Decryption rounds for 128-bit key
    #[inline]
    fn decrypt_rounds_128(&self, d1: &mut u64, d2: &mut u64) {
        // Pre-whitening (using post-whitening keys)
        // RFC 3713: D2 = D2 ^ kw3; D1 = D1 ^ kw4;
        *d2 ^= self.subkeys[24];  // kw3
        *d1 ^= self.subkeys[25];  // kw4
        
        // Rounds 18-13 (reverse)
        *d1 ^= Self::f_function(*d2, self.subkeys[23]);
        *d2 ^= Self::f_function(*d1, self.subkeys[22]);
        *d1 ^= Self::f_function(*d2, self.subkeys[21]);
        *d2 ^= Self::f_function(*d1, self.subkeys[20]);
        *d1 ^= Self::f_function(*d2, self.subkeys[19]);
        *d2 ^= Self::f_function(*d1, self.subkeys[18]);
        
        // FL^-1/FL (swapped)
        *d1 = Self::fl_inv_function(*d1, self.subkeys[16]);
        *d2 = Self::fl_function(*d2, self.subkeys[17]);
        
        // Rounds 12-7 (reverse)
        *d1 ^= Self::f_function(*d2, self.subkeys[15]);
        *d2 ^= Self::f_function(*d1, self.subkeys[14]);
        *d1 ^= Self::f_function(*d2, self.subkeys[13]);
        *d2 ^= Self::f_function(*d1, self.subkeys[12]);
        *d1 ^= Self::f_function(*d2, self.subkeys[11]);
        *d2 ^= Self::f_function(*d1, self.subkeys[10]);
        
        // FL^-1/FL (swapped)
        *d1 = Self::fl_inv_function(*d1, self.subkeys[8]);
        *d2 = Self::fl_function(*d2, self.subkeys[9]);
        
        // Rounds 6-1 (reverse)
        *d1 ^= Self::f_function(*d2, self.subkeys[7]);
        *d2 ^= Self::f_function(*d1, self.subkeys[6]);
        *d1 ^= Self::f_function(*d2, self.subkeys[5]);
        *d2 ^= Self::f_function(*d1, self.subkeys[4]);
        *d1 ^= Self::f_function(*d2, self.subkeys[3]);
        *d2 ^= Self::f_function(*d1, self.subkeys[2]);
        
        // Post-whitening (using pre-whitening keys)
        *d1 ^= self.subkeys[0];
        *d2 ^= self.subkeys[1];
    }
    */
    
    /// Encryption rounds for 192/256-bit key
    #[inline]
    fn encrypt_rounds_256(&self, d1: &mut u64, d2: &mut u64) {
        // Rounds 1-6
        *d2 ^= Self::f_function(*d1, self.subkeys[2]);
        *d1 ^= Self::f_function(*d2, self.subkeys[3]);
        *d2 ^= Self::f_function(*d1, self.subkeys[4]);
        *d1 ^= Self::f_function(*d2, self.subkeys[5]);
        *d2 ^= Self::f_function(*d1, self.subkeys[6]);
        *d1 ^= Self::f_function(*d2, self.subkeys[7]);
        
        // FL/FL^-1
        *d1 = Self::fl_function(*d1, self.subkeys[8]);
        *d2 = Self::fl_inv_function(*d2, self.subkeys[9]);
        
        // Rounds 7-12
        *d2 ^= Self::f_function(*d1, self.subkeys[10]);
        *d1 ^= Self::f_function(*d2, self.subkeys[11]);
        *d2 ^= Self::f_function(*d1, self.subkeys[12]);
        *d1 ^= Self::f_function(*d2, self.subkeys[13]);
        *d2 ^= Self::f_function(*d1, self.subkeys[14]);
        *d1 ^= Self::f_function(*d2, self.subkeys[15]);
        
        // FL/FL^-1
        *d1 = Self::fl_function(*d1, self.subkeys[16]);
        *d2 = Self::fl_inv_function(*d2, self.subkeys[17]);
        
        // Rounds 13-18
        *d2 ^= Self::f_function(*d1, self.subkeys[18]);
        *d1 ^= Self::f_function(*d2, self.subkeys[19]);
        *d2 ^= Self::f_function(*d1, self.subkeys[20]);
        *d1 ^= Self::f_function(*d2, self.subkeys[21]);
        *d2 ^= Self::f_function(*d1, self.subkeys[22]);
        *d1 ^= Self::f_function(*d2, self.subkeys[23]);
        
        // FL/FL^-1
        *d1 = Self::fl_function(*d1, self.subkeys[24]);
        *d2 = Self::fl_inv_function(*d2, self.subkeys[25]);
        
        // Rounds 19-24
        *d2 ^= Self::f_function(*d1, self.subkeys[26]);
        *d1 ^= Self::f_function(*d2, self.subkeys[27]);
        *d2 ^= Self::f_function(*d1, self.subkeys[28]);
        *d1 ^= Self::f_function(*d2, self.subkeys[29]);
        *d2 ^= Self::f_function(*d1, self.subkeys[30]);
        *d1 ^= Self::f_function(*d2, self.subkeys[31]);
        
        // Post-whitening
        *d2 ^= self.subkeys[32];  // kw3
        *d1 ^= self.subkeys[33];  // kw4
    }
    
    /* Removed - decryption now uses encryption with reversed keys per RFC 3713
    /// Decryption rounds for 192/256-bit key
    #[inline]
    fn decrypt_rounds_256(&self, d1: &mut u64, d2: &mut u64) {
        // Pre-whitening (using post-whitening keys)
        *d2 ^= self.subkeys[32];  // kw3
        *d1 ^= self.subkeys[33];  // kw4
        
        // Rounds 24-19 (reverse)
        *d2 ^= Self::f_function(*d1, self.subkeys[31]);
        *d1 ^= Self::f_function(*d2, self.subkeys[30]);
        *d2 ^= Self::f_function(*d1, self.subkeys[29]);
        *d1 ^= Self::f_function(*d2, self.subkeys[28]);
        *d2 ^= Self::f_function(*d1, self.subkeys[27]);
        *d1 ^= Self::f_function(*d2, self.subkeys[26]);
        
        // FL^-1/FL (swapped)
        *d1 = Self::fl_inv_function(*d1, self.subkeys[24]);
        *d2 = Self::fl_function(*d2, self.subkeys[25]);
        
        // Rounds 18-13 (reverse)
        *d2 ^= Self::f_function(*d1, self.subkeys[23]);
        *d1 ^= Self::f_function(*d2, self.subkeys[22]);
        *d2 ^= Self::f_function(*d1, self.subkeys[21]);
        *d1 ^= Self::f_function(*d2, self.subkeys[20]);
        *d2 ^= Self::f_function(*d1, self.subkeys[19]);
        *d1 ^= Self::f_function(*d2, self.subkeys[18]);
        
        // FL^-1/FL (swapped)
        *d1 = Self::fl_inv_function(*d1, self.subkeys[16]);
        *d2 = Self::fl_function(*d2, self.subkeys[17]);
        
        // Rounds 12-7 (reverse)
        *d2 ^= Self::f_function(*d1, self.subkeys[15]);
        *d1 ^= Self::f_function(*d2, self.subkeys[14]);
        *d2 ^= Self::f_function(*d1, self.subkeys[13]);
        *d1 ^= Self::f_function(*d2, self.subkeys[12]);
        *d2 ^= Self::f_function(*d1, self.subkeys[11]);
        *d1 ^= Self::f_function(*d2, self.subkeys[10]);
        
        // FL^-1/FL (swapped)
        *d1 = Self::fl_inv_function(*d1, self.subkeys[8]);
        *d2 = Self::fl_function(*d2, self.subkeys[9]);
        
        // Rounds 6-1 (reverse)
        *d2 ^= Self::f_function(*d1, self.subkeys[7]);
        *d1 ^= Self::f_function(*d2, self.subkeys[6]);
        *d2 ^= Self::f_function(*d1, self.subkeys[5]);
        *d1 ^= Self::f_function(*d2, self.subkeys[4]);
        *d2 ^= Self::f_function(*d1, self.subkeys[3]);
        *d1 ^= Self::f_function(*d2, self.subkeys[2]);
        
        // Post-whitening (using pre-whitening keys)
        *d1 ^= self.subkeys[0];
        *d2 ^= self.subkeys[1];
    }
    */
}

impl BlockCipher for Camellia {
    fn encrypt_block(&self, block: &mut Block) {
        self.encrypt(block);
    }
    
    fn decrypt_block(&self, block: &mut Block) {
        self.decrypt(block);
    }
}

/// Camellia with 128-bit key
pub struct Camellia128(Camellia);

impl Camellia128 {
    /// Create new Camellia-128 cipher
    pub fn new(key: &[u8; 16]) -> Self {
        Camellia128(Camellia::new(key).unwrap())
    }
}

impl crate::BlockCipher for Camellia128 {
    fn encrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.encrypt_block(block);
    }
    
    fn decrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.decrypt_block(block);
    }
    
    fn cipher_name(&self) -> &'static str {
        "Camellia-128"
    }
    
    fn key_size(&self) -> usize {
        16
    }
}

/// Camellia with 192-bit key
pub struct Camellia192(Camellia);

impl Camellia192 {
    /// Create new Camellia-192 cipher
    pub fn new(key: &[u8; 24]) -> Self {
        Camellia192(Camellia::new(key).unwrap())
    }
}

impl crate::BlockCipher for Camellia192 {
    fn encrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.encrypt_block(block);
    }
    
    fn decrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.decrypt_block(block);
    }
    
    fn cipher_name(&self) -> &'static str {
        "Camellia-192"
    }
    
    fn key_size(&self) -> usize {
        24
    }
}

/// Camellia with 256-bit key
pub struct Camellia256(Camellia);

impl Camellia256 {
    /// Create new Camellia-256 cipher
    pub fn new(key: &[u8; 32]) -> Self {
        Camellia256(Camellia::new(key).unwrap())
    }
}

impl crate::BlockCipher for Camellia256 {
    fn encrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.encrypt_block(block);
    }
    
    fn decrypt_block(&self, block: &mut [u8; crate::BLOCK_SIZE]) {
        self.0.decrypt_block(block);
    }
    
    fn cipher_name(&self) -> &'static str {
        "Camellia-256"
    }
    
    fn key_size(&self) -> usize {
        32
    }
}

/// Constant-time byte comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(all(feature = "random", feature = "getrandom"))]
/// Generate a random key of the specified size
pub fn generate_key(size: usize) -> Result<Vec<u8>, CamelliaError> {
    match size {
        16 | 24 | 32 => {
            let mut key = vec![0u8; size];
            getrandom(&mut key).map_err(|_| CamelliaError::RngFailure)?;
            Ok(key)
        }
        _ => Err(CamelliaError::InvalidKeySize { size }),
    }
}

#[cfg(all(feature = "random", feature = "getrandom"))]
/// Generate a random IV.
///
/// Fails with `RngFailure` if the system RNG does: the error used to be
/// ignored, which returned the all-zero IV — the same IV on every call.
pub fn generate_iv() -> Result<[u8; 16], CamelliaError> {
    let mut iv = [0u8; 16];
    getrandom(&mut iv).map_err(|_| CamelliaError::RngFailure)?;
    Ok(iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockCipher;
    
    #[test]
    fn test_camellia128_round_trip() {
        // Test encrypt/decrypt round trip
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        
        let cipher = Camellia128::new(&key);
        let mut block = plaintext;
        
        // Encrypt
        cipher.encrypt_block(&mut block);
        let _encrypted = block;
        // The ciphertext should be different from plaintext
        assert_ne!(&block[..], &plaintext[..]);
        
        // Decrypt
        cipher.decrypt_block(&mut block);
        
        assert_eq!(block, plaintext, "Decryption should return original");
        
        // Should get back the original plaintext
        assert_eq!(&block[..], &plaintext[..]);
    }
    
    #[test]
    fn test_f_function_properties() {
        // Test that the F-function operations are correct
        let x = 0x0123456789abcdef_u64;
        let k = 0xfedcba9876543210_u64;
        
        // In Camellia, during encryption: d2 ^= F(d1, k)
        // During decryption, to reverse: d2 ^= F(d1, k) again (since XOR is self-inverse)
        let f_result = Camellia::f_function(x, k);
        
        let mut test_value = 0x1111111111111111_u64;
        let original = test_value;
        
        // Apply F-function
        test_value ^= f_result;
        // Apply again to reverse
        test_value ^= f_result;
        
        assert_eq!(test_value, original, "F-function XOR should be reversible");
    }
    
    #[test]
    fn test_camellia_sbox() {
        use crate::constants::{SBOX1, SBOX2, SBOX3, SBOX4};
        
        // Test a few known S-box values
        assert_eq!(SBOX1[0], 0x70);
        assert_eq!(SBOX1[1], 0x82);
        assert_eq!(SBOX1[255], 0x9e);
        
        // Test that S-boxes are different (except SBOX4[0] which equals SBOX1[0] by design)
        assert_ne!(SBOX1[0], SBOX2[0]);
        assert_ne!(SBOX1[0], SBOX3[0]);
        // SBOX4[0] = SBOX1[0] because SBOX4[i] = SBOX1[i & 0x7F] | (i & 0x80), and for i=0, this equals SBOX1[0]
        assert_eq!(SBOX1[0], SBOX4[0]);
    }
    
    #[test]
    fn test_camellia_f_function_detailed() {
        // Test F-function with known values
        let x = 0x0123456789abcdef_u64;
        let k = 0xfedcba9876543210_u64;
        
        let _result = Camellia::f_function(x, k);
        
        // Test with zero
        let result_zero = Camellia::f_function(0, 0);
        assert_ne!(result_zero, 0, "F(0, 0) should not be 0 due to S-boxes");
        
        // Test linearity property: F(x, k1) ^ F(x, k2) = F(x, k1 ^ k2)
        let k1 = 0x1111111111111111_u64;
        let k2 = 0x2222222222222222_u64;
        let f1 = Camellia::f_function(x, k1);
        let f2 = Camellia::f_function(x, k2);
        let f12 = Camellia::f_function(x, k1 ^ k2);
        // F-function is not linear: F(x, k1^k2) != F(x, k1) ^ F(x, k2)
        assert_ne!(f12, f1 ^ f2);
    }
    
    #[test]
    fn test_simple_round_trip() {
        // Test with a simple manual encryption/decryption
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        
        let camellia = Camellia::new(&key).unwrap();
        
        // Manual encryption (simplified - just pre-whitening and one round)
        let mut d1 = u64::from_be_bytes(plaintext[0..8].try_into().unwrap());
        let mut d2 = u64::from_be_bytes(plaintext[8..16].try_into().unwrap());
        let original_d1 = d1;
        let original_d2 = d2;
        
        // Pre-whitening
        d1 ^= camellia.subkeys[0];
        d2 ^= camellia.subkeys[1];
        
        // One round
        d2 ^= Camellia::f_function(d1, camellia.subkeys[2]);
        
        // Now reverse it
        // Reverse round 1
        d2 ^= Camellia::f_function(d1, camellia.subkeys[2]);
        
        // Reverse pre-whitening
        d1 ^= camellia.subkeys[0];
        d2 ^= camellia.subkeys[1];
        
        // Check if we got back the original
        assert_eq!(d1, original_d1, "d1 should match original");
        assert_eq!(d2, original_d2, "d2 should match original");
    }
    
    #[test]
    fn test_camellia128_rfc3713() {

        // RFC 3713 test vector for Camellia-128
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let expected = hex::decode("67673138549669730857065648eabe43").unwrap();
        
        let cipher = Camellia128::new(key[..16].try_into().unwrap());
        let mut block = [0u8; 16];
        block.copy_from_slice(&plaintext);
        
        cipher.encrypt_block(&mut block);
        assert_eq!(&block[..], &expected[..], "Encryption should match RFC 3713");
        
        // Test decryption
        cipher.decrypt_block(&mut block);
        assert_eq!(&block[..], &plaintext[..], "Decryption should return original");
    }
    
    #[test]
    fn test_camellia256_simple() {
        // Simple test with zeros
        let key = [0u8; 32];
        let plaintext = [0u8; 16];
        
        let cipher = Camellia256::new(&key);
        let mut block = plaintext.clone();
        
        cipher.encrypt_block(&mut block);
        let _ciphertext = block.clone();
        
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "Simple round trip should work");
    }
    
    #[test]
    fn test_fl_functions() {
        // Test that FL and FL_inv are inverses
        let test_values = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xA5A5A5A5A5A5A5A5];
        let test_keys = [0x1111111111111111, 0xFFFFFFFFFFFFFFFF, 0x5555555555555555];
        
        for &val in &test_values {
            for &key in &test_keys {
                let fl_result = Camellia::fl_function(val, key);
                let fl_inv_result = Camellia::fl_inv_function(fl_result, key);
                assert_eq!(val, fl_inv_result, "FL and FL_inv should be inverses");
            }
        }
    }
    
    #[test]
    fn test_camellia256_rfc3713() {
        // RFC 3713 test vector for Camellia-256
        let key = hex::decode("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff").unwrap();
        let plaintext = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let expected = hex::decode("9acc237dff16d76c20ef7c919e3a7509").unwrap();
        
        let cipher = Camellia256::new(key[..32].try_into().unwrap());
        let mut block = [0u8; 16];
        block.copy_from_slice(&plaintext);
        
        cipher.encrypt_block(&mut block);
        assert_eq!(&block[..], &expected[..], "Encryption should match RFC 3713");
        
        // Test decryption
        cipher.decrypt_block(&mut block);
        assert_eq!(&block[..], &plaintext[..], "Decryption should return original");
    }
}

#[cfg(all(test, feature = "random", feature = "getrandom"))]
mod rng_tests {
    use super::*;

    // generate_iv used to ignore a getrandom error and return the all-zero IV.
    // A failing RNG cannot be provoked here; this pins the Result, and that two
    // IVs differ and neither is the all-zero IV the old error path returned.
    #[test]
    fn generate_iv_returns_fresh_random_ivs() {
        let a = generate_iv().expect("system RNG");
        let b = generate_iv().expect("system RNG");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 16]);
        assert_eq!(generate_key(32).expect("system RNG").len(), 32);
    }
}
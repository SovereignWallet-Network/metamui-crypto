// MetaMUI metamui sha3 - Keccak
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! Keccak-f[1600] permutation
//! 
//! Core permutation used by SHA3 functions.

/// Number of rounds for Keccak-f[1600]
pub const KECCAK_ROUNDS: usize = 24;

/// Keccak round constants
pub const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for rho step
pub const RHO_OFFSETS: [[u32; 5]; 5] = [
    [0,  36,  3, 41, 18],
    [1,  44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

/// Rotate left
#[inline(always)]
pub fn rotate_left(value: u64, amount: u32) -> u64 {
    if amount == 0 {
        value
    } else {
        (value << amount) | (value >> (64 - amount))
    }
}

/// Keccak-f[1600] permutation
pub fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..KECCAK_ROUNDS {
        // θ (Theta) step: Column parity computation
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ rotate_left(c[(x + 1) % 5], 1);
        }
        
        for x in 0..5 {
            for y in 0..5 {
                state[y * 5 + x] ^= d[x];
            }
        }
        
        // ρ (Rho) and π (Pi) steps combined
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                // Apply rho (rotation)
                let rotated = rotate_left(state[y * 5 + x], RHO_OFFSETS[x][y]);
                // Apply pi (permutation): (x,y) -> (y, (2x+3y) mod 5)
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                b[new_y * 5 + new_x] = rotated;
            }
        }
        
        // χ (Chi) step: Non-linear transformation
        for y in 0..5 {
            let t = [b[y * 5], b[y * 5 + 1], b[y * 5 + 2], b[y * 5 + 3], b[y * 5 + 4]];
            for x in 0..5 {
                state[y * 5 + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }
        
        // ι (Iota) step: Add round constant
        state[0] ^= ROUND_CONSTANTS[round];
    }
}
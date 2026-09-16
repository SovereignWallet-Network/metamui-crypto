//! AES-128 block cipher (FIPS 197, Nk = 4, Nr = 10) — the 128-bit key
//! schedule over the same round functions and S-box as `aes256`.
//!
//! Present for the constructions that fix AES-128 by specification —
//! FrodoKEM-AES generates its public matrix with AES-128-ECB (ISO/IEC
//! 18033-2 Amd 2) — not as a general-purpose cipher: the crate's AEAD and
//! mode APIs stay AES-256. Checked against the FIPS 197 Appendix C.1 vector.

use crate::aes256::{add_round_key, mix_columns, shift_rows, sub_bytes, RCON, SBOX};

/// Block size in bytes.
pub const BLOCK_SIZE: usize = 16;
/// Key size in bytes.
pub const KEY_SIZE: usize = 16;

fn sub_word(w: u32) -> u32 {
    ((SBOX[((w >> 24) & 0xff) as usize] as u32) << 24)
        | ((SBOX[((w >> 16) & 0xff) as usize] as u32) << 16)
        | ((SBOX[((w >> 8) & 0xff) as usize] as u32) << 8)
        | (SBOX[(w & 0xff) as usize] as u32)
}

/// AES-128 key expansion: 44 words (11 round keys).
pub fn expand_key(key: &[u8; KEY_SIZE]) -> [u32; 44] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / 4];
        }
        w[i] = w[i - 4] ^ temp;
    }
    w
}

/// AES-128 single-block encryption.
pub fn encrypt_block(block: &[u8; BLOCK_SIZE], expanded_key: &[u32; 44]) -> [u8; BLOCK_SIZE] {
    let mut state = [
        [block[0], block[4], block[8], block[12]],
        [block[1], block[5], block[9], block[13]],
        [block[2], block[6], block[10], block[14]],
        [block[3], block[7], block[11], block[15]],
    ];
    add_round_key(&mut state, &expanded_key[0..4]);
    for round in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &expanded_key[round * 4..(round + 1) * 4]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &expanded_key[40..44]);
    [
        state[0][0], state[1][0], state[2][0], state[3][0],
        state[0][1], state[1][1], state[2][1], state[3][1],
        state[0][2], state[1][2], state[2][2], state[3][2],
        state[0][3], state[1][3], state[2][3], state[3][3],
    ]
}

/// A keyed AES-128 block cipher.
#[derive(Clone)]
pub struct Aes128 {
    expanded: [u32; 44],
}

impl Aes128 {
    /// Expand a 16-byte key.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self { expanded: expand_key(key) }
    }

    /// Encrypt one block.
    pub fn encrypt_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        encrypt_block(block, &self.expanded)
    }
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        for w in self.expanded.iter_mut() {
            // Volatile write so the schedule is cleared even when unobserved.
            unsafe { core::ptr::write_volatile(w, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips197_appendix_c1() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let pt = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ct = Aes128::new(&key).encrypt_block(&pt);
        assert_eq!(
            ct,
            [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
        );
    }

    #[test]
    fn fips197_appendix_b_and_key_schedule_tail() {
        // FIPS 197 Appendix B: key 2b7e1516…, input 3243f6a8….
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let pt = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        assert_eq!(
            Aes128::new(&key).encrypt_block(&pt),
            [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]
        );
        // Appendix A.1: the last round-key word is 0xb6630ca6.
        assert_eq!(expand_key(&key)[43], 0xb663_0ca6);
    }
}

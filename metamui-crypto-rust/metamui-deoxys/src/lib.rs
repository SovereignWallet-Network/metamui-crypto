#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! Deoxys-II-256-128 Authenticated Encryption
//!
//! Native Rust implementation of Deoxys-II-256-128 based on Deoxys-BC-384
//! tweakable block cipher (16 rounds, 3-part TWEAKEY framework).
//!
//! Reference: Jean, Nikolić, Peyrin, Seurin — "Deoxys v1.43" (CAESAR final portfolio, 2018; Deoxys-II unchanged from v1.41)
//!            CAESAR competition submission
//!            Oasis Protocol reference implementation

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use core::fmt;
use metamui_security_utils::constant_time::ConstantTimeEq;

#[cfg(feature = "std")]
use rand::{thread_rng, RngCore};

/// Key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Nonce size in bytes (120 bits)
pub const NONCE_SIZE: usize = 15;

/// Tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Block size in bytes (128 bits)
const BLOCK_SIZE: usize = 16;

/// Number of Deoxys-BC-384 rounds
const ROUNDS: usize = 16;

// ─── AES S-box ──────────────────────────────────────────────────────────────

const SBOX: [u8; 256] = [
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ─── Deoxys-BC-384 TWEAKEY ──────────────────────────────────────────────────

/// Byte permutation h for TWEAKEY schedule
/// h = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8]
const TWEAKEY_PERM: [usize; 16] = [1, 6, 11, 12, 5, 10, 15, 0, 9, 14, 3, 4, 13, 2, 7, 8];

/// Round constant base values for 17 rounds (0..=16)
const RCON_VALUES: [u8; 17] = [
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72,
];

/// Error types for Deoxys-II
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid key length
    InvalidKeyLength,
    /// Invalid nonce length
    InvalidNonceLength,
    /// Invalid tag length
    InvalidTagLength,
    /// Authentication failed during decryption
    AuthenticationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "Invalid key length"),
            Error::InvalidNonceLength => write!(f, "Invalid nonce length"),
            Error::InvalidTagLength => write!(f, "Invalid tag length"),
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

// ─── AES Primitives ─────────────────────────────────────────────────────────

#[inline]
fn gf_mul2(a: u8) -> u8 {
    (a << 1) ^ ((a >> 7) * 0x1b)
}

#[inline]
fn gf_mul3(a: u8) -> u8 {
    gf_mul2(a) ^ a
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // Column-major order: s[col*4 + row]
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    let t = s[2]; s[2] = s[10]; s[10] = t;
    let t = s[6]; s[6] = s[14]; s[14] = t;
    let t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let off = c * 4;
        let (a0, a1, a2, a3) = (s[off], s[off + 1], s[off + 2], s[off + 3]);
        s[off]     = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3;
        s[off + 1] = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
        s[off + 2] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3);
        s[off + 3] = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3);
    }
}

fn xor_block(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

fn xor_blocks(a: &[u8; 16], b: &[u8; 16], c: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i] ^ c[i];
    }
    out
}

// ─── TWEAKEY Schedule ───────────────────────────────────────────────────────

/// Apply byte permutation h in-place
fn tweakey_permute(t: &mut [u8; 16]) {
    let old = *t;
    for i in 0..16 {
        t[i] = old[TWEAKEY_PERM[i]];
    }
}

/// LFSR2 for TK2: (x[6..0] || x[7] XOR x[5])
fn lfsr2(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        let x = *b;
        *b = ((x << 1) & 0xFE) | (((x >> 7) ^ (x >> 5)) & 1);
    }
}

/// LFSR3 for TK3: (x[0] XOR x[6] || x[7..1])
fn lfsr3(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        let x = *b;
        *b = ((x >> 1) & 0x7F) | (((x ^ (x >> 6)) & 1) << 7);
    }
}

/// Build round constant block for round r
fn rcon(r: usize) -> [u8; 16] {
    let mut rc = [0u8; 16];
    rc[0] = 1;
    rc[1] = 2;
    rc[2] = 4;
    rc[3] = 8;
    rc[4] = RCON_VALUES[r];
    rc[5] = RCON_VALUES[r];
    rc[6] = RCON_VALUES[r];
    rc[7] = RCON_VALUES[r];
    rc
}

/// Compute all 17 sub-tweakeys for Deoxys-BC-384
/// STK[r] = TK1[r] ^ TK2[r] ^ TK3[r] ^ RCON[r]
fn compute_subtweakeys(tweak: &[u8; 16], key: &[u8; 32]) -> [[u8; 16]; 17] {
    let mut stk = [[0u8; 16]; 17];
    let mut tk1 = *tweak;
    let mut tk2 = [0u8; 16];
    let mut tk3 = [0u8; 16];
    tk2.copy_from_slice(&key[16..32]); // TK2 = second half
    tk3.copy_from_slice(&key[0..16]);  // TK3 = first half

    // Round 0
    let rc0 = rcon(0);
    stk[0] = xor_blocks(&tk1, &tk2, &tk3);
    xor_block(&mut stk[0], &rc0);

    // Rounds 1..=16
    for r in 1..=ROUNDS {
        tweakey_permute(&mut tk1);

        lfsr2(&mut tk2);
        tweakey_permute(&mut tk2);

        lfsr3(&mut tk3);
        tweakey_permute(&mut tk3);

        let rc = rcon(r);
        stk[r] = xor_blocks(&tk1, &tk2, &tk3);
        xor_block(&mut stk[r], &rc);
    }

    stk
}

// ─── Deoxys-BC-384 Block Cipher ─────────────────────────────────────────────

/// Encrypt a single 16-byte block using Deoxys-BC-384.
/// Unlike AES, Deoxys-BC applies MixColumns on ALL rounds (1..=16).
fn deoxys_bc_encrypt(input: &[u8; 16], tweak: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
    let stk = compute_subtweakeys(tweak, key);
    let mut state = *input;

    // Initial AddRoundTweakey
    xor_block(&mut state, &stk[0]);

    // All 16 rounds: SubBytes, ShiftRows, MixColumns, AddRoundTweakey
    for r in 1..=ROUNDS {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        xor_block(&mut state, &stk[r]);
    }

    state
}

// ─── Deoxys-II-256-128 AEAD Mode ───────────────────────────────────────────

// Prefix values (left-shifted by 4)
const PREFIX_AD_BLOCK: u8   = 0x2; // AAD non-final block
const PREFIX_AD_FINAL: u8   = 0x6; // AAD final (padded) block
const PREFIX_MSG_BLOCK: u8  = 0x0; // Message non-final block
const PREFIX_MSG_FINAL: u8  = 0x4; // Message final (padded) block
const PREFIX_TAG: u8        = 0x1; // Tag computation
const PREFIX_SHIFT: u8      = 4;

/// Encode tweak for auth accumulation
fn encode_tag_tweak(prefix: u8, block_nr: u64) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[0] = prefix << PREFIX_SHIFT;
    tweak[8]  = (block_nr >> 56) as u8;
    tweak[9]  = (block_nr >> 48) as u8;
    tweak[10] = (block_nr >> 40) as u8;
    tweak[11] = (block_nr >> 32) as u8;
    tweak[12] = (block_nr >> 24) as u8;
    tweak[13] = (block_nr >> 16) as u8;
    tweak[14] = (block_nr >> 8) as u8;
    tweak[15] = block_nr as u8;
    tweak
}

/// Encode tweak for tag computation: [PREFIX_TAG<<4, nonce(15 bytes)]
fn encode_nonce_tweak(nonce: &[u8; 15]) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[0] = PREFIX_TAG << PREFIX_SHIFT;
    tweak[1..16].copy_from_slice(nonce);
    tweak
}

/// Encode tweak for CTR encryption: tag with bit 7 of byte 0 set, block_nr XOR'd into bytes 8-15
fn encode_enc_tweak(tag: &[u8; 16], block_nr: u64) -> [u8; 16] {
    let mut tweak = *tag;
    tweak[0] |= 0x80;
    tweak[8]  ^= (block_nr >> 56) as u8;
    tweak[9]  ^= (block_nr >> 48) as u8;
    tweak[10] ^= (block_nr >> 40) as u8;
    tweak[11] ^= (block_nr >> 32) as u8;
    tweak[12] ^= (block_nr >> 24) as u8;
    tweak[13] ^= (block_nr >> 16) as u8;
    tweak[14] ^= (block_nr >> 8) as u8;
    tweak[15] ^= block_nr as u8;
    tweak
}

/// Accumulate data blocks into auth state
fn accumulate_blocks(
    auth: &mut [u8; 16],
    data: &[u8],
    prefix_nonfinal: u8,
    prefix_final: u8,
    key: &[u8; 32],
) {
    if data.is_empty() {
        return;
    }

    let full_blocks = data.len() / BLOCK_SIZE;
    let remainder = data.len() % BLOCK_SIZE;

    // Process full blocks with non-final prefix
    for i in 0..full_blocks {
        let tweak = encode_tag_tweak(prefix_nonfinal, i as u64);
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[i * 16..(i + 1) * 16]);
        let encrypted = deoxys_bc_encrypt(&block, &tweak, key);
        xor_block(auth, &encrypted);
    }

    // Process partial last block with ISO 7816-4 padding (10* padding)
    if remainder > 0 {
        let mut block = [0u8; 16];
        block[..remainder].copy_from_slice(&data[full_blocks * 16..]);
        block[remainder] = 0x80;
        let tweak = encode_tag_tweak(prefix_final, full_blocks as u64);
        let encrypted = deoxys_bc_encrypt(&block, &tweak, key);
        xor_block(auth, &encrypted);
    }
}

/// CTR-mode encrypt/decrypt using tag-derived tweaks.
/// BC input is [0x00 || nonce(15 bytes)].
fn ctr_encrypt(
    dst: &mut [u8],
    src: &[u8],
    tag: &[u8; 16],
    nonce: &[u8; 15],
    key: &[u8; 32],
) {
    let mut enc_nonce = [0u8; 16];
    enc_nonce[0] = 0x00;
    enc_nonce[1..16].copy_from_slice(nonce);

    let full_blocks = src.len() / BLOCK_SIZE;
    let remainder = src.len() % BLOCK_SIZE;

    for i in 0..full_blocks {
        let tweak = encode_enc_tweak(tag, i as u64);
        let keystream = deoxys_bc_encrypt(&enc_nonce, &tweak, key);
        for j in 0..BLOCK_SIZE {
            dst[i * 16 + j] = src[i * 16 + j] ^ keystream[j];
        }
    }

    if remainder > 0 {
        let tweak = encode_enc_tweak(tag, full_blocks as u64);
        let keystream = deoxys_bc_encrypt(&enc_nonce, &tweak, key);
        for j in 0..remainder {
            dst[full_blocks * 16 + j] = src[full_blocks * 16 + j] ^ keystream[j];
        }
    }
}

/// Deoxys-II-256-128 authenticated encryption
pub struct DeoxysII;

impl DeoxysII {
    /// Generate random 256-bit key
    #[cfg(feature = "std")]
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        key
    }

    /// Generate random 120-bit nonce
    #[cfg(feature = "std")]
    pub fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt plaintext with associated data.
    ///
    /// Returns `ciphertext || tag` (tag is appended as the last 16 bytes).
    pub fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        if nonce.len() != NONCE_SIZE {
            return Err(Error::InvalidNonceLength);
        }

        let key32: &[u8; 32] = key.try_into().unwrap();
        let nonce15: &[u8; 15] = nonce.try_into().unwrap();
        let mut auth = [0u8; 16];

        // Phase 1: Accumulate AAD into auth
        accumulate_blocks(&mut auth, associated_data, PREFIX_AD_BLOCK, PREFIX_AD_FINAL, key32);

        // Phase 2: Accumulate plaintext into auth
        accumulate_blocks(&mut auth, plaintext, PREFIX_MSG_BLOCK, PREFIX_MSG_FINAL, key32);

        // Phase 3: Compute tag = BC(auth, nonce_tweak, key)
        let nonce_tweak = encode_nonce_tweak(nonce15);
        let tag = deoxys_bc_encrypt(&auth, &nonce_tweak, key32);

        // Phase 4: CTR-encrypt plaintext
        let mut output = vec![0u8; plaintext.len() + TAG_SIZE];
        if !plaintext.is_empty() {
            ctr_encrypt(&mut output[..plaintext.len()], plaintext, &tag, nonce15, key32);
        }
        output[plaintext.len()..].copy_from_slice(&tag);

        Ok(output)
    }

    /// Decrypt ciphertext and verify authentication.
    ///
    /// Input is `ciphertext || tag` (tag is the last 16 bytes).
    pub fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        if nonce.len() != NONCE_SIZE {
            return Err(Error::InvalidNonceLength);
        }
        if ciphertext.len() < TAG_SIZE {
            return Err(Error::InvalidTagLength);
        }

        let key32: &[u8; 32] = key.try_into().unwrap();
        let nonce15: &[u8; 15] = nonce.try_into().unwrap();
        let ct_len = ciphertext.len() - TAG_SIZE;
        let (ct_data, tag) = ciphertext.split_at(ct_len);
        let tag16: [u8; 16] = tag.try_into().unwrap();

        // Phase 1: CTR-decrypt ciphertext
        let mut plaintext = vec![0u8; ct_len];
        if ct_len > 0 {
            ctr_encrypt(&mut plaintext, ct_data, &tag16, nonce15, key32);
        }

        // Phase 2: Accumulate AAD into auth
        let mut auth = [0u8; 16];
        accumulate_blocks(&mut auth, associated_data, PREFIX_AD_BLOCK, PREFIX_AD_FINAL, key32);

        // Phase 3: Accumulate recovered plaintext into auth
        accumulate_blocks(&mut auth, &plaintext, PREFIX_MSG_BLOCK, PREFIX_MSG_FINAL, key32);

        // Phase 4: Compute expected tag
        let nonce_tweak = encode_nonce_tweak(nonce15);
        let expected_tag = deoxys_bc_encrypt(&auth, &nonce_tweak, key32);

        // Phase 5: Verify tag (constant-time)
        if expected_tag.ct_eq(&tag16).unwrap_u8() != 1 {
            // Zeroize plaintext on failure
            for b in plaintext.iter_mut() {
                *b = 0;
            }
            return Err(Error::AuthenticationFailed);
        }

        Ok(plaintext)
    }
}

/// Re-export kept for callers that used `metamui_deoxys::deoxys::DeoxysII`;
/// there is one implementation.
pub mod deoxys {
    //! `DeoxysII` under its older path.
    pub use crate::DeoxysII;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        #[cfg(feature = "std")]
        {
            let key = DeoxysII::generate_key();
            assert_eq!(key.len(), KEY_SIZE);

            let nonce = DeoxysII::generate_nonce();
            assert_eq!(nonce.len(), NONCE_SIZE);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Hello, Deoxys-II-256-128!";
        let aad = b"Additional data";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Hello, Deoxys-II!";
        let aad = b"Additional data";

        let mut ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 1; // Tamper

        let result = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"";
        let aad = b"Additional data";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let decrypted = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_aad() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"No associated data";
        let aad = b"";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Test";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, b"").unwrap();

        let wrong_key = [0x43u8; KEY_SIZE];
        let result = DeoxysII::decrypt(&wrong_key, &nonce, &ciphertext, b"");
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Test";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();
        let result = DeoxysII::decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 16]; // Wrong: should be 32
        let nonce = [0u8; NONCE_SIZE];
        assert!(matches!(
            DeoxysII::encrypt(&key, &nonce, b"test", b""),
            Err(Error::InvalidKeyLength)
        ));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = [0u8; KEY_SIZE];
        let nonce = [0u8; 16]; // Wrong: should be 15
        assert!(matches!(
            DeoxysII::encrypt(&key, &nonce, b"test", b""),
            Err(Error::InvalidNonceLength)
        ));
    }

    #[test]
    fn test_oasis_protocol_vectors() {
        // Vectors from test-vectors/deoxys/deoxys-oasisprotocol-vectors.json
        // tc_id=1: Empty plaintext and empty AAD
        let key = hex::decode("7b3af9b87736f5b47332f1b06f2eedac6b2ae9a86726e5a46322e1a05f1edd9c").unwrap();
        let nonce = hex::decode("7b30e59a4f04b96e23d88d42f7ac61").unwrap();

        let ct = DeoxysII::encrypt(&key, &nonce, b"", b"").unwrap();
        let tag_hex = hex::encode(&ct);
        assert_eq!(tag_hex, "9f1b3c417b5e0787ec5a4c7b5e254499", "tc_id=1 tag mismatch");

        let pt = DeoxysII::decrypt(&key, &nonce, &ct, b"").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_oasis_protocol_vector_1byte() {
        // tc_id=2: 1-byte plaintext with 1-byte AAD
        let key = hex::decode("7b3af9b87736f5b47332f1b06f2eedac6b2ae9a86726e5a46322e1a05f1edd9c").unwrap();
        let nonce = hex::decode("7b30e59a4f04b96e23d88d42f7ac61").unwrap();
        let pt = hex::decode("7b").unwrap();
        let aad = hex::decode("7b").unwrap();

        let ct = DeoxysII::encrypt(&key, &nonce, &pt, &aad).unwrap();
        let ct_hex = hex::encode(&ct[..1]);
        let tag_hex = hex::encode(&ct[1..]);
        assert_eq!(ct_hex, "da", "tc_id=2 ciphertext mismatch");
        assert_eq!(tag_hex, "11fa90c3ee591ed43ec49ff54abe760e", "tc_id=2 tag mismatch");

        let decrypted = DeoxysII::decrypt(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_oasis_protocol_vector_16bytes() {
        // tc_id=3: 16-byte plaintext with 16-byte AAD
        let key = hex::decode("7b3af9b87736f5b47332f1b06f2eedac6b2ae9a86726e5a46322e1a05f1edd9c").unwrap();
        let nonce = hex::decode("7b30e59a4f04b96e23d88d42f7ac61").unwrap();
        let pt = hex::decode("7b4005ca8f5419dea3682df2b77c4106").unwrap();
        let aad = hex::decode("7b3cfdbe7f4001c2834405c6874809ca").unwrap();

        let ct = DeoxysII::encrypt(&key, &nonce, &pt, &aad).unwrap();
        let ct_hex = hex::encode(&ct[..16]);
        let tag_hex = hex::encode(&ct[16..]);
        assert_eq!(ct_hex, "309e4d8b1c52fa5656505dd5a3ade76a", "tc_id=3 ciphertext mismatch");
        assert_eq!(tag_hex, "6b09b5f3d8a900247e835ae499b31dfd", "tc_id=3 tag mismatch");

        let decrypted = DeoxysII::decrypt(&key, &nonce, &ct, &aad).unwrap();
        assert_eq!(decrypted, pt);
    }
}

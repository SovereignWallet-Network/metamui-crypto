//! Ascon-AEAD128 (NIST SP 800-232 §4): authenticated encryption with a
//! 128-bit key, 128-bit nonce and 128-bit tag.
//!
//! Little-endian word I/O, IV `0x00001000808C0001`, rate 16 bytes, p^12 for
//! initialisation/finalisation and p^8 between blocks. Byte-exact to the
//! reference `crypto_aead/asconaead128` KAT (`LWC_AEAD_KAT_128_128.txt`),
//! replayed in full by `upstream_sp800232_gate`.

use crate::permutation::{ascon_permutation, load64_le, store64_le};
use crate::{AsconError, Result};
use alloc::{vec, vec::Vec};
use metamui_security_utils::Zeroize;

/// Ascon AEAD operations.
pub trait AsconAead {
    /// Encrypt plaintext with associated data and return (ciphertext, tag)
    fn encrypt(
        &self,
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])>;

    /// Decrypt ciphertext with associated data verification
    fn decrypt(
        &self,
        nonce: &[u8; 16],
        ciphertext: &[u8],
        tag: &[u8; 16],
        associated_data: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Base implementation for Ascon variants
struct AsconBase {
    key: [u8; 16],
    iv: u64,
    rounds_a: u8, // Initialization/finalization rounds
    rounds_b: u8, // Processing rounds
    rate: usize,  // Rate in bytes
}

impl Drop for AsconBase {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AsconBase {
    fn new(key: [u8; 16], iv: u64, rounds_a: u8, rounds_b: u8, rate: usize) -> Self {
        Self {
            key,
            iv,
            rounds_a,
            rounds_b,
            rate,
        }
    }

    fn initialize(&self, nonce: &[u8; 16]) -> [u64; 5] {
        // Initialize state: IV | Key | Nonce (little-endian word load, SP 800-232)
        let mut state = [0u64; 5];
        state[0] = self.iv;
        state[1] = load64_le(&self.key[0..8]);
        state[2] = load64_le(&self.key[8..16]);
        state[3] = load64_le(&nonce[0..8]);
        state[4] = load64_le(&nonce[8..16]);

        // Initial permutation (pa = rounds_a rounds)
        ascon_permutation(&mut state, self.rounds_a);

        // XOR key into the last 128 bits of state
        state[3] ^= load64_le(&self.key[0..8]);
        state[4] ^= load64_le(&self.key[8..16]);

        state
    }

    fn process_associated_data(&self, state: &mut [u64; 5], associated_data: &[u8]) {
        // SP 800-232 domain separation: XOR the separation bit into the MSB
        // of the last state word (0x80000000_00000000 in little-endian terms).
        const DOMAIN_SEP: u64 = 0x8000000000000000;

        if associated_data.is_empty() {
            // Domain separation only — no AD blocks absorbed.
            state[4] ^= DOMAIN_SEP;
            return;
        }

        let rate_words = self.rate / 8;
        let mut offset = 0;

        // Process all full rate-sized blocks (each followed by permutation)
        while offset + self.rate <= associated_data.len() {
            state[0] ^= load64_le(&associated_data[offset..offset + 8]);
            if rate_words > 1 {
                state[1] ^= load64_le(&associated_data[offset + 8..offset + 16]);
            }
            ascon_permutation(state, self.rounds_b);
            offset += self.rate;
        }

        // Process final block (0 to rate-1 remaining bytes) with 10* padding.
        // SP 800-232 little-endian: the padding byte is 0x01 at position `remaining`.
        let remaining = associated_data.len() - offset;
        let mut padded = vec![0u8; self.rate];
        if remaining > 0 {
            padded[..remaining].copy_from_slice(&associated_data[offset..]);
        }
        padded[remaining] = 0x01;

        state[0] ^= load64_le(&padded[0..8]);
        if rate_words > 1 {
            state[1] ^= load64_le(&padded[8..16]);
        }
        ascon_permutation(state, self.rounds_b);

        // Domain separation
        state[4] ^= DOMAIN_SEP;
    }

    fn finalize(&self, state: &mut [u64; 5]) -> [u8; 16] {
        // XOR key in at position rate/8 (the first state word past the rate).
        let rate_idx = self.rate / 8;
        state[rate_idx] ^= load64_le(&self.key[0..8]);
        state[rate_idx + 1] ^= load64_le(&self.key[8..16]);

        // Final permutation (pa rounds)
        ascon_permutation(state, self.rounds_a);

        // XOR key into the last 128 bits and extract them as the tag.
        let t0 = state[3] ^ load64_le(&self.key[0..8]);
        let t1 = state[4] ^ load64_le(&self.key[8..16]);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&store64_le(t0));
        tag[8..16].copy_from_slice(&store64_le(t1));
        tag
    }

    fn encrypt_impl(
        &self,
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let mut state = self.initialize(nonce);
        self.process_associated_data(&mut state, associated_data);

        let rate_words = self.rate / 8;
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut offset = 0;

        // Process all full rate-sized blocks (each followed by permutation)
        while offset + self.rate <= plaintext.len() {
            state[0] ^= load64_le(&plaintext[offset..offset + 8]);
            ciphertext[offset..offset + 8].copy_from_slice(&store64_le(state[0]));
            if rate_words > 1 {
                state[1] ^= load64_le(&plaintext[offset + 8..offset + 16]);
                ciphertext[offset + 8..offset + 16].copy_from_slice(&store64_le(state[1]));
            }
            ascon_permutation(&mut state, self.rounds_b);
            offset += self.rate;
        }

        // Process final block (0 to rate-1 remaining bytes) with 10* padding.
        let remaining = plaintext.len() - offset;
        if remaining > 0 {
            let mut padded = vec![0u8; self.rate];
            padded[..remaining].copy_from_slice(&plaintext[offset..]);
            padded[remaining] = 0x01;

            state[0] ^= load64_le(&padded[0..8]);
            if rate_words > 1 {
                state[1] ^= load64_le(&padded[8..16]);
            }

            // Extract the remaining ciphertext bytes from the updated state.
            let mut state_bytes = [0u8; 16];
            state_bytes[0..8].copy_from_slice(&store64_le(state[0]));
            if rate_words > 1 {
                state_bytes[8..16].copy_from_slice(&store64_le(state[1]));
            }
            ciphertext[offset..].copy_from_slice(&state_bytes[..remaining]);
        } else {
            // Empty final block — just absorb the padding byte.
            state[0] ^= 0x01;
        }

        let tag = self.finalize(&mut state);

        // Clear state
        for i in 0..state.len() {
            state[i] = 0;
        }

        Ok((ciphertext, tag))
    }

    fn decrypt_impl(
        &self,
        nonce: &[u8; 16],
        ciphertext: &[u8],
        tag: &[u8; 16],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut state = self.initialize(nonce);
        self.process_associated_data(&mut state, associated_data);

        let rate_words = self.rate / 8;
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut offset = 0;

        // Process all full rate-sized blocks (each followed by permutation)
        while offset + self.rate <= ciphertext.len() {
            let c0 = load64_le(&ciphertext[offset..offset + 8]);
            plaintext[offset..offset + 8].copy_from_slice(&store64_le(state[0] ^ c0));
            state[0] = c0;
            if rate_words > 1 {
                let c1 = load64_le(&ciphertext[offset + 8..offset + 16]);
                plaintext[offset + 8..offset + 16].copy_from_slice(&store64_le(state[1] ^ c1));
                state[1] = c1;
            }
            ascon_permutation(&mut state, self.rounds_b);
            offset += self.rate;
        }

        // Process final block (0 to rate-1 remaining bytes) with 10* padding.
        let remaining = ciphertext.len() - offset;
        if remaining > 0 {
            // Extract the rate bytes from the current state.
            let mut state_bytes = [0u8; 16];
            state_bytes[0..8].copy_from_slice(&store64_le(state[0]));
            if rate_words > 1 {
                state_bytes[8..16].copy_from_slice(&store64_le(state[1]));
            }

            // Decrypt the remaining bytes.
            let mut plain_chunk = vec![0u8; self.rate];
            for j in 0..remaining {
                plain_chunk[j] = ciphertext[offset + j] ^ state_bytes[j];
                plaintext[offset + j] = plain_chunk[j];
            }

            // Update state with the recovered plaintext plus padding.
            plain_chunk[remaining] = 0x01;
            state[0] ^= load64_le(&plain_chunk[0..8]);
            if rate_words > 1 {
                state[1] ^= load64_le(&plain_chunk[8..16]);
            }
        } else {
            // Empty final block — just absorb the padding byte.
            state[0] ^= 0x01;
        }

        // Verify tag
        let computed_tag = self.finalize(&mut state);

        // Constant-time tag comparison
        use metamui_crypto_utilities::ConstantTime;
        let tag_valid = ConstantTime::compare(tag, &computed_tag);

        // Clear state
        for i in 0..state.len() {
            state[i] = 0;
        }

        if !tag_valid {
            // Clear plaintext on authentication failure
            plaintext.zeroize();
            return Err(AsconError::AuthenticationFailed);
        }

        Ok(plaintext)
    }
}

/// Ascon-AEAD128 authenticated encryption (NIST SP 800-232 §4).
pub struct AsconAead128 {
    base: AsconBase,
}

impl AsconAead128 {
    /// Create a new Ascon-AEAD128 instance with a 128-bit key.
    pub fn new(key: [u8; 16]) -> Self {
        // SP 800-232 Table 8: rate 16 bytes, a = 12, b = 8, IV as a
        // little-endian word.
        let iv: u64 = 0x0000_1000_808C_0001;
        Self {
            base: AsconBase::new(key, iv, 12, 8, 16),
        }
    }
}

impl AsconAead for AsconAead128 {
    fn encrypt(
        &self,
        nonce: &[u8; 16],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16])> {
        // Note: Nonce reuse checking would require interior mutability
        self.base.encrypt_impl(nonce, plaintext, associated_data)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 16],
        ciphertext: &[u8],
        tag: &[u8; 16],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        self.base.decrypt_impl(nonce, ciphertext, tag, associated_data)
    }
}
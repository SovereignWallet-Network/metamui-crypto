// AES-256-CTR-DRBG — Simplified Variant (no Derivation Function)
//
// NIST SP 800-90A Rev. 1, Section 10.2.1
// This is the variant used by NIST PQC KAT generators.
// Requires exactly 48-byte (seedlen) entropy input.

use crate::error::{AesCtrDrbgError, Result};
use metamui_aes_256::aes256::Aes256;
use metamui_aes_256::{BLOCK_SIZE, KEY_SIZE};
use zeroize::Zeroize;

/// Seed length: Key (32) + V (16) = 48 bytes.
pub const SEEDLEN: usize = KEY_SIZE + BLOCK_SIZE;
/// Maximum requests between reseeds.
pub const RESEED_INTERVAL: u64 = 1 << 48;
/// Maximum bytes per generate() call.
pub const MAX_REQUEST_SIZE: usize = 1 << 16;

/// AES-256-CTR-DRBG without derivation function (NIST SP 800-90A §10.2.1).
///
/// This simplified variant requires exactly 48-byte entropy and is the
/// standard interface used by all NIST PQC KAT generators.
///
/// # Example
/// ```
/// use metamui_aes_ctr_drbg::AesCtrDrbg;
///
/// let seed = [0u8; 48];
/// let mut drbg = AesCtrDrbg::new(&seed, None).unwrap();
/// let mut output = [0u8; 32];
/// drbg.generate(&mut output, None).unwrap();
/// ```
pub struct AesCtrDrbg {
    /// AES-256 key (32 bytes).
    key: [u8; KEY_SIZE],
    /// Counter value V (16 bytes).
    v: [u8; BLOCK_SIZE],
    /// Reseed counter.
    reseed_counter: u64,
    /// Cached AES cipher instance.
    cipher: Aes256,
}

impl AesCtrDrbg {
    /// Instantiate a new CTR-DRBG with exactly 48 bytes of entropy.
    ///
    /// # Arguments
    /// * `entropy` - Exactly 48 bytes of initial entropy.
    /// * `personalization` - Optional personalization string, at most
    ///   48 bytes (seedlen); zero-padded to 48 bytes and XORed with entropy.
    pub fn new(entropy: &[u8], personalization: Option<&[u8]>) -> Result<Self> {
        if entropy.len() != SEEDLEN {
            return Err(AesCtrDrbgError::EntropyError(entropy.len()));
        }

        // §10.2.1.3.1: seed_material = entropy XOR pad(personalization, seedlen).
        // A string longer than seedlen used to be truncated silently; Table 3
        // caps max_personalization_string_length at seedlen, so refuse it.
        let mut seed_material = [0u8; SEEDLEN];
        seed_material.copy_from_slice(entropy);
        xor_padded(&mut seed_material, personalization)
            .map_err(|()| AesCtrDrbgError::InvalidRequest("personalization_string longer than 48 bytes"))?;

        // Start with zero key and V
        let mut drbg = Self {
            key: [0u8; KEY_SIZE],
            v: [0u8; BLOCK_SIZE],
            reseed_counter: 0,
            cipher: Aes256::new(&[0u8; KEY_SIZE]),
        };

        drbg.update(&seed_material);
        seed_material.zeroize();
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// Generate pseudorandom bytes.
    ///
    /// # Arguments
    /// * `output` - Buffer to fill with random bytes (1..65536).
    /// * `additional_input` - Optional additional input, at most 48 bytes;
    ///   zero-padded to 48 bytes. Empty is the same as `None` (§4: Null is
    ///   the empty string).
    pub fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<()> {
        if output.is_empty() || output.len() > MAX_REQUEST_SIZE {
            return Err(AesCtrDrbgError::InvalidRequest("requested_bytes out of range"));
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(AesCtrDrbgError::ReseedRequired);
        }

        // §10.2.1.5.1 step 2: if additional_input ≠ Null, pad it to seedlen and
        // update; otherwise it is 0^seedlen. This used to demand exactly
        // 48 bytes, so a shorter (or empty) input the spec pads was refused.
        let mut ai_padded = [0u8; SEEDLEN];
        xor_padded(&mut ai_padded, additional_input)
            .map_err(|()| AesCtrDrbgError::InvalidRequest("additional_input longer than 48 bytes"))?;
        let has_ai = additional_input.is_some_and(|ai| !ai.is_empty());
        if has_ai {
            self.update(&ai_padded);
        }

        // Generate output blocks
        let mut pos = 0;
        while pos < output.len() {
            increment_counter(&mut self.v);
            let block = self.cipher.encrypt_block(&self.v);
            let copy_len = core::cmp::min(BLOCK_SIZE, output.len() - pos);
            output[pos..pos + copy_len].copy_from_slice(&block[..copy_len]);
            pos += copy_len;
        }

        // §10.2.1.5.1 step 6: update with the padded additional input
        // (0^seedlen when it was Null) for backtracking resistance.
        self.update(&ai_padded);
        ai_padded.zeroize();
        self.reseed_counter += 1;

        Ok(())
    }

    /// Reseed with fresh entropy.
    ///
    /// # Arguments
    /// * `entropy` - Exactly 48 bytes of entropy.
    /// * `additional_input` - Optional additional input, at most 48 bytes
    ///   (zero-padded, XORed with entropy).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<()> {
        if entropy.len() != SEEDLEN {
            return Err(AesCtrDrbgError::EntropyError(entropy.len()));
        }

        // §10.2.1.4.1: as for personalization, an input longer than seedlen
        // used to be truncated silently; Table 3 caps it at seedlen.
        let mut seed_material = [0u8; SEEDLEN];
        seed_material.copy_from_slice(entropy);
        xor_padded(&mut seed_material, additional_input)
            .map_err(|()| AesCtrDrbgError::InvalidRequest("additional_input longer than 48 bytes"))?;

        self.update(&seed_material);
        seed_material.zeroize();
        self.reseed_counter = 1;

        Ok(())
    }

    /// Get current reseed counter value.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// CTR_DRBG_Update per NIST SP 800-90A §10.2.1.2.
    ///
    /// Generate 3 AES blocks (48 bytes), XOR with provided_data,
    /// split into new Key (32B) + V (16B), re-key cipher.
    fn update(&mut self, provided_data: &[u8; SEEDLEN]) {
        let mut temp = [0u8; SEEDLEN];

        // Generate 3 blocks
        for i in 0..3 {
            increment_counter(&mut self.v);
            let block = self.cipher.encrypt_block(&self.v);
            temp[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&block);
        }

        // XOR with provided_data
        for i in 0..SEEDLEN {
            temp[i] ^= provided_data[i];
        }

        // Update key and V, re-key cipher
        self.key.copy_from_slice(&temp[..KEY_SIZE]);
        self.v.copy_from_slice(&temp[KEY_SIZE..SEEDLEN]);
        self.cipher = Aes256::new(&self.key);
    }
}

impl Drop for AesCtrDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        self.reseed_counter = 0;
    }
}

/// `buf ^= input || 0^(seedlen - len(input))` — the no-DF padding of
/// §10.2.1.3.1 / §10.2.1.4.1 / §10.2.1.5.1. Errs, leaving `buf` untouched,
/// when `input` is longer than seedlen.
fn xor_padded(buf: &mut [u8; SEEDLEN], input: Option<&[u8]>) -> core::result::Result<(), ()> {
    let input = input.unwrap_or(&[]);
    if input.len() > SEEDLEN {
        return Err(());
    }
    for (b, x) in buf.iter_mut().zip(input) {
        *b ^= x;
    }
    Ok(())
}

/// Big-endian increment of 16-byte counter V.
pub(crate) fn increment_counter(v: &mut [u8; BLOCK_SIZE]) {
    for i in (0..BLOCK_SIZE).rev() {
        v[i] = v[i].wrapping_add(1);
        if v[i] != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_seed_first_48() {
        let seed = [0u8; 48];
        let mut drbg = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out = [0u8; 48];
        drbg.generate(&mut out, None).unwrap();
        assert_eq!(
            hex::encode(&out),
            "91618fe99a8f9420497b246f735b27a019078a9d3ca6b2a001aec0b9e07e680baf4443922a119178fb8191d4c9d0a58f"
        );
    }

    #[test]
    fn test_zero_seed_next_32() {
        let seed = [0u8; 48];
        let mut drbg = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out48 = [0u8; 48];
        drbg.generate(&mut out48, None).unwrap();
        let mut out32 = [0u8; 32];
        drbg.generate(&mut out32, None).unwrap();
        assert_eq!(
            hex::encode(&out32),
            "ac15c76d62f2ce158b012fc6a1c18dc6c080842f09452ad5822de30fdbbf67d1"
        );
    }

    #[test]
    fn test_ref_seed_first_48() {
        let seed = hex::decode(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        ).unwrap();
        let mut drbg = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out = [0u8; 48];
        drbg.generate(&mut out, None).unwrap();
        assert_eq!(
            hex::encode(&out),
            "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47"
        );
    }

    #[test]
    fn test_ref_seed_next_32() {
        let seed = hex::decode(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        ).unwrap();
        let mut drbg = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out48 = [0u8; 48];
        drbg.generate(&mut out48, None).unwrap();
        let mut out32 = [0u8; 32];
        drbg.generate(&mut out32, None).unwrap();
        assert_eq!(
            hex::encode(&out32),
            "33b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d7"
        );
    }

    #[test]
    fn test_determinism() {
        let seed = [0xABu8; 48];
        let mut drbg1 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut drbg2 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_different_seeds_differ() {
        let mut drbg1 = AesCtrDrbg::new(&[0u8; 48], None).unwrap();
        let mut drbg2 = AesCtrDrbg::new(&[1u8; 48], None).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_sequential_generates_differ() {
        let mut drbg = AesCtrDrbg::new(&[0u8; 48], None).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg.generate(&mut out1, None).unwrap();
        drbg.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_wrong_entropy_length() {
        assert!(AesCtrDrbg::new(&[0u8; 32], None).is_err());
        assert!(AesCtrDrbg::new(&[0u8; 64], None).is_err());
    }

    #[test]
    fn test_personalization_changes_output() {
        let seed = [0u8; 48];
        let pers = [0xFFu8; 48];
        let mut drbg1 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut drbg2 = AesCtrDrbg::new(&seed, Some(&pers)).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_reseed_changes_output() {
        let seed = [0u8; 48];
        let mut drbg1 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut drbg2 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        // Reseed drbg2 with different entropy
        drbg2.reseed(&[0xFFu8; 48], None).unwrap();

        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_reseed_is_deterministic() {
        let seed = [0u8; 48];
        let reseed = [0xAAu8; 48];
        let mut drbg1 = AesCtrDrbg::new(&seed, None).unwrap();
        let mut drbg2 = AesCtrDrbg::new(&seed, None).unwrap();
        drbg1.reseed(&reseed, None).unwrap();
        drbg2.reseed(&reseed, None).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_various_output_lengths() {
        let mut drbg = AesCtrDrbg::new(&[0u8; 48], None).unwrap();
        for len in [1, 15, 16, 17, 32, 48, 64, 255, 1024] {
            let mut out = vec![0u8; len];
            assert!(drbg.generate(&mut out, None).is_ok());
        }
    }

    #[test]
    fn test_reseed_counter_increments() {
        let mut drbg = AesCtrDrbg::new(&[0u8; 48], None).unwrap();
        assert_eq!(drbg.reseed_counter(), 1);
        let mut out = [0u8; 16];
        drbg.generate(&mut out, None).unwrap();
        assert_eq!(drbg.reseed_counter(), 2);
        drbg.generate(&mut out, None).unwrap();
        assert_eq!(drbg.reseed_counter(), 3);
    }
}

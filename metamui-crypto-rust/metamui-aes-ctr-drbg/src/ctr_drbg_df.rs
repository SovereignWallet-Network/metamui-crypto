// AES-256-CTR-DRBG with Block Cipher Derivation Function
//
// NIST SP 800-90A Rev. 1, Section 10.2.1 + 10.3.2
// Full variant that accepts variable-length entropy, nonce, and
// personalization inputs. The DF compresses them into a fixed-length
// seed before CTR_DRBG_Update.

use crate::ctr_drbg::{increment_counter, SEEDLEN, MAX_REQUEST_SIZE, RESEED_INTERVAL};
use crate::error::{AesCtrDrbgError, Result};
use metamui_aes_256::aes256::Aes256;
use metamui_aes_256::{BLOCK_SIZE, KEY_SIZE};
use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Minimum entropy for DF variant (256-bit security).
pub const MIN_ENTROPY_DF: usize = 32;

/// AES-256-CTR-DRBG with Block Cipher Derivation Function.
///
/// Accepts variable-length entropy (min 32 bytes), nonce, and
/// personalization inputs. Processes them through Block_Cipher_df
/// before updating state.
pub struct AesCtrDrbgDf {
    key: [u8; KEY_SIZE],
    v: [u8; BLOCK_SIZE],
    reseed_counter: u64,
    cipher: Aes256,
}

impl AesCtrDrbgDf {
    /// Instantiate with derivation function.
    ///
    /// # Arguments
    /// * `entropy` - Variable-length entropy (min 32 bytes).
    /// * `nonce` - Nonce bytes.
    /// * `personalization` - Optional personalization string.
    pub fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: Option<&[u8]>,
    ) -> Result<Self> {
        if entropy.len() < MIN_ENTROPY_DF {
            return Err(AesCtrDrbgError::EntropyError(entropy.len()));
        }

        // Concatenate inputs
        let mut combined = Vec::with_capacity(
            entropy.len() + nonce.len() + personalization.map_or(0, |p| p.len()),
        );
        combined.extend_from_slice(entropy);
        combined.extend_from_slice(nonce);
        if let Some(pers) = personalization {
            combined.extend_from_slice(pers);
        }

        // Derive seed via DF
        let seed_vec = block_cipher_df(&combined, SEEDLEN)?;
        let seed: [u8; SEEDLEN] = seed_vec.try_into()
            .map_err(|_| AesCtrDrbgError::InvalidRequest("DF output length mismatch"))?;

        // Initialize with zero state
        let mut drbg = Self {
            key: [0u8; KEY_SIZE],
            v: [0u8; BLOCK_SIZE],
            reseed_counter: 0,
            cipher: Aes256::new(&[0u8; KEY_SIZE]),
        };

        drbg.update(&seed);
        drbg.reseed_counter = 1;

        Ok(drbg)
    }

    /// Generate pseudorandom bytes.
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

        // §10.2.1.5.2 steps 2–3: additional_input = Block_Cipher_df(additional_input)
        // if one was supplied, else 0^seedlen; it feeds BOTH the pre-generate
        // update and the post-generate (backtracking-resistance) update. Until
        // 2026-09-05 the second update used zeros unconditionally, so every
        // generate with additional input diverged from the ACVP vectors.
        let ai_seed: [u8; SEEDLEN] = match additional_input {
            Some(ai) if !ai.is_empty() => block_cipher_df(ai, SEEDLEN)?
                .try_into()
                .map_err(|_| AesCtrDrbgError::InvalidRequest("DF output length mismatch"))?,
            _ => [0u8; SEEDLEN],
        };
        if additional_input.is_some_and(|ai| !ai.is_empty()) {
            self.update(&ai_seed);
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

        // §10.2.1.5.2 step 6: update with the (derived) additional input.
        self.update(&ai_seed);
        self.reseed_counter += 1;

        Ok(())
    }

    /// Reseed with fresh entropy (processed through DF).
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<()> {
        if entropy.len() < MIN_ENTROPY_DF {
            return Err(AesCtrDrbgError::EntropyError(entropy.len()));
        }

        let mut combined = Vec::with_capacity(
            entropy.len() + additional_input.map_or(0, |a| a.len()),
        );
        combined.extend_from_slice(entropy);
        if let Some(ai) = additional_input {
            combined.extend_from_slice(ai);
        }

        let seed_vec = block_cipher_df(&combined, SEEDLEN)?;
        let seed: [u8; SEEDLEN] = seed_vec.try_into()
            .map_err(|_| AesCtrDrbgError::InvalidRequest("DF output length mismatch"))?;
        self.update(&seed);
        self.reseed_counter = 1;

        Ok(())
    }

    /// Get current reseed counter.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// CTR_DRBG_Update (same as simplified variant).
    fn update(&mut self, provided_data: &[u8; SEEDLEN]) {
        let mut temp = [0u8; SEEDLEN];
        for i in 0..3 {
            increment_counter(&mut self.v);
            let block = self.cipher.encrypt_block(&self.v);
            temp[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&block);
        }
        for i in 0..SEEDLEN {
            temp[i] ^= provided_data[i];
        }
        self.key.copy_from_slice(&temp[..KEY_SIZE]);
        self.v.copy_from_slice(&temp[KEY_SIZE..SEEDLEN]);
        self.cipher = Aes256::new(&self.key);
    }
}

impl Drop for AesCtrDrbgDf {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
        self.reseed_counter = 0;
    }
}

/// Block Cipher Derivation Function (NIST SP 800-90A Rev. 1 §10.3.2).
///
/// Two stages, both with AES-256:
///
/// 1. `BCC` (§10.3.3) over `S = L ‖ N ‖ input ‖ 0x80 ‖ 0…` with the fixed
///    key `0x00 0x01 … 0x1F` and IV `i ‖ 0…` for `i = 0, 1, …`, until
///    `keylen + outlen` (48) bytes of `temp` have been produced.
/// 2. `K = leftmost(temp, keylen)`, `X = select(temp, keylen+1, keylen+outlen)`;
///    then `X = E_K(X)` repeatedly, appending each block, until `output_len`
///    bytes are available.
///
/// The second stage is what makes the DF output a pseudorandom function of
/// the whole input rather than the raw BCC chaining values; an
/// implementation that returns stage 1 directly (as this one did until
/// 2026-09-05) produces seeds that match no ACVP vector.
pub fn block_cipher_df(input: &[u8], output_len: usize) -> Result<Vec<u8>> {
    if output_len > 512 {
        // §10.3.2 step 1: number_of_bits_to_return ≤ max_number_of_bits (512 bytes)
        return Err(AesCtrDrbgError::InvalidRequest("DF output length out of range"));
    }

    // Fixed DF key: 0x00, 0x01, ..., 0x1F
    let df_key: [u8; KEY_SIZE] = core::array::from_fn(|i| i as u8);
    let df_cipher = Aes256::new(&df_key);

    // S = L(4B BE) || N(4B BE) || input || 0x80 || zero padding to a block
    let mut s = Vec::with_capacity(input.len() + 9 + BLOCK_SIZE);
    s.extend_from_slice(&(input.len() as u32).to_be_bytes());
    s.extend_from_slice(&(output_len as u32).to_be_bytes());
    s.extend_from_slice(input);
    s.push(0x80);
    while s.len() % BLOCK_SIZE != 0 {
        s.push(0x00);
    }

    // Stage 1: temp = BCC(K, IV(0) || S) || BCC(K, IV(1) || S) || ... to keylen + outlen bytes
    let mut temp = Vec::with_capacity(KEY_SIZE + BLOCK_SIZE);
    let mut i: u32 = 0;
    while temp.len() < KEY_SIZE + BLOCK_SIZE {
        // BCC (§10.3.3): chaining_value starts at 0^outlen and the IV block
        // (i ‖ 0…) is the FIRST data block — it is XORed in and encrypted
        // like every S block. Seeding the chain with the IV instead of
        // encrypting it (the pre-2026-09-05 code) skips one block cipher
        // call and matches no ACVP vector.
        let mut iv = [0u8; BLOCK_SIZE];
        iv[..4].copy_from_slice(&i.to_be_bytes());
        let mut chaining_value = [0u8; BLOCK_SIZE];
        for chunk in core::iter::once(&iv[..]).chain(s.chunks(BLOCK_SIZE)) {
            for j in 0..BLOCK_SIZE {
                chaining_value[j] ^= chunk[j];
            }
            chaining_value = df_cipher.encrypt_block(&chaining_value);
        }
        temp.extend_from_slice(&chaining_value);
        i += 1;
    }

    // Stage 2: K = leftmost keylen bytes, X = the next outlen bytes; chain E_K.
    let mut k = [0u8; KEY_SIZE];
    k.copy_from_slice(&temp[..KEY_SIZE]);
    let mut x = [0u8; BLOCK_SIZE];
    x.copy_from_slice(&temp[KEY_SIZE..KEY_SIZE + BLOCK_SIZE]);
    let stage2 = Aes256::new(&k);

    let mut result = Vec::with_capacity(output_len + BLOCK_SIZE);
    while result.len() < output_len {
        x = stage2.encrypt_block(&x);
        result.extend_from_slice(&x);
    }
    result.truncate(output_len);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_df_instantiate() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let drbg = AesCtrDrbgDf::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_df_deterministic() {
        let entropy = [0xAAu8; 32];
        let nonce = [0xBBu8; 16];
        let mut drbg1 = AesCtrDrbgDf::instantiate(&entropy, &nonce, None).unwrap();
        let mut drbg2 = AesCtrDrbgDf::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_df_personalization_changes_output() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let pers = b"some personalization string";
        let mut drbg1 = AesCtrDrbgDf::instantiate(&entropy, &nonce, None).unwrap();
        let mut drbg2 = AesCtrDrbgDf::instantiate(&entropy, &nonce, Some(pers)).unwrap();
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        drbg1.generate(&mut out1, None).unwrap();
        drbg2.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_df_reject_short_entropy() {
        let result = AesCtrDrbgDf::instantiate(&[0u8; 16], &[0u8; 8], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_df_reseed() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let mut drbg = AesCtrDrbgDf::instantiate(&entropy, &nonce, None).unwrap();
        let mut out1 = [0u8; 32];
        drbg.generate(&mut out1, None).unwrap();
        drbg.reseed(&[0x03u8; 32], None).unwrap();
        let mut out2 = [0u8; 32];
        drbg.generate(&mut out2, None).unwrap();
        assert_ne!(out1, out2);
    }
}

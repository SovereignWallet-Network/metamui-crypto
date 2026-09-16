// NIST SP 800-90A CTR_DRBG — Falcon-512 adapter
//
// Thin wrappers over the standalone metamui-aes-ctr-drbg crate,
// adapting error types and preserving the Falcon-specific API.

use crate::error::{Falcon512Error, Result};
use metamui_aes_ctr_drbg::{AesCtrDrbgDf, AesCtrDrbgError};


/// Convert AesCtrDrbgError to Falcon512Error.
fn map_err(e: AesCtrDrbgError) -> Falcon512Error {
    match e {
        AesCtrDrbgError::EntropyError(_) => Falcon512Error::InvalidParameter,
        AesCtrDrbgError::ReseedRequired => Falcon512Error::KeyGenerationFailed,
        AesCtrDrbgError::InvalidRequest(_) => Falcon512Error::InvalidParameter,
        AesCtrDrbgError::NotInstantiated => Falcon512Error::InvalidParameter,
    }
}

/// AES-256 CTR_DRBG with DF (full NIST SP 800-90A variant).
///
/// This is the DF variant used by Falcon-512 KAT generation.
/// Delegates to `metamui_aes_ctr_drbg::AesCtrDrbgDf`.
pub struct CtrDrbg {
    inner: AesCtrDrbgDf,
}

impl CtrDrbg {
    /// Instantiate with entropy, nonce, and optional personalization.
    /// Uses Block Cipher Derivation Function to compress inputs.
    pub fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: Option<&[u8]>,
    ) -> Result<Self> {
        let inner = AesCtrDrbgDf::instantiate(entropy, nonce, personalization)
            .map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Generate pseudorandom bytes.
    pub fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<()> {
        self.inner.generate(output, additional_input).map_err(map_err)
    }

    /// Reseed with new entropy.
    pub fn reseed(
        &mut self,
        entropy: &[u8],
        additional_input: Option<&[u8]>,
    ) -> Result<()> {
        self.inner.reseed(entropy, additional_input).map_err(map_err)
    }

    /// Get current reseed counter.
    pub fn reseed_counter(&self) -> u64 {
        self.inner.reseed_counter()
    }
}

/// NIST CTR_DRBG for Falcon KAT generation.
///
/// Takes a 48-byte seed, splits into 32-byte entropy + 16-byte nonce,
/// and feeds through the DF variant for NIST KAT reproducibility.
pub struct NistCtrDrbg {
    drbg: CtrDrbg,
}

impl NistCtrDrbg {
    /// Create DRBG for NIST KAT generation from a 48-byte seed (`kat-internal` only).
    #[cfg(feature = "kat-internal")]
    pub fn new_for_kat(seed: &[u8]) -> Result<Self> {
        let entropy_vec = if seed.len() >= 48 {
            seed[..48].to_vec()
        } else {
            let mut padded = vec![0u8; 48];
            padded[..seed.len()].copy_from_slice(seed);
            padded
        };

        let drbg = CtrDrbg::instantiate(&entropy_vec[..32], &entropy_vec[32..48], None)?;
        Ok(Self { drbg })
    }

    /// Generate bytes for KAT.
    pub fn randombytes(&mut self, output: &mut [u8]) -> Result<()> {
        self.drbg.generate(output, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_drbg_instantiate() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let drbg = CtrDrbg::instantiate(&entropy, &nonce, None);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_ctr_drbg_generate() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let mut drbg = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output = [0u8; 64];
        let result = drbg.generate(&mut output, None);
        assert!(result.is_ok());
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ctr_drbg_deterministic() {
        let entropy = [0xAAu8; 32];
        let nonce = [0xBBu8; 16];
        let mut drbg1 = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut drbg2 = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output1 = [0u8; 128];
        let mut output2 = [0u8; 128];
        drbg1.generate(&mut output1, None).unwrap();
        drbg2.generate(&mut output2, None).unwrap();
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_nist_kat_drbg() {
        let seed = [0x00u8; 48];
        let mut drbg = NistCtrDrbg::new_for_kat(&seed).unwrap();
        let mut output = [0u8; 32];
        let result = drbg.randombytes(&mut output);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reseed() {
        let entropy = [0x01u8; 32];
        let nonce = [0x02u8; 16];
        let mut drbg = CtrDrbg::instantiate(&entropy, &nonce, None).unwrap();
        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1, None).unwrap();
        let new_entropy = [0x03u8; 32];
        drbg.reseed(&new_entropy, None).unwrap();
        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2, None).unwrap();
        assert_ne!(output1, output2);
    }
}

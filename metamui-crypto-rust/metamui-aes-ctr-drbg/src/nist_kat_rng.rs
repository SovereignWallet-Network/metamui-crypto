// NIST KAT RNG — Thin wrapper for PQC Known Answer Test vector generation
//
// Provides the standard `randombytes(n)` interface matching the NIST PQC
// submission framework. Takes a 48-byte seed and produces deterministic
// output via the simplified AES-256-CTR-DRBG (no DF).

use crate::ctr_drbg::{AesCtrDrbg, SEEDLEN};
use crate::error::{AesCtrDrbgError, Result};

/// NIST KAT Random Number Generator.
///
/// Thin wrapper around `AesCtrDrbg` matching the NIST PQC KAT RNG
/// interface (`randombytes_init` + `randombytes`).
///
/// # Example
/// ```
/// use metamui_aes_ctr_drbg::NistKatRng;
///
/// let seed = [0u8; 48];
/// let mut rng = NistKatRng::new(&seed).unwrap();
/// let bytes = rng.randombytes(32).unwrap();
/// assert_eq!(bytes.len(), 32);
/// ```
pub struct NistKatRng {
    drbg: AesCtrDrbg,
}

impl NistKatRng {
    /// Create a new NIST KAT RNG from a 48-byte seed.
    pub fn new(seed: &[u8]) -> Result<Self> {
        if seed.len() != SEEDLEN {
            return Err(AesCtrDrbgError::EntropyError(seed.len()));
        }
        let drbg = AesCtrDrbg::new(seed, None)?;
        Ok(Self { drbg })
    }

    /// Generate `length` pseudorandom bytes.
    pub fn randombytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; length];
        self.drbg.generate(&mut output, None)?;
        Ok(output)
    }

    /// Generate random bytes into a pre-allocated buffer.
    pub fn randombytes_into(&mut self, output: &mut [u8]) -> Result<()> {
        self.drbg.generate(output, None)
    }

    /// Re-initialize with a new seed.
    pub fn randombytes_init(&mut self, seed: &[u8]) -> Result<()> {
        if seed.len() != SEEDLEN {
            return Err(AesCtrDrbgError::EntropyError(seed.len()));
        }
        self.drbg = AesCtrDrbg::new(seed, None)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nist_kat_zero_seed() {
        let mut rng = NistKatRng::new(&[0u8; 48]).unwrap();
        let out = rng.randombytes(48).unwrap();
        assert_eq!(
            hex::encode(&out),
            "91618fe99a8f9420497b246f735b27a019078a9d3ca6b2a001aec0b9e07e680baf4443922a119178fb8191d4c9d0a58f"
        );
    }

    #[test]
    fn test_nist_kat_ref_seed() {
        let seed = hex::decode(
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
        ).unwrap();
        let mut rng = NistKatRng::new(&seed).unwrap();
        let out = rng.randombytes(48).unwrap();
        assert_eq!(
            hex::encode(&out),
            "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47"
        );
    }

    #[test]
    fn test_reinit_resets_state() {
        let mut rng = NistKatRng::new(&[0u8; 48]).unwrap();
        let out1 = rng.randombytes(32).unwrap();
        rng.randombytes_init(&[0u8; 48]).unwrap();
        let out2 = rng.randombytes(32).unwrap();
        // After reinit with same seed, output should be identical
        // (but out1 is from first generate(32), out2 is from first generate(32) of new instance)
        // First generate(32) of zero seed always gives the first 32 bytes of the 48-byte output:
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_wrong_seed_length() {
        assert!(NistKatRng::new(&[0u8; 32]).is_err());
        assert!(NistKatRng::new(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_randombytes_into() {
        let mut rng = NistKatRng::new(&[0u8; 48]).unwrap();
        let mut buf = [0u8; 48];
        rng.randombytes_into(&mut buf).unwrap();
        assert_eq!(
            hex::encode(&buf),
            "91618fe99a8f9420497b246f735b27a019078a9d3ca6b2a001aec0b9e07e680baf4443922a119178fb8191d4c9d0a58f"
        );
    }

    #[test]
    fn test_sequential_calls() {
        let mut rng = NistKatRng::new(&[0u8; 48]).unwrap();
        let out1 = rng.randombytes(16).unwrap();
        let out2 = rng.randombytes(16).unwrap();
        assert_ne!(out1, out2);
    }
}

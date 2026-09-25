#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// HMAC-DRBG - HMAC-based Deterministic Random Bit Generator
///
/// Implementation of NIST SP 800-90A Rev. 1 HMAC-DRBG.
/// A deterministic random bit generator over HMAC-SHA256/384/512: every byte
/// of seed material is the caller's, and this crate draws no entropy itself.
///
/// # Features
/// - Deterministic output given the same seed material
/// - Portable scalar Rust only (see README)
/// - Support for personalization strings
/// - Reseeding capability
/// - Prediction resistance option
/// - Health tests and a CAVP/ACVP response-file runner (`cavp` feature)
///
/// # Example
/// ```
/// use metamui_hmac_drbg::{HmacDrbg, HashAlgorithm};
///
/// // Create DRBG with seed
/// let entropy = [0u8; 32]; // At least 32 bytes
/// let mut drbg = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256).unwrap();
///
/// // Generate random bytes
/// let mut output = [0u8; 32];
/// drbg.generate(&mut output, None).unwrap();
/// ```

// Module declarations
#[cfg(feature = "cavp")]
pub mod cavp;
pub mod health_tests;

use metamui_crypto_utilities::mac::hmac::Hmac;
use metamui_security_utils::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

#[cfg(feature = "std")]
use std::vec::Vec;

// Helper trait to add the methods we need
trait HmacExt {
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8>;
    fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8>;
}

impl HmacExt for Hmac {
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
        Self::hmac_sha256_small(key, message).to_vec()
    }

    fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
        metamui_sha2::sha512::hmac::hmac_sha512(key, message).to_vec()
    }
}

/// NIST SP 800-90A Rev. 1 constants
pub const MIN_ENTROPY_LENGTH: usize = 32; // 256 bits minimum entropy
pub const MAX_ENTROPY_LENGTH: usize = 1000; // Implementation defined maximum
pub const MAX_PERSONALIZATION_LENGTH: usize = 1000;
pub const MAX_ADDITIONAL_INPUT_LENGTH: usize = 1000;
/// SP 800-90A Table 2 max_number_of_bits_per_request = 2^19 bits, in bytes.
pub const MAX_REQUEST_LENGTH: usize = 65536;
pub const RESEED_INTERVAL: u64 = 1u64 << 48; // 2^48

/// HMAC-SHA384 (FIPS 198-1 over SHA-384). This is NOT HMAC-SHA512 truncated
/// to 48 bytes — SHA-384 has its own initial hash values, so the two differ
/// in every byte. The truncation shortcut shipped until 2026-09-05 and failed
/// all 30 SHA2-384 records of the ACVP hmacDRBG-1.0 gate (audit A29).
fn hmac_sha384(key: &[u8], message: &[u8]) -> Vec<u8> {
    metamui_sha2::sha384::hmac::hmac_sha384(key, message).to_vec()
}

/// Errors that can occur during HMAC-DRBG operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Entropy input is invalid
    InvalidEntropy,
    /// Personalization string is too long
    PersonalizationTooLong,
    /// Additional input is too long
    AdditionalInputTooLong,
    /// Requested output is invalid
    InvalidRequest,
    /// Reseed is required
    ReseedRequired,
    /// Power-on self-tests did not pass
    SelfTestFailed,
    /// Unsupported hash algorithm
    UnsupportedHashAlgorithm,
    /// The continuous health test failed. The instance is in the
    /// SP 800-90A §11.3 error state: its K and V have been zeroized and
    /// every later call fails until a new instance is created.
    HealthTestFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidEntropy => write!(f, "Invalid entropy input"),
            Error::PersonalizationTooLong => write!(f, "Personalization string too long"),
            Error::AdditionalInputTooLong => write!(f, "Additional input too long"),
            Error::InvalidRequest => write!(f, "Invalid output request"),
            Error::ReseedRequired => write!(f, "Reseed required"),
            Error::SelfTestFailed => write!(f, "Power-on self-tests failed"),
            Error::UnsupportedHashAlgorithm => write!(f, "Unsupported hash algorithm"),
            Error::HealthTestFailed => {
                write!(f, "Continuous health test failed; DRBG is in the error state")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Get the output length in bytes for this hash algorithm
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// Internal state for HMAC-DRBG

struct DrbgState {
    v: Vec<u8>,
    k: Vec<u8>,
    reseed_counter: u64,
}

/// HMAC-DRBG instance
///
/// K and V are zeroized on drop, on [`HmacDrbg::uninstantiate`] and when the
/// continuous health test fails. Until 2026-09-25 `uninstantiate` only reset
/// the counter (its "ZeroizeOnDrop" comment named an impl that did not
/// exist), and every update dropped the old K/V buffers unwiped.
pub struct HmacDrbg {
    state: DrbgState,
    hash_alg: HashAlgorithm,
    continuous_test: Option<health_tests::ContinuousTest>,
    /// SP 800-90A §11.3 error state, entered when a health test fails.
    error_state: bool,
}

/// SP 800-90A §4 defines Null as the empty string, so `Some(&[])` must behave
/// exactly like `None` wherever the spec branches on `≠ Null`.
fn non_null(data: Option<&[u8]>) -> Option<&[u8]> {
    data.filter(|d| !d.is_empty())
}

fn hmac(alg: HashAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Sha256 => Hmac::hmac_sha256(key, message),
        HashAlgorithm::Sha384 => hmac_sha384(key, message),
        HashAlgorithm::Sha512 => Hmac::hmac_sha512(key, message),
    }
}

impl HmacDrbg {
    /// Create a new HMAC-DRBG instance
    ///
    /// # Arguments
    /// * `entropy` - Initial entropy (minimum 32 bytes)
    /// * `nonce` - Optional nonce
    /// * `personalization` - Optional personalization string
    /// * `hash_alg` - Hash algorithm to use
    pub fn new(
        entropy: &[u8],
        nonce: Option<&[u8]>,
        personalization: Option<&[u8]>,
        hash_alg: HashAlgorithm,
    ) -> Result<Self, Error> {
        // Validate entropy
        if entropy.len() < MIN_ENTROPY_LENGTH || entropy.len() > MAX_ENTROPY_LENGTH {
            return Err(Error::InvalidEntropy);
        }

        // Validate personalization
        if let Some(p) = personalization {
            if p.len() > MAX_PERSONALIZATION_LENGTH {
                return Err(Error::PersonalizationTooLong);
            }
        }

        let outlen = hash_alg.output_length();

        // Initialize internal state
        let state = DrbgState {
            v: vec![0x01; outlen],
            k: vec![0x00; outlen],
            reseed_counter: 1,
        };

        // Prepare seed material
        let mut seed_material = Vec::with_capacity(
            entropy.len() + nonce.map_or(0, |n| n.len()) + personalization.map_or(0, |p| p.len()),
        );
        seed_material.extend_from_slice(entropy);
        if let Some(n) = nonce {
            seed_material.extend_from_slice(n);
        }
        if let Some(p) = personalization {
            seed_material.extend_from_slice(p);
        }

        // Create instance with continuous test enabled
        let mut drbg = Self {
            state,
            hash_alg,
            continuous_test: Some(health_tests::ContinuousTest::new()),
            error_state: false,
        };

        // Initialize with update
        drbg.update(Some(&seed_material));
        seed_material.zeroize();

        Ok(drbg)
    }

    /// Run power-on self-tests (POST)
    ///
    /// Should be called on application startup to verify correct operation
    pub fn run_self_tests() -> Result<(), Error> {
        let results = health_tests::HealthTests::run_all_tests();

        // Check if all tests passed
        if results.iter().all(|r| r.passed) {
            Ok(())
        } else {
            Err(Error::SelfTestFailed)
        }
    }

    /// HMAC_DRBG_Update (SP 800-90A §10.1.2.2).
    ///
    /// Step 3 returns after one round when provided_data is Null. An empty
    /// slice used to run the second round, so `Some(&[])` diverged from
    /// `None` (and from the Go binding). K and V are overwritten in place and
    /// the intermediate buffers wiped, rather than dropping the old K/V unwiped.
    fn update(&mut self, provided_data: Option<&[u8]>) {
        let provided_data = non_null(provided_data);
        let rounds: &[u8] = if provided_data.is_some() { &[0x00, 0x01] } else { &[0x00] };
        for &separator in rounds {
            // K = HMAC(K, V || separator || provided_data)
            let mut input = Vec::with_capacity(
                self.state.v.len() + 1 + provided_data.map_or(0, |d| d.len()),
            );
            input.extend_from_slice(&self.state.v);
            input.push(separator);
            if let Some(data) = provided_data {
                input.extend_from_slice(data);
            }
            let mut k = hmac(self.hash_alg, &self.state.k, &input);
            input.zeroize();
            self.state.k.copy_from_slice(&k);
            k.zeroize();

            // V = HMAC(K, V)
            let mut v = hmac(self.hash_alg, &self.state.k, &self.state.v);
            self.state.v.copy_from_slice(&v);
            v.zeroize();
        }
    }

    /// Wipe K and V and enter the SP 800-90A §11.3 error state.
    fn enter_error_state(&mut self) {
        self.wipe();
        self.error_state = true;
    }

    fn wipe(&mut self) {
        self.state.k.as_mut_slice().zeroize();
        self.state.v.as_mut_slice().zeroize();
        self.state.reseed_counter = 0;
    }

    /// Reseed the DRBG with new entropy
    pub fn reseed(&mut self, entropy: &[u8], additional_input: Option<&[u8]>) -> Result<(), Error> {
        if self.error_state {
            return Err(Error::HealthTestFailed);
        }

        // Validate entropy
        if entropy.len() < MIN_ENTROPY_LENGTH || entropy.len() > MAX_ENTROPY_LENGTH {
            return Err(Error::InvalidEntropy);
        }

        // Validate additional input
        if let Some(input) = additional_input {
            if input.len() > MAX_ADDITIONAL_INPUT_LENGTH {
                return Err(Error::AdditionalInputTooLong);
            }
        }

        // Combine entropy and additional input
        let mut seed_material = Vec::with_capacity(
            entropy.len() + additional_input.map_or(0, |i| i.len()),
        );
        seed_material.extend_from_slice(entropy);
        if let Some(input) = additional_input {
            seed_material.extend_from_slice(input);
        }

        // Update internal state
        self.update(Some(&seed_material));
        seed_material.zeroize();

        // Reset reseed counter
        self.state.reseed_counter = 1;

        Ok(())
    }

    /// Generate pseudorandom bytes
    pub fn generate(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.generate_with_resistance(output, additional_input, false)
    }

    /// Generate pseudorandom bytes with optional prediction resistance
    ///
    /// Every outlen-byte block of HMAC output goes through the continuous
    /// test before any of it is released. On a repeated block the output
    /// buffer is zeroized, K and V are wiped and the instance enters the
    /// error state: this and every later call return
    /// [`Error::HealthTestFailed`].
    pub fn generate_with_resistance(
        &mut self,
        output: &mut [u8],
        additional_input: Option<&[u8]>,
        prediction_resistance: bool,
    ) -> Result<(), Error> {
        if self.error_state {
            return Err(Error::HealthTestFailed);
        }

        // Validate request
        if output.is_empty() || output.len() > MAX_REQUEST_LENGTH {
            return Err(Error::InvalidRequest);
        }

        // Validate additional input
        if let Some(input) = additional_input {
            if input.len() > MAX_ADDITIONAL_INPUT_LENGTH {
                return Err(Error::AdditionalInputTooLong);
            }
        }

        // Check reseed counter
        if self.state.reseed_counter > RESEED_INTERVAL {
            return Err(Error::ReseedRequired);
        }

        // Check prediction resistance
        if prediction_resistance {
            return Err(Error::ReseedRequired);
        }

        // §10.1.2.5 step 2: update only when additional_input ≠ Null.
        let additional_input = non_null(additional_input);
        if additional_input.is_some() {
            self.update(additional_input);
        }

        // Generate output
        let outlen = self.hash_alg.output_length();
        let mut output_pos = 0;

        while output_pos < output.len() {
            // V = HMAC(K, V)
            let mut temp = hmac(self.hash_alg, &self.state.k, &self.state.v);
            self.state.v.copy_from_slice(&temp);

            // The continuous test compares whole outlen-byte blocks. It used
            // to compare the caller's requested bytes, so back-to-back 1-byte
            // requests collided with probability 1/256, and a failure
            // released the output and left the instance usable.
            if let Some(ref mut ct) = self.continuous_test {
                if !ct.check(&temp) {
                    temp.zeroize();
                    output.zeroize();
                    self.enter_error_state();
                    return Err(Error::HealthTestFailed);
                }
            }

            // Copy to output
            let remaining = output.len() - output_pos;
            let copy_len = remaining.min(outlen);
            output[output_pos..output_pos + copy_len].copy_from_slice(&temp[..copy_len]);
            output_pos += copy_len;

            // Clear temporary buffer
            temp.zeroize();
        }

        // Update internal state
        self.update(additional_input);

        // Increment reseed counter
        self.state.reseed_counter += 1;

        Ok(())
    }

    /// Uninstantiate the DRBG (SP 800-90A §9.4), zeroizing K and V.
    pub fn uninstantiate(mut self) {
        self.wipe();
    }
}

impl Drop for HmacDrbg {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instantiation() {
        let entropy = [0u8; 32];
        let drbg = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_deterministic_output() {
        let entropy = [0x42u8; 32];
        let nonce = [0x33u8; 16];

        let mut drbg1 = HmacDrbg::new(&entropy, Some(&nonce), None, HashAlgorithm::Sha256).unwrap();
        let mut drbg2 = HmacDrbg::new(&entropy, Some(&nonce), None, HashAlgorithm::Sha256).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.generate(&mut output1, None).unwrap();
        drbg2.generate(&mut output2, None).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_different_seeds() {
        let entropy1 = [0x11u8; 32];
        let entropy2 = [0x22u8; 32];

        let mut drbg1 = HmacDrbg::new(&entropy1, None, None, HashAlgorithm::Sha256).unwrap();
        let mut drbg2 = HmacDrbg::new(&entropy2, None, None, HashAlgorithm::Sha256).unwrap();

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        drbg1.generate(&mut output1, None).unwrap();
        drbg2.generate(&mut output2, None).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_sequential_outputs() {
        let entropy = [0u8; 32];
        let mut drbg = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256).unwrap();

        let mut outputs = Vec::new();
        for _ in 0..10 {
            let mut output = [0u8; 16];
            drbg.generate(&mut output, None).unwrap();
            outputs.push(output);
        }

        // Check all outputs are unique
        for i in 0..outputs.len() {
            for j in i + 1..outputs.len() {
                assert_ne!(outputs[i], outputs[j]);
            }
        }
    }

    #[test]
    fn test_invalid_entropy() {
        // Too short
        let entropy = [0u8; 31];
        let result = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256);
        assert!(matches!(result, Err(Error::InvalidEntropy)));

        // Too long
        let entropy = vec![0u8; MAX_ENTROPY_LENGTH + 1];
        let result = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256);
        assert!(matches!(result, Err(Error::InvalidEntropy)));
    }

    #[test]
    fn test_reseed() {
        let entropy = [0u8; 32];
        let mut drbg = HmacDrbg::new(&entropy, None, None, HashAlgorithm::Sha256).unwrap();

        let mut output1 = [0u8; 32];
        drbg.generate(&mut output1, None).unwrap();

        // Reseed
        let new_entropy = [1u8; 32];
        drbg.reseed(&new_entropy, None).unwrap();

        let mut output2 = [0u8; 32];
        drbg.generate(&mut output2, None).unwrap();

        assert_ne!(output1, output2);
    }

    /// Force the next HMAC block to repeat the one the continuous test holds.
    /// The failure must withhold the output, wipe K/V and leave the instance
    /// refusing generate and reseed (it used to return InvalidRequest with the
    /// output already written, then carry on as if nothing happened).
    #[test]
    fn test_continuous_test_failure_enters_error_state() {
        for alg in [HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512] {
            let mut drbg = HmacDrbg::new(&[0x42u8; 32], None, None, alg).unwrap();
            let next_block = hmac(alg, &drbg.state.k, &drbg.state.v);
            drbg.continuous_test.as_mut().unwrap().check(&next_block);

            let mut out = [0xAAu8; 100];
            assert_eq!(drbg.generate(&mut out, None), Err(Error::HealthTestFailed));
            assert!(out.iter().all(|&b| b == 0), "{alg:?}: output released on failure");
            assert!(drbg.state.k.iter().all(|&b| b == 0), "{alg:?}: K not wiped");
            assert!(drbg.state.v.iter().all(|&b| b == 0), "{alg:?}: V not wiped");
            assert_eq!(drbg.generate(&mut out, None), Err(Error::HealthTestFailed));
            assert_eq!(drbg.reseed(&[1u8; 32], None), Err(Error::HealthTestFailed));
        }
    }

    /// The continuous test is fed full outlen-byte blocks, however few bytes
    /// the caller asked for: a 1-byte request is compared on 64 bytes here.
    #[test]
    fn test_continuous_test_compares_full_blocks() {
        let mut drbg = HmacDrbg::new(&[0x42u8; 32], None, None, HashAlgorithm::Sha512).unwrap();
        let block = hmac(HashAlgorithm::Sha512, &drbg.state.k, &drbg.state.v);
        let mut out = [0u8; 1];
        drbg.generate(&mut out, None).unwrap();
        assert_eq!(out[0], block[0]);
        let held = drbg.continuous_test.as_ref().unwrap().last_output.as_deref();
        assert_eq!(held, Some(&block[..]));
    }

    #[test]
    fn test_wipe_zeroizes_k_and_v() {
        let mut drbg = HmacDrbg::new(&[0x42u8; 32], None, None, HashAlgorithm::Sha512).unwrap();
        assert!(drbg.state.k.iter().any(|&b| b != 0));
        drbg.wipe();
        assert!(drbg.state.k.iter().all(|&b| b == 0));
        assert!(drbg.state.v.iter().all(|&b| b == 0));
        assert_eq!(drbg.state.reseed_counter, 0);
    }

    #[test]
    fn test_run_self_tests_fails_closed_on_embedded_kat_mismatch() {
        let result = HmacDrbg::run_self_tests();
        assert!(matches!(result, Err(Error::SelfTestFailed)));
    }
}

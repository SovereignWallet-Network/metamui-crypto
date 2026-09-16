//! NIST KAT (Known Answer Test) vectors for Falcon-512
//! 
//! This module implements validation against official NIST test vectors
//! from the PQC standardization process.

use crate::error::{Result, Falcon512Error};
use crate::{PublicKey, PrivateKey};
use alloc::vec::Vec;
use alloc::string::String;

/// NIST test vector structure
#[derive(Debug, Clone)]
pub struct NistVector {
    /// Test vector index
    pub count: usize,
    /// Seed for deterministic key generation
    pub seed: Vec<u8>,
    /// Message to sign
    pub msg: Vec<u8>,
    /// Expected public key
    pub pk: Vec<u8>,
    /// Expected secret key
    pub sk: Vec<u8>,
    /// Expected signature
    pub sig: Vec<u8>,
}

/// NIST test vector validator
pub struct NistVectorValidator {
    vectors: Vec<NistVector>,
}

impl NistVectorValidator {
    /// Create a new validator with embedded test vectors
    pub fn new() -> Self {
        Self {
            vectors: Self::load_embedded_vectors(),
        }
    }
    
    /// Load embedded NIST test vectors
    fn load_embedded_vectors() -> Vec<NistVector> {
        // Fail closed until exact official vectors are embedded instead of
        // shipping placeholder byte strings as if they were NIST fixtures.
        Vec::new()
    }
    
    /// Validate key generation against test vectors
    pub fn validate_keygen(&self) -> Result<ValidationReport> {
        let _ = self;
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Validate signing against test vectors
    pub fn validate_signing(&self) -> Result<ValidationReport> {
        let _ = self;
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Validate verification against test vectors
    pub fn validate_verification(&self) -> Result<ValidationReport> {
        let _ = self;
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Run all validations
    pub fn validate_all(&self) -> Result<FullValidationReport> {
        let _ = self;
        Err(Falcon512Error::NotImplemented)
    }
}

/// Validation report for a test category
#[derive(Debug)]
pub struct ValidationReport {
    pub category: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub details: Vec<TestResult>,
}

impl ValidationReport {
    fn new(category: &str) -> Self {
        Self {
            category: category.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            details: Vec::new(),
        }
    }
    
    fn add_pass(&mut self, vector_id: usize, message: &str) {
        self.total += 1;
        self.passed += 1;
        self.details.push(TestResult {
            vector_id,
            passed: true,
            message: message.to_string(),
        });
    }
    
    fn add_fail(&mut self, vector_id: usize, message: &str) {
        self.total += 1;
        self.failed += 1;
        self.details.push(TestResult {
            vector_id,
            passed: false,
            message: message.to_string(),
        });
    }
    
    pub fn print_summary(&self) {
        #[cfg(feature = "std")]
        {
            println!("\n{} Validation Report:", self.category);
            println!("  Total:  {}", self.total);
            println!("  Passed: {} ({}%)", self.passed, 
                    if self.total > 0 { self.passed * 100 / self.total } else { 0 });
            println!("  Failed: {}", self.failed);
            
            if self.failed > 0 {
                println!("\nFailures:");
                for detail in &self.details {
                    if !detail.passed {
                        println!("  Vector {}: {}", detail.vector_id, detail.message);
                    }
                }
            }
        }
    }
}

/// Individual test result
#[derive(Debug)]
pub struct TestResult {
    pub vector_id: usize,
    pub passed: bool,
    pub message: String,
}

/// Full validation report
#[derive(Debug)]
pub struct FullValidationReport {
    pub keygen: ValidationReport,
    pub signing: ValidationReport,
    pub verification: ValidationReport,
}

impl FullValidationReport {
    pub fn print_summary(&self) {
        #[cfg(feature = "std")]
        {
            println!("\n========== NIST Vector Validation Report ==========");
            self.keygen.print_summary();
            self.signing.print_summary();
            self.verification.print_summary();
            
            let total = self.keygen.total + self.signing.total + self.verification.total;
            let passed = self.keygen.passed + self.signing.passed + self.verification.passed;
            let failed = self.keygen.failed + self.signing.failed + self.verification.failed;
            
            println!("\n========== Overall Summary ==========");
            println!("Total Tests:  {}", total);
            println!("Passed:       {} ({}%)", passed, 
                    if total > 0 { passed * 100 / total } else { 0 });
            println!("Failed:       {}", failed);
            
            if failed == 0 {
                println!("\n✅ All NIST vector tests passed!");
            } else {
                println!("\n❌ Some tests failed. See details above.");
            }
        }
    }
    
    pub fn all_passed(&self) -> bool {
        self.keygen.failed == 0 && 
        self.signing.failed == 0 && 
        self.verification.failed == 0
    }
}

/// Deterministic RNG for test vector reproduction
pub struct DeterministicRng {
    seed: [u8; 48],
    counter: u64,
}

impl DeterministicRng {
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut seed_array = [0u8; 48];
        let len = seed.len().min(48);
        seed_array[..len].copy_from_slice(&seed[..len]);
        
        Self {
            seed: seed_array,
            counter: 0,
        }
    }
    
    pub fn reset(&mut self) {
        self.counter = 0;
    }
}

impl rand::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    
    fn next_u64(&mut self) -> u64 {
        // Simple deterministic generation based on seed and counter
        use metamui_sha2::Sha256Hasher;
        
        let mut hasher = Sha256Hasher::new();
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        let hash = hasher.finalize();
        
        self.counter += 1;
        
        u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ])
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use metamui_sha2::Sha256Hasher;
        
        let mut offset = 0;
        while offset < dest.len() {
            let mut hasher = Sha256Hasher::new();
            hasher.update(&self.seed);
            hasher.update(&self.counter.to_le_bytes());
            let hash = hasher.finalize();
            
            let to_copy = (dest.len() - offset).min(32);
            dest[offset..offset + to_copy].copy_from_slice(&hash[..to_copy]);
            
            offset += to_copy;
            self.counter += 1;
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Helper to decode hex strings
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| Falcon512Error::InvalidParameter)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Serialize public key to bytes
fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(897);
    
    // Add header byte
    bytes.push(0x00);
    
    // Add polynomial coefficients (14 bits each, packed)
    let coeffs = &pk.h.coeffs;
    let mut bit_buffer = 0u32;
    let mut bits_in_buffer = 0;
    
    for &coeff in coeffs {
        // Reduce to 14 bits
        let value = (coeff as u16) & 0x3FFF;
        bit_buffer |= (value as u32) << bits_in_buffer;
        bits_in_buffer += 14;
        
        while bits_in_buffer >= 8 {
            bytes.push((bit_buffer & 0xFF) as u8);
            bit_buffer >>= 8;
            bits_in_buffer -= 8;
        }
    }
    
    if bits_in_buffer > 0 {
        bytes.push((bit_buffer & 0xFF) as u8);
    }
    
    // Pad to exactly 897 bytes
    while bytes.len() < 897 {
        bytes.push(0);
    }
    bytes.truncate(897);
    
    bytes
}

/// Serialize private key to bytes
fn serialize_private_key(sk: &PrivateKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2305);
    
    // Add all four polynomials (f, g, F, G)
    for poly in [&sk.f.coeffs, &sk.g.coeffs, &sk.big_f.coeffs, &sk.big_g.coeffs] {
        for &coeff in poly {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    
    // Pad or truncate to exactly 2305 bytes
    while bytes.len() < 2305 {
        bytes.push(0);
    }
    bytes.truncate(2305);
    
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    
    #[test]
    fn test_deterministic_rng() {
        let seed = b"test seed";
        let mut rng1 = DeterministicRng::from_seed(seed);
        let mut rng2 = DeterministicRng::from_seed(seed);
        
        // Should produce same values
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u32(), rng2.next_u32());
        
        // Reset should restart sequence
        rng1.reset();
        rng2 = DeterministicRng::from_seed(seed);
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
    
    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("00").unwrap(), vec![0x00]);
        assert_eq!(hex_decode("ff").unwrap(), vec![0xff]);
        assert_eq!(hex_decode("0102").unwrap(), vec![0x01, 0x02]);
        assert_eq!(hex_decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }
    
    #[test]
    fn test_nist_vector_loading() {
        let validator = NistVectorValidator::new();
        assert!(validator.vectors.is_empty());
        assert!(matches!(
            validator.validate_keygen(),
            Err(Falcon512Error::NotImplemented)
        ));
        assert!(matches!(
            validator.validate_signing(),
            Err(Falcon512Error::NotImplemented)
        ));
        assert!(matches!(
            validator.validate_verification(),
            Err(Falcon512Error::NotImplemented)
        ));
        assert!(matches!(
            validator.validate_all(),
            Err(Falcon512Error::NotImplemented)
        ));
    }
}

/// BIP39 mnemonic implementation

use crate::error::{CryptoUtilError, MnemonicError};
use metamui_sha2::sha256::sha256;
use std::collections::HashMap;

#[cfg(feature = "std")]
use std::vec::Vec;

use super::wordlist::ENGLISH_WORDLIST;

/// Native BIP39 implementation without external dependencies
pub struct Bip39 {
    wordlist: &'static [&'static str],
    word_map: HashMap<&'static str, usize>,
}

impl Default for Bip39 {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip39 {
    /// Create a new BIP39 instance with English wordlist
    pub fn new() -> Self {
        let mut word_map = HashMap::new();
        for (index, word) in ENGLISH_WORDLIST.iter().enumerate() {
            word_map.insert(*word, index);
        }
        
        Self {
            wordlist: ENGLISH_WORDLIST,
            word_map,
        }
    }
    
    /// Generate mnemonic from entropy
    pub fn entropy_to_mnemonic(&self, entropy: &[u8]) -> Result<String, CryptoUtilError> {
        // Validate entropy length
        let entropy_bits = entropy.len() * 8;
        if entropy_bits < 128 || entropy_bits > 256 || entropy_bits % 32 != 0 {
            return Err(CryptoUtilError::InvalidMnemonic(
                MnemonicError::InvalidEntropyLength
            ));
        }
        
        // Calculate checksum using pure SHA-256
        let hash = sha256(entropy);
        
        let checksum_bits = entropy_bits / 32;
        
        // Combine entropy and checksum
        let mut bits = Vec::new();
        
        // Add entropy bits
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        
        // Add checksum bits
        for i in 0..checksum_bits {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            bits.push((hash[byte_index] >> bit_index) & 1);
        }
        
        // Convert to words
        let mut words = Vec::new();
        for chunk in bits.chunks(11) {
            let mut index = 0;
            for (i, &bit) in chunk.iter().enumerate() {
                index |= (bit as usize) << (10 - i);
            }
            
            if index >= self.wordlist.len() {
                return Err(CryptoUtilError::InvalidMnemonic(
                    MnemonicError::InvalidWord(index)
                ));
            }
            
            words.push(self.wordlist[index]);
        }
        
        Ok(words.join(" "))
    }
    
    /// Convert mnemonic to entropy
    pub fn mnemonic_to_entropy(&self, mnemonic: &str) -> Result<Vec<u8>, CryptoUtilError> {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        
        // Validate word count
        let word_count = words.len();
        if word_count < 12 || word_count > 24 || word_count % 3 != 0 {
            return Err(CryptoUtilError::InvalidMnemonic(
                MnemonicError::InvalidWordCount(word_count)
            ));
        }
        
        // Convert words to bits
        let mut bits = Vec::new();
        for word in &words {
            let index = self.word_map.get(word)
                .ok_or_else(|| CryptoUtilError::InvalidMnemonic(
                    MnemonicError::InvalidWord(words.iter().position(|&w| w == *word).unwrap())
                ))?;
            
            // Convert to 11 bits
            for i in (0..11).rev() {
                bits.push(((index >> i) & 1) as u8);
            }
        }
        
        // Calculate expected lengths
        let total_bits = bits.len();
        let checksum_bits = total_bits / 33;
        let entropy_bits = total_bits - checksum_bits;
        
        // Extract entropy
        let mut entropy = Vec::new();
        for chunk in bits[..entropy_bits].chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                byte |= bit << (7 - i);
            }
            entropy.push(byte);
        }
        
        // Verify checksum using pure SHA-256
        let hash = sha256(&entropy);
        
        // Extract checksum from mnemonic
        let mut checksum_from_mnemonic = 0u8;
        for (i, &bit) in bits[entropy_bits..].iter().enumerate() {
            checksum_from_mnemonic |= bit << (checksum_bits - 1 - i);
        }
        
        // Extract checksum from hash
        let checksum_from_hash = hash[0] >> (8 - checksum_bits);
        
        if checksum_from_mnemonic != checksum_from_hash {
            return Err(CryptoUtilError::InvalidMnemonic(
                MnemonicError::InvalidChecksum
            ));
        }
        
        Ok(entropy)
    }
    
    /// Generate seed from mnemonic using PBKDF2
    pub fn mnemonic_to_seed(&self, mnemonic: &str, passphrase: &str) -> Vec<u8> {
        let salt = format!("mnemonic{}", passphrase);
        pbkdf2_sha512(mnemonic.as_bytes(), salt.as_bytes(), 2048, 64)
    }
    
    /// Validate mnemonic phrase
    pub fn validate_mnemonic(&self, mnemonic: &str) -> bool {
        self.mnemonic_to_entropy(mnemonic).is_ok()
    }
    
    /// Get the wordlist
    pub fn wordlist(&self) -> &[&str] {
        self.wordlist
    }
}

/// PBKDF2-SHA512 implementation with secure memory clearing
fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    // Use the utilities PBKDF2 implementation
    use crate::kdf::pbkdf2::Pbkdf2;
    Pbkdf2::pbkdf2_hmac_sha512(password, salt, iterations, dk_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy_to_mnemonic() {
        let bip39 = Bip39::new();
        
        // Test vector from BIP39 spec
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = bip39.entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(mnemonic, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }
    
    #[test]
    fn test_mnemonic_to_seed() {
        let bip39 = Bip39::new();
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Test without passphrase
        let seed = bip39.mnemonic_to_seed(mnemonic, "");
        let expected = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        assert_eq!(seed, expected);
        
        // Test with passphrase "TREZOR" - this is the common BIP39 test vector
        let seed_with_pass = bip39.mnemonic_to_seed(mnemonic, "TREZOR");
        let expected_with_pass = hex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap();
        assert_eq!(seed_with_pass, expected_with_pass);
    }
    
    #[test]
    fn test_mnemonic_validation() {
        let bip39 = Bip39::new();
        
        assert!(bip39.validate_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
        assert!(!bip39.validate_mnemonic("invalid mnemonic phrase"));
    }
    
    #[test]
    fn test_mnemonic_to_entropy() {
        let bip39 = Bip39::new();
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let entropy = bip39.mnemonic_to_entropy(mnemonic).unwrap();
        let expected = hex::decode("00000000000000000000000000000000").unwrap();
        assert_eq!(entropy, expected);
    }
    
    #[test]
    fn test_round_trip() {
        let bip39 = Bip39::new();
        
        // Test various entropy sizes
        for size in [16, 20, 24, 28, 32] {
            let entropy = vec![0xFFu8; size];
            let mnemonic = bip39.entropy_to_mnemonic(&entropy).unwrap();
            let recovered = bip39.mnemonic_to_entropy(&mnemonic).unwrap();
            assert_eq!(entropy, recovered);
        }
    }
}
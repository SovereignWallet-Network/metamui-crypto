//! BIP-39 mnemonic encoding, decoding, and seed derivation.
//!
//! Pure-Rust `no_std`-compatible implementation with zero external
//! crate dependencies beyond the in-tree `metamui-sha2` and
//! `metamui-pbkdf2` crates. Replaces `bip39` / `tiny-bip39` for
//! downstream consumers so the supply-chain-hardened-pure-impl
//! invariant holds.
//!
//! # Example
//!
//! ```
//! use metamui_bip39::Mnemonic;
//!
//! let entropy = [0u8; 16];
//! let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
//! assert_eq!(mnemonic.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
//!
//! let seed = mnemonic.to_seed("");
//! assert_eq!(seed.len(), 64);
//! ```
//!
//! # Scope
//!
//! This crate ships the BIP-39 **English** wordlist. The type system
//! has a `Language` enum to carry other wordlists, but only `English`
//! is implemented; other languages currently return `Error::UnsupportedLanguage`.
//! Adding a language is purely a data-plumbing task — drop the
//! 2048-word list into `src/wordlist_<lang>.rs` and add the variant to
//! the `Language::wordlist()` match.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use metamui_pbkdf2::PBKDF2;
use metamui_sha2::sha256::sha256;

mod wordlist_english;

/// BIP-39 errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Entropy length must be one of 16, 20, 24, 28, 32 bytes (128/160/192/224/256 bits).
    InvalidEntropyLength,
    /// Word count must be one of 12, 15, 18, 21, 24.
    InvalidWordCount,
    /// A word in the phrase is not in the selected wordlist.
    InvalidWord,
    /// The checksum bits embedded in the phrase do not match SHA-256 of the entropy.
    InvalidChecksum,
    /// The language enum variant does not yet have an in-tree wordlist.
    UnsupportedLanguage,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEntropyLength => f.write_str("BIP-39 entropy must be 128/160/192/224/256 bits"),
            Self::InvalidWordCount => f.write_str("BIP-39 phrase must be 12/15/18/21/24 words"),
            Self::InvalidWord => f.write_str("word not present in BIP-39 wordlist"),
            Self::InvalidChecksum => f.write_str("BIP-39 checksum mismatch"),
            Self::UnsupportedLanguage => f.write_str("BIP-39 language not yet supported in-tree"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// BIP-39 wordlist language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    /// English — the canonical BIP-39 wordlist.
    English,
    /// Japanese — wordlist not yet bundled.
    Japanese,
    /// Korean — wordlist not yet bundled.
    Korean,
    /// Spanish — wordlist not yet bundled.
    Spanish,
    /// Simplified Chinese — wordlist not yet bundled.
    ChineseSimplified,
    /// Traditional Chinese — wordlist not yet bundled.
    ChineseTraditional,
    /// French — wordlist not yet bundled.
    French,
    /// Italian — wordlist not yet bundled.
    Italian,
    /// Czech — wordlist not yet bundled.
    Czech,
    /// Portuguese — wordlist not yet bundled.
    Portuguese,
}

impl Default for Language {
    fn default() -> Self {
        Self::English
    }
}

impl Language {
    /// Returns the 2048-word list for this language, or
    /// `Error::UnsupportedLanguage` for languages not yet bundled.
    pub fn wordlist(&self) -> Result<&'static [&'static str; 2048]> {
        match self {
            Self::English => Ok(wordlist_english::ENGLISH),
            _ => Err(Error::UnsupportedLanguage),
        }
    }
}

/// A BIP-39 mnemonic phrase paired with its language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mnemonic {
    phrase: String,
    language: Language,
}

impl Mnemonic {
    /// Build a mnemonic from raw entropy using the English wordlist.
    ///
    /// Convenience around [`Mnemonic::from_entropy_in`] with
    /// `Language::English`.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Self::from_entropy_in(entropy, Language::English)
    }

    /// Build a mnemonic from raw entropy in the specified language.
    pub fn from_entropy_in(entropy: &[u8], language: Language) -> Result<Self> {
        let entropy_bits = entropy.len() * 8;
        if entropy_bits < 128 || entropy_bits > 256 || entropy_bits % 32 != 0 {
            return Err(Error::InvalidEntropyLength);
        }
        let wordlist = language.wordlist()?;

        let checksum_bits = entropy_bits / 32;
        let hash = sha256(entropy);

        // Bit stream: entropy bits followed by the top `checksum_bits` bits of the hash.
        let total_bits = entropy_bits + checksum_bits;
        let mut bits: Vec<u8> = Vec::with_capacity(total_bits);
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        for i in 0..checksum_bits {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            bits.push((hash[byte_idx] >> bit_idx) & 1);
        }

        // 11 bits per word.
        let mut words: Vec<&'static str> = Vec::with_capacity(total_bits / 11);
        for chunk in bits.chunks(11) {
            let mut idx = 0usize;
            for (i, &b) in chunk.iter().enumerate() {
                idx |= (b as usize) << (10 - i);
            }
            words.push(wordlist[idx]);
        }

        Ok(Mnemonic {
            phrase: words.join(" "),
            language,
        })
    }

    /// Parse and validate a mnemonic phrase against the English wordlist.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        Self::from_phrase_in(phrase, Language::English)
    }

    /// Parse and validate a mnemonic phrase in the specified language.
    pub fn from_phrase_in(phrase: &str, language: Language) -> Result<Self> {
        let _entropy = Self::phrase_to_entropy(phrase, language)?;
        // Round-trip succeeded — the phrase is well-formed.
        Ok(Mnemonic {
            phrase: phrase.split_whitespace().collect::<Vec<_>>().join(" "),
            language,
        })
    }

    /// Recover the original entropy from the phrase.
    pub fn to_entropy(&self) -> Vec<u8> {
        Self::phrase_to_entropy(&self.phrase, self.language)
            .expect("phrase was validated at construction")
    }

    fn phrase_to_entropy(phrase: &str, language: Language) -> Result<Vec<u8>> {
        let wordlist = language.wordlist()?;
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let word_count = words.len();
        if word_count < 12 || word_count > 24 || word_count % 3 != 0 {
            return Err(Error::InvalidWordCount);
        }

        let mut bits: Vec<u8> = Vec::with_capacity(word_count * 11);
        for word in &words {
            let mut found: Option<usize> = None;
            for (i, w) in wordlist.iter().enumerate() {
                if *w == *word {
                    found = Some(i);
                    break;
                }
            }
            let idx = found.ok_or(Error::InvalidWord)?;
            for i in (0..11).rev() {
                bits.push(((idx >> i) & 1) as u8);
            }
        }

        let total_bits = bits.len();
        let checksum_bits = total_bits / 33;
        let entropy_bits = total_bits - checksum_bits;

        let mut entropy: Vec<u8> = Vec::with_capacity(entropy_bits / 8);
        for chunk in bits[..entropy_bits].chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                byte |= b << (7 - i);
            }
            entropy.push(byte);
        }

        // Recover and verify the checksum.
        let hash = sha256(&entropy);
        let mut checksum_from_phrase = 0u8;
        for (i, &b) in bits[entropy_bits..].iter().enumerate() {
            checksum_from_phrase |= b << (checksum_bits - 1 - i);
        }
        let checksum_from_hash = hash[0] >> (8 - checksum_bits);

        if checksum_from_phrase != checksum_from_hash {
            return Err(Error::InvalidChecksum);
        }

        Ok(entropy)
    }

    /// Derive the 64-byte BIP-39 seed using PBKDF2-HMAC-SHA512, 2048
    /// iterations, salt = `"mnemonic" || passphrase`.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        // `metamui_pbkdf2` already implements the exact BIP-39 spec
        // (2048 iterations, 64-byte output, "mnemonic" salt prefix).
        let seed_vec = PBKDF2::bip39_mnemonic_to_seed(&self.phrase, passphrase);
        let mut out = [0u8; 64];
        out.copy_from_slice(&seed_vec[..64]);
        out
    }

    /// The canonical space-separated phrase.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The language this mnemonic was built under.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Owned copy of the phrase as a `String`.
    pub fn into_phrase(self) -> String {
        self.phrase.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_entropy_vector() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn seed_vector_no_passphrase() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed = m.to_seed("");
        let expected = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();
        assert_eq!(&seed[..], &expected[..]);
    }

    #[test]
    fn seed_vector_with_trezor_passphrase() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let seed = m.to_seed("TREZOR");
        let expected = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        )
        .unwrap();
        assert_eq!(&seed[..], &expected[..]);
    }

    #[test]
    fn roundtrip_entropy_sizes() {
        for size in [16, 20, 24, 28, 32] {
            let entropy = (0..size as u8).collect::<Vec<u8>>();
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(m.to_entropy(), entropy);
            // from_phrase should accept it.
            let m2 = Mnemonic::from_phrase(m.phrase()).unwrap();
            assert_eq!(m, m2);
        }
    }

    #[test]
    fn rejects_bad_word() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert_eq!(Mnemonic::from_phrase(bad).unwrap_err(), Error::InvalidWord);
    }

    #[test]
    fn rejects_bad_checksum() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(Mnemonic::from_phrase(bad).unwrap_err(), Error::InvalidChecksum);
    }

    #[test]
    fn rejects_bad_word_count() {
        let bad = "abandon abandon abandon";
        assert_eq!(Mnemonic::from_phrase(bad).unwrap_err(), Error::InvalidWordCount);
    }

    #[test]
    fn unsupported_language_errors() {
        assert_eq!(
            Mnemonic::from_entropy_in(&[0u8; 16], Language::Japanese).unwrap_err(),
            Error::UnsupportedLanguage
        );
    }
}

/// BIP39 wordlist management

/// English wordlist for BIP39 mnemonic generation
/// This is the standard 2048-word English wordlist
pub const ENGLISH_WORDLIST: &[&str] = &include!(concat!(env!("OUT_DIR"), "/english_array.rs"));

/// Get the English wordlist
pub fn get_english_wordlist() -> &'static [&'static str] {
    ENGLISH_WORDLIST
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wordlist_size() {
        assert_eq!(ENGLISH_WORDLIST.len(), 2048);
    }
    
    #[test]
    fn test_wordlist_order() {
        // Verify alphabetical order
        for i in 1..ENGLISH_WORDLIST.len() {
            assert!(ENGLISH_WORDLIST[i-1] <= ENGLISH_WORDLIST[i],
                "Wordlist not in order at index {}: {} > {}", 
                i-1, ENGLISH_WORDLIST[i-1], ENGLISH_WORDLIST[i]);
        }
    }
    
    #[test]
    fn test_first_and_last_words() {
        assert_eq!(ENGLISH_WORDLIST[0], "abandon");
        assert_eq!(ENGLISH_WORDLIST[2047], "zoo");
    }
}
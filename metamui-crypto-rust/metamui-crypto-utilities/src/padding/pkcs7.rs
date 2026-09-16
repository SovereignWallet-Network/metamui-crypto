/// PKCS#7 padding implementation

use crate::error::{CryptoUtilError, Result, PaddingErrorType};

#[cfg(feature = "std")]
use std::vec::Vec;

/// PKCS#7 padding utilities
pub struct Pkcs7;

impl Pkcs7 {
    /// Add PKCS#7 padding to data
    pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if block_size == 0 || block_size > 255 {
            return Err(CryptoUtilError::PaddingError(PaddingErrorType::InvalidBlockSize));
        }
        
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(vec![padding_len as u8; padding_len]);
        
        Ok(padded)
    }
    
    /// Remove PKCS#7 padding from data
    pub fn unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if block_size == 0 || block_size > 255 {
            return Err(CryptoUtilError::PaddingError(PaddingErrorType::InvalidBlockSize));
        }
        
        if data.is_empty() {
            return Err(CryptoUtilError::PaddingError(PaddingErrorType::InvalidPadding));
        }
        
        let padding_len = data[data.len() - 1] as usize;
        
        if padding_len == 0 || padding_len > block_size || padding_len > data.len() {
            return Err(CryptoUtilError::PaddingError(PaddingErrorType::InvalidPadding));
        }
        
        // Verify all padding bytes are correct
        for i in 0..padding_len {
            if data[data.len() - 1 - i] != padding_len as u8 {
                return Err(CryptoUtilError::PaddingError(PaddingErrorType::InvalidPadding));
            }
        }
        
        Ok(data[..data.len() - padding_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pkcs7_padding() {
        let data = b"hello";
        let padded = Pkcs7::pad(data, 8).unwrap();
        assert_eq!(padded, b"hello\x03\x03\x03");
        
        let unpadded = Pkcs7::unpad(&padded, 8).unwrap();
        assert_eq!(unpadded, data);
    }
}
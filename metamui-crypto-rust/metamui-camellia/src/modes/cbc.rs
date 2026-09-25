/// Cipher Block Chaining (CBC) mode

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use crate::core::{BlockCipher, Camellia};
use crate::error::CamelliaError;
use crate::types::Block;

/// Apply PKCS#7 padding
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![padding_len as u8; padding_len]);
    padded
}

/// Remove PKCS#7 padding
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    if data.is_empty() {
        return Err(CamelliaError::InvalidPadding);
    }
    
    let padding_len = data[data.len() - 1] as usize;
    
    if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
        return Err(CamelliaError::InvalidPadding);
    }
    
    // Verify padding
    for i in 0..padding_len {
        if data[data.len() - 1 - i] != padding_len as u8 {
            return Err(CamelliaError::InvalidPadding);
        }
    }
    
    Ok(data[..data.len() - padding_len].to_vec())
}

/// Encrypt data using CBC mode with PKCS#7 padding
pub fn encrypt_cbc(
    cipher: &Camellia,
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CamelliaError> {
    if iv.len() != 16 {
        return Err(CamelliaError::InvalidIvSize { size: iv.len() });
    }
    
    let padded = pkcs7_pad(plaintext, 16);
    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut prev_block = Block::default();
    prev_block.copy_from_slice(iv);
    
    for chunk in padded.chunks_exact(16) {
        let mut block = Block::default();
        
        // XOR with previous ciphertext block
        for i in 0..16 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        
        // Encrypt
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
        prev_block = block;
    }
    
    Ok(ciphertext)
}

/// Decrypt data using CBC mode with PKCS#7 padding
pub fn decrypt_cbc(
    cipher: &Camellia,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CamelliaError> {
    if iv.len() != 16 {
        return Err(CamelliaError::InvalidIvSize { size: iv.len() });
    }
    
    if ciphertext.len() % 16 != 0 {
        return Err(CamelliaError::InvalidBlockSize {
            size: ciphertext.len(),
        });
    }
    
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = Block::default();
    prev_block.copy_from_slice(iv);
    
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = Block::default();
        block.copy_from_slice(chunk);
        
        // Decrypt
        let ciphertext_block = block;
        cipher.decrypt_block(&mut block);
        
        // XOR with previous ciphertext block
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }
        
        plaintext.extend_from_slice(&block);
        prev_block = ciphertext_block;
    }
    
    // Remove padding
    pkcs7_unpad(&plaintext)
}
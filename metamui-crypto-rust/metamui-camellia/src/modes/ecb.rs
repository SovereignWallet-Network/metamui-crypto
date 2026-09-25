/// Electronic Codebook (ECB) mode
///
/// WARNING: ECB mode is not recommended for use as it doesn't provide
/// semantic security. Use CBC or CTR mode instead.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use crate::core::{BlockCipher, Camellia};
use crate::error::CamelliaError;
use crate::types::Block;

/// Encrypt data using ECB mode
pub fn encrypt_ecb(cipher: &Camellia, plaintext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    if plaintext.len() % 16 != 0 {
        return Err(CamelliaError::InvalidBlockSize {
            size: plaintext.len(),
        });
    }
    
    let mut ciphertext = vec![0u8; plaintext.len()];
    
    for (chunk_in, chunk_out) in plaintext.chunks_exact(16).zip(ciphertext.chunks_exact_mut(16)) {
        let mut block = Block::default();
        block.copy_from_slice(chunk_in);
        cipher.encrypt_block(&mut block);
        chunk_out.copy_from_slice(&block);
    }
    
    Ok(ciphertext)
}

/// Decrypt data using ECB mode
pub fn decrypt_ecb(cipher: &Camellia, ciphertext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    if ciphertext.len() % 16 != 0 {
        return Err(CamelliaError::InvalidBlockSize {
            size: ciphertext.len(),
        });
    }
    
    let mut plaintext = vec![0u8; ciphertext.len()];
    
    for (chunk_in, chunk_out) in ciphertext.chunks_exact(16).zip(plaintext.chunks_exact_mut(16)) {
        let mut block = Block::default();
        block.copy_from_slice(chunk_in);
        cipher.decrypt_block(&mut block);
        chunk_out.copy_from_slice(&block);
    }
    
    Ok(plaintext)
}
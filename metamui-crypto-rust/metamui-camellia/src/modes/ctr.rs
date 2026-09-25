/// Counter (CTR) mode

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::core::{BlockCipher, Camellia};
use crate::error::CamelliaError;
use crate::types::Block;

/// Increment counter block
fn increment_counter(counter: &mut Block) {
    for i in (0..16).rev() {
        let (new_val, overflow) = counter[i].overflowing_add(1);
        counter[i] = new_val;
        if !overflow {
            break;
        }
    }
}

/// Process data using CTR mode (encryption and decryption are the same)
pub fn process_ctr(cipher: &Camellia, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    if nonce.len() != 16 {
        return Err(CamelliaError::InvalidIvSize { size: nonce.len() });
    }
    
    let mut result = Vec::with_capacity(data.len());
    let mut counter = Block::default();
    counter.copy_from_slice(nonce);
    
    let mut data_pos = 0;
    while data_pos < data.len() {
        // Encrypt counter
        let mut keystream_block = counter;
        cipher.encrypt_block(&mut keystream_block);
        
        // XOR with data
        let chunk_len = (data.len() - data_pos).min(16);
        for i in 0..chunk_len {
            result.push(data[data_pos + i] ^ keystream_block[i]);
        }
        
        data_pos += chunk_len;
        
        // Increment counter
        increment_counter(&mut counter);
    }
    
    Ok(result)
}

/// Encrypt data using CTR mode
pub fn encrypt_ctr(cipher: &Camellia, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    process_ctr(cipher, nonce, plaintext)
}

/// Decrypt data using CTR mode
pub fn decrypt_ctr(cipher: &Camellia, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
    process_ctr(cipher, nonce, ciphertext)
}
use crate::HkdfError;

/// HMAC implementation for HKDF
pub struct Hmac<H> {
    _hasher: std::marker::PhantomData<H>,
}

pub trait Hash {
    const OUTPUT_SIZE: usize;
    const BLOCK_SIZE: usize;
    
    fn hash(data: &[u8]) -> Vec<u8>;
}

/// SHA-256 wrapper
pub struct Sha256;

impl Hash for Sha256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    
    fn hash(data: &[u8]) -> Vec<u8> {
        let hash = metamui_sha2::sha256::MetaMUISha256::new()
            .hash(data)
            .expect("SHA-256 should not fail");
        hash.to_vec()
    }
}

/// SHA-512 wrapper
pub struct Sha512;

impl Hash for Sha512 {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 128;
    
    fn hash(data: &[u8]) -> Vec<u8> {
        let hash = metamui_sha2::sha512::MetaMUISha512::new()
            .hash(data)
            .expect("SHA-512 should not fail");
        hash.to_vec()
    }
}

impl<H: Hash> Hmac<H> {
    /// Compute HMAC
    pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let block_size = H::BLOCK_SIZE;
        
        // Prepare key
        let mut k = vec![0u8; block_size];
        if key.len() > block_size {
            let hashed_key = H::hash(key);
            k[..hashed_key.len()].copy_from_slice(&hashed_key);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        
        // Inner padding
        let mut ipad = k.clone();
        for byte in ipad.iter_mut() {
            *byte ^= 0x36;
        }
        
        // Outer padding
        let mut opad = k;
        for byte in opad.iter_mut() {
            *byte ^= 0x5c;
        }
        
        // Compute HMAC
        let mut inner = ipad;
        inner.extend_from_slice(data);
        let inner_hash = H::hash(&inner);
        
        let mut outer = opad;
        outer.extend_from_slice(&inner_hash);
        H::hash(&outer)
    }
}

/// Native HKDF implementation
pub struct HkdfNative<H: Hash> {
    prk: Vec<u8>,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: Hash> HkdfNative<H> {
    /// HKDF Extract function
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        let default_salt = vec![0u8; H::OUTPUT_SIZE];
        let salt = salt.unwrap_or(&default_salt);
        Hmac::<H>::hmac(salt, ikm)
    }
    
    /// Create HKDF from input key material
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let prk = Self::extract(salt, ikm);
        Self {
            prk,
            _hasher: std::marker::PhantomData,
        }
    }
    
    /// Create HKDF from pseudo-random key
    pub fn from_prk(prk: &[u8]) -> Result<Self, HkdfError> {
        if prk.len() != H::OUTPUT_SIZE {
            return Err(HkdfError::InvalidKey(
                format!("PRK must be {} bytes", H::OUTPUT_SIZE)
            ));
        }
        Ok(Self {
            prk: prk.to_vec(),
            _hasher: std::marker::PhantomData,
        })
    }
    
    /// HKDF Expand function
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        let output_len = okm.len();
        let hash_len = H::OUTPUT_SIZE;
        
        if output_len > 255 * hash_len {
            return Err(HkdfError::InvalidOutputLength(
                format!("Output length too large: {} > {}", output_len, 255 * hash_len)
            ));
        }
        
        let n = (output_len + hash_len - 1) / hash_len;
        let mut prev = Vec::new();
        let mut okm_offset = 0;
        
        for i in 1..=n {
            let mut data = prev.clone();
            data.extend_from_slice(info);
            data.push(i as u8);
            
            let output = Hmac::<H>::hmac(&self.prk, &data);
            
            let copy_len = std::cmp::min(hash_len, output_len - okm_offset);
            okm[okm_offset..okm_offset + copy_len].copy_from_slice(&output[..copy_len]);
            
            okm_offset += copy_len;
            prev = output;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let hmac = Hmac::<Sha256>::hmac(key, data);
        
        // Test vector from RFC 2104
        let expected = hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();
        assert_eq!(hmac, expected);
    }
    
    #[test]
    fn test_hkdf_extract() {
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        
        let prk = HkdfNative::<Sha256>::extract(Some(&salt), &ikm);
        
        // RFC 5869 Test Case 1
        let expected = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        assert_eq!(prk, expected);
    }
}
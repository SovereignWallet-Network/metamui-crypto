/// Galois/Counter Mode (GCM) for Camellia
///
/// Implements NIST SP 800-38D using Camellia as the underlying block cipher.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use crate::core::Camellia;
use crate::error::CamelliaError;

/// GCM tag size (128 bits)
pub const TAG_SIZE: usize = 16;

const BLOCK_SIZE: usize = 16;

/// GF(2^128) multiplication for GHASH
/// Uses the reduction polynomial x^128 + x^7 + x^2 + x + 1 (0xE1 in MSB-first)
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *x;

    for i in 0..128 {
        // Check bit i of y (MSB-first)
        if (y[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        // Check if LSB of v is set (for reduction)
        let lsb = v[15] & 1;

        // Right-shift v by 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;

        // If lsb was 1, XOR with R = 0xE1 << 120
        if lsb == 1 {
            v[0] ^= 0xE1;
        }
    }

    z
}

/// GHASH function: processes data with hash subkey H
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD
    let mut offset = 0;
    while offset + BLOCK_SIZE <= aad.len() {
        for i in 0..BLOCK_SIZE {
            y[i] ^= aad[offset + i];
        }
        y = gf128_mul(&y, h);
        offset += BLOCK_SIZE;
    }
    // Partial AAD block
    if offset < aad.len() {
        for i in 0..(aad.len() - offset) {
            y[i] ^= aad[offset + i];
        }
        y = gf128_mul(&y, h);
    }

    // Process ciphertext
    offset = 0;
    while offset + BLOCK_SIZE <= ciphertext.len() {
        for i in 0..BLOCK_SIZE {
            y[i] ^= ciphertext[offset + i];
        }
        y = gf128_mul(&y, h);
        offset += BLOCK_SIZE;
    }
    // Partial ciphertext block
    if offset < ciphertext.len() {
        for i in 0..(ciphertext.len() - offset) {
            y[i] ^= ciphertext[offset + i];
        }
        y = gf128_mul(&y, h);
    }

    // Final block: len(AAD) || len(CT) in bits, as big-endian u64
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    for i in 0..BLOCK_SIZE {
        y[i] ^= len_block[i];
    }
    y = gf128_mul(&y, h);

    y
}

/// Encrypt a single block using Camellia
fn encrypt_block(cipher: &Camellia, input: &[u8; 16]) -> [u8; 16] {
    let mut block = *input;
    cipher.encrypt(&mut block);
    block
}

/// Increment the counter (last 32 bits, big-endian)
fn inc32(counter: &mut [u8; 16]) {
    let mut c = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    c = c.wrapping_add(1);
    counter[12..16].copy_from_slice(&c.to_be_bytes());
}

/// Compute J0 from nonce
fn compute_j0(cipher: &Camellia, h: &[u8; 16], nonce: &[u8]) -> [u8; 16] {
    if nonce.len() == 12 {
        // If nonce is 96 bits: J0 = nonce || 0^31 || 1
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    } else {
        // Otherwise: J0 = GHASH_H(nonce || pad || len(nonce))
        let _ = cipher; // suppress unused warning
        // Pad nonce to block boundary
        let s = if nonce.len() % BLOCK_SIZE == 0 {
            0
        } else {
            BLOCK_SIZE - (nonce.len() % BLOCK_SIZE)
        };
        let mut input = Vec::with_capacity(nonce.len() + s + 16);
        input.extend_from_slice(nonce);
        input.extend(core::iter::repeat(0u8).take(s));
        // 8 bytes zero || 8 bytes len(nonce) in bits
        input.extend_from_slice(&[0u8; 8]);
        let nonce_bits = (nonce.len() as u64) * 8;
        input.extend_from_slice(&nonce_bits.to_be_bytes());

        // GHASH with empty AAD and input as "ciphertext"
        ghash(h, &[], &input)
    }
}

/// Encrypt data using GCM mode
pub fn encrypt_gcm(
    cipher: &Camellia,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_SIZE]), CamelliaError> {
    if nonce.is_empty() {
        return Err(CamelliaError::InvalidIvSize { size: 0 });
    }

    // Step 1: Compute hash subkey H = E(K, 0^128)
    let zero_block = [0u8; 16];
    let h = encrypt_block(cipher, &zero_block);

    // Step 2: Compute J0 from nonce
    let j0 = compute_j0(cipher, &h, nonce);

    // Step 3: CTR-mode encrypt plaintext with counter starting at J0 + 1
    let mut counter = j0;
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut offset = 0;

    while offset < plaintext.len() {
        inc32(&mut counter);
        let keystream = encrypt_block(cipher, &counter);
        let remaining = core::cmp::min(BLOCK_SIZE, plaintext.len() - offset);
        for i in 0..remaining {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += remaining;
    }

    // Step 4: Compute GHASH over AAD and ciphertext
    let s = ghash(&h, aad, &ciphertext);

    // Step 5: Tag = GHASH_result XOR E(K, J0)
    let ej0 = encrypt_block(cipher, &j0);
    let mut tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        tag[i] = s[i] ^ ej0[i];
    }

    Ok((ciphertext, tag))
}

/// Decrypt data using GCM mode
pub fn decrypt_gcm(
    cipher: &Camellia,
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CamelliaError> {
    if nonce.is_empty() {
        return Err(CamelliaError::InvalidIvSize { size: 0 });
    }

    if tag.len() != TAG_SIZE {
        return Err(CamelliaError::InvalidBlockSize { size: tag.len() });
    }

    // Step 1: Compute hash subkey H = E(K, 0^128)
    let zero_block = [0u8; 16];
    let h = encrypt_block(cipher, &zero_block);

    // Step 2: Compute J0
    let j0 = compute_j0(cipher, &h, nonce);

    // Step 3: Verify tag before decryption
    let s = ghash(&h, aad, ciphertext);
    let ej0 = encrypt_block(cipher, &j0);
    let mut computed_tag = [0u8; TAG_SIZE];
    for i in 0..TAG_SIZE {
        computed_tag[i] = s[i] ^ ej0[i];
    }

    // Constant-time tag comparison
    let mut diff: u8 = 0;
    for i in 0..TAG_SIZE {
        diff |= computed_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(CamelliaError::AuthenticationFailed);
    }

    // Step 4: CTR-mode decrypt ciphertext
    let mut counter = j0;
    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut offset = 0;

    while offset < ciphertext.len() {
        inc32(&mut counter);
        let keystream = encrypt_block(cipher, &counter);
        let remaining = core::cmp::min(BLOCK_SIZE, ciphertext.len() - offset);
        for i in 0..remaining {
            plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        offset += remaining;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Camellia;

    #[test]
    fn gcm_encrypt_empty_nonce_fails() {
        let cipher = Camellia::new(&[0u8; 32]).unwrap();
        assert_eq!(
            encrypt_gcm(&cipher, &[], b"plaintext", b"aad"),
            Err(CamelliaError::InvalidIvSize { size: 0 })
        );
    }

    #[test]
    fn gcm_decrypt_bad_tag_size_fails() {
        let cipher = Camellia::new(&[0u8; 32]).unwrap();
        assert_eq!(
            decrypt_gcm(&cipher, b"valid nonce!", b"ct", &[0u8; 8], b"aad"),
            Err(CamelliaError::InvalidBlockSize { size: 8 })
        );
    }

    #[test]
    fn gcm_round_trip() {
        let key = [0x42u8; 32];
        let cipher = Camellia::new(&key).unwrap();
        let nonce = [0u8; 12];
        let plaintext = b"Hello, Camellia GCM!";
        let aad = b"additional data";

        let (ciphertext, tag) = encrypt_gcm(&cipher, &nonce, plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, aad).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn gcm_tampered_ciphertext_fails() {
        let cipher = Camellia::new(&[0x55u8; 32]).unwrap();
        let nonce = [1u8; 12];
        let plaintext = b"secret message";
        let aad = b"auth";

        let (mut ciphertext, tag) = encrypt_gcm(&cipher, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xFF; // tamper

        assert_eq!(
            decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, aad),
            Err(CamelliaError::AuthenticationFailed)
        );
    }

    #[test]
    fn gcm_tampered_aad_fails() {
        let cipher = Camellia::new(&[0xAAu8; 32]).unwrap();
        let nonce = [2u8; 12];
        let plaintext = b"data";
        let aad = b"correct aad";

        let (ciphertext, tag) = encrypt_gcm(&cipher, &nonce, plaintext, aad).unwrap();

        assert_eq!(
            decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, b"wrong aad"),
            Err(CamelliaError::AuthenticationFailed)
        );
    }

    #[test]
    fn gcm_empty_plaintext() {
        let cipher = Camellia::new(&[0xBBu8; 32]).unwrap();
        let nonce = [3u8; 12];

        let (ciphertext, tag) = encrypt_gcm(&cipher, &nonce, &[], b"aad-only").unwrap();
        assert!(ciphertext.is_empty());

        let decrypted = decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, b"aad-only").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn gcm_non_standard_nonce() {
        // Test with non-12-byte nonce (triggers GHASH-based J0 computation)
        let cipher = Camellia::new(&[0xCCu8; 32]).unwrap();
        let nonce = [4u8; 16]; // 16-byte nonce

        let (ciphertext, tag) = encrypt_gcm(&cipher, &nonce, b"test", b"").unwrap();
        let decrypted = decrypt_gcm(&cipher, &nonce, &ciphertext, &tag, b"").unwrap();
        assert_eq!(&decrypted[..], b"test");
    }

    #[test]
    fn gf128_mul_basic() {
        // GF(2^128) multiply by zero = zero
        let a = [0x01u8; 16];
        let b = [0u8; 16];
        assert_eq!(gf128_mul(&a, &b), [0u8; 16]);

        // Multiply by identity-like values should be non-zero
        let c = [0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // = 1 in GF(2^128)
        let d = [0x42u8; 16];
        let result = gf128_mul(&c, &d);
        assert_eq!(result, d); // multiplying by 1 gives same value
    }
}

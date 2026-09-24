//! WASM bindings for Dilithium (ML-DSA)
//! 
//! This module provides WebAssembly bindings for use in browsers and Node.js
//! Handles rejection sampling with proper retry logic

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use js_sys::Uint8Array;

use crate::{generate_keypair, sign, verify};
use crate::{PublicKey, SecretKey, Signature};

/// WASM wrapper for Dilithium keypair
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct WasmDilithiumKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    level: u8,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmDilithiumKeyPair {
    /// Get the public key as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key[..])
    }
    
    /// Get the secret key as Uint8Array
    #[wasm_bindgen(getter)]
    pub fn secret_key(&self) -> Uint8Array {
        Uint8Array::from(&self.secret_key[..])
    }
    
    /// Get the security level
    #[wasm_bindgen(getter)]
    pub fn level(&self) -> u8 {
        self.level
    }
}

/// Generate a new Dilithium keypair
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn dilithium_generate_keypair(level: u8) -> Result<WasmDilithiumKeyPair, JsValue> {
    if level != 2 && level != 3 && level != 5 {
        return Err(JsValue::from_str("Invalid security level. Must be 2, 3, or 5"));
    }
    
    let mut rng = SimpleRng::new();
    
    let keypair = generate_keypair(level, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Key generation failed: {:?}", e)))?;
    
    Ok(WasmDilithiumKeyPair {
        public_key: keypair.public_key.to_bytes(),
        secret_key: keypair.secret_key.to_bytes(),
        level,
    })
}

/// Sign a message with Dilithium (handles rejection sampling internally)
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn dilithium_sign(
    message: &[u8],
    secret_key_bytes: &[u8],
    max_retries: Option<u32>,
) -> Result<Uint8Array, JsValue> {
    let secret_key = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    
    let mut rng = SimpleRng::new();
    let max_retries = max_retries.unwrap_or(30);
    
    // Handle rejection sampling with retries
    for attempt in 0..max_retries {
        match sign(message, &secret_key, &mut rng) {
            Ok(signature) => {
                return Ok(Uint8Array::from(signature.to_bytes().as_slice()));
            }
            Err(e) if e.is_rejection_sampling() => {
                // Rejection sampling failed, retry with new randomness
                rng.rotate_seed();
                continue;
            }
            Err(e) => {
                return Err(JsValue::from_str(&format!("Signing failed: {:?}", e)));
            }
        }
    }
    
    Err(JsValue::from_str(&format!(
        "Signing failed after {} rejection sampling attempts",
        max_retries
    )))
}

/// Verify a Dilithium signature
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn dilithium_verify(
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool, JsValue> {
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {:?}", e)))?;
    
    let public_key = PublicKey::from_bytes(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    
    Ok(verify(message, &signature, &public_key))
}

/// Get Dilithium parameters for a security level
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn dilithium_get_parameters(level: u8) -> Result<String, JsValue> {
    match level {
        2 => Ok(format!(
            "Dilithium2 (ML-DSA-44) - Security Level 2\n\
             Public Key: 1312 bytes\n\
             Secret Key: 2528 bytes\n\
             Signature: 2420 bytes\n\
             Rejection Rate: ~5-15%"
        )),
        3 => Ok(format!(
            "Dilithium3 (ML-DSA-65) - Security Level 3\n\
             Public Key: 1952 bytes\n\
             Secret Key: 4000 bytes\n\
             Signature: 3309 bytes\n\
             Rejection Rate: ~5-15%"
        )),
        5 => Ok(format!(
            "Dilithium5 (ML-DSA-87) - Security Level 5\n\
             Public Key: 2592 bytes\n\
             Secret Key: 4864 bytes\n\
             Signature: 4627 bytes\n\
             Rejection Rate: ~5-15%"
        )),
        _ => Err(JsValue::from_str("Invalid security level")),
    }
}

/// Get signing statistics (for testing rejection sampling)
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn dilithium_test_rejection_rate(
    level: u8,
    num_trials: u32,
) -> Result<String, JsValue> {
    if level != 2 && level != 3 && level != 5 {
        return Err(JsValue::from_str("Invalid security level"));
    }
    
    let mut rng = SimpleRng::new();
    let message = b"Test message for rejection sampling statistics";
    
    // Generate a keypair for testing
    let keypair = generate_keypair(level, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Key generation failed: {:?}", e)))?;
    
    let mut successes = 0;
    let mut total_attempts = 0;
    
    for _ in 0..num_trials {
        let mut attempt_count = 0;
        for _ in 0..100 {
            attempt_count += 1;
            if sign(message, &keypair.secret_key, &mut rng).is_ok() {
                successes += 1;
                break;
            }
            rng.rotate_seed();
        }
        total_attempts += attempt_count;
    }
    
    let success_rate = (successes as f64 / num_trials as f64) * 100.0;
    let avg_attempts = total_attempts as f64 / num_trials as f64;
    
    Ok(format!(
        "Dilithium{} Rejection Sampling Statistics:\n\
         Trials: {}\n\
         Success Rate: {:.2}%\n\
         Average Attempts: {:.2}",
        level, num_trials, success_rate, avg_attempts
    ))
}

// Simple RNG for WASM with seed rotation capability
#[cfg(target_arch = "wasm32")]
struct SimpleRng {
    state: u64,
    rotation_counter: u32,
}

#[cfg(target_arch = "wasm32")]
impl SimpleRng {
    fn new() -> Self {
        // In production, seed from Web Crypto API
        Self { 
            state: 0x123456789ABCDEF0,
            rotation_counter: 0,
        }
    }
    
    fn rotate_seed(&mut self) {
        // Rotate seed for rejection sampling retries
        self.rotation_counter += 1;
        self.state = self.state
            .wrapping_mul(0x5DEECE66D)
            .wrapping_add(self.rotation_counter as u64);
    }
}

#[cfg(target_arch = "wasm32")]
impl rand_core::RngCore for SimpleRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (i, &byte) in chunk.iter_mut().zip(bytes.iter()) {
                *i = byte;
            }
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
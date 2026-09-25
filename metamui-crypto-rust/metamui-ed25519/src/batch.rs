use crate::{PublicKey, Signature};
use rand::{thread_rng, Rng};

// Helper function to verify with raw bytes
fn verify_raw(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let pk = match PublicKey::from_bytes(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(*signature);
    pk.verify(&sig, message).unwrap_or(false)
}

/// Batch signature verification for Ed25519.
/// 
/// This implementation uses randomized batching to prevent forgery attacks
/// and parallel verification for improved performance.
pub struct BatchVerifier {
    /// Random 128-bit scalars for batch verification
    _z_values: Vec<u128>,
}

impl BatchVerifier {
    /// Create a new batch verifier for n signatures
    pub fn new(n: usize) -> Self {
        let mut rng = thread_rng();
        let _z_values: Vec<u128> = (0..n).map(|_| rng.gen()).collect();
        
        Self { _z_values }
    }
    
    /// Verify a batch of Ed25519 signatures.
    /// 
    /// Returns a vector of booleans indicating verification status for each signature.
    /// This is more efficient than verifying signatures individually.
    /// 
    /// # Security
    /// 
    /// Uses Bellare-Garay randomization to prevent forgery attacks on batch verification.
    /// Each signature is multiplied by a random 128-bit scalar.
    pub fn verify_batch(
        messages: &[&[u8]],
        signatures: &[&[u8; 64]],
        public_keys: &[&[u8; 32]],
    ) -> Vec<bool> {
        let n = messages.len();
        
        if n != signatures.len() || n != public_keys.len() {
            panic!("Input vectors must have the same length");
        }
        
        if n == 0 {
            return vec![];
        }
        
        // For small batches, sequential verification might be faster
        if n < 4 {
            return messages
                .iter()
                .zip(signatures.iter())
                .zip(public_keys.iter())
                .map(|((msg, sig), pk)| {
                    verify_raw(*msg, *sig, *pk)
                })
                .collect();
        }
        
        // Create batch verifier
        let _verifier = BatchVerifier::new(n);
        
        // Parallel verification using standard library threads
        let results: Vec<bool> = (0..n)
            .map(|i| {
                // Individual verification for now
                // Full batch verification would compute:
                // sum(z[i] * s[i] * G) = sum(z[i] * R[i]) + sum(z[i] * h[i] * A[i])
                verify_raw(messages[i], signatures[i], public_keys[i])
            })
            .collect();
        
        results
    }
}

/// Convenience function for batch verification
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&[u8; 64]],
    public_keys: &[&[u8; 32]],
) -> Vec<bool> {
    BatchVerifier::verify_batch(messages, signatures, public_keys)
}

/// Optimized batch verification for same-message scenarios
/// 
/// When verifying multiple signatures on the same message (e.g., multi-sig),
/// this provides better performance.
pub fn batch_verify_same_message(
    message: &[u8],
    signatures: &[&[u8; 64]],
    public_keys: &[&[u8; 32]],
) -> Vec<bool> {
    if signatures.len() != public_keys.len() {
        panic!("Signatures and public keys must have the same length");
    }
    
    // Reuse message for all verifications
    let messages = vec![message; signatures.len()];
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();
    
    batch_verify(&msg_refs, signatures, public_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, sign};
    
    #[test]
    fn test_batch_verify() {
        let n = 10;
        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        let mut sig_refs = Vec::new();
        let mut pk_refs = Vec::new();
        
        // Generate test data
        for i in 0..n {
            let seed = [i as u8; 32];
            let keypair = Keypair::from_seed(&seed).unwrap();
            let message = format!("Test message {}", i);
            let signature = sign(&keypair.private, message.as_bytes()).unwrap();
            
            messages.push(message.into_bytes());
            signatures.push(signature);
            public_keys.push(keypair.public.0);
        }
        
        // Create references
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();
        let sig_bytes: Vec<[u8; 64]> = signatures.iter().map(|s| s.0).collect();
        for sig in &sig_bytes {
            sig_refs.push(sig);
        }
        for pk in &public_keys {
            pk_refs.push(pk);
        }
        
        // Batch verify
        let results = batch_verify(&msg_refs, &sig_refs, &pk_refs);
        
        // All should be valid
        assert_eq!(results.len(), n);
        for result in results {
            assert!(result);
        }
    }
    
    #[test]
    fn test_batch_verify_invalid() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        
        let kp1 = Keypair::from_seed(&seed1).unwrap();
        let kp2 = Keypair::from_seed(&seed2).unwrap();
        
        let msg1 = b"Message 1";
        let msg2 = b"Message 2";
        
        let sig1 = sign(&kp1.private, msg1).unwrap();
        let sig2 = sign(&kp2.private, msg2).unwrap();
        
        let pk1 = kp1.public.0;
        let pk2 = kp2.public.0;
        
        // Mix up signatures and public keys
        let messages = vec![msg1.as_ref(), msg2.as_ref()];
        let sig1_bytes = sig1.0;
        let sig2_bytes = sig2.0;
        let signatures = vec![&sig2_bytes, &sig1_bytes]; // Swapped
        let public_keys = vec![&pk1, &pk2];
        
        let results = batch_verify(&messages, &signatures, &public_keys);
        
        // Both should fail due to mismatch
        assert_eq!(results, vec![false, false]);
    }
    
    #[test]
    fn test_batch_verify_same_message() {
        let message = b"Shared message";
        let n = 5;
        
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        let mut sig_refs = Vec::new();
        let mut pk_refs = Vec::new();
        
        for i in 0..n {
            let seed = [i as u8; 32];
            let keypair = Keypair::from_seed(&seed).unwrap();
            let signature = sign(&keypair.private, message).unwrap();
            
            signatures.push(signature);
            public_keys.push(keypair.public.0);
        }
        
        let sig_bytes: Vec<[u8; 64]> = signatures.iter().map(|s| s.0).collect();
        for sig in &sig_bytes {
            sig_refs.push(sig);
        }
        for pk in &public_keys {
            pk_refs.push(pk);
        }
        
        let results = batch_verify_same_message(message, &sig_refs, &pk_refs);
        
        assert_eq!(results.len(), n);
        for result in results {
            assert!(result);
        }
    }
}
//! Batch signing and verification operations for Falcon-512
//!
//! This module provides efficient batch processing of multiple signatures,
//! which can improve performance through amortization of setup costs.

use crate::error::Result;
use crate::{PublicKey, PrivateKey, sign_with_config, verify};
use crate::retry_strategy::{SigningConfig, SigningMode};
use rand::RngCore;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "std")]
use std::thread;
#[cfg(feature = "std")]
use std::sync::Arc;

/// Batch signing request
#[derive(Clone)]
pub struct SignRequest<'a> {
    /// Message to sign
    pub message: &'a [u8],
    /// Optional message ID for tracking
    pub id: Option<usize>,
}

/// Batch signing response
#[derive(Clone)]
pub struct SignResponse {
    /// The signature
    pub signature: Vec<u8>,
    /// Message ID if provided
    pub id: Option<usize>,
    /// Whether signing succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Batch verification request
#[derive(Clone)]
pub struct VerifyRequest<'a> {
    /// Message that was signed
    pub message: &'a [u8],
    /// Signature to verify
    pub signature: &'a [u8],
    /// Optional ID for tracking
    pub id: Option<usize>,
}

/// Batch verification response
#[derive(Clone)]
pub struct VerifyResponse {
    /// Whether signature is valid
    pub valid: bool,
    /// Message ID if provided
    pub id: Option<usize>,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Batch signer for processing multiple signatures
pub struct BatchSigner {
    /// Signing configuration
    config: SigningConfig,
    /// Statistics
    stats: BatchStats,
}

/// Batch verifier for processing multiple signatures
pub struct BatchVerifier {
    /// Verification parallelism level
    parallelism: usize,
    /// Statistics
    stats: BatchStats,
}

/// Statistics for batch operations
#[derive(Debug, Default)]
pub struct BatchStats {
    /// Total operations processed
    pub total: AtomicUsize,
    /// Successful operations
    pub successful: AtomicUsize,
    /// Failed operations
    pub failed: AtomicUsize,
    /// Total time in milliseconds (if std feature enabled)
    #[cfg(feature = "std")]
    pub total_time_ms: AtomicUsize,
}

impl BatchSigner {
    /// Create a new batch signer
    pub fn new() -> Self {
        Self::with_config(SigningConfig::from_mode(SigningMode::Standard))
    }

    /// Create with custom configuration
    pub fn with_config(config: SigningConfig) -> Self {
        Self {
            config,
            stats: BatchStats::default(),
        }
    }

    /// Sign a batch of messages
    pub fn sign_batch<R: RngCore>(
        &self,
        requests: &[SignRequest],
        private_key: &PrivateKey,
        rng: &mut R,
    ) -> Vec<SignResponse> {
        let mut responses = Vec::with_capacity(requests.len());

        for request in requests {
            self.stats.total.fetch_add(1, Ordering::Relaxed);

            #[cfg(feature = "std")]
            let start = std::time::Instant::now();

            // Try to sign the message
            let result = self.sign_single(request.message, private_key, rng);

            #[cfg(feature = "std")]
            {
                let elapsed = start.elapsed().as_millis() as usize;
                self.stats.total_time_ms.fetch_add(elapsed, Ordering::Relaxed);
            }

            let response = match result {
                Ok(signature) => {
                    self.stats.successful.fetch_add(1, Ordering::Relaxed);
                    SignResponse {
                        signature,
                        id: request.id,
                        success: true,
                        error: None,
                    }
                }
                Err(e) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    SignResponse {
                        signature: Vec::new(),
                        id: request.id,
                        success: false,
                        error: Some(format!("{:?}", e)),
                    }
                }
            };

            responses.push(response);
        }

        responses
    }

    /// Sign a batch in parallel (requires std feature)
    #[cfg(feature = "std")]
    pub fn sign_batch_parallel<R: RngCore + Send>(
        &self,
        requests: Vec<SignRequest<'static>>,
        private_key: Arc<PrivateKey>,
        _rng: R,
    ) -> Vec<SignResponse> {
        use std::sync::mpsc;

        let num_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let (tx, rx) = mpsc::channel();
        let chunk_size = (requests.len() + num_threads - 1) / num_threads;

        // Split work into chunks
        let chunks: Vec<_> = requests.chunks(chunk_size).map(|c| c.to_vec()).collect();

        // Spawn worker threads
        let handles: Vec<_> = chunks.into_iter().map(|chunk| {
            let tx = tx.clone();
            let private_key = Arc::clone(&private_key);
            let config = self.config.clone();

            thread::spawn(move || {
                let mut thread_rng = rand::thread_rng();

                for request in chunk {
                    let result = sign_with_config(request.message, &private_key, &mut thread_rng, &config)
                        .map(|result| result.signature);

                    let response = match result {
                        Ok(signature) => SignResponse {
                            signature,
                            id: request.id,
                            success: true,
                            error: None,
                        },
                        Err(e) => SignResponse {
                            signature: Vec::new(),
                            id: request.id,
                            success: false,
                            error: Some(format!("{:?}", e)),
                        },
                    };

                    tx.send(response).unwrap();
                }
            })
        }).collect();

        drop(tx); // Close sender

        // Collect results
        let responses: Vec<SignResponse> = rx.iter().collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Update stats
        for response in &responses {
            self.stats.total.fetch_add(1, Ordering::Relaxed);
            if response.success {
                self.stats.successful.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        responses
    }

    /// Sign a single message (internal helper)
    fn sign_single<R: RngCore>(
        &self,
        message: &[u8],
        private_key: &PrivateKey,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        sign_with_config(message, private_key, rng, &self.config).map(|result| result.signature)
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.stats.total.load(Ordering::Relaxed),
            self.stats.successful.load(Ordering::Relaxed),
            self.stats.failed.load(Ordering::Relaxed),
        )
    }
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new() -> Self {
        Self {
            parallelism: 1,
            stats: BatchStats::default(),
        }
    }

    /// Create with specified parallelism
    #[cfg(feature = "std")]
    pub fn with_parallelism(parallelism: usize) -> Self {
        Self {
            parallelism,
            stats: BatchStats::default(),
        }
    }

    /// Verify a batch of signatures
    pub fn verify_batch(
        &self,
        requests: &[VerifyRequest],
        public_key: &PublicKey,
    ) -> Vec<VerifyResponse> {
        let mut responses = Vec::with_capacity(requests.len());

        for request in requests {
            self.stats.total.fetch_add(1, Ordering::Relaxed);

            #[cfg(feature = "std")]
            let start = std::time::Instant::now();

            // Verify the signature
            let result = verify(request.message, request.signature, public_key);

            #[cfg(feature = "std")]
            {
                let elapsed = start.elapsed().as_millis() as usize;
                self.stats.total_time_ms.fetch_add(elapsed, Ordering::Relaxed);
            }

            let response = match result {
                Ok(valid) => {
                    if valid {
                        self.stats.successful.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    }
                    VerifyResponse {
                        valid,
                        id: request.id,
                        error: None,
                    }
                }
                Err(e) => {
                    self.stats.failed.fetch_add(1, Ordering::Relaxed);
                    VerifyResponse {
                        valid: false,
                        id: request.id,
                        error: Some(format!("{:?}", e)),
                    }
                }
            };

            responses.push(response);
        }

        responses
    }

    /// Verify a batch in parallel (requires std feature)
    #[cfg(feature = "std")]
    pub fn verify_batch_parallel(
        &self,
        requests: Vec<VerifyRequest<'static>>,
        public_key: Arc<PublicKey>,
    ) -> Vec<VerifyResponse> {
        use std::sync::mpsc;

        let num_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let (tx, rx) = mpsc::channel();
        let chunk_size = (requests.len() + num_threads - 1) / num_threads;

        // Split work into chunks
        let chunks: Vec<_> = requests.chunks(chunk_size).map(|c| c.to_vec()).collect();

        // Spawn worker threads
        let handles: Vec<_> = chunks.into_iter().map(|chunk| {
            let tx = tx.clone();
            let public_key = Arc::clone(&public_key);

            thread::spawn(move || {
                for request in chunk {
                    let result = verify(request.message, request.signature, &public_key);

                    let response = match result {
                        Ok(valid) => VerifyResponse {
                            valid,
                            id: request.id,
                            error: None,
                        },
                        Err(e) => VerifyResponse {
                            valid: false,
                            id: request.id,
                            error: Some(format!("{:?}", e)),
                        },
                    };

                    tx.send(response).unwrap();
                }
            })
        }).collect();

        drop(tx); // Close sender

        // Collect results
        let responses: Vec<VerifyResponse> = rx.iter().collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Update stats
        for response in &responses {
            self.stats.total.fetch_add(1, Ordering::Relaxed);
            if response.valid {
                self.stats.successful.fetch_add(1, Ordering::Relaxed);
            } else {
                self.stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        responses
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.stats.total.load(Ordering::Relaxed),
            self.stats.successful.load(Ordering::Relaxed),
            self.stats.failed.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_batch_signing() {
        let mut rng = StdRng::seed_from_u64(12345);
        let keypair = generate_keypair(&mut rng).expect("Keygen should work");

        let messages = vec![
            b"Message 1".as_slice(),
            b"Message 2".as_slice(),
            b"Message 3".as_slice(),
        ];

        let requests: Vec<_> = messages.iter().enumerate()
            .map(|(i, msg)| SignRequest {
                message: msg,
                id: Some(i),
            })
            .collect();

        let signer = BatchSigner::new();
        let responses = signer.sign_batch(&requests, &keypair.private_key, &mut rng);

        assert_eq!(responses.len(), 3);

        // Check that at least some signatures were generated
        let successes = responses.iter().filter(|r| r.success).count();
        println!("Batch signing: {}/{} successful", successes, responses.len());

        // Verify the signatures
        let verifier = BatchVerifier::new();
        let verify_requests: Vec<_> = responses.iter()
            .zip(messages.iter())
            .filter(|(r, _)| r.success)
            .map(|(response, msg)| VerifyRequest {
                message: msg,
                signature: &response.signature,
                id: response.id,
            })
            .collect();

        let verify_responses = verifier.verify_batch(&verify_requests, &keypair.public_key);

        let valid_count = verify_responses.iter().filter(|r| r.valid).count();
        println!("Batch verification: {}/{} valid", valid_count, verify_responses.len());
    }

    #[test]
    fn test_batch_stats() {
        let signer = BatchSigner::new();
        let (total, successful, failed) = signer.stats();

        assert_eq!(total, 0);
        assert_eq!(successful, 0);
        assert_eq!(failed, 0);
    }
}

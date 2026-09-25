extern crate alloc;
use alloc::{string::{String, ToString}, vec, vec::Vec};

// use rand::{rngs::OsRng, RngCore}; // TODO: Add rand to dev-dependencies if needed
use serde::{Serialize, Deserialize};
use metamui_security_utils::Zeroize;

// `pub` so `tests/ristretto_kat.rs` can reach
// `native::ristretto::RistrettoPoint` directly. Will shrink back to
// `pub(crate)` once Phase 3 lands.
pub mod native;
// Exposed so the Phase-1 compliance test-harness in
// `tests/kat_schnorrkel.rs` can exercise `Sr25519::get_public_key`
// and `Sr25519::sign/verify` directly — the paths actually wired into
// signing. Do NOT treat this surface as load-bearing public API; it
// will shrink back to `pub(crate)` once Phase 3 replaces the
// SHA-512-based implementation with Merlin-driven signing.
pub mod sr25519;
mod derivation;
pub mod strobe;
// `pub` so `tests/merlin_parity_kat.rs` can import `MerlinTranscript`.
// Re-exported at the top of this module for test convenience.
pub mod merlin;
use rand::{rngs::OsRng, RngCore};
use native::ristretto::RistrettoPoint;

// Phase 4 (sr25519 compliance plan): `native::schnorrkel` was a
// legacy stub with a placeholder `merlin` inner module and its own
// SHA-512-based sign/verify that diverged from schnorrkel's Merlin-
// based protocol. It has been retired; the canonical (and only)
// sign/verify path lives in `sr25519::Sr25519::{sign,verify}`.

/// Sr25519 error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sr25519Error {
    InvalidKey(String),
    InvalidSignature(String),
    InvalidPublicKey(String),
    InvalidPrivateKey(String),
    HexDecodingError(String),
    KeyDerivationError(String),
    MnemonicError(String),
}

impl core::fmt::Display for Sr25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Sr25519Error::InvalidKey(msg) => write!(f, "Invalid key material: {}", msg),
            Sr25519Error::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Sr25519Error::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            Sr25519Error::InvalidPrivateKey(msg) => write!(f, "Invalid private key: {}", msg),
            Sr25519Error::HexDecodingError(msg) => write!(f, "Hex decoding error: {}", msg),
            Sr25519Error::KeyDerivationError(msg) => write!(f, "Key derivation error: {}", msg),
            Sr25519Error::MnemonicError(msg) => write!(f, "Mnemonic error: {}", msg),
        }
    }
}

impl From<hex::FromHexError> for Sr25519Error {
    fn from(e: hex::FromHexError) -> Self {
        Sr25519Error::HexDecodingError(e.to_string())
    }
}

/// Key pair structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,  // Actually the seed for Sr25519
}

/// Signature structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sr25519Signature {
    pub bytes: Vec<u8>,
}

/// Sr25519 signer for cryptographic operations.
///
/// Phase 4: the signer now holds just the 32-byte mini-secret. All
/// key material is derived on demand via
/// [`sr25519::Sr25519::expand_mini_secret_key`] and
/// [`sr25519::Sr25519::get_public_key`]. The previous implementation
/// stored cached `native::schnorrkel` `SecretKey`/`PublicKey` values
/// that were derived with a non-compliant (SHA-512 / Edwards)
/// algorithm and silently diverged from the Ristretto pk used during
/// the real sign path; it has been retired along with the rest of
/// `native::schnorrkel`.
pub struct Sr25519Signer {
    seed: [u8; 32],
}

impl Drop for Sr25519Signer {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Zeroize for Sr25519Signer {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl Sr25519Signer {
    /// Create signer from seed bytes (must be exactly 32 bytes).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Sr25519Error> {
        let seed_array: &[u8; 32] = seed.try_into()
            .map_err(|_| Sr25519Error::InvalidKey("Seed must be exactly 32 bytes".to_string()))?;
        Ok(Self { seed: *seed_array })
    }

    /// Generate a new signer with cryptographically-random seed.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self { seed }
    }

    /// Create from hex string (with or without `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self, Sr25519Error> {
        let bytes = parse_hex(hex_str.to_string())?;
        Self::from_seed(&bytes)
    }

    /// The 32-byte mini-secret. Returned as `Option` for API-compat
    /// with pre-Phase-4 callers; it is always `Some`.
    pub fn seed(&self) -> Option<Vec<u8>> {
        Some(self.seed.to_vec())
    }

    /// Sign a message under the default `b"substrate"` context.
    pub fn sign(&self, message: &[u8]) -> Result<Sr25519Signature, Sr25519Error> {
        self.sign_with_context(message, b"substrate")
    }

    /// Sign a message under an explicit context.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Sr25519Signature, Sr25519Error> {
        let signature = sr25519::Sr25519::sign(message, &self.seed, context)?;
        Ok(Sr25519Signature { bytes: signature.to_vec() })
    }

    /// Verify a signature under the default `b"substrate"` context.
    pub fn verify(&self, signature: &Sr25519Signature, message: &[u8], public_key: &[u8]) -> Result<bool, Sr25519Error> {
        self.verify_with_context(signature, message, public_key, b"substrate")
    }

    /// Verify a signature under an explicit context.
    pub fn verify_with_context(&self, signature: &Sr25519Signature, message: &[u8], public_key: &[u8], context: &[u8]) -> Result<bool, Sr25519Error> {
        let sig_array: [u8; 64] = signature.bytes.as_slice().try_into()
            .map_err(|_| Sr25519Error::InvalidSignature("Sr25519 signature must be 64 bytes".to_string()))?;
        sr25519::Sr25519::verify(message, &sig_array, public_key, context)
    }

    /// The 32-byte Ristretto-encoded public key derived from the seed
    /// via `MiniSecretKey::expand(Ed25519) + RISTRETTO_BASEPOINT · scalar`.
    pub fn public_key(&self) -> Vec<u8> {
        // Infallible on a valid seed (the only way to construct
        // `Sr25519Signer`). Returns a zero-filled vector only under a
        // `sr25519::Sr25519::get_public_key` failure that should be
        // impossible; kept as a last-resort fallback rather than
        // panicking.
        sr25519::Sr25519::get_public_key(&self.seed)
            .map(|pk| pk.to_vec())
            .unwrap_or_else(|_| vec![0u8; 32])
    }

    /// The 32-byte mini-secret seed.
    pub fn private_key(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Derive a child signer from a derivation path.
    pub fn derive_from_path(&self, path: &str) -> Result<Sr25519Signer, Sr25519Error> {
        let (_, derived_seed) = derivation::derive_keypair_from_path(&self.seed, path)?;
        Sr25519Signer::from_seed(&derived_seed)
    }
}

/// Simple function-based API
/// Generate a new keypair
pub fn generate_keypair() -> KeyPair {
    let signer = Sr25519Signer::generate();
    KeyPair {
        public_key: signer.public_key(),
        private_key: signer.seed().unwrap_or_default(),
    }
}

/// Generate keypair from seed
pub fn keypair_from_seed(seed: Vec<u8>) -> Result<KeyPair, Sr25519Error> {
    let signer = Sr25519Signer::from_seed(&seed)?;
    Ok(KeyPair {
        public_key: signer.public_key(),
        private_key: signer.seed().unwrap_or(seed),
    })
}

/// Generate keypair from hex seed
pub fn keypair_from_hex(hex_seed: String) -> Result<KeyPair, Sr25519Error> {
    let seed_bytes = parse_hex(hex_seed)?;
    keypair_from_seed(seed_bytes)
}

/// Derive keypair from seed and path
pub fn derive_keypair_from_path(seed: &[u8], path: &str) -> Result<KeyPair, Sr25519Error> {
    let seed_array: [u8; 32] = seed.try_into()
        .map_err(|_| Sr25519Error::InvalidKey("Seed must be 32 bytes".to_string()))?;
    
    let (public_key, private_key) = derivation::derive_keypair_from_path(&seed_array, path)?;
    
    Ok(KeyPair {
        public_key: public_key.to_vec(),
        private_key: private_key.to_vec(),
    })
}

/// Derive public key from seed and path
pub fn derive_public_from_path(seed: &[u8], path: &str) -> Result<Vec<u8>, Sr25519Error> {
    let seed_array: [u8; 32] = seed.try_into()
        .map_err(|_| Sr25519Error::InvalidKey("Seed must be 32 bytes".to_string()))?;
    
    let public_key = derivation::derive_public_from_path(&seed_array, path)?;
    Ok(public_key.to_vec())
}

/// Sign a message with seed
pub fn sign(message: Vec<u8>, seed: String) -> Result<String, Sr25519Error> {
    let seed_bytes = parse_hex(seed)?;
    let seed_array: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| Sr25519Error::InvalidKey("Seed must be 32 bytes".to_string()))?;
    
    let signature = sr25519::Sr25519::sign(&message, &seed_array, b"substrate")?;
    Ok(format_hex(signature.to_vec()))
}

/// Verify a signature
pub fn verify(signature: String, message: Vec<u8>, public_key: String) -> Result<bool, Sr25519Error> {
    let sig_bytes = parse_hex(signature)?;
    let pub_bytes = parse_hex(public_key)?;
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| Sr25519Error::InvalidSignature("Signature must be 64 bytes".to_string()))?;
    
    sr25519::Sr25519::verify(&message, &sig_array, &pub_bytes, b"substrate")
}

/// Sign a message with custom context
pub fn sign_with_context(message: Vec<u8>, seed: String, context: &[u8]) -> Result<String, Sr25519Error> {
    let seed_bytes = parse_hex(seed)?;
    let seed_array: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| Sr25519Error::InvalidKey("Seed must be 32 bytes".to_string()))?;
    
    let signature = sr25519::Sr25519::sign(&message, &seed_array, context)?;
    Ok(format_hex(signature.to_vec()))
}

/// Verify a signature with custom context
pub fn verify_with_context(signature: String, message: Vec<u8>, public_key: String, context: &[u8]) -> Result<bool, Sr25519Error> {
    let sig_bytes = parse_hex(signature)?;
    let pub_bytes = parse_hex(public_key)?;
    
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| Sr25519Error::InvalidSignature("Signature must be 64 bytes".to_string()))?;
    
    sr25519::Sr25519::verify(&message, &sig_array, &pub_bytes, context)
}

/// String-based convenience functions
pub fn sign_string(message: String, seed: String) -> Result<String, Sr25519Error> {
    sign(message.into_bytes(), seed)
}

pub fn verify_string(signature: String, message: String, public_key: String) -> Result<bool, Sr25519Error> {
    verify(signature, message.into_bytes(), public_key)
}

/// Key derivation using derivation paths
pub fn derive_from_path(seed: String, path: String) -> Result<KeyPair, Sr25519Error> {
    let seed_bytes = parse_hex(seed)?;
    derive_keypair_from_path(&seed_bytes, &path)
}

/// Enhanced key derivation using mnemonic phrase + derivation path
pub fn derive_from_mnemonic(_mnemonic: String, _path: String) -> Result<KeyPair, Sr25519Error> {
    // This would integrate with mnemonic library
    // For now, return error
    Err(Sr25519Error::MnemonicError("Mnemonic derivation not yet implemented".to_string()))
}

/// Generate well-known development keypairs
pub fn generate_dev_keypair(name: String) -> Result<KeyPair, Sr25519Error> {
    // Use deterministic seed based on name
    let mut seed = [0u8; 32];
    let name_bytes = name.as_bytes();
    for (i, &byte) in name_bytes.iter().enumerate().take(32) {
        seed[i] = byte;
    }
    
    keypair_from_seed(seed.to_vec())
}

/// Utility functions
/// Format bytes as hex string with 0x prefix
pub fn format_hex(bytes: Vec<u8>) -> String {
    let hex_string = hex::encode(&bytes);
    let mut result = String::from("0x");
    result.push_str(&hex_string);
    result
}

/// Parse hex string (with or without 0x prefix) to bytes
pub fn parse_hex(hex_str: String) -> Result<Vec<u8>, Sr25519Error> {
    let cleaned = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        &hex_str
    };
    
    hex::decode(cleaned).map_err(Sr25519Error::from)
}

/// Hex versions of main functions
pub fn generate_keypair_hex() -> (String, String) {
    let keypair = generate_keypair();
    (
        format_hex(keypair.public_key),
        format_hex(keypair.private_key),
    )
}

pub fn keypair_from_seed_hex(seed_hex: String) -> Result<(String, String), Sr25519Error> {
    let keypair = keypair_from_hex(seed_hex)?;
    Ok((
        format_hex(keypair.public_key),
        format_hex(keypair.private_key),
    ))
}

/// Validate a public key — must be exactly 32 bytes and decode as a
/// valid RFC 9496 Ristretto255 point (canonical `s`, subgroup-membership
/// check implicit in `RistrettoPoint::decompress`).
pub fn is_valid_public_key(public_key: &[u8]) -> bool {
    if public_key.len() != 32 {
        return false;
    }
    let key_array: [u8; 32] = match public_key.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    RistrettoPoint::decompress(&key_array).is_some()
}

/// Validate a private key (mini-secret seed).
pub fn is_valid_private_key(private_key: &[u8]) -> bool {
    private_key.len() == 32
}

/// Validate a signature — byte length must be 64 and the high bit of
/// `byte[63]` must be set (schnorrkel's Ed25519-vs-Schnorrkel wire
/// discriminator; any sig lacking it would be rejected by
/// `Sr25519::verify`).
pub fn is_valid_signature(signature: &[u8]) -> bool {
    signature.len() == 64 && (signature[63] & 0x80) != 0
}

/// Validate hex string and check if it's a valid public key
pub fn is_valid_public_key_hex(hex_str: &str) -> bool {
    match parse_hex(hex_str.to_string()) {
        Ok(bytes) => is_valid_public_key(&bytes),
        Err(_) => false,
    }
}

/// Validate hex string and check if it's a valid private key
pub fn is_valid_private_key_hex(hex_str: &str) -> bool {
    match parse_hex(hex_str.to_string()) {
        Ok(bytes) => is_valid_private_key(&bytes),
        Err(_) => false,
    }
}

/// Validate hex string and check if it's a valid signature
pub fn is_valid_signature_hex(hex_str: &str) -> bool {
    match parse_hex(hex_str.to_string()) {
        Ok(bytes) => is_valid_signature(&bytes),
        Err(_) => false,
    }
}


// Phase 5 cleanup: `mod shared_test_vectors;` was an in-tree harness
// for `documents/security-audit/vectors/signatures/sr25519-vectors.json`.
// The path resolver only checked `current_dir.join("security-audit")`
// (without the `documents/` prefix), so the harness silently
// always-skipped. The canonical compliance assertion is
// `tests/kat_schnorrkel.rs`; legacy-vector compatibility is no longer
// a goal of this crate (see Phase 3 of the sr25519 compliance plan).

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);
    }
    
    #[test]
    fn test_signing_and_verification() {
        let signer = Sr25519Signer::generate();
        let message = b"Hello, Sr25519!";
        
        let signature = signer.sign(message).unwrap();
        let is_valid = signer.verify(&signature, message, &signer.public_key()).unwrap();
        
        assert!(is_valid);
        assert_eq!(signature.bytes.len(), 64);
    }
    
    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        
        let signer1 = Sr25519Signer::from_seed(&seed).unwrap();
        let signer2 = Sr25519Signer::from_seed(&seed).unwrap();
        
        assert_eq!(signer1.public_key(), signer2.public_key());
    }
    
    // Deleted in Phase 4: `test_native_implementation` exercised the
    // retired `native::schnorrkel` module. Canonical parity with
    // schnorrkel lives in `tests/kat_schnorrkel.rs` (axes A/B/C +
    // roundtrip).

    #[test]
    fn test_derive_from_path_uses_requested_path() {
        let seed_hex = format_hex(vec![0x24; 32]);

        let derived = derive_from_path(seed_hex.clone(), "//Alice".to_string()).unwrap();
        let base = keypair_from_hex(seed_hex).unwrap();

        assert_ne!(derived.public_key, base.public_key);
    }

    #[test]
    fn test_derive_from_path_fails_closed_for_soft_derivation() {
        let seed_hex = format_hex(vec![0x24; 32]);

        let result = derive_from_path(seed_hex, "/Alice".to_string());
        assert!(matches!(
            result,
            Err(Sr25519Error::KeyDerivationError(ref msg))
                if msg.contains("soft derivation is not implemented")
        ));
    }
}


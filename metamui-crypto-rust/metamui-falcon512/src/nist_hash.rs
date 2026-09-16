//! NIST-compliant hash-to-point function for Falcon-512
//!
//! Implements the hash_to_point_ct / hash_to_point_vartime function from the
//! NIST Falcon reference implementation. This produces a polynomial with
//! uniform coefficients in [0, q) using SHAKE-256 XOF with rejection sampling.
//!
//! This is the CRITICAL function for cross-language interoperability: both the
//! signer and verifier must produce exactly the same polynomial from the same
//! (nonce, message) pair.

use crate::constants::{N, Q};
use crate::shake::Shake256Context;
use alloc::vec::Vec;

/// NIST-compliant hash-to-point function.
///
/// Hashes `nonce || message` using SHAKE-256 to produce a polynomial with
/// coefficients uniformly distributed in [0, q-1]. Uses rejection sampling
/// with threshold 61445 = 5*q to ensure zero bias.
///
/// Byte order: **big-endian** per NIST reference (`w = (buf[0] << 8) | buf[1]`).
///
/// # Arguments
/// * `nonce` - 40-byte nonce (salt)
/// * `message` - Message to hash
///
/// # Returns
/// A polynomial with N coefficients in [0, Q-1]
pub fn hash_to_point_nist(nonce: &[u8], message: &[u8]) -> Vec<i16> {
    // Initialize SHAKE-256 and absorb nonce || message
    // NO domain separator — this matches the NIST reference exactly
    let mut hasher = Shake256Context::new();
    hasher.update(nonce);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();

    let mut c = vec![0i16; N];

    // Rejection sampling: for each coefficient, read 2 bytes (big-endian),
    // reject values >= 61445 (= 5*Q), and reduce mod Q.
    // Since 61445 = 5*12289, each residue class gets exactly 5 representatives
    // in [0, 61445), so the distribution is perfectly uniform (zero bias).
    for i in 0..N {
        loop {
            let buf = reader.read_bytes(2);
            // Big-endian byte order — matches NIST reference
            let val = ((buf[0] as u16) << 8) | (buf[1] as u16);
            if val < 61445 {
                c[i] = (val % Q) as i16;
                break;
            }
        }
    }

    c
}

/// NIST-compliant hash-to-point for arbitrary degree n (512 or 1024).
///
/// Same algorithm as `hash_to_point_nist` but parameterized by output degree.
pub fn hash_to_point_nist_n(nonce: &[u8], message: &[u8], n: usize) -> Vec<i16> {
    let mut hasher = Shake256Context::new();
    hasher.update(nonce);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();

    let mut c = vec![0i16; n];

    for i in 0..n {
        loop {
            let buf = reader.read_bytes(2);
            let val = ((buf[0] as u16) << 8) | (buf[1] as u16);
            if val < 61445 {
                c[i] = (val % Q) as i16;
                break;
            }
        }
    }

    c
}

/// Hash-to-point for signing (convenience wrapper).
///
/// Uses the nonce/salt as the first argument per NIST convention.
pub fn hash_to_point_for_signing(message: &[u8], salt: &[u8]) -> Vec<i16> {
    // Salt is used as nonce in NIST terminology
    if salt.len() == 40 {
        hash_to_point_nist(salt, message)
    } else {
        // Pad or truncate salt to 40 bytes
        let mut nonce = [0u8; 40];
        let copy_len = salt.len().min(40);
        nonce[..copy_len].copy_from_slice(&salt[..copy_len]);
        hash_to_point_nist(&nonce, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_point_nist() {
        let nonce = [0x42u8; 40];
        let message = b"Test message for NIST hash-to-point";

        let c = hash_to_point_nist(&nonce, message);

        // Check that we have exactly N coefficients
        assert_eq!(c.len(), N);

        // Check that all coefficients are in [0, Q-1]
        for (i, &coeff) in c.iter().enumerate() {
            assert!(
                coeff >= 0 && coeff < Q as i16,
                "Coefficient {} out of range: {}",
                i,
                coeff
            );
        }

        // Check that coefficients are not all the same (statistical test)
        let first = c[0];
        let all_same = c.iter().all(|&x| x == first);
        assert!(!all_same, "All coefficients are the same — something is wrong");
    }

    #[test]
    fn test_hash_deterministic() {
        let nonce1 = [0x01u8; 40];
        let nonce2 = [0x02u8; 40];
        let message = b"Determinism test";

        // Same input should give same output
        let c1 = hash_to_point_nist(&nonce1, message);
        let c2 = hash_to_point_nist(&nonce1, message);
        assert_eq!(c1, c2, "Hash-to-point must be deterministic");

        // Different nonce should give different output
        let c3 = hash_to_point_nist(&nonce2, message);
        assert_ne!(c1, c3, "Different nonces should produce different polynomials");
    }

    #[test]
    fn test_hash_uniform_distribution() {
        let nonce = [0xABu8; 40];
        let message = b"Distribution test";

        let c = hash_to_point_nist(&nonce, message);

        // Basic uniformity check: count how many are in each third of [0, Q)
        let third = Q as i16 / 3;
        let low = c.iter().filter(|&&x| x < third).count();
        let mid = c.iter().filter(|&&x| x >= third && x < 2 * third).count();
        let high = c.iter().filter(|&&x| x >= 2 * third).count();

        // Each third should have roughly N/3 = 170 values
        // Allow generous tolerance for statistical fluctuation
        assert!(low > 100, "Too few low values: {}", low);
        assert!(mid > 100, "Too few mid values: {}", mid);
        assert!(high > 100, "Too few high values: {}", high);
    }

    #[test]
    fn test_compatibility_wrapper() {
        let salt = vec![0x55u8; 40];
        let message = b"Compatibility test";

        let c = hash_to_point_for_signing(message, &salt);

        assert_eq!(c.len(), N);
        for &coeff in &c {
            assert!(coeff >= 0 && coeff < Q as i16);
        }
    }
}

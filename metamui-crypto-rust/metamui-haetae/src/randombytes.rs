//! Random number generation for HAETAE
//!
//! This module provides cryptographically secure random number generation
//! for key generation and other operations requiring randomness.
//!
//! Transcopy from: metamui-haetae/src/randombytes.c

/// Fill buffer with cryptographically secure random bytes
///
/// # Arguments
/// * `buf` - Buffer to fill with random bytes
///
/// # Panics
/// Panics if the system random number generator is not available
///
/// Transcopy from: void randombytes(uint8_t *buf, size_t len)
#[cfg(feature = "getrandom")]
pub fn randombytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("Failed to generate random bytes");
}

/// Stand-in used when the crate is built without `getrandom` (i.e. without `std`)
///
/// # Arguments
/// * `buf` - Buffer that would be filled with random bytes
///
/// # Panics
/// Always: randomized key generation needs the `getrandom` feature, which `std` enables.
/// The deterministic seed-based entry points do not call this.
#[cfg(not(feature = "getrandom"))]
pub fn randombytes(_buf: &mut [u8]) {
    panic!("randombytes requires the 'getrandom' feature or a custom implementation");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_randombytes_different() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        randombytes(&mut buf1);
        randombytes(&mut buf2);

        // Extremely unlikely to be equal
        assert_ne!(buf1, buf2);
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_randombytes_fills_buffer() {
        let mut buf = [0u8; 32];
        randombytes(&mut buf);

        // Check that at least some bytes are non-zero
        let has_nonzero = buf.iter().any(|&b| b != 0);
        assert!(has_nonzero);
    }
}

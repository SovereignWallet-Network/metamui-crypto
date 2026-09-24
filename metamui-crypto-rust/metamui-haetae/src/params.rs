//! HAETAE Parameters
//!
//! This module defines all parameters for the three HAETAE security levels.
//! Transcopy from: metamui-haetae/include/params.h
//!
//! Security levels:
//! - HAETAE-2: 128-bit security (K=2, L=4)
//! - HAETAE-3: 192-bit security (K=3, L=6)
//! - HAETAE-5: 256-bit security (K=4, L=7)

/// Seed size in bytes (for public randomness)
pub const SEEDBYTES: usize = 32;

/// CRH output size in bytes (for hashing)
pub const CRHBYTES: usize = 64;

/// Polynomial degree
pub const N: usize = 256;

/// Root of unity for NTT
pub const ROOT_OF_UNITY: i32 = 3;

/// Modulus Q
pub const Q: i32 = 64513;

/// Double modulus (2*Q)
pub const DQ: i32 = Q << 1;

// Compile-time security level selection using Rust features
#[cfg(feature = "haetae2")]
mod haetae2_params {
    pub const K: usize = 2;
    pub const L: usize = 4;
    pub const TAU: usize = 58;
    pub const B0: f64 = 9846.02;
    pub const B1: f64 = 9838.98;
    pub const B2: f64 = 12777.52;
    pub const GAMMA: f64 = 48.858;
    pub const LN: usize = 8192;
    pub const LNHALF: usize = 4096;
    pub const LNBITS: usize = 13;
    pub const SQNM: f64 = 39.191835884530846;
    pub const D: usize = 1;
    pub const CRYPTO_BYTES: usize = 1474;
    pub const BASE_ENC_HB_Z1: usize = 132;
    pub const BASE_ENC_H: usize = 7;
    pub const ALPHA_HINT: i32 = 512;
    pub const LOG_ALPHA_HINT: usize = 9;
    pub const POLYB1_PACKEDBYTES: usize = 480;
    pub const POLYQ_PACKEDBYTES: usize = 480;
}

#[cfg(feature = "haetae3")]
mod haetae3_params {
    pub const K: usize = 3;
    pub const L: usize = 6;
    pub const TAU: usize = 80;
    pub const B0: f64 = 18314.98;
    pub const B1: f64 = 18307.70;
    pub const B2: f64 = 21906.65;
    pub const GAMMA: f64 = 57.707;
    pub const LN: usize = 8192;
    pub const LNHALF: usize = 4096;
    pub const LNBITS: usize = 13;
    pub const SQNM: f64 = 48.0;
    pub const D: usize = 1;
    pub const CRYPTO_BYTES: usize = 2349;
    pub const BASE_ENC_HB_Z1: usize = 376;
    pub const BASE_ENC_H: usize = 127;
    pub const ALPHA_HINT: i32 = 512;
    pub const LOG_ALPHA_HINT: usize = 9;
    pub const POLYB1_PACKEDBYTES: usize = 480;
    pub const POLYQ_PACKEDBYTES: usize = 480;
}

#[cfg(feature = "haetae5")]
mod haetae5_params {
    pub const K: usize = 4;
    pub const L: usize = 7;
    pub const TAU: usize = 128;
    pub const B0: f64 = 22343.66;
    pub const B1: f64 = 22334.95;
    pub const B2: f64 = 24441.49;
    pub const GAMMA: f64 = 55.13;
    pub const LN: usize = 8192;
    pub const LNHALF: usize = 4096;
    pub const LNBITS: usize = 13;
    pub const SQNM: f64 = 53.0659966456864;
    pub const D: usize = 0;
    pub const CRYPTO_BYTES: usize = 2948;
    pub const BASE_ENC_HB_Z1: usize = 501;
    pub const BASE_ENC_H: usize = 358;
    pub const ALPHA_HINT: i32 = 256;
    pub const LOG_ALPHA_HINT: usize = 8;
    pub const POLYB1_PACKEDBYTES: usize = 512;
    pub const POLYQ_PACKEDBYTES: usize = 512;
}

// Re-export the selected parameter set
#[cfg(feature = "haetae2")]
pub use haetae2_params::*;

#[cfg(feature = "haetae3")]
pub use haetae3_params::*;

#[cfg(feature = "haetae5")]
pub use haetae5_params::*;

// Derived constants (same across all security levels)
pub const HALF_ALPHA_HINT: i32 = ALPHA_HINT >> 1;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const B0SQ: u64 = (B0 * B0) as u64;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const B1SQ: u64 = (B1 * B1) as u64;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const B2SQ: u64 = (B2 * B2) as u64;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const M: usize = L - 1;

pub const ETA: usize = 1;
pub const POLYETA_PACKEDBYTES: usize = 64;

#[cfg(any(feature = "haetae2", feature = "haetae3"))]
pub const POLY2ETA_PACKEDBYTES: usize = 96;

#[cfg(feature = "haetae5")]
pub const POLY2ETA_PACKEDBYTES: usize = 64;

pub const POLYC_PACKEDBYTES: usize = 32;
pub const POLY_HIGHBITS_PACKEDBYTES: usize = N * 9 / 8;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const POLYVECK_HIGHBITS_PACKEDBYTES: usize = POLY_HIGHBITS_PACKEDBYTES * K;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const POLYVECK_BYTES: usize = K * N * core::mem::size_of::<i32>();

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const POLYVECL_BYTES: usize = L * N * core::mem::size_of::<i32>();

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const CRYPTO_PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYQ_PACKEDBYTES;

#[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
pub const CRYPTO_SECRETKEYBYTES: usize =
    CRYPTO_PUBLICKEYBYTES + M * POLYETA_PACKEDBYTES + K * POLY2ETA_PACKEDBYTES + SEEDBYTES;

/// Security level identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// HAETAE-2: 128-bit security
    #[cfg(feature = "haetae2")]
    Haetae2,
    /// HAETAE-3: 192-bit security
    #[cfg(feature = "haetae3")]
    Haetae3,
    /// HAETAE-5: 256-bit security
    #[cfg(feature = "haetae5")]
    Haetae5,
}

impl SecurityLevel {
    /// Get the current security level based on enabled features
    pub const fn current() -> Self {
        #[cfg(feature = "haetae2")]
        return Self::Haetae2;

        #[cfg(all(feature = "haetae3", not(feature = "haetae2")))]
        return Self::Haetae3;

        #[cfg(all(feature = "haetae5", not(feature = "haetae2"), not(feature = "haetae3")))]
        return Self::Haetae5;
    }

    /// Get K parameter for this security level
    #[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
    pub const fn k(&self) -> usize {
        K
    }

    /// Get L parameter for this security level
    #[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
    pub const fn l(&self) -> usize {
        L
    }

    /// Get security bits for this level
    pub const fn security_bits(&self) -> usize {
        match self {
            #[cfg(feature = "haetae2")]
            Self::Haetae2 => 128,
            #[cfg(feature = "haetae3")]
            Self::Haetae3 => 192,
            #[cfg(feature = "haetae5")]
            Self::Haetae5 => 256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(N, 256);
        assert_eq!(Q, 64513);
        assert_eq!(DQ, 129026);
        assert_eq!(SEEDBYTES, 32);
        assert_eq!(CRHBYTES, 64);
    }

    #[cfg(feature = "haetae2")]
    #[test]
    fn test_haetae2_params() {
        assert_eq!(K, 2);
        assert_eq!(L, 4);
        assert_eq!(M, 3);
        assert_eq!(CRYPTO_BYTES, 1474);
        assert_eq!(SecurityLevel::current(), SecurityLevel::Haetae2);
        assert_eq!(SecurityLevel::current().security_bits(), 128);
    }

    #[cfg(feature = "haetae3")]
    #[test]
    fn test_haetae3_params() {
        assert_eq!(K, 3);
        assert_eq!(L, 6);
        assert_eq!(M, 5);
        assert_eq!(CRYPTO_BYTES, 2349);
        assert_eq!(SecurityLevel::current(), SecurityLevel::Haetae3);
        assert_eq!(SecurityLevel::current().security_bits(), 192);
    }

    #[cfg(feature = "haetae5")]
    #[test]
    fn test_haetae5_params() {
        assert_eq!(K, 4);
        assert_eq!(L, 7);
        assert_eq!(M, 6);
        assert_eq!(CRYPTO_BYTES, 2948);
        assert_eq!(SecurityLevel::current(), SecurityLevel::Haetae5);
        assert_eq!(SecurityLevel::current().security_bits(), 256);
    }

    #[cfg(feature = "haetae3")]
    #[test]
    fn test_haetae3_rejection_constants() {
        println!("HAETAE-3 Parameters:");
        println!("  K={}, L={}, LN={}", K, L, LN);
        println!("  B0={}, B1={}, B2={}", B0, B1, B2);
        println!("  B0SQ={} (expected: {})", B0SQ, (B0 * B0) as u64);
        println!("  B1SQ={} (expected: {})", B1SQ, (B1 * B1) as u64);
        println!("  B2SQ={} (expected: {})", B2SQ, (B2 * B2) as u64);

        // Check rejection thresholds
        let threshold1 = B1SQ * LN as u64 * LN as u64;
        let threshold0 = B0SQ * LN as u64 * LN as u64;

        println!("\nRejection Thresholds:");
        println!("  B1SQ * LN * LN = {}", threshold1);
        println!("  B0SQ * LN * LN = {}", threshold0);
        println!("  LN*LN = {}", LN as u64 * LN as u64);
    }
}

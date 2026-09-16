//! # ACVP Core - Generic ACVP Infrastructure
//!
//! This crate provides generic infrastructure for NIST ACVP (Automated Cryptographic
//! Validation Protocol) test vector parsing and validation. It supports all post-quantum
//! cryptographic algorithms including ML-KEM, ML-DSA (Dilithium), SLH-DSA, Falcon, and others.
//!
//! ## Overview
//!
//! ACVP is NIST's modern standard for cryptographic algorithm testing. It provides:
//! - Hierarchical test organization (TestSuite → TestGroups → TestCases)
//! - Rich metadata and parameter set support
//! - Test type classification (keyGen, sigGen, sigVer, encapGen, decap, etc.)
//! - Validation status indicators
//! - Cross-algorithm consistency
//!
//! ## Architecture
//!
//! The crate is organized into modules:
//! - `types`: Core ACVP data structures
//! - `parser`: Generic parsing and validation
//! - `traits`: Algorithm-specific trait definitions
//! - `error`: Error types
//! - `statistics`: Test suite statistics and analysis
//!
//! ## Usage
//!
//! ```rust,ignore
//! use metamui_acvp_core::{AcvpParser, AcvpCompatible};
//!
//! // Implement AcvpCompatible for your algorithm
//! struct MyAlgorithm;
//! impl AcvpCompatible for MyAlgorithm {
//!     // Implementation details...
//! }
//!
//! // Parse test vectors
//! let parser = AcvpParser::<MyAlgorithm>::new();
//! let test_suite = parser.parse_file("vectors.json")?;
//! ```

pub mod types;
pub mod parser;
pub mod traits;
pub mod error;
pub mod statistics;
pub mod validator;

// Re-export commonly used types
pub use types::{AcvpTestSuite, AcvpTestGroup, AcvpTestCase, FieldValue};
pub use parser::AcvpParser;
pub use traits::AcvpCompatible;
pub use error::{AcvpError, Result};
pub use statistics::TestSuiteStatistics;
pub use validator::AcvpValidator;

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_library_basics() {
        // Basic smoke test to ensure modules compile
        assert!(true);
    }
}

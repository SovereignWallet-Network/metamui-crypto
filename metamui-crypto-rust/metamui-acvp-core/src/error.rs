//! Error types for ACVP operations

use thiserror::Error;

/// Result type for ACVP operations
pub type Result<T> = std::result::Result<T, AcvpError>;

/// Errors that can occur during ACVP parsing and validation
#[derive(Debug, Error)]
pub enum AcvpError {
    /// JSON parsing error
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Unknown parameter set
    #[error("Unknown parameter set: {0}")]
    UnknownParameterSet(String),

    /// Unsupported test type
    #[error("Unsupported test type: {0}")]
    UnsupportedTestType(String),

    /// Invalid test suite structure
    #[error("Invalid test suite structure: {0}")]
    InvalidTestSuite(String),

    /// Invalid test group structure
    #[error("Invalid test group: {0}")]
    InvalidTestGroup(String),

    /// Invalid test case
    #[error("Invalid test case: {0}")]
    InvalidTestCase(String),

    /// Invalid field value
    #[error("Invalid field value for '{field}': {message}")]
    InvalidField { field: String, message: String },

    /// Size mismatch
    #[error("Size mismatch for {field}: expected {expected}, got {actual}")]
    SizeMismatch {
        field: String,
        expected: usize,
        actual: usize,
    },

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

impl AcvpError {
    /// Create a new validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Self::ValidationError(msg.into())
    }

    /// Create a new invalid field error
    pub fn invalid_field<S1: Into<String>, S2: Into<String>>(field: S1, message: S2) -> Self {
        Self::InvalidField {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Create a new size mismatch error
    pub fn size_mismatch<S: Into<String>>(field: S, expected: usize, actual: usize) -> Self {
        Self::SizeMismatch {
            field: field.into(),
            expected,
            actual,
        }
    }
}

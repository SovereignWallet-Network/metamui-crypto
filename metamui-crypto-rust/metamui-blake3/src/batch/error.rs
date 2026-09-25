// BLAKE3 Batch API Error Types
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd.
// Licensed under the Apache License, Version 2.0

// Display is hand-written (not `thiserror`) so the type works under
// `no_std`; see `crate::error` for the same workspace convention.

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// Errors that can occur in BLAKE3 batch operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blake3BatchError {
    /// Batch is full (16 messages maximum)
    BatchFull,

    /// Batch is empty
    EmptyBatch,

    /// Invalid hex string
    InvalidHex,

    /// Invalid hash size
    InvalidHashSize,

    /// AVX-512 not available on this CPU
    Avx512NotAvailable,

    /// Invalid batch size
    InvalidBatchSize(usize),
}

impl fmt::Display for Blake3BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BatchFull => write!(f, "batch is full (maximum 16 messages)"),
            Self::EmptyBatch => write!(f, "batch is empty"),
            Self::InvalidHex => write!(f, "invalid hex string"),
            Self::InvalidHashSize => write!(f, "invalid hash size (expected 32 bytes)"),
            Self::Avx512NotAvailable => write!(f, "AVX-512 not available on this CPU"),
            Self::InvalidBatchSize(n) => write!(f, "invalid batch size: {}", n),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Blake3BatchError {}

impl Blake3BatchError {
    /// Check if this error indicates AVX-512 is not available
    pub fn is_avx512_unavailable(&self) -> bool {
        matches!(self, Self::Avx512NotAvailable)
    }

    /// Check if this error is about batch capacity
    pub fn is_capacity_error(&self) -> bool {
        matches!(self, Self::BatchFull | Self::EmptyBatch | Self::InvalidBatchSize(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Blake3BatchError::BatchFull;
        assert_eq!(err.to_string(), "batch is full (maximum 16 messages)");
    }

    #[test]
    fn test_error_is_avx512_unavailable() {
        assert!(Blake3BatchError::Avx512NotAvailable.is_avx512_unavailable());
        assert!(!Blake3BatchError::BatchFull.is_avx512_unavailable());
    }

    #[test]
    fn test_error_is_capacity_error() {
        assert!(Blake3BatchError::BatchFull.is_capacity_error());
        assert!(Blake3BatchError::EmptyBatch.is_capacity_error());
        assert!(!Blake3BatchError::InvalidHex.is_capacity_error());
    }
}

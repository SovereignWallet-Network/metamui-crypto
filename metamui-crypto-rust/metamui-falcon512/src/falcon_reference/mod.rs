//! Reference implementation of Falcon-512 sampling algorithm
//! 
//! This module provides a correct implementation of the Fast Fourier Sampling
//! algorithm used in Falcon, based on the Python reference implementation
//! and the official specification.

pub mod ffldl;
pub mod ffsampling;
pub mod basis;
pub mod gaussian;
pub mod numerical_stability;
pub mod extended_precision;

// Hybrid modules for improved precision
pub mod ffldl_hybrid;
pub mod ffsampling_hybrid;
pub mod basis_hybrid;

pub use ffsampling::ReferenceFFSampler;
pub use basis::ReferenceBasis;
pub use ffsampling_hybrid::HybridFFSampler;
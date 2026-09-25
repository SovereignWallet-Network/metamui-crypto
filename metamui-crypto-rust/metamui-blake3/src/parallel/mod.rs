// MetaMUI BLAKE3 - Parallel Module
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// Licensed under the Apache License, Version 2.0

//! Parallel BLAKE3 hashing
//!
//! Multi-threaded hashing on Rayon: [`tree::hash`] splits one message into
//! chunks and hashes them in parallel, [`ParallelHasher`] hashes many
//! messages at once. Both compute the ordinary BLAKE3 digest, through the
//! installed [`crate::backend`] (portable unless another was installed).

/// Core parallel tree hashing implementation
#[cfg(feature = "multithreading")]
pub mod tree;

/// High-level parallel hashing utilities
pub mod utils;

// Re-export core parallel hashing function
#[cfg(feature = "multithreading")]
pub use tree::{hash, hash_keyed};

// Re-export high-level utilities
pub use utils::ParallelHasher;

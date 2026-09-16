// MetaMUI Falcon - Metal Shader Constants
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metal shader constants and kernel names for Falcon GPU operations.
//!
//! # Available Kernels
//!
//! - `falcon_ntt_forward`: Forward NTT (Cooley-Tukey butterfly)
//! - `falcon_ntt_inverse`: Inverse NTT (Gentleman-Sande butterfly)
//! - `falcon_pointwise_mul`: NTT-domain pointwise multiply mod q
//! - `falcon_batch_verify`: Batch signature verification
//!
//! # Tuning Parameters
//!
//! - Threadgroup size: 256 (optimal for M1-M4 GPU cores)
//! - GPU crossover: ~100 signatures for batch verify
//! - Buffer pool: 8 buffers per size bucket

/// Kernel function names
pub const KERNEL_NTT_FORWARD: &str = "falcon_ntt_forward";
pub const KERNEL_NTT_INVERSE: &str = "falcon_ntt_inverse";
pub const KERNEL_POINTWISE_MUL: &str = "falcon_pointwise_mul";
pub const KERNEL_BATCH_VERIFY: &str = "falcon_batch_verify";

/// Falcon NTT constants
pub const NTT_Q: u32 = 12289;
pub const FALCON512_N: u32 = 512;
pub const FALCON512_LOGN: u32 = 9;
pub const FALCON1024_N: u32 = 1024;
pub const FALCON1024_LOGN: u32 = 10;

/// GPU tuning parameters
pub const THREADGROUP_SIZE: usize = 256;
pub const GPU_CROSSOVER_BATCH: usize = 100;
pub const MAX_BUFFERS_PER_SIZE: usize = 8;

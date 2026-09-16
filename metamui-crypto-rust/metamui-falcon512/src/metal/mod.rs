// MetaMUI Falcon - Pure Rust Metal GPU Acceleration
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>

//! Pure Rust Metal GPU-accelerated batch operations for Falcon-512/1024.
//!
//! Provides GPU-parallel batch verification and NTT operations on macOS
//! using `objc2-metal` for pure Rust Metal bindings.
//!
//! # Architecture
//!
//! - **Pure Rust**: No C dependencies, uses objc2-metal bindings
//! - **Batch-first**: GPU acceleration only for batch operations (>=100 items)
//! - **Hybrid**: CPU for small batches, GPU for large batches
//! - **Buffer pooling**: Reuses Metal buffers across operations
//!
//! # Performance Targets
//!
//! On Apple M3 Max (2024):
//! - Batch verify 1000 signatures: ~2M cycles (vs ~45M cycles CPU)
//! - GPU crossover point: ~100 signatures
//!
//! # Usage
//!
//! ```rust,ignore
//! use metamui_falcon512::metal::MetalFalconBatch;
//!
//! if let Some(batch) = MetalFalconBatch::new() {
//!     let results = batch.verify_batch(&signatures, &public_key, &messages)?;
//! }
//! ```

/// Metal shader documentation and constants
pub mod shaders;

#[cfg(all(feature = "metal", target_os = "macos"))]
use std::vec::Vec;
#[cfg(all(feature = "metal", target_os = "macos"))]
use std::sync::{Arc, Mutex};
#[cfg(all(feature = "metal", target_os = "macos"))]
use std::collections::HashMap;

#[cfg(all(feature = "metal", target_os = "macos"))]
use objc2_metal::{
    MTLCreateSystemDefaultDevice,
    MTLDevice,
    MTLLibrary,
    MTLComputePipelineState,
    MTLCommandQueue,
    MTLCommandBuffer,
    MTLCommandEncoder,
    MTLComputeCommandEncoder,
    MTLBuffer,
};
#[cfg(all(feature = "metal", target_os = "macos"))]
use objc2_foundation::NSString;
#[cfg(all(feature = "metal", target_os = "macos"))]
use objc2::rc::Retained;

/// Metal shader source (embedded at compile time)
#[cfg(all(feature = "metal", target_os = "macos"))]
const FALCON_METAL_SOURCE: &str = include_str!("shaders/falcon_ntt.metal");

// ================================================================
// Error type
// ================================================================

/// Metal GPU error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetalError {
    /// Metal GPU not available on this system
    NotAvailable,
    /// Device initialization failed
    InitializationFailed,
    /// Shader compilation failed
    ShaderCompilationFailed,
    /// Pipeline creation failed
    PipelineCreationFailed,
    /// Buffer creation failed
    BufferCreationFailed,
    /// Command execution failed
    ExecutionFailed,
    /// Invalid input parameters
    InvalidInput,
}

impl core::fmt::Display for MetalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MetalError::NotAvailable => write!(f, "Metal GPU not available"),
            MetalError::InitializationFailed => write!(f, "Metal initialization failed"),
            MetalError::ShaderCompilationFailed => write!(f, "Metal shader compilation failed"),
            MetalError::PipelineCreationFailed => write!(f, "Metal pipeline creation failed"),
            MetalError::BufferCreationFailed => write!(f, "Metal buffer creation failed"),
            MetalError::ExecutionFailed => write!(f, "Metal execution failed"),
            MetalError::InvalidInput => write!(f, "Invalid input"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MetalError {}

// ================================================================
// Buffer pool (reuse Metal buffers across operations)
// ================================================================

#[cfg(all(feature = "metal", target_os = "macos"))]
struct MetalBufferPool {
    device: Retained<objc2::runtime::ProtocolObject<dyn MTLDevice>>,
    pools: Mutex<HashMap<usize, Vec<Retained<objc2::runtime::ProtocolObject<dyn MTLBuffer>>>>>,
    max_per_size: usize,
}

#[cfg(all(feature = "metal", target_os = "macos"))]
impl MetalBufferPool {
    fn new(device: Retained<objc2::runtime::ProtocolObject<dyn MTLDevice>>) -> Self {
        Self {
            device,
            pools: Mutex::new(HashMap::new()),
            max_per_size: shaders::MAX_BUFFERS_PER_SIZE,
        }
    }

    fn get_buffer(&self, size: usize) -> Option<Retained<objc2::runtime::ProtocolObject<dyn MTLBuffer>>> {
        use objc2_metal::MTLResourceOptions;

        // Try pool first
        {
            let mut pools = self.pools.lock().unwrap();
            if let Some(buffers) = pools.get_mut(&size) {
                if let Some(buffer) = buffers.pop() {
                    return Some(buffer);
                }
            }
        }

        // Allocate new
        self.device.newBufferWithLength_options(
            size,
            MTLResourceOptions::MTLResourceStorageModeShared,
        )
    }

    fn return_buffer(&self, size: usize, buffer: Retained<objc2::runtime::ProtocolObject<dyn MTLBuffer>>) {
        let mut pools = self.pools.lock().unwrap();
        let entry = pools.entry(size).or_insert_with(Vec::new);
        if entry.len() < self.max_per_size {
            entry.push(buffer);
        }
    }
}

// ================================================================
// MetalFalconBatch: GPU-accelerated batch operations
// ================================================================

/// GPU-accelerated batch operations for Falcon-512/1024.
///
/// Pre-compiles Metal shader pipelines on creation. Reuses buffers
/// across operations via a pool. Falls back to CPU for small batches.
#[cfg(all(feature = "metal", target_os = "macos"))]
pub struct MetalFalconBatch {
    device: Retained<objc2::runtime::ProtocolObject<dyn MTLDevice>>,
    command_queue: Retained<objc2::runtime::ProtocolObject<dyn MTLCommandQueue>>,
    ntt_forward_pipeline: Retained<objc2::runtime::ProtocolObject<dyn MTLComputePipelineState>>,
    ntt_inverse_pipeline: Retained<objc2::runtime::ProtocolObject<dyn MTLComputePipelineState>>,
    pointwise_mul_pipeline: Retained<objc2::runtime::ProtocolObject<dyn MTLComputePipelineState>>,
    batch_verify_pipeline: Retained<objc2::runtime::ProtocolObject<dyn MTLComputePipelineState>>,
    buffer_pool: Arc<MetalBufferPool>,
}

/// Stub for non-macOS platforms.
#[cfg(not(all(feature = "metal", target_os = "macos")))]
pub struct MetalFalconBatch;

#[cfg(all(feature = "metal", target_os = "macos"))]
impl MetalFalconBatch {
    /// Initialize Metal GPU batch operations.
    ///
    /// Returns `Some(batch)` if Metal is available and all pipelines
    /// compiled successfully. Returns `None` on CI machines, VMs, etc.
    pub fn new() -> Option<Self> {
        Self::new_with_diagnostics(false)
    }

    /// Initialize with optional diagnostic output for debugging shader compilation.
    pub fn new_with_diagnostics(diagnostics: bool) -> Option<Self> {
        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {}

        let device_ptr = unsafe { MTLCreateSystemDefaultDevice() };
        if device_ptr.is_null() {
            if diagnostics { eprintln!("[Metal] MTLCreateSystemDefaultDevice returned null"); }
            return None;
        }
        let device = unsafe { Retained::from_raw(device_ptr)? };
        if diagnostics { eprintln!("[Metal] Device acquired: OK"); }

        let command_queue = device.newCommandQueue()?;
        if diagnostics { eprintln!("[Metal] Command queue created: OK"); }

        // Compile shader library
        let library = match Self::compile_library(&device) {
            Ok(lib) => {
                if diagnostics { eprintln!("[Metal] Shader library compiled: OK"); }
                lib
            }
            Err(e) => {
                if diagnostics { eprintln!("[Metal] Shader compilation FAILED: {}", e); }
                return None;
            }
        };

        // Create pipelines for each kernel
        let kernels = [
            (shaders::KERNEL_NTT_FORWARD, "ntt_forward"),
            (shaders::KERNEL_NTT_INVERSE, "ntt_inverse"),
            (shaders::KERNEL_POINTWISE_MUL, "pointwise_mul"),
            (shaders::KERNEL_BATCH_VERIFY, "batch_verify"),
        ];
        let mut pipelines = Vec::new();
        for (name, label) in &kernels {
            match Self::create_pipeline(&device, &library, name) {
                Ok(p) => {
                    if diagnostics { eprintln!("[Metal] Pipeline '{}': OK", label); }
                    pipelines.push(p);
                }
                Err(e) => {
                    if diagnostics { eprintln!("[Metal] Pipeline '{}' FAILED: {}", label, e); }
                    return None;
                }
            }
        }

        let buffer_pool = Arc::new(MetalBufferPool::new(device.clone()));

        Some(Self {
            device,
            command_queue,
            ntt_forward_pipeline: pipelines.remove(0),
            ntt_inverse_pipeline: pipelines.remove(0),
            pointwise_mul_pipeline: pipelines.remove(0),
            batch_verify_pipeline: pipelines.remove(0),
            buffer_pool,
        })
    }

    /// Check if Metal GPU is available.
    pub fn is_available() -> bool {
        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {}

        let device_ptr = unsafe { MTLCreateSystemDefaultDevice() };
        !device_ptr.is_null()
    }

    fn compile_library(
        device: &Retained<objc2::runtime::ProtocolObject<dyn MTLDevice>>,
    ) -> Result<Retained<objc2::runtime::ProtocolObject<dyn MTLLibrary>>, MetalError> {
        let source = NSString::from_str(FALCON_METAL_SOURCE);
        device.newLibraryWithSource_options_error(&source, None)
            .map_err(|e| {
                eprintln!("[Metal] MSL compile error: {}", e);
                MetalError::ShaderCompilationFailed
            })
    }

    fn create_pipeline(
        device: &Retained<objc2::runtime::ProtocolObject<dyn MTLDevice>>,
        library: &Retained<objc2::runtime::ProtocolObject<dyn MTLLibrary>>,
        name: &str,
    ) -> Result<Retained<objc2::runtime::ProtocolObject<dyn MTLComputePipelineState>>, MetalError> {
        let name_ns = NSString::from_str(name);
        let function = library.newFunctionWithName(&name_ns)
            .ok_or(MetalError::PipelineCreationFailed)?;
        device.newComputePipelineStateWithFunction_error(&function)
            .map_err(|_| MetalError::PipelineCreationFailed)
    }

    /// Batch-verify Falcon-512 signatures on GPU.
    ///
    /// # Arguments
    ///
    /// * `s1_polys` - Decompressed s1 polynomials (one per signature)
    /// * `c_polys` - Challenge polynomials (one per signature)
    /// * `h` - Public key polynomial (shared)
    /// * `n` - Polynomial degree (512 or 1024)
    ///
    /// # Returns
    ///
    /// `Vec<bool>` where `results[i]` = true if signature i is valid.
    ///
    /// Falls back to CPU if batch_size < GPU_CROSSOVER_BATCH.
    pub fn verify_batch(
        &self,
        s1_polys: &[Vec<i16>],
        c_polys: &[Vec<u16>],
        h: &[u16],
        n: usize,
    ) -> Result<Vec<bool>, MetalError> {
        let batch_size = s1_polys.len();
        if batch_size == 0 { return Ok(Vec::new()); }
        if c_polys.len() != batch_size { return Err(MetalError::InvalidInput); }

        // CPU fallback for small batches
        if batch_size < shaders::GPU_CROSSOVER_BATCH {
            return Ok(self.verify_batch_cpu(s1_polys, c_polys, h, n));
        }

        self.verify_batch_gpu(s1_polys, c_polys, h, n)
    }

    /// CPU fallback for small batches.
    ///
    /// Uses NTT polynomial multiplication (negacyclic convolution mod x^n+1)
    /// to compute s0 = c - s1·h (mod q), then checks the norm bound.
    fn verify_batch_cpu(
        &self,
        s1_polys: &[Vec<i16>],
        c_polys: &[Vec<u16>],
        h: &[u16],
        n: usize,
    ) -> Vec<bool> {
        let q = shaders::NTT_Q as i32;
        let beta_sq = 34034726i64;

        // Convert h from u16 to i16 for NTT multiply
        let h_i16: Vec<i16> = h.iter().map(|&v| v as i16).collect();

        s1_polys.iter().zip(c_polys.iter()).map(|(s1, c)| {
            // NTT polynomial multiply: s1·h mod (x^n+1) mod q
            let s1h = crate::ntt_falcon::multiply_ntt(s1, &h_i16);

            let mut norm_sq: i64 = 0;
            for i in 0..n {
                let c_val = c[i] as i32;
                let s1h_val = s1h[i] as i32;

                // s0 = c - s1·h, centered in [-q/2, q/2)
                let diff = (c_val - s1h_val).rem_euclid(q);
                let s0 = if diff >= (q + 1) / 2 { diff - q } else { diff } as i64;
                let s1_val = s1[i] as i64;

                norm_sq += s0 * s0 + s1_val * s1_val;
            }
            norm_sq <= beta_sq // floor(beta^2) is accepted (#352)
        }).collect()
    }

    /// GPU batch verification.
    ///
    /// Pre-computes s0 = c - NTT(s1·h) on CPU (using SIMD-optimized NTT),
    /// then dispatches parallel norm checking on GPU.
    fn verify_batch_gpu(
        &self,
        s1_polys: &[Vec<i16>],
        c_polys: &[Vec<u16>],
        h: &[u16],
        n: usize,
    ) -> Result<Vec<bool>, MetalError> {
        use objc2_metal::{MTLResourceOptions, MTLSize};
        use std::ptr::NonNull;
        use std::ffi::c_void;

        let batch_size = s1_polys.len();
        let q = shaders::NTT_Q as i32;
        let h_i16: Vec<i16> = h.iter().map(|&v| v as i16).collect();

        // Step 1: Pre-compute s0 for each signature on CPU (NTT poly multiply)
        let mut s0_flat: Vec<i16> = Vec::with_capacity(batch_size * n);
        let mut s1_flat: Vec<i16> = Vec::with_capacity(batch_size * n);

        for (s1, c) in s1_polys.iter().zip(c_polys.iter()) {
            let s1h = crate::ntt_falcon::multiply_ntt(s1, &h_i16);
            for i in 0..n {
                let c_val = c[i] as i32;
                let s1h_val = s1h[i] as i32;
                let diff = (c_val - s1h_val).rem_euclid(q);
                let s0_val = if diff >= (q + 1) / 2 { diff - q } else { diff };
                s0_flat.push(s0_val as i16);
            }
            s1_flat.extend_from_slice(s1);
        }

        // Step 2: Create Metal buffers for GPU norm check
        let s0_ptr = NonNull::new(s0_flat.as_ptr() as *mut c_void)
            .ok_or(MetalError::InvalidInput)?;
        let s0_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                s0_ptr,
                s0_flat.len() * 2,
                MTLResourceOptions::MTLResourceStorageModeShared,
            )
        }.ok_or(MetalError::BufferCreationFailed)?;

        let s1_ptr = NonNull::new(s1_flat.as_ptr() as *mut c_void)
            .ok_or(MetalError::InvalidInput)?;
        let s1_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                s1_ptr,
                s1_flat.len() * 2,
                MTLResourceOptions::MTLResourceStorageModeShared,
            )
        }.ok_or(MetalError::BufferCreationFailed)?;

        // Result buffer: one u32 per signature
        let result_size = batch_size * 4;
        let result_buffer = self.buffer_pool.get_buffer(result_size)
            .ok_or(MetalError::BufferCreationFailed)?;

        // Params buffer: { n, batch_size }
        let params = [n as u32, batch_size as u32];
        let params_ptr = NonNull::new(params.as_ptr() as *mut c_void)
            .ok_or(MetalError::InvalidInput)?;
        let params_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                params_ptr,
                8,
                MTLResourceOptions::MTLResourceStorageModeShared,
            )
        }.ok_or(MetalError::BufferCreationFailed)?;

        // Step 3: Dispatch GPU norm check
        let command_buffer = self.command_queue.commandBuffer()
            .ok_or(MetalError::ExecutionFailed)?;
        let encoder = command_buffer.computeCommandEncoder()
            .ok_or(MetalError::ExecutionFailed)?;

        unsafe {
            encoder.setComputePipelineState(&self.batch_verify_pipeline);
            encoder.setBuffer_offset_atIndex(Some(&s0_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(&s1_buffer), 0, 1);
            encoder.setBuffer_offset_atIndex(Some(&result_buffer), 0, 2);
            encoder.setBuffer_offset_atIndex(Some(&params_buffer), 0, 3);
        }

        let tg_size = std::cmp::min(
            self.batch_verify_pipeline.maxTotalThreadsPerThreadgroup(),
            shaders::THREADGROUP_SIZE,
        );
        let grid = MTLSize { width: batch_size * tg_size, height: 1, depth: 1 };
        let tg = MTLSize { width: tg_size, height: 1, depth: 1 };

        encoder.dispatchThreads_threadsPerThreadgroup(grid, tg);
        encoder.endEncoding();

        unsafe {
            command_buffer.commit();
            command_buffer.waitUntilCompleted();
        }

        // Step 4: Read results
        let result_ptr = result_buffer.contents();
        let results = unsafe {
            std::slice::from_raw_parts(result_ptr.as_ptr() as *const u32, batch_size)
        };

        let valid: Vec<bool> = results.iter().map(|&r| r != 0).collect();

        // Return buffer to pool
        self.buffer_pool.return_buffer(result_size, result_buffer);

        Ok(valid)
    }
}

// ================================================================
// Stub implementation for non-macOS
// ================================================================

#[cfg(not(all(feature = "metal", target_os = "macos")))]
impl MetalFalconBatch {
    /// Always returns None on non-macOS platforms.
    pub fn new() -> Option<Self> { None }

    /// Always returns None on non-macOS platforms.
    pub fn new_with_diagnostics(_diagnostics: bool) -> Option<Self> { None }

    /// Always returns false on non-macOS.
    pub fn is_available() -> bool { false }
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metal_device_detection() {
        // Verify is_available() returns without panicking
        let available = MetalFalconBatch::is_available();
        println!("Metal device available: {}", available);
        // On macOS with Apple Silicon this should be true
        #[cfg(all(feature = "metal", target_os = "macos"))]
        assert!(available, "Metal should be available on macOS with GPU");
    }

    #[test]
    fn test_metal_initialization_and_shader_compilation() {
        // This is the critical test: it verifies that the Metal Shading Language
        // compiler can parse and compile our falcon_ntt.metal shader.
        // `cargo check` only checks Rust syntax — the .metal file is just a
        // string constant, so shader bugs only surface at runtime.
        let batch = MetalFalconBatch::new_with_diagnostics(true);

        #[cfg(all(feature = "metal", target_os = "macos"))]
        {
            assert!(batch.is_some(), "MetalFalconBatch::new() should succeed on macOS with GPU");
            println!("Metal shader compilation: OK (all 4 pipelines created)");
        }

        #[cfg(not(all(feature = "metal", target_os = "macos")))]
        {
            assert!(batch.is_none(), "MetalFalconBatch should be None on non-macOS");
        }
    }

    #[test]
    fn test_batch_verify_cpu_fallback_small_batch() {
        // Small batches (< 100) always use CPU fallback path
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        let n = 512;
        let q = 12289i64;

        // Create a simple test case: s1 = [1, 0, 0, ...], h = [1, 0, 0, ...], c = [1, 0, 0, ...]
        // s0 = c - s1*h = [0, 0, ...], norm = s0² + s1² = 1 (valid)
        let s1: Vec<i16> = {
            let mut v = vec![0i16; n];
            v[0] = 1;
            v
        };
        let h: Vec<u16> = {
            let mut v = vec![0u16; n];
            v[0] = 1;
            v
        };
        let c: Vec<u16> = {
            let mut v = vec![0u16; n];
            v[0] = 1;  // c[0] = s1[0]*h[0] mod q = 1
            v
        };

        // 5 signatures (below GPU crossover) — should use CPU fallback
        let s1_polys: Vec<Vec<i16>> = vec![s1.clone(); 5];
        let c_polys: Vec<Vec<u16>> = vec![c.clone(); 5];

        let results = batch.verify_batch(&s1_polys, &c_polys, &h, n)
            .expect("CPU fallback verify should succeed");
        assert_eq!(results.len(), 5);
        for (i, &valid) in results.iter().enumerate() {
            assert!(valid, "signature {} should be valid (simple test case)", i);
        }
        println!("CPU fallback batch verify: 5/5 valid");
    }

    #[test]
    fn test_batch_verify_cpu_fallback_invalid() {
        // Verify that invalid signatures are detected
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        let n = 512;

        // Create an invalid case: s1 = [6000, 6000, ...], making norm huge
        let s1_big: Vec<i16> = vec![6000i16; n];
        let h: Vec<u16> = vec![1u16; n];
        let c: Vec<u16> = vec![0u16; n];

        let s1_polys = vec![s1_big];
        let c_polys = vec![c];

        let results = batch.verify_batch(&s1_polys, &c_polys, &h, n)
            .expect("verify should succeed (returning invalid result)");
        assert_eq!(results.len(), 1);
        assert!(!results[0], "enormous s1 norm should fail verification");
        println!("CPU fallback invalid detection: OK");
    }

    #[test]
    fn test_batch_verify_empty() {
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        let h: Vec<u16> = vec![0u16; 512];
        let results = batch.verify_batch(&[], &[], &h, 512).expect("empty batch");
        assert!(results.is_empty());
        println!("Empty batch verify: OK");
    }

    #[test]
    fn test_batch_verify_input_validation() {
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        let n = 512;
        let h: Vec<u16> = vec![0u16; n];
        let s1_polys = vec![vec![0i16; n]; 3];
        let c_polys = vec![vec![0u16; n]; 5]; // Mismatched length!

        let result = batch.verify_batch(&s1_polys, &c_polys, &h, n);
        assert!(result.is_err(), "mismatched input lengths should error");
        println!("Input validation: OK");
    }

    #[test]
    fn test_batch_verify_with_real_signatures() {
        // End-to-end test: generate real Falcon-512 keypairs and signatures,
        // then verify them via the Metal batch path
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);

        // Generate a keypair
        let keypair = crate::generate_keypair(&mut rng)
            .expect("keygen should succeed");

        let n = 512;
        let q = 12289u32;

        // Sign multiple messages
        let messages: Vec<Vec<u8>> = (0..10).map(|i| {
            format!("Metal GPU batch verify test message #{}", i).into_bytes()
        }).collect();

        let mut s1_polys: Vec<Vec<i16>> = Vec::new();
        let mut c_polys: Vec<Vec<u16>> = Vec::new();

        for msg in &messages {
            let sig_bytes = crate::falcon_complete::sign_complete(msg, &keypair.private_key, &mut rng)
                .expect("signing should succeed");

            // Decode the NIST-format signature → (nonce, s1)
            let (nonce, s1) = crate::nist_encoding::decode_signature(&sig_bytes, 9)
                .expect("decode should succeed");

            // Compute challenge polynomial c = hash_to_point(nonce || msg)
            let c_i16 = crate::nist_hash::hash_to_point_nist(&nonce, msg);
            let c: Vec<u16> = c_i16.iter().map(|&v| ((v as i32 + q as i32) % q as i32) as u16).collect();

            s1_polys.push(s1);
            c_polys.push(c);
        }

        // Get h from public key
        let h: Vec<u16> = keypair.public_key.h.coeffs.iter().map(|&v| v as u16).collect();

        // Verify via batch (CPU fallback for <100)
        let results = batch.verify_batch(&s1_polys, &c_polys, &h, n)
            .expect("batch verify should succeed");

        assert_eq!(results.len(), 10);
        let valid_count = results.iter().filter(|&&v| v).count();
        println!("Real signature batch verify: {}/{} valid", valid_count, results.len());
        assert_eq!(valid_count, 10, "all 10 real signatures should verify");
    }

    #[test]
    fn test_gpu_path_with_real_signatures() {
        // Force-test the GPU path by calling verify_batch_gpu directly
        // (bypasses the <100 CPU fallback threshold)
        let batch = match MetalFalconBatch::new() {
            Some(b) => b,
            None => { println!("Metal not available, skipping"); return; }
        };

        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
        let keypair = crate::generate_keypair(&mut rng)
            .expect("keygen should succeed");

        let n = 512;
        let q = 12289u32;

        let messages: Vec<Vec<u8>> = (0..5).map(|i| {
            format!("GPU path test message #{}", i).into_bytes()
        }).collect();

        let mut s1_polys: Vec<Vec<i16>> = Vec::new();
        let mut c_polys: Vec<Vec<u16>> = Vec::new();

        for msg in &messages {
            let sig_bytes = crate::falcon_complete::sign_complete(msg, &keypair.private_key, &mut rng)
                .expect("signing should succeed");
            let (nonce, s1) = crate::nist_encoding::decode_signature(&sig_bytes, 9)
                .expect("decode should succeed");
            let c_i16 = crate::nist_hash::hash_to_point_nist(&nonce, msg);
            let c: Vec<u16> = c_i16.iter().map(|&v| ((v as i32 + q as i32) % q as i32) as u16).collect();
            s1_polys.push(s1);
            c_polys.push(c);
        }

        let h: Vec<u16> = keypair.public_key.h.coeffs.iter().map(|&v| v as u16).collect();

        // Directly call GPU path (bypassing CPU fallback threshold)
        let results = batch.verify_batch_gpu(&s1_polys, &c_polys, &h, n)
            .expect("GPU batch verify should succeed");

        assert_eq!(results.len(), 5);
        let valid_count = results.iter().filter(|&&v| v).count();
        println!("GPU path batch verify: {}/{} valid", valid_count, results.len());
        assert_eq!(valid_count, 5, "all 5 signatures should verify via GPU");
    }
}

//! Batch execution engine for GPU operations
//!
//! Provides efficient batch processing of ML-KEM operations on GPU.

use super::device::{GpuDevice, NttPipeline, PolyOpsPipeline, GpuError};
use super::kernels::{PolyOp, ZETAS, N, K, Q};
use wgpu::util::DeviceExt;
use std::sync::Arc;

/// Batch executor for GPU operations
pub struct BatchExecutor {
    device: Arc<GpuDevice>,
    ntt_pipeline: NttPipeline,
    poly_ops_pipeline: PolyOpsPipeline,
    /// Maximum batch size for efficient processing
    max_batch_size: usize,
}

impl BatchExecutor {
    /// Create a new batch executor
    pub fn new(device: Arc<GpuDevice>) -> Result<Self, GpuError> {
        let ntt_pipeline = device.create_ntt_pipeline()?;
        let poly_ops_pipeline = device.create_poly_ops_pipeline()?;
        
        // Determine optimal batch size based on GPU capabilities
        let max_batch_size = device.capabilities().compute_units as usize * 4;
        
        Ok(Self {
            device,
            ntt_pipeline,
            poly_ops_pipeline,
            max_batch_size,
        })
    }
    
    /// Perform batch NTT on multiple polynomials
    pub fn batch_ntt(&self, polynomials: &mut [u32], batch_size: usize, is_inverse: bool) -> Result<(), GpuError> {
        if polynomials.len() != batch_size * N as usize {
            return Err(GpuError::InitFailed(
                format!("Invalid polynomial buffer size: expected {}, got {}", 
                    batch_size * N as usize, polynomials.len())
            ));
        }
        
        // Create GPU buffers
        let poly_buffer = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Polynomial Buffer"),
            contents: bytemuck::cast_slice(polynomials),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
        });
        
        let params = [batch_size as u32, is_inverse as u32, 0, 0];
        let params_buffer = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Parameters Buffer"),
            contents: bytemuck::cast_slice(&params),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        // Create bind group
        let bind_group = self.device.device().create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("NTT Bind Group"),
            layout: &self.ntt_pipeline.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: poly_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: self.ntt_pipeline.zetas_buffer.as_entire_binding(),
                },
            ],
        });
        
        // Create command encoder
        let mut encoder = self.device.device().create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("NTT Command Encoder"),
        });
        
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("NTT Compute Pass"),
                timestamp_writes: None,
            });
            
            // Select appropriate pipeline based on batch size
            if batch_size > 1000 {
                compute_pass.set_pipeline(&self.ntt_pipeline.mega_batch_pipeline);
                let workgroups = (batch_size + 3) / 4; // Process 4 polynomials per workgroup
                compute_pass.set_bind_group(0, &bind_group, &[]);
                compute_pass.dispatch_workgroups(workgroups as u32, 1, 1);
            } else {
                compute_pass.set_pipeline(&self.ntt_pipeline.forward_pipeline);
                compute_pass.set_bind_group(0, &bind_group, &[]);
                compute_pass.dispatch_workgroups(batch_size as u32, 1, 1);
            }
        }
        
        // Copy results back to host
        let staging_buffer = self.device.device().create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: (polynomials.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        
        encoder.copy_buffer_to_buffer(
            &poly_buffer, 0,
            &staging_buffer, 0,
            (polynomials.len() * std::mem::size_of::<u32>()) as u64,
        );
        
        self.device.queue().submit(std::iter::once(encoder.finish()));
        
        // Wait for GPU to complete
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        
        self.device.device().poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().map_err(|e| GpuError::InitFailed(format!("Buffer mapping failed: {:?}", e)))?;
        
        {
            let data = buffer_slice.get_mapped_range();
            polynomials.copy_from_slice(bytemuck::cast_slice(&data));
        }
        
        staging_buffer.unmap();
        
        Ok(())
    }
    
    /// Perform batch polynomial operations
    pub fn batch_poly_op(
        &self, 
        poly_a: &[u32], 
        poly_b: &[u32], 
        result: &mut [u32],
        batch_size: usize,
        operation: PolyOp,
    ) -> Result<(), GpuError> {
        let poly_size = N as usize;
        
        if poly_a.len() != batch_size * poly_size || 
           poly_b.len() != batch_size * poly_size ||
           result.len() != batch_size * poly_size {
            return Err(GpuError::InitFailed("Invalid buffer sizes".to_string()));
        }
        
        // Create GPU buffers
        let buffer_a = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Polynomial A Buffer"),
            contents: bytemuck::cast_slice(poly_a),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        let buffer_b = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Polynomial B Buffer"),
            contents: bytemuck::cast_slice(poly_b),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        let result_buffer = self.device.device().create_buffer(&wgpu::BufferDescriptor {
            label: Some("Result Buffer"),
            size: (result.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        
        let params = [batch_size as u32, operation as u32, 0, 0];
        let params_buffer = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Parameters Buffer"),
            contents: bytemuck::cast_slice(&params),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        // Create bind group
        let bind_group = self.device.device().create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Poly Ops Bind Group"),
            layout: &self.poly_ops_pipeline.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: buffer_a.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: buffer_b.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: result_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: params_buffer.as_entire_binding(),
                },
            ],
        });
        
        // Execute compute pass
        let mut encoder = self.device.device().create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("Poly Ops Command Encoder"),
        });
        
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Poly Ops Compute Pass"),
                timestamp_writes: None,
            });
            
            compute_pass.set_pipeline(&self.poly_ops_pipeline.batch_ops_pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            compute_pass.dispatch_workgroups(batch_size as u32, 1, 1);
        }
        
        // Copy results back
        let staging_buffer = self.device.device().create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: (result.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        
        encoder.copy_buffer_to_buffer(
            &result_buffer, 0,
            &staging_buffer, 0,
            (result.len() * std::mem::size_of::<u32>()) as u64,
        );
        
        self.device.queue().submit(std::iter::once(encoder.finish()));
        
        // Map and read results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        
        self.device.device().poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().map_err(|e| GpuError::InitFailed(format!("Buffer mapping failed: {:?}", e)))?;
        
        {
            let data = buffer_slice.get_mapped_range();
            result.copy_from_slice(bytemuck::cast_slice(&data));
        }
        
        staging_buffer.unmap();
        
        Ok(())
    }
    
    /// Perform matrix-vector multiplication for ML-KEM
    pub fn matrix_vector_mul(
        &self,
        matrix: &[u32],  // k×k matrix of polynomials
        vector: &[u32],  // k vector of polynomials
        result: &mut [u32], // k result vector
        batch_size: usize,
    ) -> Result<(), GpuError> {
        let k = K as usize;
        let poly_size = N as usize;
        let matrix_size = k * k * poly_size;
        let vector_size = k * poly_size;
        
        if matrix.len() != batch_size * matrix_size ||
           vector.len() != batch_size * vector_size ||
           result.len() != batch_size * vector_size {
            return Err(GpuError::InitFailed("Invalid buffer sizes for matrix-vector mul".to_string()));
        }
        
        // Create combined input buffer (matrix followed by vector)
        let mut combined_input = Vec::with_capacity(batch_size * (matrix_size + vector_size));
        for i in 0..batch_size {
            let mat_offset = i * matrix_size;
            let vec_offset = i * vector_size;
            combined_input.extend_from_slice(&matrix[mat_offset..mat_offset + matrix_size]);
            combined_input.extend_from_slice(&vector[vec_offset..vec_offset + vector_size]);
        }
        
        let input_a = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Matrix Buffer"),
            contents: bytemuck::cast_slice(&combined_input[..batch_size * matrix_size]),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        let input_b = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Vector Buffer"),
            contents: bytemuck::cast_slice(&combined_input[batch_size * matrix_size..]),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        let result_buffer = self.device.device().create_buffer(&wgpu::BufferDescriptor {
            label: Some("Result Buffer"),
            size: (result.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        
        let params = [batch_size as u32, 0, 0, 0];
        let params_buffer = self.device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Parameters Buffer"),
            contents: bytemuck::cast_slice(&params),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        // Create bind group
        let bind_group = self.device.device().create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Matrix-Vector Bind Group"),
            layout: &self.poly_ops_pipeline.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: input_a.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_b.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: result_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: params_buffer.as_entire_binding(),
                },
            ],
        });
        
        // Execute compute pass
        let mut encoder = self.device.device().create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("Matrix-Vector Command Encoder"),
        });
        
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Matrix-Vector Compute Pass"),
                timestamp_writes: None,
            });
            
            compute_pass.set_pipeline(&self.poly_ops_pipeline.matrix_vector_pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            // Dispatch k workgroups per batch (one for each row)
            compute_pass.dispatch_workgroups((batch_size * k) as u32, 1, 1);
        }
        
        // Copy results back
        let staging_buffer = self.device.device().create_buffer(&wgpu::BufferDescriptor {
            label: Some("Staging Buffer"),
            size: (result.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        
        encoder.copy_buffer_to_buffer(
            &result_buffer, 0,
            &staging_buffer, 0,
            (result.len() * std::mem::size_of::<u32>()) as u64,
        );
        
        self.device.queue().submit(std::iter::once(encoder.finish()));
        
        // Map and read results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        
        self.device.device().poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().map_err(|e| GpuError::InitFailed(format!("Buffer mapping failed: {:?}", e)))?;
        
        {
            let data = buffer_slice.get_mapped_range();
            result.copy_from_slice(bytemuck::cast_slice(&data));
        }
        
        staging_buffer.unmap();
        
        Ok(())
    }
    
    /// Get maximum batch size
    pub fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }
    
    /// Estimate speedup for given batch size
    pub fn estimate_speedup(&self, batch_size: usize) -> f32 {
        let caps = self.device.capabilities();
        let base_speedup = (caps.compute_units as f32 / 100.0) * (caps.memory_bandwidth / 100.0);
        
        // Adjust for batch size efficiency
        let batch_efficiency = if batch_size < 100 {
            0.5
        } else if batch_size < 1000 {
            0.75
        } else if batch_size < 5000 {
            0.9
        } else {
            1.0
        };
        
        base_speedup * batch_efficiency * 30.0 // Target 30-50x speedup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_batch_executor_creation() {
        if let Ok(device) = GpuDevice::new() {
            let device = Arc::new(device);
            let executor = BatchExecutor::new(device);
            assert!(executor.is_ok());
        }
    }
    
    #[test]
    fn test_batch_ntt() {
        if let Ok(device) = GpuDevice::new() {
            let device = Arc::new(device);
            if let Ok(executor) = BatchExecutor::new(device) {
                let batch_size = 100;
                let mut polynomials = vec![0u32; batch_size * N as usize];
                
                // Initialize with test data
                for i in 0..polynomials.len() {
                    polynomials[i] = (i % Q as usize) as u32;
                }
                
                let result = executor.batch_ntt(&mut polynomials, batch_size, false);
                assert!(result.is_ok());
            }
        }
    }
}
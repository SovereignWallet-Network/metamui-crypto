//! GPU-accelerated NTT implementation
//!
//! Provides optimized Number Theoretic Transform operations on GPU.

use super::device::GpuDevice;
use super::kernels::{N, Q, ZETAS};
use wgpu::util::DeviceExt;

/// GPU NTT processor
pub struct NttGpu {
    device: wgpu::Device,
    queue: wgpu::Queue,
    ntt_pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    zetas_buffer: wgpu::Buffer,
}

impl NttGpu {
    /// Create new NTT processor
    pub fn new(device: &GpuDevice) -> Result<Self, super::device::GpuError> {
        let shader_source = include_str!("kernels/ntt.wgsl");
        let shader_module = device.device().create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("NTT Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_source.into()),
        });
        
        let bind_group_layout = device.device().create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("NTT Bind Group Layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });
        
        let pipeline_layout = device.device().create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("NTT Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        
        let ntt_pipeline = device.device().create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("NTT Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: "ntt_batch_process",
            compilation_options: Default::default(),
        });
        
        // Create zetas buffer
        let zetas_buffer = device.device().create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Zetas Buffer"),
            contents: bytemuck::cast_slice(&ZETAS),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        Ok(Self {
            device: device.device().clone(),
            queue: device.queue().clone(),
            ntt_pipeline,
            bind_group_layout,
            zetas_buffer,
        })
    }
    
    /// Perform forward NTT
    pub fn forward(&self, polynomials: &mut [u32], batch_size: usize) -> Result<(), super::device::GpuError> {
        self.transform(polynomials, batch_size, false)
    }
    
    /// Perform inverse NTT
    pub fn inverse(&self, polynomials: &mut [u32], batch_size: usize) -> Result<(), super::device::GpuError> {
        self.transform(polynomials, batch_size, true)
    }
    
    /// Internal transform function
    fn transform(&self, polynomials: &mut [u32], batch_size: usize, is_inverse: bool) -> Result<(), super::device::GpuError> {
        let poly_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Polynomial Buffer"),
            contents: bytemuck::cast_slice(polynomials),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
        });
        
        let params = [batch_size as u32, is_inverse as u32, 0, 0];
        let params_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Parameters Buffer"),
            contents: bytemuck::cast_slice(&params),
            usage: wgpu::BufferUsages::STORAGE,
        });
        
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("NTT Bind Group"),
            layout: &self.bind_group_layout,
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
                    resource: self.zetas_buffer.as_entire_binding(),
                },
            ],
        });
        
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("NTT Command Encoder"),
        });
        
        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("NTT Compute Pass"),
                timestamp_writes: None,
            });
            
            compute_pass.set_pipeline(&self.ntt_pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            compute_pass.dispatch_workgroups(batch_size as u32, 1, 1);
        }
        
        // Create staging buffer for readback
        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
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
        
        self.queue.submit(std::iter::once(encoder.finish()));
        
        // Map buffer and read results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            tx.send(result).unwrap();
        });
        
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv().unwrap().map_err(|e| super::device::GpuError::InitFailed(format!("{:?}", e)))?;
        
        {
            let data = buffer_slice.get_mapped_range();
            polynomials.copy_from_slice(bytemuck::cast_slice(&data));
        }
        
        staging_buffer.unmap();
        
        Ok(())
    }
    
    /// Perform batch NTT operations in parallel
    pub fn batch_transform(&self, batches: Vec<Vec<u32>>, is_inverse: bool) -> Result<Vec<Vec<u32>>, super::device::GpuError> {
        let mut results = Vec::new();
        
        for mut batch in batches {
            let batch_size = batch.len() / (N as usize);
            self.transform(&mut batch, batch_size, is_inverse)?;
            results.push(batch);
        }
        
        Ok(results)
    }
}
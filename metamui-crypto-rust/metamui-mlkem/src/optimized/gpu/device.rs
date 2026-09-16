//! GPU device management for ML-KEM-768
//!
//! Provides cross-platform GPU device initialization and capability detection.

use wgpu::{Adapter, Device, Queue, AdapterInfo, Features, Limits};
use wgpu::util::DeviceExt;

/// GPU-specific errors
#[derive(Debug)]
pub enum GpuError {
    /// GPU not available
    NotAvailable,
    /// Initialization failed
    InitFailed(String),
    /// Pipeline creation failed
    PipelineFailed(String),
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::NotAvailable => write!(f, "GPU not available"),
            GpuError::InitFailed(msg) => write!(f, "GPU initialization failed: {}", msg),
            GpuError::PipelineFailed(msg) => write!(f, "Pipeline creation failed: {}", msg),
        }
    }
}

impl std::error::Error for GpuError {}

type Result<T> = std::result::Result<T, GpuError>;

/// GPU device capabilities
#[derive(Debug, Clone)]
pub struct DeviceCapabilities {
    /// Device name
    pub name: String,
    /// Backend type (Vulkan, Metal, DX12, WebGPU)
    pub backend: wgpu::Backend,
    /// Maximum workgroup size
    pub max_workgroup_size: u32,
    /// Maximum buffer size
    pub max_buffer_size: u64,
    /// Supports f16 operations
    pub supports_f16: bool,
    /// Supports timestamp queries
    pub supports_timestamps: bool,
    /// Number of compute units (estimated)
    pub compute_units: u32,
    /// Memory bandwidth (GB/s, estimated)
    pub memory_bandwidth: f32,
}

/// NTT pipeline components
pub struct NttPipeline {
    pub forward_pipeline: wgpu::ComputePipeline,
    pub mega_batch_pipeline: wgpu::ComputePipeline,
    pub bind_group_layout: wgpu::BindGroupLayout,
    pub zetas_buffer: wgpu::Buffer,
}

/// Polynomial operations pipeline components
pub struct PolyOpsPipeline {
    pub batch_ops_pipeline: wgpu::ComputePipeline,
    pub basemul_pipeline: wgpu::ComputePipeline,
    pub matrix_vector_pipeline: wgpu::ComputePipeline,
    pub bind_group_layout: wgpu::BindGroupLayout,
}

/// GPU device wrapper with ML-KEM specific optimizations
pub struct GpuDevice {
    device: Device,
    queue: Queue,
    adapter: Adapter,
    adapter_info: AdapterInfo,
    capabilities: DeviceCapabilities,
}

impl GpuDevice {
    /// Create a new GPU device with automatic selection
    pub fn new() -> Result<Self> {
        pollster::block_on(Self::init())
    }
    
    /// Initialize GPU device asynchronously
    async fn init() -> Result<Self> {
        // Create wgpu instance with all backends
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });
        
        // Request high-performance adapter
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or_else(|| GpuError::NotAvailable)?;
        
        let adapter_info = adapter.get_info();
        let features = adapter.features();
        let limits = adapter.limits();
        
        log::info!("GPU Adapter: {} ({:?})", adapter_info.name, adapter_info.backend);
        
        // Request device with required features for ML-KEM
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    required_features: Features::empty(),
                    required_limits: Limits {
                        max_compute_invocations_per_workgroup: 256,
                        max_compute_workgroup_size_x: 256,
                        max_compute_workgroup_size_y: 256,
                        max_compute_workgroup_size_z: 64,
                        max_compute_workgroups_per_dimension: 65535,
                        max_buffer_size: 256 * 1024 * 1024, // 256MB minimum
                        max_storage_buffer_binding_size: 128 * 1024 * 1024,
                        ..Default::default()
                    },
                    label: Some("ML-KEM-768 GPU Device"),
                },
                None,
            )
            .await
            .map_err(|e| GpuError::InitFailed(format!("{}", e)))?;
        
        // Detect capabilities
        let capabilities = Self::detect_capabilities(&adapter_info, &features, &limits);
        
        Ok(Self {
            device,
            queue,
            adapter,
            adapter_info,
            capabilities,
        })
    }
    
    /// Create device with specific backend preference
    pub async fn with_backend(backend: wgpu::Backends) -> Result<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: backend,
            ..Default::default()
        });
        
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or_else(|| GpuError::NotAvailable)?;
        
        let adapter_info = adapter.get_info();
        let features = adapter.features();
        let limits = adapter.limits();
        
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    required_features: Features::empty(),
                    required_limits: Limits::default(),
                    label: Some("ML-KEM-768 GPU Device"),
                },
                None,
            )
            .await
            .map_err(|e| GpuError::InitFailed(format!("{}", e)))?;
        
        let capabilities = Self::detect_capabilities(&adapter_info, &features, &limits);
        
        Ok(Self {
            device,
            queue,
            adapter,
            adapter_info,
            capabilities,
        })
    }
    
    /// Detect device capabilities
    fn detect_capabilities(
        info: &AdapterInfo,
        features: &Features,
        limits: &Limits,
    ) -> DeviceCapabilities {
        // Estimate compute units and memory bandwidth based on backend and device
        let (compute_units, memory_bandwidth) = match info.backend {
            wgpu::Backend::Metal => {
                // Apple Silicon optimizations
                if info.name.contains("M1") {
                    (8, 68.0) // M1: 8 GPU cores, 68 GB/s
                } else if info.name.contains("M2") {
                    (10, 100.0) // M2: 10 GPU cores, 100 GB/s
                } else if info.name.contains("M3") {
                    (10, 150.0) // M3: 10 GPU cores, 150 GB/s
                } else if info.name.contains("Pro") {
                    (16, 200.0) // M1/M2/M3 Pro: 16 GPU cores, 200 GB/s
                } else if info.name.contains("Max") {
                    (32, 400.0) // M1/M2/M3 Max: 32 GPU cores, 400 GB/s
                } else if info.name.contains("Ultra") {
                    (64, 800.0) // M1/M2 Ultra: 64 GPU cores, 800 GB/s
                } else {
                    (8, 50.0) // Conservative estimate
                }
            }
            wgpu::Backend::Vulkan | wgpu::Backend::Dx12 => {
                // NVIDIA/AMD GPUs
                if info.name.contains("RTX 4090") {
                    (16384, 1008.0)
                } else if info.name.contains("RTX 4080") {
                    (9728, 716.0)
                } else if info.name.contains("RTX 4070") {
                    (5888, 504.0)
                } else if info.name.contains("RTX 3090") {
                    (10496, 936.0)
                } else if info.name.contains("RTX 3080") {
                    (8704, 760.0)
                } else if info.name.contains("RX 7900") {
                    (12288, 960.0)
                } else if info.name.contains("RX 7800") {
                    (7680, 624.0)
                } else {
                    (2048, 200.0) // Conservative estimate
                }
            }
            _ => (1024, 100.0), // WebGPU or other backends
        };
        
        DeviceCapabilities {
            name: info.name.clone(),
            backend: info.backend,
            max_workgroup_size: limits.max_compute_workgroup_size_x,
            max_buffer_size: limits.max_buffer_size,
            supports_f16: features.contains(Features::SHADER_F16),
            supports_timestamps: features.contains(Features::TIMESTAMP_QUERY),
            compute_units,
            memory_bandwidth,
        }
    }
    
    /// Check if GPU is available
    pub fn is_available() -> bool {
        pollster::block_on(Self::check_availability())
    }
    
    async fn check_availability() -> bool {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });
        
        instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .is_some()
    }
    
    /// Get device handle
    pub fn device(&self) -> &Device {
        &self.device
    }
    
    /// Get queue handle
    pub fn queue(&self) -> &Queue {
        &self.queue
    }
    
    /// Get adapter info
    pub fn adapter_info(&self) -> &AdapterInfo {
        &self.adapter_info
    }
    
    /// Get device capabilities
    pub fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }
    
    /// Create compute shader module
    pub fn create_shader_module(&self, source: &str) -> wgpu::ShaderModule {
        self.device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("ML-KEM Compute Shader"),
            source: wgpu::ShaderSource::Wgsl(source.into()),
        })
    }
    
    /// Create NTT compute pipeline
    pub fn create_ntt_pipeline(&self) -> Result<NttPipeline> {
        let ntt_source = include_str!("kernels/ntt.wgsl");
        let ntt_module = self.create_shader_module(ntt_source);
        
        // Create bind group layout for NTT
        let bind_group_layout = self.device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("NTT Bind Group Layout"),
            entries: &[
                // Polynomials buffer
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
                // Parameters buffer
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
                // Zetas buffer
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
        
        let pipeline_layout = self.device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("NTT Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        
        // Create compute pipelines for different entry points
        let ntt_forward = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("NTT Forward Pipeline"),
            layout: Some(&pipeline_layout),
            module: &ntt_module,
            entry_point: "ntt_batch_process",
            compilation_options: Default::default(),
        });
        
        let ntt_mega_batch = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("NTT Mega Batch Pipeline"),
            layout: Some(&pipeline_layout),
            module: &ntt_module,
            entry_point: "ntt_mega_batch",
            compilation_options: Default::default(),
        });
        
        // Initialize zetas buffer with precomputed values
        let zetas_data = Self::generate_zetas();
        let zetas_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Zetas Buffer"),
            contents: bytemuck::cast_slice(&zetas_data),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });
        
        Ok(NttPipeline {
            forward_pipeline: ntt_forward,
            mega_batch_pipeline: ntt_mega_batch,
            bind_group_layout,
            zetas_buffer,
        })
    }
    
    /// Create polynomial operations pipeline
    pub fn create_poly_ops_pipeline(&self) -> Result<PolyOpsPipeline> {
        let poly_ops_source = include_str!("kernels/poly_ops.wgsl");
        let poly_ops_module = self.create_shader_module(poly_ops_source);
        
        // Create bind group layout for polynomial operations
        let bind_group_layout = self.device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Poly Ops Bind Group Layout"),
            entries: &[
                // Input polynomial A
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // Input polynomial B
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
                // Result polynomial
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // Parameters
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
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
        
        let pipeline_layout = self.device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Poly Ops Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });
        
        // Create pipelines for different operations
        let batch_ops = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Poly Batch Ops Pipeline"),
            layout: Some(&pipeline_layout),
            module: &poly_ops_module,
            entry_point: "poly_batch_ops_fast",
            compilation_options: Default::default(),
        });
        
        let basemul = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Poly Basemul Pipeline"),
            layout: Some(&pipeline_layout),
            module: &poly_ops_module,
            entry_point: "poly_basemul",
            compilation_options: Default::default(),
        });
        
        let matrix_vector = self.device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Matrix Vector Mul Pipeline"),
            layout: Some(&pipeline_layout),
            module: &poly_ops_module,
            entry_point: "matrix_vector_mul_optimized",
            compilation_options: Default::default(),
        });
        
        Ok(PolyOpsPipeline {
            batch_ops_pipeline: batch_ops,
            basemul_pipeline: basemul,
            matrix_vector_pipeline: matrix_vector,
            bind_group_layout,
        })
    }
    
    /// Generate zetas for NTT
    fn generate_zetas() -> [u32; 128] {
        // Precomputed zetas in Montgomery form for ML-KEM
        [
            2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
            3158, 622, 1577, 182, 962, 2127, 1855, 1468,
            573, 2004, 264, 383, 2500, 1458, 1727, 3199,
            2648, 1017, 732, 608, 1787, 411, 3124, 1758,
            1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
            516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
            2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
            2931, 961, 1821, 2604, 448, 2264, 677, 2054,
            2226, 430, 555, 843, 2078, 871, 1550, 105,
            422, 587, 177, 3094, 3038, 2869, 1574, 1653,
            3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
            1739, 644, 2457, 349, 418, 329, 3173, 3254,
            817, 1097, 603, 610, 1322, 2044, 1864, 384,
            2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
            2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
            3221, 3021, 996, 991, 958, 1869, 1522, 1628,
        ]
    }
    
    /// Submit command buffer
    pub fn submit(&self, commands: impl IntoIterator<Item = wgpu::CommandBuffer>) {
        self.queue.submit(commands);
    }
    
    /// Wait for all operations to complete
    pub fn wait(&self) {
        self.device.poll(wgpu::Maintain::Wait);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gpu_availability() {
        let available = GpuDevice::is_available();
        println!("GPU available: {}", available);
        
        if available {
            let device = GpuDevice::new();
            assert!(device.is_ok());
            
            if let Ok(device) = device {
                let caps = device.capabilities();
                println!("GPU: {}", caps.name);
                println!("Backend: {:?}", caps.backend);
                println!("Compute units: {}", caps.compute_units);
                println!("Memory bandwidth: {} GB/s", caps.memory_bandwidth);
            }
        }
    }
}
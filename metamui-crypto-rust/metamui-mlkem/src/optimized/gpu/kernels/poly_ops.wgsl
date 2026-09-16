// ML-KEM Polynomial Operations - WebGPU Compute Shader
// Implements polynomial arithmetic operations for ML-KEM-768
// Optimized for batch processing with shared memory and vectorization

const Q: u32 = 3329u;
const N: u32 = 256u;
const WORKGROUP_SIZE: u32 = 128u;
const BARRETT_SHIFT: u32 = 26u;
const BARRETT_MULT: u32 = 20159u;
const MONT_R: u32 = 2285u;
const MONT_R2: u32 = 1353u;
const Q_INV: u32 = 62209u;
const N_INV_MONT: u32 = 3303u;

// Shared memory for optimized access patterns
var<workgroup> shared_a: array<u32, 256>;
var<workgroup> shared_b: array<u32, 256>;
var<workgroup> shared_result: array<u32, 256>;

// Storage buffers for polynomial operations
@group(0) @binding(0) var<storage, read> poly_a: array<u32>;
@group(0) @binding(1) var<storage, read> poly_b: array<u32>;
@group(0) @binding(2) var<storage, read_write> poly_result: array<u32>;
@group(0) @binding(3) var<storage, read> params: array<u32>; // [batch_size, operation_type, stride, flags]

// Operation types
const OP_ADD: u32 = 0u;
const OP_SUB: u32 = 1u;
const OP_MUL: u32 = 2u;
const OP_POINTWISE_MUL: u32 = 3u;
const OP_REDUCE: u32 = 4u;
const OP_TO_MONT: u32 = 5u;
const OP_FROM_MONT: u32 = 6u;
const OP_BASEMUL: u32 = 7u;
const OP_BASEMUL_ACC: u32 = 8u;

// Barrett reduction
fn barrett_reduce(a: u32) -> u32 {
    let t = (a * BARRETT_MULT) >> BARRETT_SHIFT;
    let r = a - t * Q;
    return select(r, r - Q, r >= Q);
}

// Montgomery reduction
fn montgomery_reduce(a: u32) -> u32 {
    let t = (a * Q_INV) & 0xFFFFu;
    let m = t * Q;
    return (a + m) >> 16u;
}

// Montgomery multiplication
fn montgomery_multiply(a: u32, b: u32) -> u32 {
    let product = a * b;
    return montgomery_reduce(product);
}

// Convert to Montgomery form
fn to_montgomery(a: u32) -> u32 {
    return montgomery_multiply(a, MONT_R2);
}

// Convert from Montgomery form
fn from_montgomery(a: u32) -> u32 {
    return montgomery_reduce(a);
}

// Conditional subtraction for reduction
fn cond_sub(a: u32) -> u32 {
    return select(a, a - Q, a >= Q);
}

// Modular addition
fn mod_add(a: u32, b: u32) -> u32 {
    let sum = a + b;
    return cond_sub(sum);
}

// Modular subtraction
fn mod_sub(a: u32, b: u32) -> u32 {
    let diff = a + Q - b;
    return cond_sub(diff);
}

// Polynomial addition kernel
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_add(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let a = poly_a[idx];
    let b = poly_b[idx];
    poly_result[idx] = mod_add(a, b);
}

// Polynomial subtraction kernel
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_sub(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let a = poly_a[idx];
    let b = poly_b[idx];
    poly_result[idx] = mod_sub(a, b);
}

// Pointwise multiplication kernel (for NTT domain)
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_pointwise_mul(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let a = poly_a[idx];
    let b = poly_b[idx];
    poly_result[idx] = montgomery_multiply(a, b);
}

// Batch polynomial multiplication (requires NTT)
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_mul_batch(@builtin(global_invocation_id) global_id: vec3<u32>,
                  @builtin(workgroup_id) workgroup_id: vec3<u32>) {
    let batch_idx = workgroup_id.x;
    let batch_size = params[0];
    
    if (batch_idx >= batch_size) {
        return;
    }
    
    let thread_idx = global_id.x % WORKGROUP_SIZE;
    let base_offset = batch_idx * N;
    
    // This assumes inputs are already in NTT domain
    // Perform pointwise multiplication
    for (var i = thread_idx; i < N; i = i + WORKGROUP_SIZE) {
        let idx = base_offset + i;
        let a = poly_a[idx];
        let b = poly_b[idx];
        poly_result[idx] = montgomery_multiply(a, b);
    }
}

// Coefficient reduction kernel
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_reduce(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let val = poly_a[idx];
    poly_result[idx] = barrett_reduce(val);
}

// Convert polynomial to Montgomery form
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_to_montgomery(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let val = poly_a[idx];
    poly_result[idx] = to_montgomery(val);
}

// Convert polynomial from Montgomery form
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_from_montgomery(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let batch_size = params[0];
    let idx = global_id.x;
    
    if (idx >= batch_size * N) {
        return;
    }
    
    let val = poly_a[idx];
    poly_result[idx] = from_montgomery(val);
}

// Batch operation selector
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_batch_op(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let operation = params[1];
    
    switch(operation) {
        case OP_ADD: {
            poly_add(global_id);
        }
        case OP_SUB: {
            poly_sub(global_id);
        }
        case OP_POINTWISE_MUL: {
            poly_pointwise_mul(global_id);
        }
        case OP_REDUCE: {
            poly_reduce(global_id);
        }
        case OP_TO_MONT: {
            poly_to_montgomery(global_id);
        }
        case OP_FROM_MONT: {
            poly_from_montgomery(global_id);
        }
        default: {
            // Invalid operation, do nothing
        }
    }
}

// Optimized base multiplication (for NTT domain)
fn basemul(a0: u32, a1: u32, b0: u32, b1: u32, zeta: u32) -> vec2<u32> {
    let r0 = montgomery_multiply(a1, b1);
    let r0_scaled = montgomery_multiply(r0, zeta);
    let r0_final = mod_add(montgomery_multiply(a0, b0), r0_scaled);
    
    let r1 = montgomery_multiply(a0, b1);
    let r1_partial = mod_add(r1, montgomery_multiply(a1, b0));
    
    return vec2<u32>(r0_final, r1_partial);
}

// Vectorized polynomial base multiplication
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_basemul(@builtin(global_invocation_id) global_id: vec3<u32>,
               @builtin(workgroup_id) workgroup_id: vec3<u32>,
               @builtin(local_invocation_id) local_id: vec3<u32>) {
    let batch_size = params[0];
    let poly_idx = workgroup_id.x;
    
    if (poly_idx >= batch_size) {
        return;
    }
    
    let base_offset = poly_idx * N;
    let thread_idx = local_id.x;
    
    // Load zeta values for base multiplication
    let zeta1 = 2285u; // Example zeta value
    let zeta2 = 2571u;
    
    // Each thread processes 2 coefficient pairs
    for (var i = thread_idx * 4u; i < N; i = i + WORKGROUP_SIZE * 4u) {
        if (i < N) {
            let a0 = poly_a[base_offset + i];
            let a1 = poly_a[base_offset + i + 1u];
            let b0 = poly_b[base_offset + i];
            let b1 = poly_b[base_offset + i + 1u];
            
            let result = basemul(a0, a1, b0, b1, zeta1);
            
            poly_result[base_offset + i] = result.x;
            poly_result[base_offset + i + 1u] = result.y;
            
            if (i + 2u < N) {
                let a2 = poly_a[base_offset + i + 2u];
                let a3 = poly_a[base_offset + i + 3u];
                let b2 = poly_b[base_offset + i + 2u];
                let b3 = poly_b[base_offset + i + 3u];
                
                let result2 = basemul(a2, a3, b2, b3, zeta2);
                
                poly_result[base_offset + i + 2u] = result2.x;
                poly_result[base_offset + i + 3u] = result2.y;
            }
        }
    }
}

// Ultra-fast batch polynomial operations using shared memory
@compute @workgroup_size(256u)
fn poly_batch_ops_fast(@builtin(global_invocation_id) global_id: vec3<u32>,
                      @builtin(workgroup_id) workgroup_id: vec3<u32>,
                      @builtin(local_invocation_id) local_id: vec3<u32>) {
    let batch_size = params[0];
    let operation = params[1];
    let stride = params[2];
    
    let batch_idx = workgroup_id.x;
    if (batch_idx >= batch_size) {
        return;
    }
    
    let thread_idx = local_id.x;
    let base_offset = batch_idx * N;
    
    // Load data into shared memory (coalesced access)
    if (thread_idx < N) {
        shared_a[thread_idx] = poly_a[base_offset + thread_idx];
        shared_b[thread_idx] = poly_b[base_offset + thread_idx];
    }
    
    workgroupBarrier();
    
    // Perform operation
    if (thread_idx < N) {
        var result: u32;
        let a = shared_a[thread_idx];
        let b = shared_b[thread_idx];
        
        switch(operation) {
            case OP_ADD: {
                result = mod_add(a, b);
            }
            case OP_SUB: {
                result = mod_sub(a, b);
            }
            case OP_POINTWISE_MUL: {
                result = montgomery_multiply(a, b);
            }
            case OP_REDUCE: {
                result = barrett_reduce(a);
            }
            case OP_TO_MONT: {
                result = to_montgomery(a);
            }
            case OP_FROM_MONT: {
                result = from_montgomery(a);
            }
            default: {
                result = a;
            }
        }
        
        shared_result[thread_idx] = result;
    }
    
    workgroupBarrier();
    
    // Write results back to global memory (coalesced)
    if (thread_idx < N) {
        poly_result[base_offset + thread_idx] = shared_result[thread_idx];
    }
}

// Matrix-vector multiplication for ML-KEM-768 (k=3)
@compute @workgroup_size(128u)
fn matrix_vector_mul_optimized(@builtin(global_invocation_id) global_id: vec3<u32>,
                              @builtin(workgroup_id) workgroup_id: vec3<u32>,
                              @builtin(local_invocation_id) local_id: vec3<u32>) {
    const k: u32 = 3u; // ML-KEM-768 has k=3
    let batch_idx = workgroup_id.x / k;
    let row = workgroup_id.x % k;
    let batch_size = params[0];
    
    if (batch_idx >= batch_size) {
        return;
    }
    
    let thread_idx = local_id.x;
    let base_offset = batch_idx * k * k * N;
    
    // Initialize accumulator in shared memory
    if (thread_idx * 2u < N) {
        shared_result[thread_idx * 2u] = 0u;
        shared_result[thread_idx * 2u + 1u] = 0u;
    }
    
    workgroupBarrier();
    
    // Compute matrix-vector product for this row
    for (var col = 0u; col < k; col = col + 1u) {
        // Load matrix and vector elements
        if (thread_idx * 2u < N) {
            let mat_offset = base_offset + (row * k + col) * N;
            let vec_offset = base_offset + (k * k + col) * N;
            
            shared_a[thread_idx * 2u] = poly_a[mat_offset + thread_idx * 2u];
            shared_a[thread_idx * 2u + 1u] = poly_a[mat_offset + thread_idx * 2u + 1u];
            shared_b[thread_idx * 2u] = poly_b[vec_offset + thread_idx * 2u];
            shared_b[thread_idx * 2u + 1u] = poly_b[vec_offset + thread_idx * 2u + 1u];
        }
        
        workgroupBarrier();
        
        // Perform pointwise multiplication and accumulation
        if (thread_idx * 2u < N) {
            let prod0 = montgomery_multiply(shared_a[thread_idx * 2u], shared_b[thread_idx * 2u]);
            let prod1 = montgomery_multiply(shared_a[thread_idx * 2u + 1u], shared_b[thread_idx * 2u + 1u]);
            
            shared_result[thread_idx * 2u] = mod_add(shared_result[thread_idx * 2u], prod0);
            shared_result[thread_idx * 2u + 1u] = mod_add(shared_result[thread_idx * 2u + 1u], prod1);
        }
        
        workgroupBarrier();
    }
    
    // Write final result to global memory
    if (thread_idx * 2u < N) {
        let res_offset = base_offset + row * N;
        poly_result[res_offset + thread_idx * 2u] = shared_result[thread_idx * 2u];
        poly_result[res_offset + thread_idx * 2u + 1u] = shared_result[thread_idx * 2u + 1u];
    }
}

// Batch polynomial multiplication with accumulation
@compute @workgroup_size(WORKGROUP_SIZE)
fn poly_basemul_acc(@builtin(global_invocation_id) global_id: vec3<u32>,
                   @builtin(workgroup_id) workgroup_id: vec3<u32>,
                   @builtin(local_invocation_id) local_id: vec3<u32>) {
    let batch_size = params[0];
    let num_polys = params[2]; // Number of polynomials to multiply and accumulate
    let batch_idx = workgroup_id.x;
    
    if (batch_idx >= batch_size) {
        return;
    }
    
    let thread_idx = local_id.x;
    let base_offset = batch_idx * num_polys * N;
    
    // Initialize accumulator
    for (var i = thread_idx * 2u; i < N; i = i + WORKGROUP_SIZE * 2u) {
        if (i < N) {
            poly_result[batch_idx * N + i] = 0u;
            if (i + 1u < N) {
                poly_result[batch_idx * N + i + 1u] = 0u;
            }
        }
    }
    
    workgroupBarrier();
    
    // Multiply and accumulate
    for (var p = 0u; p < num_polys / 2u; p = p + 1u) {
        let a_offset = base_offset + p * 2u * N;
        let b_offset = base_offset + (p * 2u + 1u) * N;
        
        for (var i = thread_idx * 2u; i < N; i = i + WORKGROUP_SIZE * 2u) {
            if (i < N) {
                let a0 = poly_a[a_offset + i];
                let a1 = poly_a[a_offset + i + 1u];
                let b0 = poly_b[b_offset + i];
                let b1 = poly_b[b_offset + i + 1u];
                
                let prod0 = montgomery_multiply(a0, b0);
                let prod1 = montgomery_multiply(a1, b1);
                
                let res_idx = batch_idx * N + i;
                poly_result[res_idx] = mod_add(poly_result[res_idx], prod0);
                poly_result[res_idx + 1u] = mod_add(poly_result[res_idx + 1u], prod1);
            }
        }
    }
}
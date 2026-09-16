/**
 * Falcon NTT Metal GPU Compute Kernels
 *
 * Forward/inverse NTT over Z_q[x]/(x^n+1) where q = 12289
 * using Montgomery arithmetic for branchless modular reduction.
 *
 * Batch verification kernel: each thread group verifies one signature.
 *
 * Optimized for Apple Silicon (M1/M2/M3/M4) unified memory architecture.
 */

#include <metal_stdlib>
using namespace metal;

// ================================================================
// Falcon NTT constants
// ================================================================

constant uint NTT_Q        = 12289;       // Falcon prime
constant uint NTT_QHALF    = 6144;        // (q-1)/2
constant uint MONT_R       = 65536;       // R = 2^16
constant uint MONT_QINV    = 12287;       // -q^{-1} mod R = 12287
constant uint MONT_R2MODQ  = 10952;       // R^2 mod q

// Polynomial sizes
constant uint FALCON512_N  = 512;
constant uint FALCON512_LOGN = 9;
constant uint FALCON1024_N = 1024;
constant uint FALCON1024_LOGN = 10;

// Norm bound: beta^2 for Falcon-512
constant long BETA_SQ_512 = 34034726;

// ================================================================
// Montgomery arithmetic (branchless, constant-time)
// ================================================================

/// Montgomery reduction: T -> T * R^{-1} mod q
/// Input: 0 <= T < q * R
/// Output: 0 <= result < q
inline uint mont_reduce(uint t) {
    uint m = (t * MONT_QINV) & 0xFFFF;  // m = t * (-q^{-1}) mod R
    uint u = (t + m * NTT_Q) >> 16;      // u = (t + m*q) / R
    return (u >= NTT_Q) ? (u - NTT_Q) : u;
}

/// Montgomery multiply: a * b * R^{-1} mod q
inline uint mont_mul(uint a, uint b) {
    return mont_reduce(a * b);
}

/// Convert to Montgomery form: a * R mod q
inline uint to_mont(uint a) {
    return mont_mul(a, MONT_R2MODQ);
}

/// Convert from Montgomery form: a * R^{-1} mod q
inline uint from_mont(uint a) {
    return mont_reduce(a);
}

/// Modular add: (a + b) mod q (branchless)
inline uint addmod(uint a, uint b) {
    uint s = a + b;
    return (s >= NTT_Q) ? (s - NTT_Q) : s;
}

/// Modular sub: (a - b) mod q (branchless)
inline uint submod(uint a, uint b) {
    uint d = a + NTT_Q - b;
    return (d >= NTT_Q) ? (d - NTT_Q) : d;
}

// ================================================================
// NTT Forward: Cooley-Tukey butterfly
//
// For batch operations, each thread group processes one polynomial.
// Thread ID within group = butterfly index within the current layer.
// ================================================================

/**
 * Forward NTT for one polynomial.
 *
 * Buffers:
 *   [0] poly_buffer:   array of batch_size * n uint16 coefficients
 *   [1] twiddle_buffer: precomputed twiddle factors in Montgomery form (n uint32)
 *   [2] params_buffer:  { n (uint32), logn (uint32), batch_size (uint32) }
 *
 * Each thread group processes one polynomial from the batch.
 * Threadgroup ID = polynomial index within the batch.
 * Threads within group cooperate on butterfly layers.
 */
kernel void falcon_ntt_forward(
    device uint16_t*       poly_buffer    [[buffer(0)]],
    const device uint32_t* twiddle_buffer [[buffer(1)]],
    const device uint32_t* params_buffer  [[buffer(2)]],
    uint gid                              [[thread_position_in_grid]],
    uint tid                              [[thread_position_in_threadgroup]],
    uint tg_id                            [[threadgroup_position_in_grid]],
    uint tg_size                          [[threads_per_threadgroup]])
{
    uint n     = params_buffer[0];
    uint logn  = params_buffer[1];
    uint batch = params_buffer[2];

    if (tg_id >= batch) return;

    // Pointer to this polynomial's coefficients
    device uint16_t* poly = poly_buffer + tg_id * n;

    // Load into threadgroup shared memory (Montgomery form)
    threadgroup uint shared_poly[1024];  // max Falcon-1024

    uint elems_per_thread = (n + tg_size - 1) / tg_size;
    for (uint i = 0; i < elems_per_thread; i++) {
        uint idx = tid + i * tg_size;
        if (idx < n) {
            shared_poly[idx] = to_mont((uint)poly[idx]);
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Butterfly layers: Cooley-Tukey, decimation-in-time
    uint tw_idx = 0;
    for (uint layer = 0; layer < logn; layer++) {
        uint half_len = 1u << (logn - 1 - layer);  // distance between butterfly pairs
        uint groups = 1u << layer;                   // number of butterfly groups

        for (uint i = tid; i < n / 2; i += tg_size) {
            uint group = i / half_len;
            uint j = i % half_len;
            uint u_idx = group * 2 * half_len + j;
            uint v_idx = u_idx + half_len;

            uint w = twiddle_buffer[tw_idx + group];
            uint u = shared_poly[u_idx];
            uint v = mont_mul(shared_poly[v_idx], w);

            shared_poly[u_idx] = addmod(u, v);
            shared_poly[v_idx] = submod(u, v);
        }
        tw_idx += groups;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Write back (convert from Montgomery)
    for (uint i = 0; i < elems_per_thread; i++) {
        uint idx = tid + i * tg_size;
        if (idx < n) {
            uint val = from_mont(shared_poly[idx]);
            poly[idx] = (uint16_t)val;
        }
    }
}

/**
 * Inverse NTT: Gentleman-Sande butterfly (reversed layer order).
 *
 * Same buffer layout as forward NTT.
 */
kernel void falcon_ntt_inverse(
    device uint16_t*       poly_buffer    [[buffer(0)]],
    const device uint32_t* twiddle_buffer [[buffer(1)]],
    const device uint32_t* params_buffer  [[buffer(2)]],
    uint gid                              [[thread_position_in_grid]],
    uint tid                              [[thread_position_in_threadgroup]],
    uint tg_id                            [[threadgroup_position_in_grid]],
    uint tg_size                          [[threads_per_threadgroup]])
{
    uint n     = params_buffer[0];
    uint logn  = params_buffer[1];
    uint batch = params_buffer[2];

    if (tg_id >= batch) return;

    device uint16_t* poly = poly_buffer + tg_id * n;

    threadgroup uint shared_poly[1024];

    uint elems_per_thread = (n + tg_size - 1) / tg_size;
    for (uint i = 0; i < elems_per_thread; i++) {
        uint idx = tid + i * tg_size;
        if (idx < n) {
            shared_poly[idx] = to_mont((uint)poly[idx]);
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Inverse butterfly: reversed layer order with inverse twiddle factors
    uint tw_idx = 0;
    for (uint layer = logn; layer > 0; layer--) {
        uint half_len = 1u << (layer - 1);
        uint groups = 1u << (logn - layer);

        for (uint i = tid; i < n / 2; i += tg_size) {
            uint group = i / half_len;
            uint j = i % half_len;
            uint u_idx = group * 2 * half_len + j;
            uint v_idx = u_idx + half_len;

            uint w = twiddle_buffer[tw_idx + group];
            uint u = shared_poly[u_idx];
            uint v = shared_poly[v_idx];

            shared_poly[u_idx] = addmod(u, v);
            shared_poly[v_idx] = mont_mul(submod(u, v), w);
        }
        tw_idx += groups;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Scale by n^{-1} mod q and write back
    uint n_inv = twiddle_buffer[tw_idx];  // n^{-1} in Montgomery form
    for (uint i = 0; i < elems_per_thread; i++) {
        uint idx = tid + i * tg_size;
        if (idx < n) {
            uint val = mont_mul(shared_poly[idx], n_inv);
            val = from_mont(val);
            poly[idx] = (uint16_t)val;
        }
    }
}

/**
 * Pointwise polynomial multiply: c = a * b mod q
 *
 * Input NTT-domain polynomials, output NTT-domain product.
 * Each thread processes one coefficient (embarrassingly parallel).
 *
 * Buffers:
 *   [0] a_buffer: batch_size * n uint16 (NTT domain)
 *   [1] b_buffer: batch_size * n uint16 (NTT domain)
 *   [2] c_buffer: batch_size * n uint16 (output)
 *   [3] params:   { n, batch_size }
 */
kernel void falcon_pointwise_mul(
    const device uint16_t* a_buffer     [[buffer(0)]],
    const device uint16_t* b_buffer     [[buffer(1)]],
    device uint16_t*       c_buffer     [[buffer(2)]],
    const device uint32_t* params       [[buffer(3)]],
    uint gid                            [[thread_position_in_grid]])
{
    uint n     = params[0];
    uint batch = params[1];
    uint total = n * batch;

    if (gid >= total) return;

    uint a = to_mont((uint)a_buffer[gid]);
    uint b = to_mont((uint)b_buffer[gid]);
    uint c = mont_mul(a, b);
    c_buffer[gid] = (uint16_t)from_mont(c);
}

// ================================================================
// Batch Verification Kernel
//
// Each thread group verifies one complete Falcon-512 signature:
//   1. Compute s0 = c - s1*h (mod q) via NTT
//   2. Check ||s0||^2 + ||s1||^2 < beta^2
//
// This is embarrassingly parallel across signatures.
// ================================================================

/**
 * Batch signature norm check.
 *
 * The CPU pre-computes s0 = c - NTT(s1·h) (using SIMD-optimized NTT multiply),
 * then this kernel checks ||s0||² + ||s1||² < β² in parallel across signatures.
 *
 * This hybrid approach is optimal because:
 *   - CPU SIMD (AVX2/NEON) excels at NTT polynomial multiplication
 *   - GPU excels at parallel norm reduction across hundreds of signatures
 *
 * Buffers:
 *   [0] s0_buffer:     batch * n int16 (pre-computed s0 per signature)
 *   [1] s1_buffer:     batch * n int16 (decompressed s1 per signature)
 *   [2] result_buffer: batch uint32 (1 = valid, 0 = invalid)
 *   [3] params:        { n (uint32), batch_size (uint32) }
 *
 * Each threadgroup processes one signature.
 */
kernel void falcon_batch_verify(
    const device int16_t*  s0_buffer     [[buffer(0)]],
    const device int16_t*  s1_buffer     [[buffer(1)]],
    device uint32_t*       result_buffer [[buffer(2)]],
    const device uint32_t* params        [[buffer(3)]],
    uint tid                             [[thread_position_in_threadgroup]],
    uint tg_id                           [[threadgroup_position_in_grid]],
    uint tg_size                         [[threads_per_threadgroup]])
{
    uint n     = params[0];
    uint batch = params[1];

    if (tg_id >= batch) return;

    // Pointers to this signature's data
    const device int16_t* s0 = s0_buffer + tg_id * n;
    const device int16_t* s1 = s1_buffer + tg_id * n;

    // Accumulate ||s0||² + ||s1||² per thread stripe
    threadgroup long partial_norms[256];  // one per thread
    long my_norm = 0;

    uint elems_per_thread = (n + tg_size - 1) / tg_size;
    for (uint i = 0; i < elems_per_thread; i++) {
        uint idx = tid + i * tg_size;
        if (idx < n) {
            long s0_val = (long)s0[idx];
            long s1_val = (long)s1[idx];
            my_norm += s0_val * s0_val + s1_val * s1_val;
        }
    }

    partial_norms[tid] = my_norm;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    // Parallel reduction to sum norms
    for (uint stride = tg_size / 2; stride > 0; stride >>= 1) {
        if (tid < stride) {
            partial_norms[tid] += partial_norms[tid + stride];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Thread 0 writes result
    if (tid == 0) {
        result_buffer[tg_id] = (partial_norms[0] <= BETA_SQ_512) ? 1 : 0; // floor(beta^2) is accepted (#352)
    }
}

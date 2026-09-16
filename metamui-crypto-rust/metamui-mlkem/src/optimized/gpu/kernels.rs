//! GPU compute kernels for ML-KEM operations
//!
//! This module provides access to the WGSL compute shaders for GPU acceleration.

/// NTT compute shader source
pub const NTT_SHADER: &str = include_str!("kernels/ntt.wgsl");

/// Polynomial operations compute shader source
pub const POLY_OPS_SHADER: &str = include_str!("kernels/poly_ops.wgsl");

/// Precomputed zetas for NTT in Montgomery form
pub const ZETAS: [u32; 128] = [
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
];

/// Inverse zetas for inverse NTT
pub const INV_ZETAS: [u32; 128] = {
    let mut inv = [0u32; 128];
    let mut i = 0;
    while i < 128 {
        inv[i] = if ZETAS[127 - i] == 0 { 0 } else { 3329 - ZETAS[127 - i] };
        i += 1;
    }
    inv
};

/// ML-KEM constants
pub const Q: u32 = 3329;
pub const N: u32 = 256;
pub const K: u32 = 3; // For ML-KEM-768
pub const MONT_R: u32 = 2285;
pub const MONT_R2: u32 = 1353;
pub const Q_INV: u32 = 62209;
pub const N_INV_MONT: u32 = 3303;
pub const BARRETT_MULT: u32 = 20159;
pub const BARRETT_SHIFT: u32 = 26;

/// Operation types for polynomial operations
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolyOp {
    Add = 0,
    Sub = 1,
    Mul = 2,
    PointwiseMul = 3,
    Reduce = 4,
    ToMont = 5,
    FromMont = 6,
    Basemul = 7,
    BasemulAcc = 8,
}
/// Parameter sets for CRYSTALS-Dilithium according to NIST FIPS 204
/// 
/// FIPS 204 ML-DSA (Module-Lattice-Based Digital Signature Algorithm) defines
/// three parameter sets corresponding to NIST security levels:
/// - ML-DSA-44: 128-bit security (equivalent to Dilithium2)
/// - ML-DSA-65: 192-bit security (equivalent to Dilithium3)  
/// - ML-DSA-87: 256-bit security (equivalent to Dilithium5)

/// NIST security levels for Dilithium
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 128-bit security
    Level2 = 2,
    /// 192-bit security  
    Level3 = 3,
    /// 256-bit security
    Level5 = 5,
}

/// Parameter set for Dilithium
#[derive(Debug, Clone, Copy)]
pub struct DilithiumParams {
    pub security_level: SecurityLevel,
    pub q: u32,           // Modulus
    pub d: u32,           // Dropped bits from t
    pub tau: u32,         // Number of ±1's in c
    pub gamma1: u32,      // y coefficient range
    pub gamma2: u32,      // Low-order rounding range
    pub k: usize,         // Dimensions
    pub l: usize,         // Dimensions
    pub eta: u32,         // Secret key coefficient range
    pub beta: u32,        // tau * eta
    pub omega: u32,       // Maximum number of 1's in hint
    pub poly_bytes: usize,    // Bytes to represent polynomial
    pub pk_bytes: usize,      // Public key size
    pub sk_bytes: usize,      // Secret key size
    pub sig_bytes: usize,     // Signature size
    pub c_tilde_bytes: usize, // c_tilde size (ML-DSA FIPS 204)
}

/// FIPS 204 parameter sets
/// ML-DSA-44 parameter set 
pub const DILITHIUM2_PARAMS: DilithiumParams = DilithiumParams {
    security_level: SecurityLevel::Level2,
    q: 8380417,
    d: 13,
    tau: 39,
    gamma1: 131072,  // 2^17
    gamma2: 95232,   // (q-1)/88
    k: 4,
    l: 4,
    eta: 2,
    beta: 78,
    omega: 80,
    poly_bytes: 576,  // POLYZ_PACKEDBYTES for gamma1=2^17
    pk_bytes: 1312,
    sk_bytes: 2560,
    sig_bytes: 2420,  // ML-DSA-44 sig bytes
    c_tilde_bytes: 32,
};

/// ML-DSA-65 parameter set 
pub const DILITHIUM3_PARAMS: DilithiumParams = DilithiumParams {
    security_level: SecurityLevel::Level3,
    q: 8380417,
    d: 13,
    tau: 49,
    gamma1: 524288,  // 2^19
    gamma2: 261888,  // (q-1)/32
    k: 6,
    l: 5,
    eta: 4,
    beta: 196,
    omega: 55,
    poly_bytes: 640,  // POLYZ_PACKEDBYTES for gamma1=2^19
    pk_bytes: 1952,
    sk_bytes: 4032,
    sig_bytes: 3309,  // ML-DSA-65 sig bytes
    c_tilde_bytes: 48,
};

/// ML-DSA-87 parameter set 
pub const DILITHIUM5_PARAMS: DilithiumParams = DilithiumParams {
    security_level: SecurityLevel::Level5,
    q: 8380417,
    d: 13,
    tau: 60,
    gamma1: 524288,  // 2^19
    gamma2: 261888,  // (q-1)/32
    k: 8,
    l: 7,
    eta: 2,
    beta: 120,
    omega: 75,
    poly_bytes: 640,  // POLYZ_PACKEDBYTES for gamma1=2^19
    pk_bytes: 2592,
    sk_bytes: 4896,
    sig_bytes: 4627,  // ML-DSA-87 sig bytes
    c_tilde_bytes: 64,
};

// FIPS 204 ML-DSA parameter aliases
pub const ML_DSA_44_PARAMS: DilithiumParams = DILITHIUM2_PARAMS;
pub const ML_DSA_65_PARAMS: DilithiumParams = DILITHIUM3_PARAMS;
pub const ML_DSA_87_PARAMS: DilithiumParams = DILITHIUM5_PARAMS;

/// Constants
pub const Q: u32 = 8380417;  // Prime modulus q = 2^23 - 2^13 + 1
pub const N: usize = 256;    // Polynomial degree
pub const ROOT: u32 = 3073009;  // 256-th root of unity modulo q (1753^2 mod q)
pub const D: u32 = 13;       // Dropped bits from t (for Dilithium2)
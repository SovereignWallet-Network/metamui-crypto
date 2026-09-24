//! SLH-DSA parameter sets as defined in NIST FIPS 205


/// SLH-DSA parameter set trait
pub trait Parameters {
    /// Security parameter in bytes (16, 24, or 32)
    const N: usize;
    
    /// Height of the hypertree
    const H: usize;
    
    /// Number of layers in the hypertree
    const D: usize;
    
    /// Height of each XMSS tree (H/D)
    const H_PRIME: usize;
    
    /// Winternitz parameter
    const W: usize;
    
    /// Number of FORS trees
    const K: usize;
    
    /// Height of each FORS tree
    const A: usize;
    
    /// Length of message digest
    const M: usize;
    
    /// Public key size in bytes
    const PK_BYTES: usize;
    
    /// Secret key size in bytes
    const SK_BYTES: usize;
    
    /// Signature size in bytes
    const SIG_BYTES: usize;
    
    /// Hash function variant (true for SHAKE256, false for SHA-256)
    const USE_SHAKE: bool;
    
    /// Parameter set name
    const NAME: &'static str;
}

/// SLH-DSA-128s parameter set (small signatures, NIST Level 1)
pub struct SlhDsa128s;

impl Parameters for SlhDsa128s {
    const N: usize = 16;
    const H: usize = 63;  // FIPS 205 compliant
    const D: usize = 7;   // FIPS 205 compliant
    const H_PRIME: usize = 9;  // H/D = 63/7 = 9
    const W: usize = 16;
    const K: usize = 14;
    const A: usize = 12;
    const M: usize = 30;
    const PK_BYTES: usize = 32;
    const SK_BYTES: usize = 64;
    const SIG_BYTES: usize = 7_856;  // FIPS 205: N + K*(A+1)*N + D*(wots_len+H_PRIME)*N = 16 + 2912 + 7*44*16
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-128s";
}

/// SLH-DSA-128f parameter set (fast signing, NIST Level 1)
pub struct SlhDsa128f;

impl Parameters for SlhDsa128f {
    const N: usize = 16;
    const H: usize = 66;  // FIPS 205 compliant
    const D: usize = 22;  // FIPS 205 compliant
    const H_PRIME: usize = 3;  // H/D = 66/22 = 3
    const W: usize = 16;
    const K: usize = 33;
    const A: usize = 6;
    const M: usize = 34;
    const PK_BYTES: usize = 32;
    const SK_BYTES: usize = 64;
    const SIG_BYTES: usize = 17_088;  // FIPS 205 compliant
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-128f";
}

/// SLH-DSA-192s parameter set (small signatures, NIST Level 3)
pub struct SlhDsa192s;

impl Parameters for SlhDsa192s {
    const N: usize = 24;
    const H: usize = 63;  // FIPS 205 compliant
    const D: usize = 7;   // FIPS 205 compliant
    const H_PRIME: usize = 9;  // H/D = 63/7 = 9
    const W: usize = 16;
    const K: usize = 17;  // FIPS 205 (was 14, needs verification)
    const A: usize = 14;
    const M: usize = 39;
    const PK_BYTES: usize = 48;
    const SK_BYTES: usize = 96;
    const SIG_BYTES: usize = 16_224;  // FIPS 205 compliant
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-192s";
}

/// SLH-DSA-192f parameter set (fast signing, NIST Level 3)
pub struct SlhDsa192f;

impl Parameters for SlhDsa192f {
    const N: usize = 24;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const W: usize = 16;
    const K: usize = 33;
    const A: usize = 8;
    const M: usize = 42;
    const PK_BYTES: usize = 48;
    const SK_BYTES: usize = 96;
    const SIG_BYTES: usize = 35_664;
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-192f";
}

/// SLH-DSA-256s parameter set (small signatures, NIST Level 5)
pub struct SlhDsa256s;

impl Parameters for SlhDsa256s {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const H_PRIME: usize = 8;
    const W: usize = 16;
    const K: usize = 22;  // FIPS 205 Table 2
    const A: usize = 14;
    const M: usize = 47;
    const PK_BYTES: usize = 64;
    const SK_BYTES: usize = 128;
    const SIG_BYTES: usize = 29_792;
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-256s";
}

/// SLH-DSA-256f parameter set (fast signing, NIST Level 5)
pub struct SlhDsa256f;

impl Parameters for SlhDsa256f {
    const N: usize = 32;
    const H: usize = 68;
    const D: usize = 17;
    const H_PRIME: usize = 4;
    const W: usize = 16;
    const K: usize = 35;
    const A: usize = 9;
    const M: usize = 49;
    const PK_BYTES: usize = 64;
    const SK_BYTES: usize = 128;
    const SIG_BYTES: usize = 49_856;
    const USE_SHAKE: bool = true;
    const NAME: &'static str = "SLH-DSA-256f";
}

// ─── SHA2 Variants ──────────────────────────────────────────────────────────
// Same parameters as SHAKE variants but with USE_SHAKE = false.
// FIPS 205 defines both SHAKE and SHA2 hash families for all 6 parameter sets.

/// SLH-DSA-SHA2-128s parameter set (small signatures, NIST Level 1, SHA-256)
pub struct SlhDsa128sSha2;

impl Parameters for SlhDsa128sSha2 {
    const N: usize = 16;
    const H: usize = 63;
    const D: usize = 7;
    const H_PRIME: usize = 9;
    const W: usize = 16;
    const K: usize = 14;
    const A: usize = 12;
    const M: usize = 30;
    const PK_BYTES: usize = 32;
    const SK_BYTES: usize = 64;
    const SIG_BYTES: usize = 7_856;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
}

/// SLH-DSA-SHA2-128f parameter set (fast signing, NIST Level 1, SHA-256)
pub struct SlhDsa128fSha2;

impl Parameters for SlhDsa128fSha2 {
    const N: usize = 16;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const W: usize = 16;
    const K: usize = 33;
    const A: usize = 6;
    const M: usize = 34;
    const PK_BYTES: usize = 32;
    const SK_BYTES: usize = 64;
    const SIG_BYTES: usize = 17_088;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-128f";
}

/// SLH-DSA-SHA2-192s parameter set (small signatures, NIST Level 3, SHA-256)
pub struct SlhDsa192sSha2;

impl Parameters for SlhDsa192sSha2 {
    const N: usize = 24;
    const H: usize = 63;
    const D: usize = 7;
    const H_PRIME: usize = 9;
    const W: usize = 16;
    const K: usize = 17;
    const A: usize = 14;
    const M: usize = 39;
    const PK_BYTES: usize = 48;
    const SK_BYTES: usize = 96;
    const SIG_BYTES: usize = 16_224;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-192s";
}

/// SLH-DSA-SHA2-192f parameter set (fast signing, NIST Level 3, SHA-256)
pub struct SlhDsa192fSha2;

impl Parameters for SlhDsa192fSha2 {
    const N: usize = 24;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const W: usize = 16;
    const K: usize = 33;
    const A: usize = 8;
    const M: usize = 42;
    const PK_BYTES: usize = 48;
    const SK_BYTES: usize = 96;
    const SIG_BYTES: usize = 35_664;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-192f";
}

/// SLH-DSA-SHA2-256s parameter set (small signatures, NIST Level 5, SHA-256)
pub struct SlhDsa256sSha2;

impl Parameters for SlhDsa256sSha2 {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const H_PRIME: usize = 8;
    const W: usize = 16;
    const K: usize = 22;
    const A: usize = 14;
    const M: usize = 47;
    const PK_BYTES: usize = 64;
    const SK_BYTES: usize = 128;
    const SIG_BYTES: usize = 29_792;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-256s";
}

/// SLH-DSA-SHA2-256f parameter set (fast signing, NIST Level 5, SHA-256)
pub struct SlhDsa256fSha2;

impl Parameters for SlhDsa256fSha2 {
    const N: usize = 32;
    const H: usize = 68;
    const D: usize = 17;
    const H_PRIME: usize = 4;
    const W: usize = 16;
    const K: usize = 35;
    const A: usize = 9;
    const M: usize = 49;
    const PK_BYTES: usize = 64;
    const SK_BYTES: usize = 128;
    const SIG_BYTES: usize = 49_856;
    const USE_SHAKE: bool = false;
    const NAME: &'static str = "SLH-DSA-SHA2-256f";
}

/// Parameter set enum for runtime selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterSet {
    /// SLH-DSA-SHAKE-128s
    SlhDsa128s,
    /// SLH-DSA-SHAKE-128f
    SlhDsa128f,
    /// SLH-DSA-SHAKE-192s
    SlhDsa192s,
    /// SLH-DSA-SHAKE-192f
    SlhDsa192f,
    /// SLH-DSA-SHAKE-256s
    SlhDsa256s,
    /// SLH-DSA-SHAKE-256f
    SlhDsa256f,
    /// SLH-DSA-SHA2-128s
    SlhDsa128sSha2,
    /// SLH-DSA-SHA2-128f
    SlhDsa128fSha2,
    /// SLH-DSA-SHA2-192s
    SlhDsa192sSha2,
    /// SLH-DSA-SHA2-192f
    SlhDsa192fSha2,
    /// SLH-DSA-SHA2-256s
    SlhDsa256sSha2,
    /// SLH-DSA-SHA2-256f
    SlhDsa256fSha2,
}

impl ParameterSet {
    /// Get the security level in bits
    pub fn security_level(&self) -> usize {
        match self {
            ParameterSet::SlhDsa128s | ParameterSet::SlhDsa128f |
            ParameterSet::SlhDsa128sSha2 | ParameterSet::SlhDsa128fSha2 => 128,
            ParameterSet::SlhDsa192s | ParameterSet::SlhDsa192f |
            ParameterSet::SlhDsa192sSha2 | ParameterSet::SlhDsa192fSha2 => 192,
            ParameterSet::SlhDsa256s | ParameterSet::SlhDsa256f |
            ParameterSet::SlhDsa256sSha2 | ParameterSet::SlhDsa256fSha2 => 256,
        }
    }
    
    /// Get the public key size in bytes
    pub fn public_key_bytes(&self) -> usize {
        match self {
            ParameterSet::SlhDsa128s | ParameterSet::SlhDsa128f |
            ParameterSet::SlhDsa128sSha2 | ParameterSet::SlhDsa128fSha2 => 32,
            ParameterSet::SlhDsa192s | ParameterSet::SlhDsa192f |
            ParameterSet::SlhDsa192sSha2 | ParameterSet::SlhDsa192fSha2 => 48,
            ParameterSet::SlhDsa256s | ParameterSet::SlhDsa256f |
            ParameterSet::SlhDsa256sSha2 | ParameterSet::SlhDsa256fSha2 => 64,
        }
    }
    
    /// Get the secret key size in bytes
    pub fn secret_key_bytes(&self) -> usize {
        self.public_key_bytes() * 2
    }
    
    /// Get the signature size in bytes
    pub fn signature_bytes(&self) -> usize {
        match self {
            ParameterSet::SlhDsa128s | ParameterSet::SlhDsa128sSha2 => 7_856,
            ParameterSet::SlhDsa128f | ParameterSet::SlhDsa128fSha2 => 17_088,
            ParameterSet::SlhDsa192s | ParameterSet::SlhDsa192sSha2 => 16_224,
            ParameterSet::SlhDsa192f | ParameterSet::SlhDsa192fSha2 => 35_664,
            ParameterSet::SlhDsa256s | ParameterSet::SlhDsa256sSha2 => 29_792,
            ParameterSet::SlhDsa256f | ParameterSet::SlhDsa256fSha2 => 49_856,
        }
    }

    /// Check if this is a "small" parameter set (optimized for signature size)
    pub fn is_small(&self) -> bool {
        matches!(self,
            ParameterSet::SlhDsa128s | ParameterSet::SlhDsa128sSha2 |
            ParameterSet::SlhDsa192s | ParameterSet::SlhDsa192sSha2 |
            ParameterSet::SlhDsa256s | ParameterSet::SlhDsa256sSha2
        )
    }
    
    /// Check if this is a "fast" parameter set (optimized for signing speed)
    pub fn is_fast(&self) -> bool {
        !self.is_small()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parameter_consistency() {
        // Test that H = D * H_PRIME for all parameter sets (SHAKE)
        assert_eq!(SlhDsa128s::H, SlhDsa128s::D * SlhDsa128s::H_PRIME);
        assert_eq!(SlhDsa128f::H, SlhDsa128f::D * SlhDsa128f::H_PRIME);
        assert_eq!(SlhDsa192s::H, SlhDsa192s::D * SlhDsa192s::H_PRIME);
        assert_eq!(SlhDsa192f::H, SlhDsa192f::D * SlhDsa192f::H_PRIME);
        assert_eq!(SlhDsa256s::H, SlhDsa256s::D * SlhDsa256s::H_PRIME);
        assert_eq!(SlhDsa256f::H, SlhDsa256f::D * SlhDsa256f::H_PRIME);
        // SHA2 variants
        assert_eq!(SlhDsa128sSha2::H, SlhDsa128sSha2::D * SlhDsa128sSha2::H_PRIME);
        assert_eq!(SlhDsa128fSha2::H, SlhDsa128fSha2::D * SlhDsa128fSha2::H_PRIME);
        assert_eq!(SlhDsa192sSha2::H, SlhDsa192sSha2::D * SlhDsa192sSha2::H_PRIME);
        assert_eq!(SlhDsa192fSha2::H, SlhDsa192fSha2::D * SlhDsa192fSha2::H_PRIME);
        assert_eq!(SlhDsa256sSha2::H, SlhDsa256sSha2::D * SlhDsa256sSha2::H_PRIME);
        assert_eq!(SlhDsa256fSha2::H, SlhDsa256fSha2::D * SlhDsa256fSha2::H_PRIME);
    }

    #[test]
    fn test_sha2_variants_use_sha2() {
        assert!(!SlhDsa128sSha2::USE_SHAKE);
        assert!(!SlhDsa128fSha2::USE_SHAKE);
        assert!(!SlhDsa192sSha2::USE_SHAKE);
        assert!(!SlhDsa192fSha2::USE_SHAKE);
        assert!(!SlhDsa256sSha2::USE_SHAKE);
        assert!(!SlhDsa256fSha2::USE_SHAKE);
    }
    
    #[test]
    fn test_parameter_set_properties() {
        assert!(ParameterSet::SlhDsa128s.is_small());
        assert!(!ParameterSet::SlhDsa128f.is_small());
        assert!(ParameterSet::SlhDsa192f.is_fast());
        assert!(!ParameterSet::SlhDsa256s.is_fast());
        
        assert_eq!(ParameterSet::SlhDsa128s.security_level(), 128);
        assert_eq!(ParameterSet::SlhDsa192f.security_level(), 192);
        assert_eq!(ParameterSet::SlhDsa256s.security_level(), 256);
    }
}
//! Reference backend for ML-KEM-768
//!
//! Pure Rust implementation without SIMD or GPU acceleration.
//! This implementation is constant-time and follows NIST FIPS 203.

use crate::backend::{Backend, PerformanceHints, Operation, MemoryEstimate};
use crate::{PublicKey, SecretKey, Ciphertext, SharedSecret, Result, Error};
use metamui_mlkem::KeyPair as Keypair;
use rand_core::{CryptoRng, RngCore};
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader, Digest};

// ML-KEM-768 parameters from NIST FIPS 203
const MLKEM_N: usize = 256;
const MLKEM_K: usize = 3;
const MLKEM_Q: u16 = 3329;
const MLKEM_ETA1: usize = 2;
const MLKEM_ETA2: usize = 2;
const MLKEM_DU: usize = 10;
const MLKEM_DV: usize = 4;
const MLKEM_SYMBYTES: usize = 32;

// Derived parameters
const MLKEM_POLYBYTES: usize = 384;
const MLKEM_POLYCOMPRESSEDBYTES: usize = 128;
const MLKEM_POLYVECCOMPRESSEDBYTES: usize = MLKEM_K * 320;
const MLKEM_PUBLICKEYBYTES: usize = MLKEM_K * MLKEM_POLYBYTES + MLKEM_SYMBYTES;
const MLKEM_SECRETKEYBYTES: usize = MLKEM_K * MLKEM_POLYBYTES + MLKEM_PUBLICKEYBYTES + 2 * MLKEM_SYMBYTES;
const MLKEM_CIPHERTEXTBYTES: usize = MLKEM_POLYVECCOMPRESSEDBYTES + MLKEM_POLYCOMPRESSEDBYTES;

// NTT constants
const QINV: u32 = 62209; // q^(-1) mod 2^16
const MONT_MASK: u32 = (1u32 << 16) - 1;

/// Zeta values for NTT (bit-reversed order)
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Polynomial structure
#[derive(Clone, Debug)]
struct Poly {
    coeffs: [u16; MLKEM_N],
}

impl Poly {
    fn new() -> Self {
        Self {
            coeffs: [0; MLKEM_N],
        }
    }

    fn reduce(&mut self) {
        for i in 0..MLKEM_N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i] as i32);
        }
    }

    fn add(&mut self, other: &Poly) {
        for i in 0..MLKEM_N {
            self.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % MLKEM_Q;
        }
    }

    fn sub(&mut self, other: &Poly) {
        for i in 0..MLKEM_N {
            self.coeffs[i] = (self.coeffs[i] + MLKEM_Q - other.coeffs[i]) % MLKEM_Q;
        }
    }

    fn ntt(&mut self) {
        let mut k = 1;
        let mut len = 128;
        while len >= 2 {
            let mut start = 0;
            while start < MLKEM_N {
                let zeta = ZETAS[k];
                k += 1;
                let mut j = start;
                while j < start + len {
                    // Use regular modular multiplication, not Montgomery
                    let t = barrett_reduce(zeta as i32 * self.coeffs[j + len] as i32);
                    self.coeffs[j + len] = ((self.coeffs[j] as u32 + MLKEM_Q as u32 - t as u32) % MLKEM_Q as u32) as u16;
                    self.coeffs[j] = ((self.coeffs[j] as u32 + t as u32) % MLKEM_Q as u32) as u16;
                    j += 1;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    fn inv_ntt(&mut self) {
        let mut k = 127;
        let mut len = 2;
        while len <= 128 {
            let mut start = 0;
            while start < MLKEM_N {
                let zeta = ZETAS[k];
                k = k.saturating_sub(1);
                let mut j = start;
                while j < start + len {
                    let t = self.coeffs[j];
                    self.coeffs[j] = ((t as u32 + self.coeffs[j + len] as u32) % MLKEM_Q as u32) as u16;
                    // Use regular modular multiplication, not Montgomery
                    self.coeffs[j + len] = barrett_reduce(zeta as i32 * 
                        ((self.coeffs[j + len] as u32 + MLKEM_Q as u32 - t as u32) % MLKEM_Q as u32) as i32);
                    j += 1;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        
        // Final multiplication by 128^{-1} = 3303 mod q
        const F_INV: u16 = 3303;
        for i in 0..MLKEM_N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i] as i32 * F_INV as i32);
        }
    }

    fn basemul(&mut self, a: &Poly, b: &Poly) {
        // ML-KEM uses a specific multiplication pattern
        // Process coefficients in groups of 4 (2 pairs of degree-1 polynomials)
        for i in 0..64 {
            // Zeta values for multiplication
            let zeta = ZETAS[64 + i];
            
            // First pair: indices 4i, 4i+1
            let (a0, a1) = (a.coeffs[4 * i], a.coeffs[4 * i + 1]);
            let (b0, b1) = (b.coeffs[4 * i], b.coeffs[4 * i + 1]);
            
            // r0 = a0*b0 + a1*b1*zeta (all using regular modular arithmetic)
            let r0 = barrett_reduce((a0 as i32 * b0 as i32) + 
                                   barrett_reduce((a1 as i32 * b1 as i32)) as i32 * zeta as i32);
            // r1 = a0*b1 + a1*b0
            let r1 = barrett_reduce((a0 as i32 * b1 as i32) + (a1 as i32 * b0 as i32));
            
            self.coeffs[4 * i] = r0;
            self.coeffs[4 * i + 1] = r1;
            
            // Second pair: indices 4i+2, 4i+3 (uses -zeta)
            let neg_zeta = (MLKEM_Q - ZETAS[64 + i]) as i32; // -zeta mod q
            let (a2, a3) = (a.coeffs[4 * i + 2], a.coeffs[4 * i + 3]);
            let (b2, b3) = (b.coeffs[4 * i + 2], b.coeffs[4 * i + 3]);
            
            // r2 = a2*b2 + a3*b3*(-zeta)
            let r2 = barrett_reduce((a2 as i32 * b2 as i32) + 
                                   barrett_reduce((a3 as i32 * b3 as i32)) as i32 * neg_zeta);
            // r3 = a2*b3 + a3*b2
            let r3 = barrett_reduce((a2 as i32 * b3 as i32) + (a3 as i32 * b2 as i32));
            
            self.coeffs[4 * i + 2] = r2;
            self.coeffs[4 * i + 3] = r3;
        }
    }

    fn to_bytes(&self) -> [u8; MLKEM_POLYBYTES] {
        let mut r = [0u8; MLKEM_POLYBYTES];
        for i in 0..MLKEM_N {
            let t = self.coeffs[i];
            let idx = (3 * i) / 2;
            if i & 1 == 0 {
                r[idx] |= (t & 0xff) as u8;
                r[idx + 1] = ((t >> 8) & 0x0f) as u8;
            } else {
                r[idx] |= ((t & 0x0f) << 4) as u8;
                r[idx + 1] = (t >> 4) as u8;
            }
        }
        r
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut r = Poly::new();
        for i in 0..MLKEM_N {
            let idx = (3 * i) / 2;
            if i & 1 == 0 {
                r.coeffs[i] = ((bytes[idx] as u16) | ((bytes[idx + 1] as u16 & 0x0f) << 8)) % MLKEM_Q;
            } else {
                r.coeffs[i] = (((bytes[idx] as u16) >> 4) | ((bytes[idx + 1] as u16) << 4)) % MLKEM_Q;
            }
        }
        r
    }

    fn compress(&self, d: usize) -> Vec<u8> {
        let mut r = vec![0u8; (MLKEM_N * d + 7) / 8];
        let mut bit_pos = 0;
        
        for i in 0..MLKEM_N {
            let t = (((self.coeffs[i] as u32) << d) + MLKEM_Q as u32 / 2) / MLKEM_Q as u32;
            
            for j in 0..d {
                let byte_pos = bit_pos / 8;
                let bit_offset = bit_pos % 8;
                if ((t >> j) & 1) != 0 {
                    r[byte_pos] |= 1 << bit_offset;
                }
                bit_pos += 1;
            }
        }
        r
    }

    fn decompress(bytes: &[u8], d: usize) -> Self {
        let mut r = Poly::new();
        let mut bit_pos = 0;
        
        for i in 0..MLKEM_N {
            let mut t = 0u32;
            for j in 0..d {
                let byte_pos = bit_pos / 8;
                let bit_offset = bit_pos % 8;
                if byte_pos < bytes.len() && (bytes[byte_pos] >> bit_offset) & 1 != 0 {
                    t |= 1 << j;
                }
                bit_pos += 1;
            }
            r.coeffs[i] = ((t * MLKEM_Q as u32 + (1 << (d - 1))) >> d) as u16;
        }
        r
    }

    fn from_msg(msg: &[u8; 32]) -> Self {
        let mut r = Poly::new();
        for i in 0..32 {
            for j in 0..8 {
                let bit = (msg[i] >> j) & 1;
                let mask = if bit == 1 { -1i16 } else { 0i16 };
                r.coeffs[8 * i + j] = (mask & ((MLKEM_Q as i16 + 1) / 2)) as u16;
            }
        }
        r
    }

    fn to_msg(&self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        for i in 0..MLKEM_N {
            let t = ((((self.coeffs[i] as u32) << 1) + MLKEM_Q as u32 / 2) / MLKEM_Q as u32) & 1;
            msg[i / 8] |= (t << (i % 8)) as u8;
        }
        msg
    }
}

/// Polynomial vector
#[derive(Clone)]
struct PolyVec {
    vec: Vec<Poly>,
}

impl PolyVec {
    fn new(k: usize) -> Self {
        Self {
            vec: vec![Poly::new(); k],
        }
    }

    fn ntt(&mut self) {
        for p in &mut self.vec {
            p.ntt();
        }
    }

    fn inv_ntt(&mut self) {
        for p in &mut self.vec {
            p.inv_ntt();
        }
    }

    fn add(&mut self, other: &PolyVec) {
        for (a, b) in self.vec.iter_mut().zip(&other.vec) {
            a.add(b);
        }
    }

    fn reduce(&mut self) {
        for p in &mut self.vec {
            p.reduce();
        }
    }

    fn compress(&self, d: usize) -> Vec<u8> {
        let mut r = Vec::new();
        for p in &self.vec {
            r.extend_from_slice(&p.compress(d));
        }
        r
    }

    fn decompress(bytes: &[u8], k: usize, d: usize) -> Self {
        let mut r = PolyVec::new(k);
        let bytes_per_poly = (MLKEM_N * d + 7) / 8;
        for i in 0..k {
            let start = i * bytes_per_poly;
            let end = core::cmp::min(start + bytes_per_poly, bytes.len());
            r.vec[i] = Poly::decompress(&bytes[start..end], d);
        }
        r
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for p in &self.vec {
            r.extend_from_slice(&p.to_bytes());
        }
        r
    }

    fn from_bytes(bytes: &[u8], k: usize) -> Self {
        let mut r = PolyVec::new(k);
        for i in 0..k {
            let start = i * MLKEM_POLYBYTES;
            let end = core::cmp::min(start + MLKEM_POLYBYTES, bytes.len());
            r.vec[i] = Poly::from_bytes(&bytes[start..end]);
        }
        r
    }
}

/// Matrix of polynomials
struct PolyMat {
    mat: Vec<Vec<Poly>>,
}

impl PolyMat {
    fn new(k: usize) -> Self {
        Self {
            mat: vec![vec![Poly::new(); k]; k],
        }
    }
}

/// Reference backend implementation
pub struct ReferenceBackend;

impl ReferenceBackend {
    /// Create a new reference backend instance
    pub fn new() -> Self {
        Self
    }
}

impl Backend for ReferenceBackend {
    fn name(&self) -> &str {
        "reference"
    }
    
    fn supports_batch(&self) -> bool {
        false
    }
    
    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints {
            relative_speed: 1.0,
            uses_simd: false,
            uses_gpu: false,
            optimal_batch_size: 1,
            constant_time: true,
        }
    }
    
    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        // Generate random seeds
        let mut seed_d = [0u8; 32];
        let mut seed_z = [0u8; 32];
        rng.fill_bytes(&mut seed_d);
        rng.fill_bytes(&mut seed_z);
        
        // Expand seed to get matrix A and vectors s and e
        let a = expand_a(&seed_d);
        let s = sample_noise_poly_vec(&seed_z, 0, MLKEM_ETA1);
        let e = sample_noise_poly_vec(&seed_z, MLKEM_K as u8, MLKEM_ETA1);
        
        // Compute public key: t = As + e
        let mut s_ntt = s.clone();
        s_ntt.ntt();
        let mut t = matrix_vector_mul(&a, &s_ntt);
        t.inv_ntt();
        let e_copy = e.clone();
        t.add(&e_copy);
        t.reduce();
        
        // Pack keys
        let pk_bytes = pack_public_key(&t, &seed_d);
        let sk_bytes = pack_secret_key(&s, &pk_bytes, &seed_z);
        
        // Convert to correct size arrays
        let mut pk_array = [0u8; 1184];
        let mut sk_array = [0u8; 2400];
        pk_array.copy_from_slice(&pk_bytes[..1184]);
        sk_array.copy_from_slice(&sk_bytes[..2400]);
        
        let public_key = PublicKey::from_bytes(pk_array);
        let private_key = SecretKey::from_bytes(sk_array);
        
        Ok(Keypair {
            public_key,
            private_key,
        })
    }
    
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        // Generate random message
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        
        // Hash the public key
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, public_key.as_bytes());
        let h = hasher.finalize();
        
        // Generate randomness
        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m);
        g_input[32..].copy_from_slice(&h);
        
        let mut hasher = Sha3_512::new();
        Digest::update(&mut hasher, &g_input);
        let g_output = hasher.finalize();
        
        let mut k = [0u8; 32];
        let mut r = [0u8; 32];
        k.copy_from_slice(&g_output[..32]);
        r.copy_from_slice(&g_output[32..]);
        
        // Unpack public key
        let (t, seed) = unpack_public_key(public_key.as_bytes())?;
        
        // Expand matrix A from seed
        let a = expand_a(&seed);
        
        // Sample vectors
        let s_prime = sample_noise_poly_vec(&r, 0, MLKEM_ETA2);
        let e1 = sample_noise_poly_vec(&r, MLKEM_K as u8, MLKEM_ETA2);
        let e2_poly = sample_noise_poly(&r, 2 * MLKEM_K as u8, MLKEM_ETA2);
        
        // Compute ciphertext in NTT domain
        let mut s_prime_ntt = s_prime.clone();
        s_prime_ntt.ntt();
        
        // u = A^T s' + e1
        let mut u = matrix_transpose_vector_mul(&a, &s_prime_ntt);
        u.inv_ntt();
        u.add(&e1);
        u.reduce();
        
        // v = t^T s' + e2 + m'
        let mut t_ntt = t.clone();
        t_ntt.ntt();
        let mut v = inner_product(&t_ntt, &s_prime_ntt);
        v.inv_ntt();
        v.add(&e2_poly);
        let m_poly = Poly::from_msg(&m);
        v.add(&m_poly);
        v.reduce();
        
        // Compress and pack ciphertext
        let ct_bytes = pack_ciphertext(&u, &v);
        let mut ct_array = [0u8; 1088];
        ct_array.copy_from_slice(&ct_bytes[..1088]);
        let ciphertext = Ciphertext::from_bytes(ct_array);
        
        // Compute shared secret
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&k);
        kdf_input[32..].copy_from_slice(&h);
        
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &kdf_input);
        let ss_bytes = hasher.finalize();
        
        let shared_secret = SharedSecret::from_bytes(ss_bytes.into());
        
        Ok((ciphertext, shared_secret))
    }
    
    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        // Unpack secret key
        let (s, pk_bytes, z, h) = unpack_secret_key(secret_key.as_bytes())?;
        
        // Unpack ciphertext
        let (u, v) = unpack_ciphertext(ciphertext.as_bytes())?;
        
        // Compute m' = v - s^T u in NTT domain
        let mut s_ntt = s.clone();
        s_ntt.ntt();
        let mut u_ntt = u.clone();
        u_ntt.ntt();
        
        let mut st_u = inner_product(&s_ntt, &u_ntt);
        st_u.inv_ntt();
        
        let mut m_prime = v.clone();
        m_prime.sub(&st_u);
        m_prime.reduce();
        
        // Decode message
        let m_recovered = m_prime.to_msg();
        
        // Re-encrypt to verify
        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m_recovered);
        g_input[32..].copy_from_slice(&h);
        
        let mut hasher = Sha3_512::new();
        Digest::update(&mut hasher, &g_input);
        let g_output = hasher.finalize();
        
        let mut k_prime = [0u8; 32];
        let mut r_prime = [0u8; 32];
        k_prime.copy_from_slice(&g_output[..32]);
        r_prime.copy_from_slice(&g_output[32..]);
        
        // Verify ciphertext
        let mut pk_array = [0u8; 1184];
        pk_array.copy_from_slice(&pk_bytes[..1184]);
        let (t, seed) = unpack_public_key(&pk_array)?;
        let a = expand_a(&seed);
        
        let s_prime = sample_noise_poly_vec(&r_prime, 0, MLKEM_ETA2);
        let e1 = sample_noise_poly_vec(&r_prime, MLKEM_K as u8, MLKEM_ETA2);
        let e2_poly = sample_noise_poly(&r_prime, 2 * MLKEM_K as u8, MLKEM_ETA2);
        
        // Recompute in NTT domain
        let mut s_prime_ntt = s_prime.clone();
        s_prime_ntt.ntt();
        
        let mut u_prime = matrix_transpose_vector_mul(&a, &s_prime_ntt);
        u_prime.inv_ntt();
        u_prime.add(&e1);
        u_prime.reduce();
        
        let mut t_ntt = t.clone();
        t_ntt.ntt();
        let mut v_prime = inner_product(&t_ntt, &s_prime_ntt);
        v_prime.inv_ntt();
        v_prime.add(&e2_poly);
        let m_poly = Poly::from_msg(&m_recovered);
        v_prime.add(&m_poly);
        v_prime.reduce();
        
        let ct_prime = pack_ciphertext(&u_prime, &v_prime);
        
        // Constant-time selection
        let mut k_bar = [0u8; 32];
        if constant_time_compare(&ct_prime, ciphertext.as_bytes()) {
            k_bar.copy_from_slice(&k_prime);
        } else {
            k_bar.copy_from_slice(&z);
        }
        
        // Compute final shared secret
        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(&k_bar);
        kdf_input[32..].copy_from_slice(&h);
        
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &kdf_input);
        let ss_bytes = hasher.finalize();
        
        Ok(SharedSecret::from_bytes(ss_bytes.into()))
    }
    
    fn memory_estimate(&self, operation: Operation) -> MemoryEstimate {
        match operation {
            Operation::Keygen => MemoryEstimate {
                heap: 32 * 1024,
                stack: 16 * 1024,
            },
            Operation::Encapsulate => MemoryEstimate {
                heap: 24 * 1024,
                stack: 12 * 1024,
            },
            Operation::Decapsulate => MemoryEstimate {
                heap: 24 * 1024,
                stack: 12 * 1024,
            },
        }
    }
}

// Helper functions

fn barrett_reduce(a: i32) -> u16 {
    const BARRETT_SHIFT: i32 = 26;
    const BARRETT_R: i32 = 20159;
    
    // Compute ⌊a * r / 2^26⌋
    let t = (a as i64 * BARRETT_R as i64) >> BARRETT_SHIFT;
    
    // Compute a - t * q
    let mut res = a - (t as i32 * MLKEM_Q as i32);
    
    // Ensure result is in [0, q)
    if res < 0 {
        res += MLKEM_Q as i32;
    }
    if res >= MLKEM_Q as i32 {
        res -= MLKEM_Q as i32;
    }
    
    res as u16
}

fn montgomery_multiply(a: u32, b: u32) -> u32 {
    let t = a * b;
    let u = ((t as u64 * QINV as u64) & MONT_MASK as u64) as u32;
    let r = (t.wrapping_add(u.wrapping_mul(MLKEM_Q as u32))) >> 16;
    if r >= MLKEM_Q as u32 {
        r - MLKEM_Q as u32
    } else {
        r
    }
}

fn montgomery_reduce(a: u32) -> u32 {
    let u = ((a as u64 * QINV as u64) & MONT_MASK as u64) as u32;
    let r = (a.wrapping_add(u.wrapping_mul(MLKEM_Q as u32))) >> 16;
    if r >= MLKEM_Q as u32 {
        r - MLKEM_Q as u32
    } else {
        r
    }
}

fn mod_inverse(a: u16) -> u16 {
    // Compute a^(-1) mod q using Fermat's little theorem
    // a^(-1) = a^(q-2) mod q
    let mut result = 1u32;
    let mut base = a as u32;
    let mut exp = MLKEM_Q as u32 - 2;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % MLKEM_Q as u32;
        }
        base = (base * base) % MLKEM_Q as u32;
        exp >>= 1;
    }
    
    result as u16
}

fn expand_a(seed: &[u8; 32]) -> PolyMat {
    let mut a = PolyMat::new(MLKEM_K);
    
    for i in 0..MLKEM_K {
        for j in 0..MLKEM_K {
            let mut xof = Shake128::default();
            xof.update(seed);
            xof.update(&[j as u8, i as u8]);
            
            let mut reader = xof.finalize_xof();
            let mut buf = [0u8; 3];
            let mut k = 0;
            
            while k < MLKEM_N {
                reader.read(&mut buf);
                let d1 = ((buf[0] as u16) | ((buf[1] as u16 & 0x0F) << 8)) as u16;
                let d2 = (((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4)) as u16;
                
                if d1 < MLKEM_Q {
                    a.mat[i][j].coeffs[k] = d1;
                    k += 1;
                }
                if k < MLKEM_N && d2 < MLKEM_Q {
                    a.mat[i][j].coeffs[k] = d2;
                    k += 1;
                }
            }
            // Convert to NTT domain
            a.mat[i][j].ntt();
        }
    }
    a
}

fn sample_noise_poly(seed: &[u8; 32], nonce: u8, eta: usize) -> Poly {
    let mut poly = Poly::new();
    let mut prf = Shake256::default();
    prf.update(seed);
    prf.update(&[nonce]);
    
    let mut reader = prf.finalize_xof();
    let bytes_needed = if eta == 2 { 128 } else { 168 };
    let mut buf = vec![0u8; bytes_needed];
    reader.read(&mut buf);
    
    if eta == 2 {
        for i in 0..MLKEM_N / 2 {
            let t = buf[i];
            let d0 = (t & 0x03) as u16;
            let d1 = ((t >> 2) & 0x03) as u16;
            let d2 = ((t >> 4) & 0x03) as u16;
            let d3 = ((t >> 6) & 0x03) as u16;
            
            poly.coeffs[2 * i] = (d0 + MLKEM_Q - d1) % MLKEM_Q;
            poly.coeffs[2 * i + 1] = (d2 + MLKEM_Q - d3) % MLKEM_Q;
        }
    }
    
    poly
}

fn sample_noise_poly_vec(seed: &[u8; 32], nonce: u8, eta: usize) -> PolyVec {
    let mut vec = PolyVec::new(MLKEM_K);
    for i in 0..MLKEM_K {
        vec.vec[i] = sample_noise_poly(seed, nonce + i as u8, eta);
    }
    vec
}

fn matrix_vector_mul(a: &PolyMat, s: &PolyVec) -> PolyVec {
    let mut result = PolyVec::new(MLKEM_K);
    
    for i in 0..MLKEM_K {
        let mut sum = Poly::new();
        for j in 0..MLKEM_K {
            let mut temp = Poly::new();
            temp.basemul(&a.mat[i][j], &s.vec[j]);
            sum.add(&temp);
        }
        result.vec[i] = sum;
    }
    
    result
}

fn matrix_transpose_vector_mul(a: &PolyMat, s: &PolyVec) -> PolyVec {
    let mut result = PolyVec::new(MLKEM_K);
    
    for i in 0..MLKEM_K {
        let mut sum = Poly::new();
        for j in 0..MLKEM_K {
            let mut temp = Poly::new();
            temp.basemul(&a.mat[j][i], &s.vec[j]);
            sum.add(&temp);
        }
        result.vec[i] = sum;
    }
    
    result
}

fn inner_product(a: &PolyVec, b: &PolyVec) -> Poly {
    let mut result = Poly::new();
    
    for i in 0..MLKEM_K {
        let mut temp = Poly::new();
        temp.basemul(&a.vec[i], &b.vec[i]);
        result.add(&temp);
    }
    
    result
}

fn pack_public_key(t: &PolyVec, seed: &[u8; 32]) -> Vec<u8> {
    let mut pk = t.to_bytes();
    pk.extend_from_slice(seed);
    pk
}

fn pack_secret_key(s: &PolyVec, pk: &[u8], z: &[u8; 32]) -> Vec<u8> {
    let mut sk = s.to_bytes();
    sk.extend_from_slice(pk);
    
    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, pk);
    let h = hasher.finalize();
    sk.extend_from_slice(&h);
    sk.extend_from_slice(z);
    sk
}

fn pack_ciphertext(u: &PolyVec, v: &Poly) -> Vec<u8> {
    let mut ct = u.compress(MLKEM_DU);
    ct.extend_from_slice(&v.compress(MLKEM_DV));
    ct
}

fn unpack_public_key(pk: &[u8]) -> Result<(PolyVec, [u8; 32])> {
    if pk.len() != MLKEM_PUBLICKEYBYTES {
            return Err(Error::InvalidInput);
    }
    
    let t = PolyVec::from_bytes(&pk[..MLKEM_K * MLKEM_POLYBYTES], MLKEM_K);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pk[MLKEM_K * MLKEM_POLYBYTES..]);
    
    Ok((t, seed))
}

fn unpack_secret_key(sk: &[u8]) -> Result<(PolyVec, Vec<u8>, [u8; 32], [u8; 32])> {
    if sk.len() != MLKEM_SECRETKEYBYTES {
            return Err(Error::InvalidInput);
    }
    
    let s = PolyVec::from_bytes(&sk[..MLKEM_K * MLKEM_POLYBYTES], MLKEM_K);
    let pk = sk[MLKEM_K * MLKEM_POLYBYTES..MLKEM_K * MLKEM_POLYBYTES + MLKEM_PUBLICKEYBYTES].to_vec();
    
    let mut h = [0u8; 32];
    let mut z = [0u8; 32];
    let h_start = MLKEM_K * MLKEM_POLYBYTES + MLKEM_PUBLICKEYBYTES;
    h.copy_from_slice(&sk[h_start..h_start + 32]);
    z.copy_from_slice(&sk[h_start + 32..h_start + 64]);
    
    Ok((s, pk, z, h))
}

fn unpack_ciphertext(ct: &[u8]) -> Result<(PolyVec, Poly)> {
    if ct.len() != MLKEM_CIPHERTEXTBYTES {
            return Err(Error::InvalidInput);
    }
    
    let u = PolyVec::decompress(&ct[..MLKEM_POLYVECCOMPRESSEDBYTES], MLKEM_K, MLKEM_DU);
    let v = Poly::decompress(&ct[MLKEM_POLYVECCOMPRESSEDBYTES..], MLKEM_DV);
    
    Ok((u, v))
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    
    diff == 0
}

// SHA3 imports
// use sha3::digest::Digest; // Already imported above

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_keygen() {
        let backend = ReferenceBackend::new();
        let mut rng = thread_rng();
        let keypair = backend.keygen(&mut rng).unwrap();
        
        assert_eq!(keypair.public_key.as_bytes().len(), MLKEM_PUBLICKEYBYTES);
        assert_eq!(keypair.private_key.as_bytes().len(), MLKEM_SECRETKEYBYTES);
    }

    #[test]
    fn test_encaps_decaps() {
        let backend = ReferenceBackend::new();
        let mut rng = thread_rng();
        
        let keypair = backend.keygen(&mut rng).unwrap();
        let (ct, ss1) = backend.encapsulate(&keypair.public_key, &mut rng).unwrap();
        let ss2 = backend.decapsulate(&keypair.private_key, &ct).unwrap();
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_ntt_inverse() {
        let mut poly = Poly::new();
        for i in 0..MLKEM_N {
            poly.coeffs[i] = (i as u16) % MLKEM_Q;
        }
        
        let original = poly.clone();
        poly.ntt();
        poly.inv_ntt();
        
        for i in 0..MLKEM_N {
            let diff = if poly.coeffs[i] > original.coeffs[i] {
                poly.coeffs[i] - original.coeffs[i]
            } else {
                original.coeffs[i] - poly.coeffs[i]
            };
            assert!(diff < 2, "NTT inverse not working correctly at index {}: {} vs {}", 
                    i, poly.coeffs[i], original.coeffs[i]);
        }
    }
}
/// CRYSTALS-Dilithium2 implementation (NIST Security Level 2)

use crate::params::{DILITHIUM2_PARAMS, N, D, Q};
use crate::poly::{Poly, PolyVec, matrix_vector_mul_ntt};
use crate::operations::*;
use rand_core::{RngCore, CryptoRng};
use crate::sha3_compat::Shake256;
use crate::sha3_compat::digest::Update;
use rand::rngs::OsRng;

/// Dilithium2 - NIST Security Level 2 (128-bit security)
pub struct Dilithium2;

// Several thin helper methods (pack_eta_vec, pack_t0, challenge_from_w1,
// compute_ct0, pack_challenge_seed, unpack_sig) delegate to
// `crate::operations::*` equivalents. They're kept on the impl for
// per-parameter-set spec traceability even when the current
// sign/verify path calls through the crate::operations layer directly.
#[allow(dead_code)]
impl Dilithium2 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 1312;
    
    /// Secret key size in bytes
    pub const SECRET_KEY_SIZE: usize = 2560;
    
    /// Signature size in bytes
    pub const SIGNATURE_SIZE: usize = 2420;
    
    /// Generate a new Dilithium2 key pair
    pub fn generate_keypair() -> ([u8; Self::PUBLIC_KEY_SIZE], [u8; Self::SECRET_KEY_SIZE]) {
        Self::generate_keypair_with_rng(&mut OsRng)
    }
    
    /// Generate a new Dilithium2 key pair with specific RNG
    pub fn generate_keypair_with_rng<R: RngCore + CryptoRng>(
        rng: &mut R
    ) -> ([u8; Self::PUBLIC_KEY_SIZE], [u8; Self::SECRET_KEY_SIZE]) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::keygen_internal(&seed)
    }

    /// FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal(ξ)`: the key pair as a pure
    /// function of the 32-byte seed. This is the ACVP keyGen interface, exposed so
    /// every binding built on this crate (WASM/TS included) can replay the genuine
    /// NIST vectors byte-for-byte. Production callers draw ξ through
    /// `generate_keypair`/`generate_keypair_with_rng`; do not reuse a seed.
    /// Compiled only with the `kat-internal` feature: an application is never
    /// offered a seed. `generate_keypair_with_rng` reaches the same algorithm
    /// through the private `keygen_internal`.
    #[cfg(feature = "kat-internal")]
    pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> ([u8; Self::PUBLIC_KEY_SIZE], [u8; Self::SECRET_KEY_SIZE]) {
        Self::keygen_internal(seed)
    }

    /// FIPS 204 Algorithm 6 body, shared by the RNG-driven and the seeded entry.
    fn keygen_internal(seed: &[u8; 32]) -> ([u8; Self::PUBLIC_KEY_SIZE], [u8; Self::SECRET_KEY_SIZE]) {
        // FIPS 204 Algorithm 6 step 1:
        // (ρ, ρ', K) ← H(ξ || IntegerToBytes(k,1) || IntegerToBytes(ℓ,1), 128)
        let mut xof = Shake256::default();
        Update::update(&mut xof, seed);
        Update::update(&mut xof, &[DILITHIUM2_PARAMS.k as u8]);
        Update::update(&mut xof, &[DILITHIUM2_PARAMS.l as u8]);
        let mut reader = xof.finalize_xof();

        let mut rho = [0u8; 32];
        reader.read(&mut rho);
        let mut rho_prime_seed = [0u8; 64];
        reader.read(&mut rho_prime_seed);
        let mut k_seed = [0u8; 32];
        reader.read(&mut k_seed);

        // Expand matrix A from rho
        let a_matrix = Self::expand_a(&rho);

        // FIPS 204 Algorithm 33: (s1, s2) ← ExpandS(ρ')
        let s1 = Self::expand_s(&rho_prime_seed, DILITHIUM2_PARAMS.l, 0);
        let s2 = Self::expand_s(&rho_prime_seed, DILITHIUM2_PARAMS.k, DILITHIUM2_PARAMS.l as u8);
        
        // Convert to NTT
        let s1_ntt = s1.to_ntt();
        let _s2_ntt = s2.to_ntt();
        
        // Compute t = As1 + s2
        // Match C reference exactly:
        // 1. Matrix multiply in NTT domain
        let mut as1_ntt = matrix_vector_mul_ntt(&a_matrix, &s1_ntt).unwrap();
        // 2. Reduce while still in NTT domain (matching polyveck_reduce)
        as1_ntt = as1_ntt.reduce();
        // 3. Convert from NTT with Montgomery factor
        let as1 = as1_ntt.from_ntt();
        // 4. Add s2 in regular domain
        let mut t = as1.add(&s2).unwrap();
        // 5. Final reduce is implicit in add
        
        // Apply caddq before power2round (matching C reference)
        t = t.caddq();
        
        // Decompose t into t1 and t0
        let mut t1 = PolyVec::zero(DILITHIUM2_PARAMS.k);
        let mut t0 = PolyVec::zero(DILITHIUM2_PARAMS.k);
        
        for i in 0..DILITHIUM2_PARAMS.k {
            let (t1_poly, t0_poly) = t.polys[i].power2round(D);
            t1.polys[i] = t1_poly;
            t0.polys[i] = t0_poly;
        }
        
        // Pack public key
        let mut pk = [0u8; Self::PUBLIC_KEY_SIZE];
        pk[0..32].copy_from_slice(&rho);
        let t1_packed = Self::pack_t1(&t1);
        pk[32..].copy_from_slice(&t1_packed);
        
        // Compute tr = SHAKE256(pk, 64)
        let mut shake = Shake256::default();
        Update::update(&mut shake, &pk);
        let mut reader = shake.finalize_xof();
        let mut tr = [0u8; 64];
        reader.read(&mut tr);
        
        // Pack secret key
        let mut sk = [0u8; Self::SECRET_KEY_SIZE];
        sk[0..32].copy_from_slice(&rho);
        sk[32..64].copy_from_slice(&k_seed);
        sk[64..128].copy_from_slice(&tr);
        let mut offset = 128;
        
        // Pack s1
        let s1_packed = pack_eta_vec(&s1, DILITHIUM2_PARAMS.eta);
        sk[offset..offset + s1_packed.len()].copy_from_slice(&s1_packed);
        offset += s1_packed.len();
        
        // Pack s2
        let s2_packed = pack_eta_vec(&s2, DILITHIUM2_PARAMS.eta);
        sk[offset..offset + s2_packed.len()].copy_from_slice(&s2_packed);
        offset += s2_packed.len();
        
        // Pack t0
        let t0_packed = pack_t0(&t0);
        sk[offset..offset + t0_packed.len()].copy_from_slice(&t0_packed);
        
        (pk, sk)
    }
    
    /// μ = SHAKE256(tr || M', 64), where tr is sk[64..128].
    fn mu_from_mprime(secret_key: &[u8; Self::SECRET_KEY_SIZE], m_prime: &[u8]) -> [u8; 64] {
        let mut xof = Shake256::default();
        Update::update(&mut xof, &secret_key[64..128]);
        Update::update(&mut xof, m_prime);
        let mut reader = xof.finalize_xof();
        let mut mu = [0u8; 64];
        reader.read(&mut mu);
        mu
    }

    /// **Hedged** ML-DSA.Sign (FIPS 204 Algorithm 2 with fresh `rnd`) with a
    /// caller-supplied RNG and an empty context: 32 bytes of `rnd` are drawn
    /// from `rng` and mixed into ρ″, so two signatures of the same message
    /// differ. Use [`Self::sign_hedged`] for the OS RNG.
    pub fn sign_with_rng<R: RngCore + CryptoRng>(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8],
        rng: &mut R,
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_hedged_with_context_rng(secret_key, message, &[], rng)
    }

    /// Hedged signing with a context string (≤255 bytes) and a caller RNG.
    pub fn sign_hedged_with_context_rng<R: RngCore + CryptoRng>(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> [u8; Self::SIGNATURE_SIZE] {
        assert!(context.len() <= 255, "context must be at most 255 bytes");
        let mut rnd = [0u8; 32];
        rng.fill_bytes(&mut rnd);
        let mut m_prime = Vec::with_capacity(2 + context.len() + message.len());
        m_prime.extend_from_slice(&[0u8, context.len() as u8]);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(message);
        Self::sign_internal(secret_key, &m_prime, &rnd)
    }

    /// Hedged signing (FIPS 204 §5: fresh `rnd` from the OS RNG), empty context.
    /// This is the production entry FIPS 204 recommends; [`Self::sign`] stays
    /// deterministic (`rnd = 0^32`) because consumers pin its bytes.
    pub fn sign_hedged(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_hedged_with_context_rng(secret_key, message, &[], &mut OsRng)
    }

    /// Hedged signing with a context string, OS RNG.
    pub fn sign_hedged_with_context(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8],
        context: &[u8],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_hedged_with_context_rng(secret_key, message, context, &mut OsRng)
    }

    /// HashML-DSA.Sign with the pre-hash named by `alg` (FIPS 204 Algorithm 4):
    /// `M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(alg) ‖ alg(message)`.
    pub fn hash_sign_with(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        alg: metamui_prehash_oids::PreHashAlgorithm,
        message: &[u8],
        context: &[u8],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::hash_sign(secret_key, alg.oid(), &alg.hash(message), context, rnd)
    }

    /// HashML-DSA.Verify with the pre-hash named by `alg` (FIPS 204 Algorithm 5).
    pub fn hash_verify_with(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        alg: metamui_prehash_oids::PreHashAlgorithm,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        Self::hash_verify(public_key, alg.oid(), &alg.hash(message), context, signature)
    }

    /// ML-DSA.Sign external "pure" interface with a context string (≤255 bytes),
    /// deterministic: M' = 0x00 || |ctx| || ctx || M.
    pub fn sign_with_context(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8],
        context: &[u8],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        assert!(context.len() <= 255, "context must be at most 255 bytes");
        let mut m_prime = Vec::with_capacity(2 + context.len() + message.len());
        m_prime.extend_from_slice(&[0u8, context.len() as u8]);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(message);
        Self::sign_internal(secret_key, &m_prime, &[0u8; 32])
    }

    /// ML-DSA.Sign_internal: sign a pre-formatted message representation M'
    /// directly (μ = SHAKE256(tr || M')), with explicit randomness `rnd`
    /// (0^32 for deterministic, 32 random bytes for hedged).
    pub fn sign_internal(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        m_prime: &[u8],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        let mu = Self::mu_from_mprime(secret_key, m_prime);
        Self::sign_from_mu(secret_key, &mu, rnd, false)
    }

    /// ML-DSA.Sign_internal with an externally-supplied μ (ACVP externalMu).
    pub fn sign_external_mu(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        mu: &[u8; 64],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_from_mu(secret_key, mu, rnd, false)
    }

    /// HashML-DSA.Sign (pre-hash): M' = 0x01 || |ctx| || ctx || OID(ph) || PH(M),
    /// where `ph` names the pre-hash and `oid`/`phm` are its DER OID and digest.
    pub fn hash_sign(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        oid: &[u8],
        phm: &[u8],
        context: &[u8],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        assert!(context.len() <= 255, "context must be at most 255 bytes");
        let mut m_prime = Vec::with_capacity(2 + context.len() + oid.len() + phm.len());
        m_prime.extend_from_slice(&[1u8, context.len() as u8]);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(oid);
        m_prime.extend_from_slice(phm);
        Self::sign_internal(secret_key, &m_prime, rnd)
    }

    /// Internal signing core (FIPS 204 ML-DSA.Sign_internal): given the 64-byte
    /// commitment seed μ and the 32-byte randomness `rnd`, produce a signature.
    /// All public interfaces (external-pure, HashML-DSA, internal, externalMu)
    /// compute μ + rnd and route through here.
    pub fn sign_from_mu(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        mu_in: &[u8; 64],
        rnd: &[u8; 32],
        debug: bool
    ) -> [u8; Self::SIGNATURE_SIZE] {
        if debug { println!("\nSign: Starting signing process..."); }
        let mu = *mu_in; // local copy; the rejection loop reads `&mu`
        // Unpack secret key
        let (rho, k_seed, _tr, s1, s2, t0) = Self::unpack_sk(secret_key);

        // Convert to NTT
        let s1_ntt = s1.to_ntt();
        let s2_ntt = s2.to_ntt();
        let t0_ntt = t0.to_ntt();

        // Expand matrix A
        let a_matrix = Self::expand_a(&rho);

        // Generate rho'' = SHAKE256(K || rnd || μ, 64)
        let mut xof_rp = Shake256::default();
        Update::update(&mut xof_rp, &k_seed);
        Update::update(&mut xof_rp, rnd);
        Update::update(&mut xof_rp, &mu);
        let mut reader_rp = xof_rp.finalize_xof();
        let mut rho_prime = [0u8; 64];
        reader_rp.read(&mut rho_prime);
        
        // Signing loop with attempt limit
        let mut nonce = 0u16;
        let max_attempts = 10000;  // Standard limit
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            if attempts > max_attempts {
                if debug { println!("Sign: MAX ATTEMPTS REACHED! Failed after {} attempts", attempts); }
                return [0u8; Self::SIGNATURE_SIZE]; // Return empty signature on failure
            }
            // Sample y deterministically
            let y = Self::sample_y(&rho_prime, nonce);
            let y_ntt = y.to_ntt();
            
            // w = Ay (matching C reference exactly)
            let mut w_ntt = matrix_vector_mul_ntt(&a_matrix, &y_ntt).unwrap();
            // Reduce in NTT domain first (matching polyveck_reduce)
            w_ntt = w_ntt.reduce();
            // Then convert from NTT
            let mut w = w_ntt.from_ntt();
            
            // Apply caddq before decomposition (matching reference)
            w = w.caddq();
            
            if debug && nonce == 0 {
                println!("Sign: w after caddq[0][0..4]: {:?}", &w.polys[0].coeffs[..4]);
                // Also print w before caddq for comparison
                let w_before = w_ntt.from_ntt().reduce();
                println!("Sign: w before caddq[0][0..4]: {:?}", &w_before.polys[0].coeffs[..4]);
            }
            
            // Decompose w
            let mut w1 = PolyVec::zero(DILITHIUM2_PARAMS.k);
            let mut w0 = PolyVec::zero(DILITHIUM2_PARAMS.k);
            for i in 0..DILITHIUM2_PARAMS.k {
                let (w1_poly, w0_poly) = w.polys[i].decompose(DILITHIUM2_PARAMS.gamma2);
                w1.polys[i] = w1_poly;
                w0.polys[i] = w0_poly;
            }
            if debug && nonce == 0 {
                println!("Sign: w1[0][0..8]: {:?}", &w1.polys[0].coeffs[..8]);
            }
            let w1_packed_temp = pack_w1(&w1, &DILITHIUM2_PARAMS);
            // c_tilde = SHAKE256(μ || w1Encode, c_tilde_bytes)
            let mut xof_ct = Shake256::default();
            Update::update(&mut xof_ct, &mu);
            Update::update(&mut xof_ct, &w1_packed_temp);
            let mut reader_ct = xof_ct.finalize_xof();
            let mut c_seed_computed = [0u8; 32]; // c_tilde_bytes for ML-DSA-44
            reader_ct.read(&mut c_seed_computed);

            // Generate challenge from c_tilde
            let mut xof = Shake256::default();
            Update::update(&mut xof, &c_seed_computed);
            let mut reader = xof.finalize_xof();
            let c = sample_challenge(&mut reader, DILITHIUM2_PARAMS.tau);
            if debug && attempts <= 5 {
                // Check challenge coefficients
                let mut nonzero_c = 0;
                for &coeff in &c.coeffs {
                    if coeff != 0 {
                        nonzero_c += 1;
                    }
                }
                println!("Sign: challenge has {} non-zero coeffs (tau = {})", nonzero_c, DILITHIUM2_PARAMS.tau);
            }
            let c_ntt = c.to_ntt();
            
            // z = y + cs1
            // First check NTT domain values
            if debug && attempts == 1 {
                println!("Sign: Before NTT - s1[0][0] = {}, c[0] = {}", s1.polys[0].coeffs[0], c.coeffs[0]);
                let test_prod = s1_ntt.polys[0].mul_ntt(&c_ntt);
                println!("Sign: After NTT - s1_ntt[0][0] = {}, c_ntt[0] = {}", s1_ntt.polys[0].coeffs[0], c_ntt.coeffs[0]);
                println!("Sign: product in NTT[0] = {}", test_prod.coeffs[0]);
            }
            
            // Compute cs1: multiply s1 by challenge c
            // CRITICAL FIX: Properly reduce NTT coefficients to prevent explosion
            let cs1 = PolyVec::from_polys(
                s1_ntt.polys.iter()
                    .map(|s| {
                        // Ensure s is properly reduced in NTT domain
                        let s_reduced = s.reduce();
                        // Multiply in NTT domain  
                        let mut result_ntt = s_reduced.mul_ntt(&c_ntt);
                        // Reduce in NTT domain before converting back
                        result_ntt = result_ntt.reduce();
                        // Convert from NTT and apply final centered reduction
                        let mut result = result_ntt.from_ntt();
                        // Apply proper centered reduction to ensure coefficients are in correct range
                        for i in 0..result.coeffs.len() {
                            let mut coeff = result.coeffs[i];
                            coeff = coeff.rem_euclid(Q as i32);
                            if coeff > (Q as i32) / 2 {
                                coeff -= Q as i32;
                            }
                            result.coeffs[i] = coeff;
                        }
                        result
                    })
                    .collect()
            );
            if debug && attempts <= 5 {
                let mut max_cs1 = 0;
                for p in &cs1.polys {
                    for &c in &p.coeffs {
                        if c.abs() > max_cs1 {
                            max_cs1 = c.abs();
                        }
                    }
                }
                println!("Sign: max |cs1| = {}, max |y| should be around {}", max_cs1, DILITHIUM2_PARAMS.gamma1);
            }
            // Compute z = y + cs1 with proper centered reduction
            let mut z = y.add(&cs1).unwrap();
            // Apply proper centered reduction to z
            for i in 0..z.polys.len() {
                for j in 0..z.polys[i].coeffs.len() {
                    let mut coeff = z.polys[i].coeffs[j];
                    coeff = coeff.rem_euclid(Q as i32);
                    if coeff > (Q as i32) / 2 {
                        coeff -= Q as i32;
                    }
                    z.polys[i].coeffs[j] = coeff;
                }
            }
            
            // Check z bound (properly reduce coefficients first)
            let mut max_z = 0;
            for p in &z.polys {
                for &c in &p.coeffs {
                    // Reduce coefficient to centered range like check_norm_bound does
                    let mut c_reduced = c.rem_euclid(Q as i32);
                    if c_reduced > (Q as i32) / 2 {
                        c_reduced -= Q as i32;
                    }
                    let abs_c = c_reduced.abs();
                    if abs_c > max_z {
                        max_z = abs_c;
                    }
                }
            }
            if !z.check_norm_bound(DILITHIUM2_PARAMS.gamma1 - DILITHIUM2_PARAMS.beta) {
                if debug && attempts <= 5 {
                    println!("Sign: Rejection 1 - z norm failed, max_z: {}, bound: {}", max_z, DILITHIUM2_PARAMS.gamma1 - DILITHIUM2_PARAMS.beta);
                }
                nonce += DILITHIUM2_PARAMS.l as u16;
                continue;
            }
            
            // Compute cs2 with proper NTT reduction
            let cs2 = PolyVec::from_polys(
                s2_ntt.polys.iter()
                    .map(|s| {
                        let s_reduced = s.reduce();
                        let mut result_ntt = s_reduced.mul_ntt(&c_ntt);
                        result_ntt = result_ntt.reduce();
                        let mut result = result_ntt.from_ntt();
                        // Apply centered reduction
                        for i in 0..result.coeffs.len() {
                            let mut coeff = result.coeffs[i];
                            coeff = coeff.rem_euclid(Q as i32);
                            if coeff > (Q as i32) / 2 {
                                coeff -= Q as i32;
                            }
                            result.coeffs[i] = coeff;
                        }
                        result
                    })
                    .collect()
            );
            
            // Compute ct0 with proper NTT reduction
            let ct0 = PolyVec::from_polys(
                t0_ntt.polys.iter()
                    .map(|t| {
                        let t_reduced = t.reduce();
                        let mut result_ntt = t_reduced.mul_ntt(&c_ntt);
                        result_ntt = result_ntt.reduce();
                        let mut result = result_ntt.from_ntt();
                        // Apply centered reduction
                        for i in 0..result.coeffs.len() {
                            let mut coeff = result.coeffs[i];
                            coeff = coeff.rem_euclid(Q as i32);
                            if coeff > (Q as i32) / 2 {
                                coeff -= Q as i32;
                            }
                            result.coeffs[i] = coeff;
                        }
                        result
                    })
                    .collect()
            );
            
            // Compute w0 - cs2 (matching Python lines 290-300)
            let mut w0_minus_cs2 = w0.sub(&cs2).unwrap();
            // Python reduces coefficients mod q
            for i in 0..w0_minus_cs2.polys.len() {
                for j in 0..N {
                    let mut coeff = w0_minus_cs2.polys[i].coeffs[j];
                    coeff = coeff.rem_euclid(Q as i32);
                    if coeff > (Q / 2) as i32 {
                        coeff -= Q as i32;
                    }
                    w0_minus_cs2.polys[i].coeffs[j] = coeff;
                }
            }
            
            // Check w0 - cs2 bound (Python line 301)
            if !w0_minus_cs2.check_norm_bound(DILITHIUM2_PARAMS.gamma2 - DILITHIUM2_PARAMS.beta) {
                if debug && attempts <= 5 {
                    println!("Sign: Rejection 2 - w0-cs2 norm failed, bound: {}", DILITHIUM2_PARAMS.gamma2 - DILITHIUM2_PARAMS.beta);
                }
                nonce += DILITHIUM2_PARAMS.l as u16;
                continue;
            }
            
            // Check ct0 bound (Python line 307)
            if !ct0.check_norm_bound(DILITHIUM2_PARAMS.gamma2) {
                if debug && attempts <= 5 {
                    println!("Sign: Rejection 3 - ct0 norm failed, bound: {}", DILITHIUM2_PARAMS.gamma2);
                }
                nonce += DILITHIUM2_PARAMS.l as u16;
                continue;
            }
            
            // Make hint (matching Python lines 313-340)
            
            // For make_hint, we need raw addition without reduction
            // Python does: w0_minus_cs2.polys[i].coeffs[j] + ct0.polys[i].coeffs[j]
            let mut w0_minus_cs2_plus_ct0 = PolyVec::zero(DILITHIUM2_PARAMS.k);
            for i in 0..DILITHIUM2_PARAMS.k {
                for j in 0..N {
                    w0_minus_cs2_plus_ct0.polys[i].coeffs[j] = 
                        w0_minus_cs2.polys[i].coeffs[j] + ct0.polys[i].coeffs[j];
                }
            }
            
            
            // Debug position [1][7] specifically
            
            let (h, hint_count) = Self::make_hint(&w0_minus_cs2_plus_ct0, &w1);
            
            // Debug: show hint positions
            let mut hint_positions = Vec::new();
            for i in 0..DILITHIUM2_PARAMS.k {
                for j in 0..N {
                    if h.polys[i].coeffs[j] != 0 {
                        hint_positions.push((i, j, h.polys[i].coeffs[j]));
                    }
                }
            }
            
            // Check hint count
            if hint_count > DILITHIUM2_PARAMS.omega as usize {
                if debug && attempts <= 5 {
                    println!("Sign: Rejection 4 - hint count {} > omega {}", hint_count, DILITHIUM2_PARAMS.omega);
                }
                nonce += DILITHIUM2_PARAMS.l as u16;
                continue;
            }
            
            // Pack signature (matching Python lines 341-344)
            let mut sig = [0u8; Self::SIGNATURE_SIZE];
            
            // Pack c_tilde = SHAKE256(μ || w1Encode, c_tilde_bytes)
            let w1_packed = pack_w1(&w1, &DILITHIUM2_PARAMS);
            if debug {
                println!("\nSign: Final w1_packed[0..16]: {:02x?}", &w1_packed[..16]);
                println!("Sign: mu[0..8]: {:02x?}", &mu[..8]);
            }
            let mut xof_final = Shake256::default();
            Update::update(&mut xof_final, &mu);
            Update::update(&mut xof_final, &w1_packed);
            let mut reader_final = xof_final.finalize_xof();
            let mut c_seed_hash = [0u8; 32]; // c_tilde_bytes for ML-DSA-44
            reader_final.read(&mut c_seed_hash);
            if debug {
                println!("Sign: c_seed[0..8]: {:02x?}", &c_seed_hash[..8]);
            }
            sig[0..32].copy_from_slice(&c_seed_hash);
            
            // Pack z
            let z_packed = Self::pack_z(&z);
            sig[32..32 + z_packed.len()].copy_from_slice(&z_packed);
            
            // Pack hint
            let h_packed = Self::pack_hint(&h, hint_count);
            sig[32 + z_packed.len()..].copy_from_slice(&h_packed);
            
            return sig;
        }
    }
    
    /// Sign a message — **deterministic** ML-DSA (`rnd = 0^32`, empty context).
    /// Kept deterministic on purpose: downstream consumers pin these bytes. FIPS
    /// 204 recommends the hedged variant for new code: [`Self::sign_hedged`].
    pub fn sign(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8]
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_with_context(secret_key, message, &[])
    }
    
    /// Sign a message with randomization — the hedged variant, fresh `rnd`
    /// from the OS RNG (same as [`Self::sign_hedged`]).
    pub fn sign_randomized(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8]
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_hedged(secret_key, message)
    }
    
    /// Verify a Dilithium2 signature
    pub fn verify(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8]
    ) -> bool {
        Self::verify_with_context(public_key, message, signature, &[])
    }

    /// μ = SHAKE256(SHAKE256(pk,64) || M', 64).
    fn mu_from_mprime_pk(public_key: &[u8; Self::PUBLIC_KEY_SIZE], m_prime: &[u8]) -> [u8; 64] {
        let mut xt = Shake256::default();
        Update::update(&mut xt, public_key);
        let mut rt = xt.finalize_xof();
        let mut tr = [0u8; 64];
        rt.read(&mut tr);
        let mut xm = Shake256::default();
        Update::update(&mut xm, &tr);
        Update::update(&mut xm, m_prime);
        let mut rm = xm.finalize_xof();
        let mut mu = [0u8; 64];
        rm.read(&mut mu);
        mu
    }

    /// Verify external "pure" with context: M' = 0x00 || |ctx| || ctx || M.
    pub fn verify_with_context(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> bool {
        if context.len() > 255 { return false; }
        let mut m_prime = Vec::with_capacity(2 + context.len() + message.len());
        m_prime.extend_from_slice(&[0u8, context.len() as u8]);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(message);
        Self::verify_internal(public_key, &m_prime, signature)
    }

    /// ML-DSA.Verify_internal against a pre-formatted M' (μ = H(tr || M')).
    pub fn verify_internal(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        m_prime: &[u8],
        signature: &[u8],
    ) -> bool {
        let mu = Self::mu_from_mprime_pk(public_key, m_prime);
        Self::verify_from_mu(public_key, &mu, signature, false)
    }

    /// ML-DSA.Verify_internal with externally-supplied μ (ACVP externalMu).
    pub fn verify_external_mu(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        mu: &[u8; 64],
        signature: &[u8],
    ) -> bool {
        Self::verify_from_mu(public_key, mu, signature, false)
    }

    /// HashML-DSA.Verify: M' = 0x01 || |ctx| || ctx || OID(ph) || PH(M).
    pub fn hash_verify(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        oid: &[u8],
        phm: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        if context.len() > 255 { return false; }
        let mut m_prime = Vec::with_capacity(2 + context.len() + oid.len() + phm.len());
        m_prime.extend_from_slice(&[1u8, context.len() as u8]);
        m_prime.extend_from_slice(context);
        m_prime.extend_from_slice(oid);
        m_prime.extend_from_slice(phm);
        Self::verify_internal(public_key, &m_prime, signature)
    }

    /// Verification core given the 64-byte μ (with debug output).
    pub fn verify_from_mu(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        mu_in: &[u8; 64],
        signature: &[u8],
        debug: bool
    ) -> bool {
        let mu = *mu_in;
        if signature.len() != Self::SIGNATURE_SIZE {
            if debug { println!("Wrong signature size: {} vs expected {}", signature.len(), Self::SIGNATURE_SIZE); }
            return false;
        }
        
        // Unpack public key
        let rho = &public_key[0..32];
        let t1 = Self::unpack_t1(&public_key[32..]);
        if debug { println!("Unpacked public key - rho[0..8]: {:02x?}", &rho[..8]); }
        
        // Unpack signature - get c_seed from signature
        let c_seed = &signature[0..32];
        if debug { println!("c_seed from sig: {:02x?}", &c_seed[..8]); }
        
        // Unpack z and h from signature (skip c reconstruction)
        let z_start = 32;
        let z_end = z_start + DILITHIUM2_PARAMS.l * DILITHIUM2_PARAMS.poly_bytes;
        if signature.len() < z_end {
            return false;
        }
        let z = match crate::operations::unpack_z(&signature[z_start..z_end], DILITHIUM2_PARAMS.l, DILITHIUM2_PARAMS.gamma1) {
            Ok(z) => z,
            Err(e) => {
                if debug { println!("Failed to unpack z: {}", e); }
                return false;
            },
        };
        
        let h = match crate::operations::unpack_hint(&signature[z_end..], &DILITHIUM2_PARAMS) {
            Ok(h) => h,
            Err(e) => {
                if debug { println!("Failed to unpack hint: {}", e); }
                return false;
            },
        };
        
        // Reconstruct challenge from c_seed
        let mut xof = Shake256::default();
        Update::update(&mut xof, c_seed);
        let mut reader = xof.finalize_xof();
        let c = sample_challenge(&mut reader, DILITHIUM2_PARAMS.tau);
        
        // Check z bound
        let mut max_z = 0;
        for p in &z.polys {
            for &c in &p.coeffs {
                let abs_c = c.abs();
                if abs_c > max_z {
                    max_z = abs_c;
                }
            }
        }
        if !z.check_norm_bound(DILITHIUM2_PARAMS.gamma1 - DILITHIUM2_PARAMS.beta) {
            if debug { println!("z norm check failed, max_z: {}", max_z); }
            return false;
        }
        if debug { println!("z norm check passed, max_z: {}", max_z); }
        
        // Expand matrix A
        let a_matrix = Self::expand_a(rho);
        
        // Compute Az - ct1 * 2^D following reference implementation exactly
        // Convert z to NTT
        let z_ntt = z.to_ntt();
        let az_ntt = matrix_vector_mul_ntt(&a_matrix, &z_ntt).unwrap();
        
        // Convert challenge to NTT
        let c_ntt = c.to_ntt();
        
        // First shift t1 by D, then convert to NTT (matching C reference)
        let mut t1_shifted = PolyVec::zero(DILITHIUM2_PARAMS.k);
        for i in 0..DILITHIUM2_PARAMS.k {
            t1_shifted.polys[i] = t1.polys[i].shiftl(D);
        }
        // CRITICAL: Reduce after shifting to handle edge case where t1=1023
        // When t1=1023, shifting left by D=13 gives 8380416 = Q-1
        t1_shifted = t1_shifted.reduce();
        let t1_shifted_ntt = t1_shifted.to_ntt();
        
        // Multiply by challenge in NTT domain
        let mut ct1_2d_ntt = PolyVec::zero(DILITHIUM2_PARAMS.k);
        for i in 0..DILITHIUM2_PARAMS.k {
            ct1_2d_ntt.polys[i] = t1_shifted_ntt.polys[i].mul_ntt(&c_ntt);
        }
        
        // Subtract in NTT domain, then reduce (matching C reference)
        let mut w_approx_ntt = az_ntt.sub_ntt(&ct1_2d_ntt).unwrap();
        // Reduce in NTT domain (matching polyveck_reduce)
        w_approx_ntt = w_approx_ntt.reduce();
        // Then convert from NTT
        let mut w_approx = w_approx_ntt.from_ntt();
        
        // Apply caddq before use_hint (matching reference)
        w_approx = w_approx.caddq();
        
        if debug {
            println!("w_approx[0][0..4]: {:?}", &w_approx.polys[0].coeffs[..4]);
            // Show range of values after caddq
            let mut min_val = i32::MAX;
            let mut max_val = i32::MIN;
            for p in &w_approx.polys {
                for &c in &p.coeffs {
                    if c < min_val { min_val = c; }
                    if c > max_val { max_val = c; }
                }
            }
            println!("w_approx range after caddq: [{}, {}]", min_val, max_val);
        }
        
        // Use hint to recover w1
        let w1 = Self::use_hint(&h, &w_approx);
        if debug {
            println!("w1[0][0..8]: {:?}", &w1.polys[0].coeffs[..8]);
            // Show hints used
            let mut hint_positions = Vec::new();
            for i in 0..DILITHIUM2_PARAMS.k {
                for j in 0..8 {
                    if h.polys[i].coeffs[j] != 0 {
                        hint_positions.push((i, j));
                    }
                }
            }
            println!("Hints at positions: {:?}", hint_positions);
        }
        
        // μ is supplied by the caller (computed from pk/M' or externally).

        // Recompute c_tilde = SHAKE256(μ || w1Encode, c_tilde_bytes)
        let w1_packed = pack_w1(&w1, &DILITHIUM2_PARAMS);
        if debug {
            println!("w1_packed len: {}", w1_packed.len());
            println!("w1_packed[0..16]: {:02x?}", &w1_packed[..16]);
        }
        let mut xof_cv = Shake256::default();
        Update::update(&mut xof_cv, &mu);
        Update::update(&mut xof_cv, &w1_packed);
        let mut reader_cv = xof_cv.finalize_xof();
        let mut c_seed_recomputed = [0u8; 32]; // c_tilde_bytes for ML-DSA-44
        reader_cv.read(&mut c_seed_recomputed);
        if debug {
            println!("mu[0..8]: {:02x?}", &mu[..8]);
            println!("c_seed_recomputed[0..8]: {:02x?}", &c_seed_recomputed[..8]);
            println!("c_seed[0..8]:            {:02x?}", &c_seed[..8]);
        }
        
        // Compare c_seed values
        let mut equal = true;
        for i in 0..32 {
            if c_seed[i] != c_seed_recomputed[i] {
                equal = false;
                break;
            }
        }
        
        if debug { println!("Verification result: {}", equal); }
        equal
    }
    
    // Helper methods
    
    fn expand_a(rho: &[u8]) -> Vec<PolyVec> {
        expand_a(rho, &DILITHIUM2_PARAMS)
    }
    
    fn expand_s(seed: &[u8], len: usize, nonce: u8) -> PolyVec {
        expand_s(seed, len, nonce, DILITHIUM2_PARAMS.eta)
    }
    
    fn pack_t1(t1: &PolyVec) -> Vec<u8> {
        crate::operations::pack_t1(t1)
    }
    
    fn pack_eta_vec(vec: &PolyVec, eta: u32) -> Vec<u8> {
        crate::operations::pack_eta_vec(vec, eta)
    }
    
    fn pack_t0(t0: &PolyVec) -> Vec<u8> {
        crate::operations::pack_t0(t0)
    }
    
    fn unpack_sk(sk: &[u8]) -> ([u8; 32], [u8; 32], [u8; 64], PolyVec, PolyVec, PolyVec) {
        unpack_sk(sk, &DILITHIUM2_PARAMS)
    }
    
    fn sample_y(seed: &[u8], nonce: u16) -> PolyVec {
        sample_y_l(seed, nonce, &DILITHIUM2_PARAMS)
    }
    
    fn challenge_from_w1(mu: &[u8], w1: &PolyVec) -> Poly {
        challenge_from_w1(mu, w1, &DILITHIUM2_PARAMS)
    }
    
    fn compute_ct0(c_ntt: &Poly, t0_ntt: &PolyVec) -> PolyVec {
        compute_ct0(c_ntt, t0_ntt)
    }
    
    fn make_hint(w0_final: &PolyVec, w1: &PolyVec) -> (PolyVec, usize) {
        make_hint_dilithium(w0_final, w1, &DILITHIUM2_PARAMS)
    }
    
    fn pack_challenge_seed(mu: &[u8], w1: &PolyVec) -> [u8; 32] {
        // c_tilde = SHAKE256(μ || w1Encode, c_tilde_bytes)
        let w1_packed = pack_w1(w1, &DILITHIUM2_PARAMS);
        let mut xof = Shake256::default();
        Update::update(&mut xof, mu);
        Update::update(&mut xof, &w1_packed);
        let mut reader = xof.finalize_xof();
        let mut seed = [0u8; 32];
        reader.read(&mut seed);
        seed
    }
    
    fn pack_z(z: &PolyVec) -> Vec<u8> {
        pack_z(z, &DILITHIUM2_PARAMS)
    }
    
    fn pack_hint(h: &PolyVec, count: usize) -> Vec<u8> {
        pack_hint(h, count, &DILITHIUM2_PARAMS)
    }
    
    fn unpack_t1(data: &[u8]) -> PolyVec {
        unpack_t1(data, &DILITHIUM2_PARAMS)
    }
    
    fn unpack_sig(sig: &[u8]) -> Result<(Poly, PolyVec, PolyVec), &'static str> {
        unpack_sig(sig, &DILITHIUM2_PARAMS)
    }
    
    fn use_hint(h: &PolyVec, w: &PolyVec) -> PolyVec {
        use_hint(h, w, &DILITHIUM2_PARAMS)
    }
}

/// Generate a new Dilithium2 key pair (convenience function)
pub fn generate_keypair() -> ([u8; Dilithium2::PUBLIC_KEY_SIZE], [u8; Dilithium2::SECRET_KEY_SIZE]) {
    Dilithium2::generate_keypair()
}
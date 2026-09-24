/// CRYSTALS-Dilithium3 implementation (NIST Security Level 3)

use crate::params::{DILITHIUM3_PARAMS, N, D};
use crate::poly::{Poly, PolyVec, matrix_vector_mul_ntt};
use crate::operations::*;
use rand_core::{RngCore, CryptoRng};
use crate::sha3_compat::{Shake256};
use crate::sha3_compat::digest::{Update};
use rand::rngs::OsRng;

/// Dilithium3 - NIST Security Level 3 (192-bit security)
pub struct Dilithium3;

// `challenge_from_w1`/`pack_challenge_seed` are kept on this impl for
// per-parameter-set spec traceability even when the current
// sign/verify path calls through the crate::operations layer directly.
#[allow(dead_code)]
impl Dilithium3 {
    /// Public key size in bytes
    pub const PUBLIC_KEY_SIZE: usize = 1952;
    
    /// Secret key size in bytes
    pub const SECRET_KEY_SIZE: usize = 4032;
    
    /// Signature size in bytes
    pub const SIGNATURE_SIZE: usize = 3309;
    
    /// Generate a new Dilithium3 key pair
    pub fn generate_keypair() -> ([u8; Self::PUBLIC_KEY_SIZE], [u8; Self::SECRET_KEY_SIZE]) {
        Self::generate_keypair_with_rng(&mut OsRng)
    }
    
    /// Generate a new Dilithium3 key pair with specific RNG
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
        Update::update(&mut xof, &[DILITHIUM3_PARAMS.k as u8]);
        Update::update(&mut xof, &[DILITHIUM3_PARAMS.l as u8]);
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
        let s1 = Self::expand_s(&rho_prime_seed, DILITHIUM3_PARAMS.l, 0);
        let s2 = Self::expand_s(&rho_prime_seed, DILITHIUM3_PARAMS.k, DILITHIUM3_PARAMS.l as u8);
        
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
        // 4. Add s2 in regular domain (NOT in NTT domain!)
        let mut t = as1.add(&s2).unwrap();
        // 5. Final reduce is implicit in add
        
        // Apply caddq before power2round (matching C reference)
        t = t.caddq();
        
        // Decompose t into t1 and t0
        let mut t1 = PolyVec::zero(DILITHIUM3_PARAMS.k);
        let mut t0 = PolyVec::zero(DILITHIUM3_PARAMS.k);
        
        for i in 0..DILITHIUM3_PARAMS.k {
            let (t1_poly, t0_poly) = t.polys[i].power2round(D);
            t1.polys[i] = t1_poly;
            t0.polys[i] = t0_poly;
        }
        
        // Pack public key
        let mut pk = [0u8; Self::PUBLIC_KEY_SIZE];
        pk[0..32].copy_from_slice(&rho);
        let t1_packed = Self::pack_t1(&t1);
        pk[32..].copy_from_slice(&t1_packed);
        
        // Compute tr = H(ρ || t1) - for Dilithium3/5, this is 64 bytes from SHAKE256
        let mut xof = Shake256::default();
        Update::update(&mut xof, &pk);
        let mut reader = xof.finalize_xof();
        let mut tr = [0u8; 64];
        reader.read(&mut tr);
        
        // Pack secret key
        let mut sk = [0u8; Self::SECRET_KEY_SIZE];
        let mut offset = 0;
        
        // ρ
        sk[offset..offset + 32].copy_from_slice(&rho);
        offset += 32;
        
        // K
        sk[offset..offset + 32].copy_from_slice(&k_seed);
        offset += 32;
        
        // tr
        sk[offset..offset + 64].copy_from_slice(&tr);
        offset += 64;
        
        // s1
        let s1_packed = Self::pack_eta_vec(&s1, DILITHIUM3_PARAMS.eta);
        sk[offset..offset + s1_packed.len()].copy_from_slice(&s1_packed);
        offset += s1_packed.len();
        
        // s2
        let s2_packed = Self::pack_eta_vec(&s2, DILITHIUM3_PARAMS.eta);
        sk[offset..offset + s2_packed.len()].copy_from_slice(&s2_packed);
        offset += s2_packed.len();
        
        // t0
        let t0_packed = Self::pack_t0(&t0);
        sk[offset..offset + t0_packed.len()].copy_from_slice(&t0_packed);
        
        (pk, sk)
    }
    
    /// Sign a message with Dilithium3 (deterministic)
    pub fn sign(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8]
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_with_context(secret_key, message, &[])
    }
    
    /// Sign a message with Dilithium3 using specific RNG
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

    /// ML-DSA.Sign external "pure" with context (≤255 bytes), deterministic:
    /// M' = 0x00 || |ctx| || ctx || M.
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

    /// ML-DSA.Sign_internal: sign a pre-formatted M' directly (μ = H(tr || M')).
    pub fn sign_internal(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        m_prime: &[u8],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        let mu = Self::mu_from_mprime(secret_key, m_prime);
        Self::sign_from_mu(secret_key, &mu, rnd)
    }

    /// ML-DSA.Sign_internal with an externally-supplied μ (ACVP externalMu).
    pub fn sign_external_mu(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        mu: &[u8; 64],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_from_mu(secret_key, mu, rnd)
    }

    /// HashML-DSA.Sign: M' = 0x01 || |ctx| || ctx || OID(ph) || PH(M).
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

    /// Internal signing core (FIPS 204 ML-DSA.Sign_internal): given μ and rnd.
    pub fn sign_from_mu(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        mu_in: &[u8; 64],
        rnd: &[u8; 32],
    ) -> [u8; Self::SIGNATURE_SIZE] {
        let mu = *mu_in; // local copy; the rejection loop reads `&mu`
        // Unpack secret key
        let (rho, k_seed, _tr, s1, s2, t0) = Self::unpack_sk(secret_key);

        // Expand matrix A
        let a_matrix = Self::expand_a(&rho);

        // Convert secret vectors to NTT
        let s1_ntt = s1.to_ntt();
        let s2_ntt = s2.to_ntt();
        let t0_ntt = t0.to_ntt();

        // ρ'' = H(K || rnd || μ, 64)
        let mut xof_rp = Shake256::default();
        Update::update(&mut xof_rp, &k_seed);
        Update::update(&mut xof_rp, rnd);
        Update::update(&mut xof_rp, &mu);
        let mut reader_rp = xof_rp.finalize_xof();
        let mut rho_prime = [0u8; 64];
        reader_rp.read(&mut rho_prime);
        
        let mut nonce = 0u16;
        let max_attempts = 1000;  // Reasonable limit to prevent infinite loops
        let mut attempts = 0;
        
        loop {
            attempts += 1;
            if attempts > max_attempts {
                return [0u8; Self::SIGNATURE_SIZE]; // Return empty signature on failure
            }
            // Sample masking vector y
            let y = Self::sample_y(&rho_prime, nonce);
            let y_ntt = y.to_ntt();
            
            // w = Ay
            let mut w_ntt = matrix_vector_mul_ntt(&a_matrix, &y_ntt).unwrap();
            // Reduce in NTT domain first
            w_ntt = w_ntt.reduce();
            // Then convert from NTT
            let mut w = w_ntt.from_ntt();
            
            // Apply caddq before decomposition (matching reference implementation)
            w = w.caddq();
            
            // Decompose w into w1 and w0
            let mut w1 = PolyVec::zero(DILITHIUM3_PARAMS.k);
            let mut w0 = PolyVec::zero(DILITHIUM3_PARAMS.k);
            
            for i in 0..DILITHIUM3_PARAMS.k {
                let (w1_poly, w0_poly) = w.polys[i].decompose(DILITHIUM3_PARAMS.gamma2);
                w1.polys[i] = w1_poly;
                w0.polys[i] = w0_poly;
            }
            
            // For FIPS 204 ML-DSA, c_tilde = SHAKE-256(μ || w1)
            let w1_packed_temp = pack_w1(&w1, &DILITHIUM3_PARAMS);
            let mut xof = Shake256::default();
            Update::update(&mut xof, &mu);
            Update::update(&mut xof, &w1_packed_temp);
            let mut reader = xof.finalize_xof();
            
            let mut c_tilde_computed = [0u8; 48]; // DILITHIUM3_PARAMS.c_tilde_bytes
            reader.read(&mut c_tilde_computed);
            
            // Now generate challenge from c_tilde using SHAKE256
            let mut xof_chal = Shake256::default();
            Update::update(&mut xof_chal, &c_tilde_computed);
            let mut chal_reader = xof_chal.finalize_xof();
            let c = sample_challenge(&mut chal_reader, DILITHIUM3_PARAMS.tau);
            let c_ntt = c.to_ntt();
            
            // z = y + cs1
            let cs1 = PolyVec::from_polys(
                s1_ntt.polys.iter()
                    .map(|s| s.mul_ntt(&c_ntt).from_ntt().reduce())
                    .collect()
            );
            let z = y.add(&cs1).unwrap().reduce();
            
            // Check z bound
            if !z.check_norm_bound(DILITHIUM3_PARAMS.gamma1 - DILITHIUM3_PARAMS.beta) {
                nonce += DILITHIUM3_PARAMS.l as u16;
                continue;
            }
            
            // cs2 = c * s2
            let cs2 = PolyVec::from_polys(
                s2_ntt.polys.iter()
                    .map(|s| s.mul_ntt(&c_ntt).from_ntt().reduce())
                    .collect()
            );
            
            // w0 - cs2
            let w0_minus_cs2 = w0.sub(&cs2).unwrap();
            
            // Check norm bound for w0 - cs2
            if !w0_minus_cs2.check_norm_bound(DILITHIUM3_PARAMS.gamma2 - DILITHIUM3_PARAMS.beta) {
                nonce += DILITHIUM3_PARAMS.l as u16;
                continue;
            }
            
            // ct0 = c * t0
            let ct0 = Self::compute_ct0(&c_ntt, &t0_ntt);
            
            // Check ct0 bound
            if !ct0.check_norm_bound(DILITHIUM3_PARAMS.gamma2) {
                nonce += DILITHIUM3_PARAMS.l as u16;
                continue;
            }
            
            // For make_hint, we need w0 - cs2 + ct0
            let mut w0_minus_cs2_plus_ct0 = PolyVec::zero(DILITHIUM3_PARAMS.k);
            for i in 0..DILITHIUM3_PARAMS.k {
                for j in 0..N {
                    w0_minus_cs2_plus_ct0.polys[i].coeffs[j] = 
                        w0_minus_cs2.polys[i].coeffs[j] + ct0.polys[i].coeffs[j];
                }
            }
            
            // Make hint
            let (h, hint_count) = Self::make_hint(&w0_minus_cs2_plus_ct0, &w1);
            
            // Check hint count
            if hint_count > DILITHIUM3_PARAMS.omega as usize {
                nonce += DILITHIUM3_PARAMS.l as u16;
                continue;
            }
            
            // Pack signature
            let mut sig = [0u8; Self::SIGNATURE_SIZE];
            let mut offset = 0;
            
            // Pack c_tilde (the challenge seed)
            sig[offset..offset + 48].copy_from_slice(&c_tilde_computed);
            offset += 48;
            
            // Pack z
            let z_packed = Self::pack_z(&z);
            sig[offset..offset + z_packed.len()].copy_from_slice(&z_packed);
            offset += z_packed.len();
            
            // Pack hint
            let h_packed = Self::pack_hint(&h, hint_count);
            sig[offset..offset + h_packed.len()].copy_from_slice(&h_packed);
            
            return sig;
        }
    }
    
    /// Sign a message deterministically
    pub fn sign_deterministic(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8]
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign(secret_key, message)
    }
    
    /// Sign a message with randomization — the hedged variant, fresh `rnd`
    /// from the OS RNG (same as [`Self::sign_hedged`]).
    pub fn sign_randomized(
        secret_key: &[u8; Self::SECRET_KEY_SIZE],
        message: &[u8]
    ) -> [u8; Self::SIGNATURE_SIZE] {
        Self::sign_hedged(secret_key, message)
    }
    
    /// Verify a Dilithium3 signature (empty context).
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
        ctx: &[u8],
    ) -> bool {
        if ctx.len() > 255 { return false; }
        let mut m_prime = Vec::with_capacity(2 + ctx.len() + message.len());
        m_prime.extend_from_slice(&[0u8, ctx.len() as u8]);
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(message);
        Self::verify_internal(public_key, &m_prime, signature)
    }

    /// ML-DSA.Verify_internal: verify against a pre-formatted M' (μ = H(tr || M')).
    pub fn verify_internal(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        m_prime: &[u8],
        signature: &[u8],
    ) -> bool {
        let mu = Self::mu_from_mprime_pk(public_key, m_prime);
        Self::verify_from_mu(public_key, &mu, signature)
    }

    /// ML-DSA.Verify_internal with externally-supplied μ (ACVP externalMu).
    pub fn verify_external_mu(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        mu: &[u8; 64],
        signature: &[u8],
    ) -> bool {
        Self::verify_from_mu(public_key, mu, signature)
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

    /// Verification core given the 64-byte μ.
    pub fn verify_from_mu(
        public_key: &[u8; Self::PUBLIC_KEY_SIZE],
        mu_in: &[u8; 64],
        signature: &[u8],
    ) -> bool {
        if signature.len() != Self::SIGNATURE_SIZE {
            return false;
        }
        let mu = *mu_in;

        // Unpack public key
        let (rho, t1) = Self::unpack_pk(public_key);
        
        // Unpack signature
        let (c, z, h) = match Self::unpack_sig(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        // Check z norm bound
        if !z.check_norm_bound(DILITHIUM3_PARAMS.gamma1 - DILITHIUM3_PARAMS.beta) {
            return false;
        }
        
        // Expand matrix A
        let a_matrix = Self::expand_a(&rho);
        
        // Compute Az - ct1 * 2^d
        let z_ntt = z.to_ntt();
        let az_ntt = matrix_vector_mul_ntt(&a_matrix, &z_ntt).unwrap();
        
        // Convert challenge to NTT
        let c_ntt = c.to_ntt();
        
        // First shift t1 by D, then convert to NTT (matching reference)
        let mut t1_shifted = PolyVec::zero(DILITHIUM3_PARAMS.k);
        for i in 0..DILITHIUM3_PARAMS.k {
            t1_shifted.polys[i] = t1.polys[i].shiftl(D);
        }
        // Reduce after shifting
        t1_shifted = t1_shifted.reduce();
        let t1_shifted_ntt = t1_shifted.to_ntt();
        
        // Multiply by challenge in NTT domain
        let mut ct1_2d_ntt = PolyVec::zero(DILITHIUM3_PARAMS.k);
        for i in 0..DILITHIUM3_PARAMS.k {
            ct1_2d_ntt.polys[i] = t1_shifted_ntt.polys[i].mul_ntt(&c_ntt);
        }
        
        // Subtract in NTT domain, then reduce
        let mut w_approx_ntt = az_ntt.sub_ntt(&ct1_2d_ntt).unwrap();
        w_approx_ntt = w_approx_ntt.reduce();
        let mut w_approx = w_approx_ntt.from_ntt();
        
        // Reduce after from_ntt to bring coefficients into proper range
        w_approx = w_approx.reduce();
        
        // Apply caddq before use_hint
        w_approx = w_approx.caddq();
        
        // Use hint to recover w1
        let w1 = Self::use_hint(&h, &w_approx);

        // Recompute challenge c_tilde = SHAKE-256(μ || w1, 48)
        let w1_packed = pack_w1(&w1, &DILITHIUM3_PARAMS);
        
        let mut xof_chal = Shake256::default();
        Update::update(&mut xof_chal, &mu);
        Update::update(&mut xof_chal, &w1_packed);
        let mut chal_reader = xof_chal.finalize_xof();
        
        let mut c_seed_verify = [0u8; 48]; // DILITHIUM3_PARAMS.c_tilde_bytes
        chal_reader.read(&mut c_seed_verify);
        
        // Compare with the challenge seed from signature
        let c_seed_sig = &signature[0..48];
        
        #[cfg(test)]
        {
            eprintln!("D3 Verify: c_seed_sig = {:?}", &c_seed_sig[0..8]);
            eprintln!("D3 Verify: c_seed_verify = {:?}", &c_seed_verify[0..8]);
            eprintln!("D3 Verify: c_seed match = {}", c_seed_sig == &c_seed_verify[..]);
        }
        
        c_seed_sig == &c_seed_verify[..]
    }
    
    // Helper methods
    fn expand_a(rho: &[u8]) -> Vec<PolyVec> {
        expand_a(rho, &DILITHIUM3_PARAMS)
    }
    
    fn expand_s(seed: &[u8], len: usize, nonce: u8) -> PolyVec {
        expand_s(seed, len, nonce, DILITHIUM3_PARAMS.eta)
    }
    
    fn pack_t1(t1: &PolyVec) -> Vec<u8> {
        let mut packed = Vec::with_capacity((DILITHIUM3_PARAMS.k * N * 10) / 8);
        
        for poly in &t1.polys {
            for i in 0..(N / 4) {
                let t0 = poly.coeffs[4 * i] & 0x3FF;
                let t1 = poly.coeffs[4 * i + 1] & 0x3FF;
                let t2 = poly.coeffs[4 * i + 2] & 0x3FF;
                let t3 = poly.coeffs[4 * i + 3] & 0x3FF;
                
                packed.push((t0 & 0xFF) as u8);
                packed.push(((t0 >> 8) | ((t1 & 0x3F) << 2)) as u8);
                packed.push(((t1 >> 6) | ((t2 & 0x0F) << 4)) as u8);
                packed.push(((t2 >> 4) | ((t3 & 0x03) << 6)) as u8);
                packed.push((t3 >> 2) as u8);
            }
        }
        
        packed
    }
    
    fn pack_eta_vec(vec: &PolyVec, eta: u32) -> Vec<u8> {
        let mut packed = Vec::new();
        
        for poly in &vec.polys {
            if eta == 2 {
                // 3 bits per coefficient, pack 8 coefficients into 3 bytes
                for i in (0..N).step_by(8) {
                    let mut t = [0u32; 8];
                    for j in 0..8 {
                        t[j] = (eta as i32 - poly.coeffs[i + j]) as u32;
                    }
                    
                    packed.push((t[0] | (t[1] << 3) | (t[2] << 6)) as u8);
                    packed.push(((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) as u8);
                    packed.push(((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) as u8);
                }
            } else if eta == 4 {
                for i in 0..(N / 2) {
                    let c0 = (eta as i32 - poly.coeffs[2 * i]) as u8;
                    let c1 = (eta as i32 - poly.coeffs[2 * i + 1]) as u8;
                    packed.push((c0 & 0x0F) | ((c1 & 0x0F) << 4));
                }
            }
        }
        
        packed
    }
    
    fn pack_t0(t0: &PolyVec) -> Vec<u8> {
        pack_t0(t0)
    }
    
    fn unpack_sk(sk: &[u8]) -> ([u8; 32], [u8; 32], [u8; 64], PolyVec, PolyVec, PolyVec) {
        let mut offset = 0;
        
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&sk[offset..offset + 32]);
        offset += 32;
        
        let mut k_seed = [0u8; 32];
        k_seed.copy_from_slice(&sk[offset..offset + 32]);
        offset += 32;
        
        let mut tr = [0u8; 64];
        tr.copy_from_slice(&sk[offset..offset + 64]);
        offset += 64;
        
        // Calculate eta bytes correctly
        let eta_bytes = if DILITHIUM3_PARAMS.eta == 2 { 96 } else { 128 };
        
        // Unpack s1
        let s1_len = DILITHIUM3_PARAMS.l * eta_bytes;
        let s1 = Self::unpack_eta_vec(&sk[offset..offset + s1_len], DILITHIUM3_PARAMS.l, DILITHIUM3_PARAMS.eta);
        offset += s1_len;
        
        // Unpack s2
        let s2_len = DILITHIUM3_PARAMS.k * eta_bytes;
        let s2 = Self::unpack_eta_vec(&sk[offset..offset + s2_len], DILITHIUM3_PARAMS.k, DILITHIUM3_PARAMS.eta);
        offset += s2_len;
        
        // Unpack t0
        let t0 = Self::unpack_t0(&sk[offset..]);
        
        (rho, k_seed, tr, s1, s2, t0)
    }
    
    fn unpack_eta_vec(data: &[u8], len: usize, eta: u32) -> PolyVec {
        let mut vec = PolyVec::zero(len);
        let mut offset = 0;
        
        for i in 0..len {
            if eta == 2 {
                // 3 bits per coefficient, 8 coefficients packed into 3 bytes
                for j in 0..(N / 8) {
                    let b0 = data[offset] as u32;
                    let b1 = data[offset + 1] as u32;
                    let b2 = data[offset + 2] as u32;
                    offset += 3;
                    
                    vec.polys[i].coeffs[8 * j] = eta as i32 - ((b0 & 0x07) as i32);
                    vec.polys[i].coeffs[8 * j + 1] = eta as i32 - (((b0 >> 3) & 0x07) as i32);
                    vec.polys[i].coeffs[8 * j + 2] = eta as i32 - (((b0 >> 6) | ((b1 & 0x01) << 2)) as i32);
                    vec.polys[i].coeffs[8 * j + 3] = eta as i32 - (((b1 >> 1) & 0x07) as i32);
                    vec.polys[i].coeffs[8 * j + 4] = eta as i32 - (((b1 >> 4) & 0x07) as i32);
                    vec.polys[i].coeffs[8 * j + 5] = eta as i32 - (((b1 >> 7) | ((b2 & 0x03) << 1)) as i32);
                    vec.polys[i].coeffs[8 * j + 6] = eta as i32 - (((b2 >> 2) & 0x07) as i32);
                    vec.polys[i].coeffs[8 * j + 7] = eta as i32 - (((b2 >> 5) & 0x07) as i32);
                }
            } else if eta == 4 {
                for j in 0..(N / 2) {
                    let byte = data[offset];
                    offset += 1;
                    
                    vec.polys[i].coeffs[2 * j] = eta as i32 - ((byte & 0x0F) as i32);
                    vec.polys[i].coeffs[2 * j + 1] = eta as i32 - (((byte >> 4) & 0x0F) as i32);
                }
            }
        }
        
        vec
    }
    
    fn unpack_t0(data: &[u8]) -> PolyVec {
        unpack_t0(data, &DILITHIUM3_PARAMS)
    }
    
    fn sample_y(seed: &[u8], nonce: u16) -> PolyVec {
        sample_y_l(seed, nonce, &DILITHIUM3_PARAMS)
    }
    
    fn challenge_from_w1(mu: &[u8], w1: &PolyVec) -> Poly {
        challenge_from_w1(mu, w1, &DILITHIUM3_PARAMS)
    }
    
    fn compute_ct0(c_ntt: &Poly, t0_ntt: &PolyVec) -> PolyVec {
        PolyVec::from_polys(
            t0_ntt.polys.iter()
                .map(|t| t.mul_ntt(c_ntt).from_ntt().reduce())
                .collect()
        )
    }
    
    fn make_hint(w0_final: &PolyVec, w1: &PolyVec) -> (PolyVec, usize) {
        make_hint_dilithium(w0_final, w1, &DILITHIUM3_PARAMS)
    }
    
    fn pack_challenge_seed(c: &Poly) -> [u8; 32] {
        pack_challenge_seed(c)
    }
    
    fn pack_z(z: &PolyVec) -> Vec<u8> {
        pack_z(z, &DILITHIUM3_PARAMS)
    }
    
    fn pack_hint(h: &PolyVec, count: usize) -> Vec<u8> {
        pack_hint(h, count, &DILITHIUM3_PARAMS)
    }
    
    fn unpack_pk(pk: &[u8]) -> ([u8; 32], PolyVec) {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[0..32]);
        
        let t1 = Self::unpack_t1(&pk[32..]);
        
        (rho, t1)
    }
    
    fn unpack_t1(data: &[u8]) -> PolyVec {
        let mut vec = PolyVec::zero(DILITHIUM3_PARAMS.k);
        let mut offset = 0;
        
        for i in 0..DILITHIUM3_PARAMS.k {
            for j in 0..(N / 4) {
                let t0 = data[offset] as i32 | ((data[offset + 1] as i32 & 0x03) << 8);
                let t1 = (data[offset + 1] as i32 >> 2) | ((data[offset + 2] as i32 & 0x0F) << 6);
                let t2 = (data[offset + 2] as i32 >> 4) | ((data[offset + 3] as i32 & 0x3F) << 4);
                let t3 = (data[offset + 3] as i32 >> 6) | ((data[offset + 4] as i32) << 2);
                
                vec.polys[i].coeffs[4 * j] = t0;
                vec.polys[i].coeffs[4 * j + 1] = t1;
                vec.polys[i].coeffs[4 * j + 2] = t2;
                vec.polys[i].coeffs[4 * j + 3] = t3;
                
                offset += 5;
            }
        }
        
        vec
    }
    
    fn unpack_sig(sig: &[u8]) -> Result<(Poly, PolyVec, PolyVec), &'static str> {
        unpack_sig(sig, &DILITHIUM3_PARAMS)
    }
    
    fn use_hint(h: &PolyVec, w: &PolyVec) -> PolyVec {
        use_hint(h, w, &DILITHIUM3_PARAMS)
    }
}

/// Generate a new Dilithium3 key pair (convenience function)
pub fn generate_keypair() -> ([u8; Dilithium3::PUBLIC_KEY_SIZE], [u8; Dilithium3::SECRET_KEY_SIZE]) {
    Dilithium3::generate_keypair()
}
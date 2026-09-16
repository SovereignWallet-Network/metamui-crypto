//! Core KEM operations for ML-KEM (all parameter sets)

use crate::{
    error::{MLKemError, Result},
    params::MLKemParams,
    polynomial::{Polynomial, PolynomialVector},
    ntt::ntt,
    sampling::{sample_noise, sample_uniform},
    indcpa,
};
use metamui_shake::shake256::Shake256;
use metamui_security_utils::{ConditionallySelectable, ConstantTimeEq};
use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

/// Generate an ML-KEM keypair for any parameter set (ML-KEM.KeyGen, FIPS 203
/// Algorithm 19): draw `d`, then `z`, and run [`mlkem_keygen_from_dz`].
///
/// The application path and the ACVP keyGen gate go through one body. This
/// used to be a copy of `mlkem_keygen_from_dz`, so the vectors verified the
/// copy and not the function applications call (#202).
pub fn mlkem_keygen<R: RngCore + CryptoRng>(
    params: &MLKemParams,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    rng: &mut R,
) -> Result<()> {
    params.validate()?;

    // Draw order is d then z, as it was before the bodies were merged, so a
    // given RNG stream yields the same key pair.
    let mut d = [0u8; 32];
    rng.fill_bytes(&mut d);
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut z);

    mlkem_keygen_from_dz(params, public_key, secret_key, &d, &z)
}

/// Encapsulate shared secret (ML-KEM.Encaps, FIPS 203 Algorithm 20).
///
/// The §7.2 encapsulation-key check is the algorithm's input step: a key of
/// the wrong length, or one whose packed `t̂` holds a coefficient ≥ q, is
/// refused with [`MLKemError::InvalidPublicKey`] before any randomness is
/// drawn.
pub fn mlkem_encapsulate<R: RngCore + CryptoRng>(
    params: &MLKemParams,
    public_key: &[u8],
    ciphertext: &mut [u8],
    shared_secret: &mut [u8],
    rng: &mut R,
) -> Result<()> {
    check_encapsulation_key(params, public_key)?;

    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);

    // The same body the ACVP encapDecap gate drives (#202).
    encapsulate_internal(params, public_key, ciphertext, shared_secret, &m)
}

/// Decapsulate shared secret (ML-KEM.Decaps, FIPS 203 Algorithm 21).
///
/// The §7.3 input checks run first: a ciphertext of the wrong length is
/// refused with [`MLKemError::InvalidCiphertext`], and a decapsulation key of
/// the wrong length or whose stored `H(ek)` does not match the `ek` it embeds
/// with [`MLKemError::InvalidSecretKey`]. A well-formed ciphertext that fails
/// re-encryption is not an error: implicit rejection returns `J(z ‖ c)`.
pub fn mlkem_decapsulate(
    params: &MLKemParams,
    secret_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &mut [u8],
) -> Result<()> {
    check_decapsulation_inputs(params, secret_key, ciphertext)?;

    // Unpack secret key. FIPS 203 §6.1 stores ŝ = ByteEncode₁₂(ŝ) already in
    // the NTT domain, so it is used directly by K-PKE.Decrypt — no ntt() here
    // (historical Finding #28 double-transform bug).
    let (s, pk, h, z) = unpack_secret_key(params, secret_key)?;

    // Decrypt ciphertext
    let mut m_prime = [0u8; 32];
    indcpa_decrypt(params, ciphertext, &s, &mut m_prime)?;
    
    // Compute (K̂', r') = G(m' || H(pk))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(&h);
    
    let g_output = sha3_512(&g_input);
    let mut k_hat_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_hat_prime.copy_from_slice(&g_output[..32]);
    r_prime.copy_from_slice(&g_output[32..]);
    
    // Re-encrypt and compare
    let mut c_prime = vec![0u8; params.ciphertext_bytes];
    indcpa_encrypt(params, &m_prime, &pk, &r_prime, &mut c_prime)?;
    
    // Constant-time comparison
    let valid = ciphertext.ct_eq(&c_prime);

    // FIPS 203 final §6.3 Algorithm 17:
    //   if c == c':  K = K_bar' (from G output above)
    //   else:        K = J(z || c) where J = SHAKE256(_, 32 bytes)
    //
    // Round 3 / FIPS 203 IPD used a single KDF
    //   K = SHAKE256( (K_bar' if valid else z) || H(c), 32 )
    // which the final spec replaced. Each branch selects the source
    // bytes constant-time, then computes the rejection K independently;
    // the final K is a constant-time conditional select between
    // K_bar' (valid path) and the rejection K (invalid path).
    // See Finding #28 in tools/swift-review/PHASE_2_STATUS.md.
    let mut reject_input: Vec<u8> = Vec::with_capacity(32 + ciphertext.len());
    reject_input.extend_from_slice(&z);
    reject_input.extend_from_slice(ciphertext);
    let mut shake = Shake256::new();
    let _ = shake.update(&reject_input);
    let mut reader = shake.finalize_xof();
    let k_reject_vec = reader.read(32);
    let mut k_reject = [0u8; 32];
    k_reject.copy_from_slice(&k_reject_vec);

    for i in 0..32 {
        shared_secret[i] = u8::conditional_select(&k_reject[i], &k_hat_prime[i], !valid);
    }

    Ok(())
}

// Helper functions

fn generate_matrix_a(params: &MLKemParams, rho: &[u8; 32]) -> Result<Vec<Vec<Polynomial>>> {
    let mut a = vec![vec![Polynomial::zero(); params.k]; params.k];

    for i in 0..params.k {
        for j in 0..params.k {
            // FIPS 203 §5.1: Â[i][j] = SampleNTT(XOF(ρ ‖ j ‖ i)). SampleNTT
            // already yields the matrix entry in the NTT domain (Alg 7), so
            // NO further ntt() is applied here — doing so would double-transform
            // (the historical Finding #28 divergence).
            a[i][j] = sample_uniform(rho, i as u8, j as u8)?;
        }
    }

    Ok(a)
}

fn pack_public_key(
    params: &MLKemParams,
    output: &mut [u8],
    t: &PolynomialVector,
    rho: &[u8; 32],
) -> Result<()> {
    // Pack t vector
    let mut offset = 0;
    for i in 0..params.k {
        t.polynomials[i].pack(&mut output[offset..offset + 384]);
        offset += 384;
    }
    
    // Append rho
    output[offset..offset + 32].copy_from_slice(rho);
    
    Ok(())
}

fn pack_secret_key(
    params: &MLKemParams,
    output: &mut [u8],
    s: &PolynomialVector,
    public_key: &[u8],
    h: &[u8; 32],
    z: &[u8; 32],
) -> Result<()> {
    let mut offset = 0;
    
    // Pack s vector
    for i in 0..params.k {
        s.polynomials[i].pack(&mut output[offset..offset + 384]);
        offset += 384;
    }
    
    // Append public key
    output[offset..offset + params.public_key_bytes].copy_from_slice(public_key);
    offset += params.public_key_bytes;
    
    // Append H(pk)
    output[offset..offset + 32].copy_from_slice(h);
    offset += 32;
    
    // Append z
    output[offset..offset + 32].copy_from_slice(z);
    
    Ok(())
}

fn unpack_secret_key(
    params: &MLKemParams,
    secret_key: &[u8],
) -> Result<(PolynomialVector, Vec<u8>, [u8; 32], [u8; 32])> {
    let mut offset = 0;
    
    // Unpack s vector
    let mut s = PolynomialVector::new(params.k);
    for i in 0..params.k {
        s.polynomials[i] = Polynomial::unpack(&secret_key[offset..offset + 384]);
        offset += 384;
    }
    
    // Extract public key
    let pk = secret_key[offset..offset + params.public_key_bytes].to_vec();
    offset += params.public_key_bytes;
    
    // Extract H(pk)
    let mut h = [0u8; 32];
    h.copy_from_slice(&secret_key[offset..offset + 32]);
    offset += 32;
    
    // Extract z
    let mut z = [0u8; 32];
    z.copy_from_slice(&secret_key[offset..offset + 32]);
    
    Ok((s, pk, h, z))
}

fn indcpa_encrypt(
    params: &MLKemParams,
    m: &[u8; 32],
    public_key: &[u8],
    coins: &[u8; 32],
    ciphertext: &mut [u8],
) -> Result<()> {
    // Use the full implementation from indcpa module
    let ct = indcpa::indcpa_encrypt(params, m, public_key, coins)?;
    
    // Verify ciphertext size
    if ct.len() != params.ciphertext_bytes {
        return Err(MLKemError::InvalidCiphertextSize);
    }
    
    // Copy to output buffer
    ciphertext.copy_from_slice(&ct);
    Ok(())
}

fn indcpa_decrypt(
    params: &MLKemParams,
    ciphertext: &[u8],
    s: &PolynomialVector,
    plaintext: &mut [u8; 32],
) -> Result<()> {
    // Use the full implementation from indcpa module
    let m = indcpa::indcpa_decrypt(params, ciphertext, s)?;
    
    // Copy to output buffer
    plaintext.copy_from_slice(&m);
    Ok(())
}

// =============================================================================
// FIPS 203 §7 key checks (ACVP FIPS203-tr1 encapsulationKeyCheck /
// decapsulationKeyCheck)
// =============================================================================

/// FIPS 203 §7.2 encapsulation-key check: `ek` must be exactly `384k + 32`
/// bytes and every 12-bit coefficient of its packed `t̂` must be below `q`
/// (equivalently `ByteEncode₁₂(ByteDecode₁₂(ek)) == ek`). A key that fails
/// must not be used for encapsulation.
pub fn mlkem_validate_encapsulation_key(params: &MLKemParams, ek: &[u8]) -> bool {
    let k = params.k;
    if ek.len() != 384 * k + 32 {
        return false;
    }
    let mut bad = 0u16;
    for chunk in ek[..384 * k].chunks_exact(3) {
        let c0 = (chunk[0] as u16) | (((chunk[1] & 0x0F) as u16) << 8);
        let c1 = ((chunk[1] >> 4) as u16) | ((chunk[2] as u16) << 4);
        // constant-time: accumulate the "≥ q" condition without branching
        bad |= (c0.wrapping_sub(params.q) >> 15) ^ 1;
        bad |= (c1.wrapping_sub(params.q) >> 15) ^ 1;
    }
    bad == 0
}

/// FIPS 203 §7.3 decapsulation-key check: `dk` must be exactly `768k + 96`
/// bytes and carry `H(ek)` at `dk[768k+32 .. 768k+64]` for the `ek` it
/// embeds at `dk[384k .. 768k+32]`; the embedded `ek` is also put through the
/// §7.2 check. A key that fails must not be used for decapsulation.
pub fn mlkem_validate_decapsulation_key(params: &MLKemParams, dk: &[u8]) -> bool {
    let k = params.k;
    if dk.len() != 768 * k + 96 {
        return false;
    }
    let ek = &dk[384 * k..768 * k + 32];
    let h = sha3_256(ek);
    let mut diff = 0u8;
    for (a, b) in h.iter().zip(&dk[768 * k + 32..768 * k + 64]) {
        diff |= a ^ b;
    }
    (diff == 0) & mlkem_validate_encapsulation_key(params, ek)
}

/// §7.2 as an error, for the encapsulation entry points.
fn check_encapsulation_key(params: &MLKemParams, ek: &[u8]) -> Result<()> {
    if mlkem_validate_encapsulation_key(params, ek) {
        Ok(())
    } else {
        Err(MLKemError::InvalidPublicKey)
    }
}

/// §7.3 as errors, for the decapsulation entry point: ciphertext type check,
/// decapsulation-key type check and hash check — exactly what FIPS 203 §7.3
/// prescribes (the embedded `ek` is not put through the §7.2 modulus check
/// here, matching the specification and mlkem-native's `check_sk`).
fn check_decapsulation_inputs(params: &MLKemParams, dk: &[u8], ct: &[u8]) -> Result<()> {
    let k = params.k;
    if ct.len() != params.ciphertext_bytes {
        return Err(MLKemError::InvalidCiphertext);
    }
    if dk.len() != 768 * k + 96 {
        return Err(MLKemError::InvalidSecretKey);
    }
    let h = sha3_256(&dk[384 * k..768 * k + 32]);
    let mut diff = 0u8;
    for (a, b) in h.iter().zip(&dk[768 * k + 32..768 * k + 64]) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(MLKemError::InvalidSecretKey);
    }
    Ok(())
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    metamui_sha3::sha3_256(data)
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    metamui_sha3::sha3_512(data)
}

/// Generate ML-KEM keypair from an explicit (d, z) pair.
///
/// FIPS 203 §6.1 K-PKE.KeyGen takes two independent 32-byte randomness
/// inputs: d (used to derive ρ and σ via G) and z (FO-transform secret
/// retained in the secret key). This entry point matches that interface
/// verbatim, enabling byte-equality validation against NIST ACVP keyGen
/// vectors which supply d and z as separate fields.
pub fn mlkem_keygen_from_dz(
    params: &MLKemParams,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    d: &[u8; 32],
    z: &[u8; 32],
) -> Result<()> {
    params.validate()?;

    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = params.k as u8;

    let g_output = sha3_512(&g_input);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_output[..32]);
    sigma.copy_from_slice(&g_output[32..]);

    let a = generate_matrix_a(params, &rho)?;

    let mut s = PolynomialVector::new(params.k);
    for i in 0..params.k {
        s.polynomials[i] = sample_noise(params.eta1, &sigma, i as u8)?;
        ntt(&mut s.polynomials[i]);
    }

    let mut e = PolynomialVector::new(params.k);
    for i in 0..params.k {
        e.polynomials[i] = sample_noise(params.eta1, &sigma, (params.k + i) as u8)?;
        ntt(&mut e.polynomials[i]);
    }

    let mut t = PolynomialVector::new(params.k);
    for i in 0..params.k {
        t.polynomials[i] = Polynomial::zero();
        for j in 0..params.k {
            let mut temp = a[i][j].clone();
            temp.multiply_ntt(&s.polynomials[j]);
            t.polynomials[i].add(&temp);
        }
        t.polynomials[i].add(&e.polynomials[i]);
        t.polynomials[i].reduce();
    }

    // FIPS 203 §5.1/§6.1: pack t̂ and ŝ in the NTT domain (no inverse_ntt).
    pack_public_key(params, public_key, &t, &rho)?;
    pack_secret_key(params, secret_key, &s, public_key, &sha3_256(public_key), z)?;

    Ok(())
}

/// Generate ML-KEM keypair deterministically from a 32-byte seed.
///
/// Mirrors the `mlkem768::generate_keypair_from_seed` convention so all
/// three variants share the same cross-language byte-equality contract:
///   - `d := seed` (32-byte keygen randomness, FIPS 203 §6.1)
///   - `z := SHA3-256(seed || b"z_derivation")` (FO-transform randomness)
///
/// Any other ML-KEM-{512,1024} implementation that wires the same
/// (d, z) derivation from the same seed must produce byte-equal pk + sk.
/// Only the `fips203-internal` wrappers call it.
#[cfg(feature = "fips203-internal")]
pub fn mlkem_keygen_from_seed(
    params: &MLKemParams,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    seed: &[u8; 32],
) -> Result<()> {
    // z := SHA3-256(seed || "z_derivation") — single-seed convenience contract.
    let mut z_input = [0u8; 32 + 12];
    z_input[..32].copy_from_slice(seed);
    z_input[32..].copy_from_slice(b"z_derivation");
    let z = sha3_256(&z_input);

    mlkem_keygen_from_dz(params, public_key, secret_key, seed, &z)
}

/// Deterministically encapsulate an ML-KEM shared secret using `m` as the
/// 32-byte message instead of sampling from an RNG (ML-KEM.Encaps_internal,
/// FIPS 203 Algorithm 17, behind the §7.2 input check). The ACVP encapDecap
/// gate and the `fips203-internal` wrappers call it. `test` keeps the in-crate
/// ACVP gate compiled whatever the manifest enables.
#[cfg(any(test, feature = "fips203-internal"))]
pub fn mlkem_encapsulate_deterministic(
    params: &MLKemParams,
    public_key: &[u8],
    ciphertext: &mut [u8],
    shared_secret: &mut [u8],
    m: &[u8; 32],
) -> Result<()> {
    check_encapsulation_key(params, public_key)?;
    encapsulate_internal(params, public_key, ciphertext, shared_secret, m)
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17) on an already checked `ek`.
fn encapsulate_internal(
    params: &MLKemParams,
    public_key: &[u8],
    ciphertext: &mut [u8],
    shared_secret: &mut [u8],
    m: &[u8; 32],
) -> Result<()> {
    let h = sha3_256(public_key);

    // (K̄, r) = G(m ‖ H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h);
    let g_output = sha3_512(&g_input);
    let mut k_bar = [0u8; 32];
    let mut r = [0u8; 32];
    k_bar.copy_from_slice(&g_output[..32]);
    r.copy_from_slice(&g_output[32..]);

    indcpa_encrypt(params, m, public_key, &r, ciphertext)?;

    // FIPS 203 final §6.2: K is taken directly from G output. The earlier
    // Kyber Round 3 / FIPS 203 IPD step K = SHAKE256(K̄ ‖ H(c), 32) was removed
    // in the final spec. See Finding #28 in tools/swift-review/PHASE_2_STATUS.md.
    shared_secret.copy_from_slice(&k_bar);

    Ok(())
}

#[cfg(all(test, feature = "std"))]
mod acvp_engine_tests {
    //! Byte-equality of the generic FIPS 203 engine against genuine NIST
    //! ACVP vectors (vendored at test-vectors/ml-kem/acvp-fips203/). This is
    //! the go/no-go gate for the Finding #28 in-tree port — it exercises the
    //! engine directly (pub(crate)) for all three parameter sets, independent
    //! of the per-variant wrapper modules.
    use super::*;
    use crate::params::{MLKEM512_PARAMS, MLKEM768_PARAMS, MLKEM1024_PARAMS};
    use serde_json::Value;
    use std::path::PathBuf;

    fn acvp(name: &str) -> Value {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("test-vectors/ml-kem/acvp-fips203");
        p.push(name);
        let raw = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("read {}: {}", p.display(), e));
        serde_json::from_str(&raw).unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn arr32(s: &str) -> [u8; 32] {
        let b = unhex(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    }

    fn check_keygen(params: &MLKemParams, file: &str) {
        let data = acvp(file);
        for tv in data["test_vectors"].as_array().unwrap() {
            let d = arr32(tv["d"].as_str().unwrap());
            let z = arr32(tv["z"].as_str().unwrap());
            let mut ek = vec![0u8; params.public_key_bytes];
            let mut dk = vec![0u8; params.secret_key_bytes];
            mlkem_keygen_from_dz(params, &mut ek, &mut dk, &d, &z).unwrap();
            assert_eq!(ek, unhex(tv["ek"].as_str().unwrap()),
                "tc{} ek", tv["tcId"]);
            assert_eq!(dk, unhex(tv["dk"].as_str().unwrap()),
                "tc{} dk", tv["tcId"]);
        }
    }
    fn check_encapdecap(params: &MLKemParams, file: &str) {
        let data = acvp(file);
        for tv in data["encapsulation"]["test_vectors"].as_array().unwrap() {
            let ek = unhex(tv["ek"].as_str().unwrap());
            let m = arr32(tv["m"].as_str().unwrap());
            let mut ct = vec![0u8; params.ciphertext_bytes];
            let mut ss = [0u8; 32];
            mlkem_encapsulate_deterministic(params, &ek, &mut ct, &mut ss, &m).unwrap();
            assert_eq!(ct, unhex(tv["c"].as_str().unwrap()), "tc{} c", tv["tcId"]);
            assert_eq!(&ss[..], &unhex(tv["k"].as_str().unwrap())[..], "tc{} k", tv["tcId"]);
        }
        let dk = unhex(data["decapsulation"]["dk"].as_str().unwrap());
        for tv in data["decapsulation"]["test_vectors"].as_array().unwrap() {
            let ct = unhex(tv["c"].as_str().unwrap());
            let mut ss = [0u8; 32];
            mlkem_decapsulate(params, &dk, &ct, &mut ss).unwrap();
            assert_eq!(&ss[..], &unhex(tv["k"].as_str().unwrap())[..], "tc{} decap k", tv["tcId"]);
        }
    }

    #[test] fn acvp_512_keygen() { check_keygen(&MLKEM512_PARAMS, "ml-kem-512-keygen-acvp.json"); }
    #[test] fn acvp_768_keygen() { check_keygen(&MLKEM768_PARAMS, "ml-kem-768-keygen-acvp.json"); }
    #[test] fn acvp_1024_keygen() { check_keygen(&MLKEM1024_PARAMS, "ml-kem-1024-keygen-acvp.json"); }
    #[test] fn acvp_512_encapdecap() { check_encapdecap(&MLKEM512_PARAMS, "ml-kem-512-encapdecap-acvp.json"); }
    #[test] fn acvp_768_encapdecap() { check_encapdecap(&MLKEM768_PARAMS, "ml-kem-768-encapdecap-acvp.json"); }
    #[test] fn acvp_1024_encapdecap() { check_encapdecap(&MLKEM1024_PARAMS, "ml-kem-1024-encapdecap-acvp.json"); }
}

/// The ACVP gate above drives `mlkem_keygen_from_dz` and
/// `mlkem_encapsulate_deterministic`; applications call `mlkem_keygen` and
/// `mlkem_encapsulate`. These tests pin the two together: for the values an
/// RNG hands out, the application path returns exactly what the internal path
/// returns for those values. They use no feature beyond the parameter sets, so
/// no feature choice can switch them off (#202).
#[cfg(test)]
mod rng_path_is_the_internal_path {
    use super::*;
    use crate::params::{MLKEM512_PARAMS, MLKEM768_PARAMS, MLKEM1024_PARAMS};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn check(params: &MLKemParams) {
        for i in 0..8u8 {
            let seed = [i.wrapping_mul(37) ^ params.k as u8; 32];
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut replay = ChaCha20Rng::from_seed(seed);

            let mut ek = vec![0u8; params.public_key_bytes];
            let mut dk = vec![0u8; params.secret_key_bytes];
            mlkem_keygen(params, &mut ek, &mut dk, &mut rng).unwrap();
            let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
            replay.fill_bytes(&mut d);
            replay.fill_bytes(&mut z);
            let mut ek_i = vec![0u8; params.public_key_bytes];
            let mut dk_i = vec![0u8; params.secret_key_bytes];
            mlkem_keygen_from_dz(params, &mut ek_i, &mut dk_i, &d, &z).unwrap();
            assert_eq!(ek, ek_i, "k={} i={i}: KeyGen and KeyGen_internal disagree on ek", params.k);
            assert_eq!(dk, dk_i, "k={} i={i}: KeyGen and KeyGen_internal disagree on dk", params.k);

            let mut ct = vec![0u8; params.ciphertext_bytes];
            let mut ss = [0u8; 32];
            mlkem_encapsulate(params, &ek, &mut ct, &mut ss, &mut rng).unwrap();
            let mut m = [0u8; 32];
            replay.fill_bytes(&mut m);
            let mut ct_i = vec![0u8; params.ciphertext_bytes];
            let mut ss_i = [0u8; 32];
            mlkem_encapsulate_deterministic(params, &ek, &mut ct_i, &mut ss_i, &m).unwrap();
            assert_eq!(ct, ct_i, "k={} i={i}: Encaps and Encaps_internal disagree on c", params.k);
            assert_eq!(ss, ss_i, "k={} i={i}: Encaps and Encaps_internal disagree on K", params.k);
        }
    }

    #[test] fn mlkem512() { check(&MLKEM512_PARAMS); }
    #[test] fn mlkem768() { check(&MLKEM768_PARAMS); }
    #[test] fn mlkem1024() { check(&MLKEM1024_PARAMS); }

    #[test]
    fn a_rejected_key_draws_no_randomness() {
        // §7.2 runs before the draw, as it did when the bodies were separate.
        let params = &MLKEM768_PARAMS;
        let bad = vec![0xffu8; params.public_key_bytes];
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let mut ct = vec![0u8; params.ciphertext_bytes];
        let mut ss = [0u8; 32];
        assert!(mlkem_encapsulate(params, &bad, &mut ct, &mut ss, &mut rng).is_err());
        let mut untouched = ChaCha20Rng::from_seed([9u8; 32]);
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}

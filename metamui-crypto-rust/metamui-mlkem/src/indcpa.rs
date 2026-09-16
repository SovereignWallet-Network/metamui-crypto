//! IND-CPA secure PKE scheme for ML-KEM

use crate::{
    error::Result,
    params::MLKemParams,
    polynomial::{Polynomial, PolynomialVector},
    ntt::{ntt, inverse_ntt},
    sampling::{sample_noise, sample_uniform},
    compress::{compress, decompress},
};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

// NOTE: K-PKE.KeyGen (FIPS 203 Alg 13) lives in `crate::kem` (it shares the
// G(d‖k) seed expansion and key packing with ML-KEM.KeyGen). This module
// provides K-PKE.Encrypt (Alg 14) and K-PKE.Decrypt (Alg 15).

/// IND-CPA encryption
pub fn indcpa_encrypt(
    params: &MLKemParams,
    m: &[u8; 32],
    public_key: &[u8],
    coins: &[u8; 32],
) -> Result<Vec<u8>> {
    // Unpack public key. FIPS 203 §5.1 ek packs t̂ in the NTT domain, so
    // ByteDecode₁₂ yields t̂ ready for use — no re-ntt later.
    let (pkpv, seed) = unpack_public_key(params, public_key)?;
    
    // Encode message
    let k = encode_message(m);
    
    // Generate matrix A^T
    let mut at = vec![vec![Polynomial::zero(); params.k]; params.k];
    for i in 0..params.k {
        for j in 0..params.k {
            // FIPS 203 §5.2: Âᵀ[i][j] = SampleNTT(XOF(ρ ‖ i ‖ j)) — the
            // transpose vs keygen comes from swapping the two index bytes.
            // SampleNTT already yields an NTT-domain entry (Alg 7); no ntt().
            at[i][j] = sample_uniform(&seed, j as u8, i as u8)?;
        }
    }
    
    #[cfg(test)]
    {
        println!("Encrypt: A^T[0][0][0..4] = {:?}", &at[0][0].coefficients[..4]);
        // Note: A^T[0][0] = A[0][0] when indices are swapped
        // So this should match A[0][0] from keygen
    }
    
    // Sample vectors with noise
    let mut nonce = 0u8;
    let mut sp = PolynomialVector::new(params.k);
    for i in 0..params.k {
        sp.polynomials[i] = sample_noise(params.eta1, coins, nonce)?;
        nonce += 1;
    }
    
    let mut ep = PolynomialVector::new(params.k);
    for i in 0..params.k {
        ep.polynomials[i] = sample_noise(params.eta2, coins, nonce)?;
        nonce += 1;
    }
    
    let epp = sample_noise(params.eta2, coins, nonce)?;
    
    // Convert r (sp) to NTT domain: r̂ = NTT(r). e1 (ep) and e2 (epp) stay in
    // the normal domain — they are added after the inverse NTT below.
    for i in 0..params.k {
        ntt(&mut sp.polynomials[i]);
    }

    // pkpv holds t̂ already in the NTT domain (see unpack above) — no ntt().

    // Compute b = A^T s + e1
    let mut b = PolynomialVector::new(params.k);
    for i in 0..params.k {
        b.polynomials[i] = Polynomial::zero();
        for j in 0..params.k {
            let mut temp = at[i][j].clone();
            temp.multiply_ntt(&sp.polynomials[j]);
            b.polynomials[i].add(&temp);
        }
    }
    
    // Compute v = t^T s' (dot product of vectors)
    let mut v = Polynomial::zero();
    for i in 0..params.k {
        let mut temp = pkpv.polynomials[i].clone();
        temp.multiply_ntt(&sp.polynomials[i]);
        v.add(&temp);
    }
    
    // Convert b and v back from NTT
    for i in 0..params.k {
        inverse_ntt(&mut b.polynomials[i]);
        // Based on testing, inverse_ntt already produces normal form
    }
    inverse_ntt(&mut v);
    // Based on testing, inverse_ntt already produces normal form
    
    // Add errors and message (all in normal form now)
    for i in 0..params.k {
        b.polynomials[i].add(&ep.polynomials[i]);
        b.polynomials[i].reduce();
    }
    
    v.add(&epp);
    v.add(&k);
    v.reduce();
    
    // Compress and pack ciphertext
    let mut ciphertext = Vec::new();
    
    // Compress b (u in the paper)
    for i in 0..params.k {
        // Normalize to [0, Q) before compression
        b.polynomials[i].normalize();
        let compressed = compress(&b.polynomials[i], params.du);
        ciphertext.extend_from_slice(&compressed);
    }
    
    // Compress v
    // Normalize to [0, Q) before compression
    v.normalize();
    let compressed_v = compress(&v, params.dv);
    ciphertext.extend_from_slice(&compressed_v);
    
    Ok(ciphertext)
}

/// IND-CPA decryption
pub fn indcpa_decrypt(
    params: &MLKemParams,
    ciphertext: &[u8],
    secret_key: &PolynomialVector,  // Assumed to be in NTT form
) -> Result<[u8; 32]> {
    // Unpack ciphertext
    let mut u = PolynomialVector::new(params.k);
    let mut offset = 0;
    
    // Decompress u
    for i in 0..params.k {
        let compressed_size = (256 * params.du + 7) / 8;
        u.polynomials[i] = decompress(&ciphertext[offset..offset + compressed_size], params.du);
        offset += compressed_size;
    }
    
    // Decompress v
    let v = decompress(&ciphertext[offset..], params.dv);
    
    // Convert u to NTT domain for multiplication with secret key
    for i in 0..params.k {
        ntt(&mut u.polynomials[i]);
    }
    
    // Compute s^T u in NTT domain
    let mut mp = Polynomial::zero();
    for i in 0..params.k {
        let mut temp = secret_key.polynomials[i].clone();
        temp.multiply_ntt(&u.polynomials[i]);
        mp.add(&temp);
    }
    
    // Convert back from NTT
    inverse_ntt(&mut mp);
    // Based on testing, inverse_ntt already produces normal form
    
    // Compute m = v - s^T u
    let mut m_poly = v.clone();
    m_poly.sub(&mp);
    m_poly.reduce();
    
    // Decode message
    let m = decode_message(&m_poly);
    
    Ok(m)
}

fn unpack_public_key(params: &MLKemParams, public_key: &[u8]) -> Result<(PolynomialVector, [u8; 32])> {
    let mut t = PolynomialVector::new(params.k);
    let mut offset = 0;
    
    // Unpack t vector (polynomials are in normal domain)
    for i in 0..params.k {
        t.polynomials[i] = Polynomial::unpack(&public_key[offset..offset + 384]);
        offset += 384;
    }
    
    // Extract seed (rho)
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&public_key[offset..offset + 32]);
    
    Ok((t, seed))
}

fn encode_message(m: &[u8; 32]) -> Polynomial {
    let mut poly = Polynomial::zero();
    
    for i in 0..32 {
        for j in 0..8 {
            let bit = (m[i] >> j) & 1;
            poly.coefficients[8 * i + j] = (bit as i16) * ((crate::polynomial::Q + 1) / 2);
        }
    }
    
    poly
}

fn decode_message(poly: &Polynomial) -> [u8; 32] {
    let mut m = [0u8; 32];
    
    for i in 0..32 {
        for j in 0..8 {
            // Get coefficient - it should be close to 0 or ±Q/2
            let mut coeff = poly.coefficients[8 * i + j];
            
            // Normalize to [0, Q)
            while coeff < 0 {
                coeff += crate::polynomial::Q;
            }
            while coeff >= crate::polynomial::Q {
                coeff -= crate::polynomial::Q;
            }
            
            // Decode bit using the standard Kyber/ML-KEM decoding
            // Round to nearest: multiply by 2, add Q/2, divide by Q
            let t = ((coeff << 1) + crate::polynomial::Q / 2) / crate::polynomial::Q;
            m[i] |= ((t & 1) as u8) << j;
        }
    }
    
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::ntt;
    use crate::params::MLKEM768_PARAMS;
    use metamui_sha3::sha3_512;

    /// K-PKE encrypt→decrypt round-trip. Builds a keypair through the same
    /// FIPS 203 primitives the KEM uses (t̂/ŝ kept in the NTT domain), then
    /// checks the 32-byte message survives K-PKE.Encrypt / K-PKE.Decrypt.
    #[test]
    fn kpke_encrypt_decrypt_roundtrip() {
        let params = &MLKEM768_PARAMS;
        let d = [0x24u8; 32];

        // (ρ, σ) = G(d ‖ k)
        let mut g_in = [0u8; 33];
        g_in[..32].copy_from_slice(&d);
        g_in[32] = params.k as u8;
        let g = sha3_512(&g_in);
        let mut rho = [0u8; 32];
        let mut sigma = [0u8; 32];
        rho.copy_from_slice(&g[..32]);
        sigma.copy_from_slice(&g[32..]);

        // Â (NTT domain — SampleNTT output, no extra ntt)
        let mut a = vec![vec![Polynomial::zero(); params.k]; params.k];
        for i in 0..params.k {
            for j in 0..params.k {
                a[i][j] = sample_uniform(&rho, i as u8, j as u8).unwrap();
            }
        }
        // ŝ, ê = NTT(CBD)
        let mut s = PolynomialVector::new(params.k);
        let mut e = PolynomialVector::new(params.k);
        for i in 0..params.k {
            s.polynomials[i] = sample_noise(params.eta1, &sigma, i as u8).unwrap();
            ntt(&mut s.polynomials[i]);
            e.polynomials[i] = sample_noise(params.eta1, &sigma, (params.k + i) as u8).unwrap();
            ntt(&mut e.polynomials[i]);
        }
        // t̂ = Â ∘ ŝ + ê  (all NTT domain)
        let mut t = PolynomialVector::new(params.k);
        for i in 0..params.k {
            for j in 0..params.k {
                let mut tmp = a[i][j].clone();
                tmp.multiply_ntt(&s.polynomials[j]);
                t.polynomials[i].add(&tmp);
            }
            t.polynomials[i].add(&e.polynomials[i]);
            t.polynomials[i].reduce();
        }
        // ek = ByteEncode₁₂(t̂) ‖ ρ
        let mut pk = vec![0u8; params.public_key_bytes];
        let mut off = 0;
        for i in 0..params.k {
            t.polynomials[i].pack(&mut pk[off..off + 384]);
            off += 384;
        }
        pk[off..off + 32].copy_from_slice(&rho);

        let m = [0xA5u8; 32];
        let coins = [0x13u8; 32];
        let ct = indcpa_encrypt(params, &m, &pk, &coins).unwrap();
        assert_eq!(ct.len(), params.ciphertext_bytes);

        // ŝ is the K-PKE decryption key (NTT domain).
        let m_dec = indcpa_decrypt(params, &ct, &s).unwrap();
        assert_eq!(m, m_dec, "K-PKE round-trip must recover the message");
    }
}

//! Packing operations for HAETAE keys and signatures
//!
//! This module provides bit-level serialization for public keys, secret keys, and signatures.
//! Signature packing uses rANS entropy coding for compression.
//!
//! Transcopy from: metamui-haetae/src/packing.c

use crate::params::{K, L, M, N, SEEDBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
                    CRYPTO_BYTES, POLYQ_PACKEDBYTES, POLYETA_PACKEDBYTES,
                    BASE_ENC_H, BASE_ENC_HB_Z1};
// s1 is poly2eta-packed only for D=1 (HAETAE-2/3); HAETAE-5 packs it with
// polyeta and never reads this constant, which `-D warnings` turns into an error.
#[cfg(any(feature = "haetae2", feature = "haetae3"))]
use crate::params::POLY2ETA_PACKEDBYTES;
use crate::polyvec::{PolyVecK, PolyVecL, PolyVecM};
use crate::polymat::{polymatkl_expand, polymatkl_double};
use crate::poly::Poly;
use crate::encoding::{encode_h, decode_h, encode_hb_z1, decode_hb_z1};

/// Pack public key: pk = (seed, b)
///
/// Packs the public key into CRYPTO_PUBLICKEYBYTES bytes.
///
/// # Arguments
/// * `pk` - Output buffer for packed public key
/// * `b` - Polynomial vector containing public key coefficients
/// * `seed` - Seed for matrix A
///
/// Transcopy from: void pack_pk(uint8_t pk[], polyveck *b, const uint8_t seed[SEEDBYTES])
pub fn pack_pk(pk: &mut [u8; CRYPTO_PUBLICKEYBYTES], b: &PolyVecK, seed: &[u8; SEEDBYTES]) {
    // Copy seed to beginning of pk
    pk[..SEEDBYTES].copy_from_slice(seed);

    // Pack each polynomial of b
    for i in 0..K {
        let offset = SEEDBYTES + i * POLYQ_PACKEDBYTES;
        let mut packed_poly = [0u8; POLYQ_PACKEDBYTES];
        b.vec[i].polyq_pack(&mut packed_poly);
        pk[offset..offset + POLYQ_PACKEDBYTES].copy_from_slice(&packed_poly);
    }
}

/// Unpack public key: (seed, b) = pk
///
/// Unpacks the public key from CRYPTO_PUBLICKEYBYTES bytes.
///
/// # Arguments
/// * `b` - Output polynomial vector for public key coefficients
/// * `seed` - Output buffer for seed
/// * `pk` - Input packed public key
///
/// Transcopy from: void unpack_pk(polyveck *b, uint8_t seed[SEEDBYTES], const uint8_t pk[])
pub fn unpack_pk(b: &mut PolyVecK, seed: &mut [u8; SEEDBYTES], pk: &[u8; CRYPTO_PUBLICKEYBYTES]) {
    // Extract seed from beginning of pk
    seed.copy_from_slice(&pk[..SEEDBYTES]);

    // Unpack each polynomial of b
    for i in 0..K {
        let offset = SEEDBYTES + i * POLYQ_PACKEDBYTES;
        let mut packed_poly = [0u8; POLYQ_PACKEDBYTES];
        packed_poly.copy_from_slice(&pk[offset..offset + POLYQ_PACKEDBYTES]);
        b.vec[i].polyq_unpack(&packed_poly);
    }
}

/// Pack secret key: sk = (pk, s0, s1, key)
///
/// Packs the secret key into CRYPTO_SECRETKEYBYTES bytes.
///
/// # Arguments
/// * `sk` - Output buffer for packed secret key
/// * `pk` - Packed public key
/// * `s0` - Secret polynomial vector (M polynomials)
/// * `s1` - Secret polynomial vector (K polynomials)
/// * `key` - Secret seed
///
/// Transcopy from: void pack_sk(uint8_t sk[], const uint8_t pk[], const polyvecm *s0, const polyveck *s1, const uint8_t key[])
pub fn pack_sk(
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
    s0: &PolyVecM,
    s1: &PolyVecK,
    key: &[u8; SEEDBYTES]
) {
    let mut offset = 0;

    // Copy public key
    sk[offset..offset + CRYPTO_PUBLICKEYBYTES].copy_from_slice(pk);
    offset += CRYPTO_PUBLICKEYBYTES;

    // Pack s0 (M polynomials)
    for i in 0..M {
        let mut packed_poly = [0u8; POLYETA_PACKEDBYTES];
        s0.vec[i].polyeta_pack(&mut packed_poly);
        sk[offset..offset + POLYETA_PACKEDBYTES].copy_from_slice(&packed_poly);
        offset += POLYETA_PACKEDBYTES;
    }

    // Pack s1 (K polynomials)
    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        // HAETAE-2 and HAETAE-3 have D=1, use poly2eta_pack (96 bytes)
        for i in 0..K {
            let mut packed_poly = [0u8; POLY2ETA_PACKEDBYTES];
            s1.vec[i].poly2eta_pack(&mut packed_poly);
            sk[offset..offset + POLY2ETA_PACKEDBYTES].copy_from_slice(&packed_poly);
            offset += POLY2ETA_PACKEDBYTES;
        }
    }

    #[cfg(feature = "haetae5")]
    {
        // HAETAE-5 has D=0, uses polyeta_pack (64 bytes)
        for i in 0..K {
            let mut packed_poly = [0u8; POLYETA_PACKEDBYTES];
            s1.vec[i].polyeta_pack(&mut packed_poly);
            sk[offset..offset + POLYETA_PACKEDBYTES].copy_from_slice(&packed_poly);
            offset += POLYETA_PACKEDBYTES;
        }
    }

    // Copy key
    sk[offset..offset + SEEDBYTES].copy_from_slice(key);
}

/// Unpack secret key: (A, s0, s1, key) = sk
///
/// Unpacks the secret key and expands the matrix A.
///
/// # Arguments
/// * `A` - Output matrix A (K×L)
/// * `s0` - Output secret vector (M polynomials)
/// * `s1` - Output secret vector (K polynomials)
/// * `key` - Output secret seed
/// * `sk` - Input packed secret key
///
/// Transcopy from: void unpack_sk(polyvecl A[K], polyvecm *s0, polyveck *s1, uint8_t *key, const uint8_t sk[])
#[allow(non_snake_case)] // Mirrors the C parameter name `A` from the HAETAE reference.
pub fn unpack_sk(
    A: &mut [crate::polyvec::PolyVecL; K],
    s0: &mut PolyVecM,
    s1: &mut PolyVecK,
    key: &mut [u8; SEEDBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES]
) {
    let mut offset = 0;
    let mut rhoprime = [0u8; SEEDBYTES];
    let mut b1 = PolyVecK::new();

    // Unpack public key to get seed and b1
    let mut pk_array = [0u8; CRYPTO_PUBLICKEYBYTES];
    pk_array.copy_from_slice(&sk[..CRYPTO_PUBLICKEYBYTES]);
    unpack_pk(&mut b1, &mut rhoprime, &pk_array);
    offset += CRYPTO_PUBLICKEYBYTES;

    // Unpack s0
    for i in 0..M {
        let mut packed_poly = [0u8; POLYETA_PACKEDBYTES];
        packed_poly.copy_from_slice(&sk[offset..offset + POLYETA_PACKEDBYTES]);
        s0.vec[i].polyeta_unpack(&packed_poly);
        offset += POLYETA_PACKEDBYTES;
    }

    // Unpack s1
    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        // HAETAE-2 and HAETAE-3 have D=1, use poly2eta_unpack (96 bytes)
        for i in 0..K {
            let mut packed_poly = [0u8; POLY2ETA_PACKEDBYTES];
            packed_poly.copy_from_slice(&sk[offset..offset + POLY2ETA_PACKEDBYTES]);
            s1.vec[i].poly2eta_unpack(&packed_poly);
            offset += POLY2ETA_PACKEDBYTES;
        }
    }

    #[cfg(feature = "haetae5")]
    {
        // HAETAE-5 has D=0, uses polyeta_unpack (64 bytes)
        for i in 0..K {
            let mut packed_poly = [0u8; POLYETA_PACKEDBYTES];
            packed_poly.copy_from_slice(&sk[offset..offset + POLYETA_PACKEDBYTES]);
            s1.vec[i].polyeta_unpack(&packed_poly);
            offset += POLYETA_PACKEDBYTES;
        }
    }

    // Extract key
    key.copy_from_slice(&sk[offset..offset + SEEDBYTES]);

    // Expand matrix A' = PRG(rhoprime)
    polymatkl_expand(A, &rhoprime);
    polymatkl_double(A);

    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        // For D=1: first column of A = 2(a-b1*2^d)
        let mut a = PolyVecK::new();
        a.expand(&rhoprime);

        b1.double();
        let b1_temp = b1.clone();
        b1.sub(&a, &b1_temp);
        b1.double();
        b1.ntt();

        // Append b1 into A's first column
        for i in 0..K {
            A[i].vec[0] = b1.vec[i].clone();
        }
    }

    #[cfg(feature = "haetae5")]
    {
        // For D=0: b1 already contains NTT(-2b) from keygen, use directly
        for i in 0..K {
            A[i].vec[0] = b1.vec[i].clone();
        }
    }
}

/// Pack signature: sig = (c, LB(z1), offset_hb_z1, offset_h, Enc(HB(z1)), Enc(h))
///
/// Packs the signature into CRYPTO_BYTES bytes using rANS entropy coding for
/// compression of highbits(z1) and hint vector h.
///
/// # Arguments
/// * `sig` - Output buffer for packed signature (CRYPTO_BYTES bytes)
/// * `c` - Challenge polynomial (bit-packed)
/// * `lowbits_z1` - Low bits of z1 decomposition (L polynomials)
/// * `highbits_z1` - High bits of z1 decomposition (L polynomials)
/// * `h` - Hint vector (K polynomials)
///
/// # Returns
/// 0 on success, 1 if encoding fails or signature is too large
///
/// Transcopy from: int pack_sig(uint8_t sig[CRYPTO_BYTES], const poly *c,
///                               const polyvecl *lowbits_z1, const polyvecl *highbits_z1,
///                               const polyveck *h)
pub fn pack_sig(
    sig: &mut [u8; CRYPTO_BYTES],
    c: &Poly,
    lowbits_z1: &PolyVecL,
    highbits_z1: &PolyVecL,
    h: &PolyVecK,
) -> i32 {
    let mut encoded_h = vec![0u8; N * K];
    let mut encoded_hb_z1 = vec![0u8; N * L];

    // Initialize/padding with zeros:
    sig.fill(0);

    let mut offset = 0;

    // Encode challenge as bit-packed polynomial (N bits = N/8 bytes)
    for i in 0..N {
        sig[i / 8] |= ((c.coeffs[i] & 1) << (i % 8)) as u8;
    }
    offset += N / 8;

    // Pack lowbits(z1) as byte-packed polynomials (L * N bytes)
    for i in 0..L {
        for j in 0..N {
            sig[offset + N * i + j] = lowbits_z1.vec[i].coeffs[j] as u8;
        }
    }
    offset += L * N;

    // rANS encode highbits(z1)
    let hb_z1_flat: Vec<i32> = highbits_z1.vec.iter()
        .flat_map(|poly| poly.coeffs.iter().copied())
        .collect();

    let size_enc_hb_z1 = encode_hb_z1(&mut encoded_hb_z1, &hb_z1_flat);

    // rANS encode hint vector h
    let h_flat: Vec<i32> = h.vec.iter()
        .flat_map(|poly| poly.coeffs.iter().copied())
        .collect();
    let size_enc_h = encode_h(&mut encoded_h, &h_flat);

    if size_enc_h == 0 || size_enc_hb_z1 == 0 {
        return 1; // encoding failed
    }

    // The size of the encoded h and HB(z1) does not always fit in one byte,
    // thus we output a one byte offset to a fixed baseline
    if size_enc_h < BASE_ENC_H as u16
        || size_enc_hb_z1 < BASE_ENC_HB_Z1 as u16
        || size_enc_h > (BASE_ENC_H + 255) as u16
        || size_enc_hb_z1 > (BASE_ENC_HB_Z1 + 255) as u16
    {
        return 1; // encoding size offset out of range
    }


    let offset_enc_hb_z1 = (size_enc_hb_z1 - BASE_ENC_HB_Z1 as u16) as u8;
    let offset_enc_h = (size_enc_h - BASE_ENC_H as u16) as u8;

    let total_size = N / 8 + L * N + 2 + size_enc_hb_z1 as usize + size_enc_h as usize;
    if total_size > CRYPTO_BYTES {
        return 1; // signature too big
    }

    // Write size offsets
    sig[offset] = offset_enc_hb_z1;
    sig[offset + 1] = offset_enc_h;
    offset += 2;

    // Write encoded highbits(z1)
    sig[offset..offset + size_enc_hb_z1 as usize]
        .copy_from_slice(&encoded_hb_z1[..size_enc_hb_z1 as usize]);
    offset += size_enc_hb_z1 as usize;

    // Write encoded hint
    sig[offset..offset + size_enc_h as usize]
        .copy_from_slice(&encoded_h[..size_enc_h as usize]);

    // Remainder is already zero-padded

    0
}

/// Unpack signature: (c, LB(z1), HB(z1), h) = sig
///
/// Unpacks the signature from CRYPTO_BYTES bytes, decompressing rANS-encoded
/// components and verifying zero padding.
///
/// # Arguments
/// * `c` - Output challenge polynomial
/// * `lowbits_z1` - Output low bits of z1 decomposition (L polynomials)
/// * `highbits_z1` - Output high bits of z1 decomposition (L polynomials)
/// * `h` - Output hint vector (K polynomials)
/// * `sig` - Input packed signature (CRYPTO_BYTES bytes)
///
/// # Returns
/// 0 on success, 1 if signature is malformed
///
/// Transcopy from: int unpack_sig(poly *c, polyvecl *lowbits_z1,
///                                 polyvecl *highbits_z1, polyveck *h,
///                                 const uint8_t sig[CRYPTO_BYTES])
pub fn unpack_sig(
    c: &mut Poly,
    lowbits_z1: &mut PolyVecL,
    highbits_z1: &mut PolyVecL,
    h: &mut PolyVecK,
    sig: &[u8; CRYPTO_BYTES],
) -> i32 {
    let mut offset = 0;

    // Unpack challenge polynomial (bit-packed)
    for i in 0..N {
        c.coeffs[i] = ((sig[i / 8] >> (i % 8)) & 1) as i32;
    }
    offset += N / 8;

    // Unpack lowbits(z1) (byte-packed)
    for i in 0..L {
        for j in 0..N {
            lowbits_z1.vec[i].coeffs[j] = sig[offset + N * i + j] as i8 as i32;
        }
    }
    offset += L * N;

    // Read size offsets
    let size_enc_hb_z1 = sig[offset] as u16 + BASE_ENC_HB_Z1 as u16;
    let size_enc_h = sig[offset + 1] as u16 + BASE_ENC_H as u16;
    offset += 2;

    // Check total signature size
    if CRYPTO_BYTES < (N / 8 + L * N + 2 + size_enc_h as usize + size_enc_hb_z1 as usize) {
        return 1; // invalid size_enc_h and/or size_enc_hb_z1
    }

    // Decode highbits(z1)
    let mut hb_z1_flat = vec![0i32; N * L];
    if decode_hb_z1(&mut hb_z1_flat, &sig[offset..], size_enc_hb_z1) != 0 {
        return 1; // decoding failed
    }

    // Unflatten highbits(z1)
    for i in 0..L {
        for j in 0..N {
            highbits_z1.vec[i].coeffs[j] = hb_z1_flat[i * N + j];
        }
    }
    offset += size_enc_hb_z1 as usize;

    // Decode hint vector h
    let mut h_flat = vec![0i32; N * K];
    if decode_h(&mut h_flat, &sig[offset..], size_enc_h) != 0 {
        return 1; // decoding failed
    }

    // Unflatten hint vector
    for i in 0..K {
        for j in 0..N {
            h.vec[i].coeffs[j] = h_flat[i * N + j];
        }
    }
    offset += size_enc_h as usize;

    // Verify zero padding
    for i in offset..CRYPTO_BYTES {
        if sig[i] != 0 {
            return 1; // zero padding verification failed
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_pk() {
        let seed = [42u8; SEEDBYTES];
        let mut b = PolyVecK::new();

        // Initialize b with some test values
        for i in 0..K {
            for j in 0..256 {
                b.vec[i].coeffs[j] = ((i * 1000 + j) % 16384) as i32;
            }
        }

        // Pack
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        pack_pk(&mut pk, &b, &seed);

        // Unpack
        let mut b_unpacked = PolyVecK::new();
        let mut seed_unpacked = [0u8; SEEDBYTES];
        unpack_pk(&mut b_unpacked, &mut seed_unpacked, &pk);

        // Verify
        assert_eq!(seed, seed_unpacked);
        for i in 0..K {
            for j in 0..256 {
                assert_eq!(b.vec[i].coeffs[j], b_unpacked.vec[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn test_pack_unpack_sk() {
        let pk = [123u8; CRYPTO_PUBLICKEYBYTES];
        let key = [231u8; SEEDBYTES];
        let mut s0 = PolyVecM::new();
        let mut s1 = PolyVecK::new();

        // Initialize with test values in valid range
        for i in 0..M {
            for j in 0..256 {
                s0.vec[i].coeffs[j] = (j as i32 % 3) - 1; // [-1, 0, 1] for ETA=1
            }
        }

        for i in 0..K {
            for j in 0..256 {
                s1.vec[i].coeffs[j] = (j as i32 % 3) - 1;
            }
        }

        // Pack
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        pack_sk(&mut sk, &pk, &s0, &s1, &key);

        // Check that pk and key are stored correctly
        assert_eq!(&sk[..CRYPTO_PUBLICKEYBYTES], &pk);
        assert_eq!(&sk[sk.len() - SEEDBYTES..], &key);
    }
}

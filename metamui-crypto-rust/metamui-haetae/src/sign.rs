//! HAETAE signature scheme operations
//!
//! This module implements key generation, signing, and verification for the
//! HAETAE post-quantum signature scheme.
//!
//! Transcopy from: metamui-haetae/src/sign.c
//!
//! The reference C code declares intermediate buffers and then writes to
//! them through `&mut` out-parameters; Rust sees the initial `::new()`
//! assignments as "values never read" because the first read happens
//! through a function that writes-before-read. The lint is noise in this
//! direct transliteration — silence it file-wide.

#![allow(unused_assignments)]

use crate::params::*;
use crate::polyvec::{PolyVecK, PolyVecL, PolyVecM, polyvecmk_uniform_eta, polyvecmk_sqsing_value};
use crate::polymat::{polymatkm_expand, polymatkm_pointwise_montgomery, polymatkl_pointwise_montgomery};
use crate::polyfix::{PolyFixVecL, PolyFixVecK, polyfixveclk_sample_hyperball, polyfixveclk_sqnorm2};
use crate::poly::{Poly, poly_challenge};
use crate::ntt::{ntt, invntt_tomont};
use crate::packing::{pack_pk, pack_sk, pack_sig, unpack_sk};
use crate::randombytes::randombytes;

/// Generate public and private key pair
///
/// # Arguments
/// * `pk` - Output buffer for public key (CRYPTO_PUBLICKEYBYTES bytes)
/// * `sk` - Output buffer for secret key (CRYPTO_SECRETKEYBYTES bytes)
///
/// # Returns
/// 0 on success
///
/// Transcopy from: int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
pub fn crypto_sign_keypair(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES]
) -> i32 {
    let mut seed = [0u8; SEEDBYTES];
    randombytes(&mut seed);
    keypair_internal(pk, sk, &seed)
}

/// Deterministic keypair generation from a caller-supplied 32-byte seed.
///
/// This is the entry point the upstream PQCgenKAT harness replays: the seed
/// is the 32-byte KeyGen seed drawn from the NIST AES-CTR-DRBG. An
/// application generates keys with `crypto_sign_keypair` or
/// `api::KeyPair::generate`, which draw the seed from the operating system.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
///
/// Transcopy from: int crypto_sign_keypair_internal(uint8_t *vk, uint8_t *sk,
///                                                   uint8_t seed[SEEDBYTES])
#[cfg(feature = "kat-internal")]
pub fn crypto_sign_keypair_internal(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    seed: &[u8; SEEDBYTES],
) -> i32 {
    keypair_internal(pk, sk, seed)
}

/// Body of `crypto_sign_keypair_internal`; the randomized `crypto_sign_keypair`
/// feeds it an operating-system seed.
pub(crate) fn keypair_internal(
    pk: &mut [u8; CRYPTO_PUBLICKEYBYTES],
    sk: &mut [u8; CRYPTO_SECRETKEYBYTES],
    seed: &[u8; SEEDBYTES],
) -> i32 {
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
    let mut counter: u16 = 0;

    let mut s1 = PolyVecM::new();
    let mut b = PolyVecK::new();
    let mut s2 = PolyVecK::new();

    // Get entropy ρ from the caller-supplied KeyGen seed
    seedbuf[..SEEDBYTES].copy_from_slice(seed);

    // Sample seeds with entropy ρ
    let mut reader = crate::shake::shake256_multi(&[&seedbuf[..SEEDBYTES]]);
    reader.read_into(&mut seedbuf);

    let rhoprime = &seedbuf[..SEEDBYTES];
    let sigma = &seedbuf[SEEDBYTES..SEEDBYTES + CRHBYTES];
    let key = &seedbuf[SEEDBYTES + CRHBYTES..2 * SEEDBYTES + CRHBYTES];

    // Expand Matrix A0 and vector a
    let mut mat_a: [PolyVecM; K] = core::array::from_fn(|_| PolyVecM::new());
    polymatkm_expand(&mut mat_a, rhoprime.try_into().unwrap());

    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        // HAETAE-2/3: D = 1 (rounding mode)
        let mut a = PolyVecK::new();
        let mut b0 = PolyVecK::new();

        a.expand(rhoprime.try_into().unwrap());

        loop {
            // Sample secret vectors s1 and s2
            polyvecmk_uniform_eta(&mut s1, &mut s2, sigma.try_into().unwrap(), counter);
            counter += (M + K) as u16;

            // b = a + A0 * s1 + s2 mod q
            let mut s1hat = s1.clone();
            s1hat.ntt();
            polymatkm_pointwise_montgomery(&mut b, &mat_a, &s1hat);
            b.invntt_tomont();

            b.add_assign(&s2);
            b.add_assign(&a);
            b.freeze();

            // round off D bits
            b.decompose_vk(&mut b0);
            s2.sub_assign(&b0);

            let squared_singular_value = polyvecmk_sqsing_value(&s1, &s2);
            // Match the reference's double-precision threshold GAMMA*GAMMA*N
            // exactly: `GAMMA as i64` would truncate 48.858 -> 48 and reject
            // a different candidate set, producing a different key.
            if (squared_singular_value as f64) <= GAMMA * GAMMA * (N as f64) {
                break;
            }
        }
    }

    #[cfg(feature = "haetae5")]
    {
        // HAETAE-5: D = 0 (no rounding)
        //
        // Performance optimization: This code path results in ~7× faster key generation
        // compared to HAETAE-2 (60µs vs 431µs) due to:
        // 1. Early rejection checking: Test sqsing_value BEFORE expensive matrix operations
        // 2. Looser threshold: GAMMA=57.707 vs HAETAE-2's 48.858 (+39% more lenient)
        // 3. Fewer iterations: Average 1-2 rejections vs HAETAE-2's 5-10
        // This is BY DESIGN per HAETAE specification - not a bug or measurement error.
        loop {
            // Sample secret vectors s1 and s2
            polyvecmk_uniform_eta(&mut s1, &mut s2, sigma.try_into().unwrap(), counter);
            counter += (M + K) as u16;

            let squared_singular_value = polyvecmk_sqsing_value(&s1, &s2);
            // Match the reference's double-precision threshold GAMMA*GAMMA*N
            // exactly: `GAMMA as i64` would truncate 48.858 -> 48 and reject
            // a different candidate set, producing a different key.
            if (squared_singular_value as f64) <= GAMMA * GAMMA * (N as f64) {
                break;
            }
        }

        // b = A0 * s1 + s2 mod q
        let mut s1hat = s1.clone();
        let mut s2hat = s2.clone();
        s1hat.ntt();
        s2hat.ntt();
        polymatkm_pointwise_montgomery(&mut b, &mat_a, &s1hat);
        b.frommont();

        b.add_assign(&s2hat);
        b.double_negate();
        b.caddq(); // directly compute and store NTT(-2b)
    }

    pack_pk(pk, &b, rhoprime.try_into().unwrap());
    pack_sk(sk, pk, &s1, &s2, key.try_into().unwrap());

    0
}

/// Generate signature for a message
///
/// Computes a HAETAE signature using rejection sampling with hyperball sampling,
/// challenge generation, and hint computation.
///
/// # Arguments
/// * `sig` - Output buffer for signature (CRYPTO_BYTES bytes)
/// * `siglen` - Output length of signature (always CRYPTO_BYTES)
/// * `m` - Message to be signed
/// * `mlen` - Length of message
/// * `sk` - Secret key (CRYPTO_SECRETKEYBYTES bytes)
///
/// # Returns
/// 0 on success
///
/// Transcopy from: int crypto_sign_signature(uint8_t *sig, size_t *siglen,
///                                            const uint8_t *m, size_t mlen,
///                                            const uint8_t *sk)
pub fn crypto_sign_signature(
    sig: &mut [u8; CRYPTO_BYTES],
    siglen: &mut usize,
    m: &[u8],
    mlen: usize,
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> i32 {
    // Public API: empty context, fresh hedging randomness.
    let mut rnd = [0u8; SEEDBYTES];
    randombytes(&mut rnd);
    signature_internal(sig, siglen, m, mlen, &[0u8], &rnd, sk)
}

/// Compute a detached signature with explicit context prefix and hedging seed.
///
/// This is the entry point the upstream PQCgenKAT harness replays:
/// * `pre` is the context prefix `(ctxlen || ctx)` (so empty context = `[0x00]`).
/// * `rnd` is the 32-byte hedging seed drawn from the NIST AES-CTR-DRBG.
///
/// An application signs with `crypto_sign_signature` or `api::SigningKey::sign`,
/// which draw `rnd` from the operating system.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
///
/// Transcopy from: int crypto_sign_signature_internal(uint8_t *sig,
///   size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *pre,
///   size_t prelen, const uint8_t rnd[SEEDBYTES], const uint8_t *sk)
#[cfg(feature = "kat-internal")]
pub fn crypto_sign_signature_internal(
    sig: &mut [u8; CRYPTO_BYTES],
    siglen: &mut usize,
    m: &[u8],
    mlen: usize,
    pre: &[u8],
    rnd: &[u8; SEEDBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> i32 {
    signature_internal(sig, siglen, m, mlen, pre, rnd, sk)
}

/// Body of `crypto_sign_signature_internal`; the randomized
/// `crypto_sign_signature` feeds it an operating-system `rnd`.
pub(crate) fn signature_internal(
    sig: &mut [u8; CRYPTO_BYTES],
    siglen: &mut usize,
    m: &[u8],
    mlen: usize,
    pre: &[u8],
    rnd: &[u8; SEEDBYTES],
    sk: &[u8; CRYPTO_SECRETKEYBYTES],
) -> i32 {
    let mut buf = vec![0u8; POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES];
    let mut seedbuf = [0u8; CRHBYTES];
    let mut key = [0u8; SEEDBYTES];
    let mut mu = [0u8; CRHBYTES];
    let mut b: u8 = 0; // one bit (actually 2 bits: b and b')
    let mut counter: u16 = 0;

    let mut s1 = PolyVecM::new();
    let mut a1: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
    let mut cs1 = PolyVecL::new();
    let mut s2 = PolyVecK::new();
    let mut cs2 = PolyVecK::new();
    let mut highbits = PolyVecK::new();
    let mut ay = PolyVecK::new();

    let mut y1 = PolyFixVecL::new();
    let mut z1 = PolyFixVecL::new();
    let mut z1tmp = PolyFixVecL::new();
    let mut y2 = PolyFixVecK::new();
    let mut z2 = PolyFixVecK::new();
    let mut z2tmp = PolyFixVecK::new();

    let mut z1rnd = PolyVecL::new();
    let mut hb_z1 = PolyVecL::new();
    let mut lb_z1 = PolyVecL::new();
    let mut z2rnd = PolyVecK::new();
    let mut h = PolyVecK::new();
    let mut htmp = PolyVecK::new();

    let mut c = Poly::new();
    let mut chat = Poly::new();
    let mut z1rnd0 = Poly::new();
    let mut lsb = Poly::new();

    // Unpack secret key
    unpack_sk(&mut a1, &mut s1, &mut s2, &mut key, sk);

    // mu = H(vk_part_of_sk || pre || m)   (context-bound, KS X 123456 SignInternal)
    // pre = [ctxlen] || ctx is supplied by the caller (empty context => [0x00]).
    let mut reader = crate::shake::shake256_multi(&[&sk[..CRYPTO_PUBLICKEYBYTES], pre, &m[..mlen]]);
    reader.read_into(&mut mu);

    // hedged signing seed = H(key || rnd || mu)
    let mut reader = crate::shake::shake256_multi(&[&key, rnd, &mu]);
    reader.read_into(&mut seedbuf);

    // Transform s1 and s2 to NTT domain
    s1.ntt();
    s2.ntt();

    // Rejection sampling loop

    loop {

        /*------------------ 1. Sample y1 and y2 from hyperball ------------------*/

        counter = polyfixveclk_sample_hyperball(&mut y1, &mut y2, &mut b, &seedbuf, counter);

        /*------------------- 2. Compute a challenge c --------------------------*/
        // Round y1 and y2
        z1rnd = y1.round();
        z2rnd = y2.round();

        // A * round(y) mod q = A1 * round(y1) + 2 * round(y2) mod q
        z1rnd0 = z1rnd.vec[0].clone();
        z1rnd.ntt();
        polymatkl_pointwise_montgomery(&mut ay, &a1, &z1rnd);
        ay.invntt_tomont();
        z2rnd.double();
        ay.add_assign(&z2rnd);

        // Recover A * round(y) mod 2q
        ay.poly_fromcrt_inplace(&z1rnd0);
        ay.freeze2q();

        // HighBits of (A * round(y) mod 2q)
        highbits.highbits_hint(&ay);

        // LSB(round(y_0))
        lsb.lsb(&z1rnd0);

        // Pack HighBits of A * round(y) mod 2q and LSB of round(y0)
        let hb_buf: &mut [u8; POLYVECK_HIGHBITS_PACKEDBYTES] =
            (&mut buf[..POLYVECK_HIGHBITS_PACKEDBYTES]).try_into().unwrap();
        highbits.pack_highbits(hb_buf);
        let lsb_buf: &mut [u8; POLYC_PACKEDBYTES] =
            (&mut buf[POLYVECK_HIGHBITS_PACKEDBYTES..POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES]).try_into().unwrap();
        lsb.pack_lsb(lsb_buf);

        // c = challenge(highbits, lsb, mu)
        poly_challenge(&mut c, &buf, &mu);

        /*------------------- 3. Compute z = y + (-1)^b c * s --------------------*/
        // cs = c * s = c * (s1 || s2)
        cs1.vec[0] = c.clone();
        chat = c.clone();
        ntt(&mut chat.coeffs);

        for i in 1..L {
            cs1.vec[i].pointwise_montgomery(&chat, &s1.vec[i - 1]);
            invntt_tomont(&mut cs1.vec[i].coeffs);
        }

        cs2.poly_pointwise_montgomery(&s2, &chat);
        cs2.invntt_tomont();

        // z = y + (-1)^b cs = z1 + z2
        cs1.cneg(b & 1);
        cs2.cneg(b & 1);
        z1.add(&y1, &cs1);
        z2.add(&y2, &cs2);

        // reject if norm(z) >= B'
        let sqnorm_z = polyfixveclk_sqnorm2(&z1, &z2);
        let threshold1 = B1SQ * LN as u64 * LN as u64;
        let reject1 = (threshold1.wrapping_sub(sqnorm_z)) >> 63;
        let reject1 = reject1 & 1;

        z1tmp.double(&z1);
        z2tmp.double(&z2);

        let z1tmp_temp = z1tmp.clone();
        z1tmp.sub(&z1tmp_temp, &y1);
        let z2tmp_temp = z2tmp.clone();
        z2tmp.sub(&z2tmp_temp, &y2);

        // reject if norm(2z-y) < B and b' = 0
        let sqnorm_2z_minus_y = polyfixveclk_sqnorm2(&z1tmp, &z2tmp);
        let threshold0 = B0SQ * LN as u64 * LN as u64;
        let reject2 = (sqnorm_2z_minus_y.wrapping_sub(threshold0)) >> 63;
        let reject2 = (reject2 & 1) & (((b & 0x2) >> 1) as u64);

        if (reject1 | reject2) != 0 {
            continue; // goto reject
        }

        /*------------------- 4. Make a hint -------------------------------------*/
        // Round z1 and z2
        z1rnd = z1.round();
        z2rnd = z2.round();

        // recover A1 * round(z1) - qcj mod 2q
        z2rnd.double();
        htmp.sub(&ay, &z2rnd);
        htmp.freeze2q();

        // HighBits of (A * round(z) - qcj mod 2q) and (A1 * round(z1) - qcj mod 2q)
        htmp.highbits_hint_inplace();
        h.sub(&highbits, &htmp);
        h.cadd_dq2alpha();

        /*------------------ Decompose(z1) and Pack signature -------------------*/
        lb_z1.lowbits(&z1rnd);
        hb_z1.highbits(&z1rnd);

        if pack_sig(sig, &c, &lb_z1, &hb_z1, &h) != 0 {
            continue; // reject if signature is too big (goto reject)
        }

        *siglen = CRYPTO_BYTES;
        break; // Success!
    }

    0
}

/// Pre-expanded A1 matrix for fast verification.
///
/// Stores the fully-constructed A1 matrix in NTT domain, eliminating
/// K×M SHAKE128 hash calls during each verify operation. Use this when
/// verifying multiple signatures against the same public key.
///
/// # Memory
/// Size is K×L×N×4 bytes (8-28 KB depending on security level).
/// This is an in-memory cache; the wire-format public key is unchanged.
pub struct ExpandedA1 {
    /// A1 matrix in NTT domain (K×L), fully constructed:
    /// Column 0 = NTT(2*(a - 2b)) for HAETAE-2/3, or NTT(-2b) for HAETAE-5
    /// Columns 1..L = 2 * A0 (expanded from seed, treated as NTT domain)
    pub(crate) a1_hat: [PolyVecL; K],
    /// Original packed PK bytes (needed for mu = H(pk || pre || m))
    pub(crate) pk_bytes: [u8; CRYPTO_PUBLICKEYBYTES],
}

impl ExpandedA1 {
    /// Expand A1 matrix from a standard public key.
    ///
    /// This performs the one-time hash expansion (K×M SHAKE128 calls)
    /// so that subsequent verify calls skip all hashing except the
    /// message hash and challenge recomputation.
    pub fn from_pk(pk: &[u8; CRYPTO_PUBLICKEYBYTES]) -> Self {
        use crate::packing::unpack_pk;
        use crate::polymat::{polymatkl_expand, polymatkl_double};

        let mut rhoprime = [0u8; SEEDBYTES];
        let mut b = PolyVecK::new();
        unpack_pk(&mut b, &mut rhoprime, pk);

        let mut a1: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
        polymatkl_expand(&mut a1, &rhoprime);
        polymatkl_double(&mut a1);

        #[cfg(any(feature = "haetae2", feature = "haetae3"))]
        {
            let mut a = PolyVecK::new();
            a.expand(&rhoprime);
            b.double();
            let a_temp = a.clone();
            let b_temp = b.clone();
            b.sub(&a_temp, &b_temp);
            b.double();
            b.ntt();
        }
        // HAETAE-5: b from PK already stores NTT(-2b) from keygen

        for i in 0..K {
            a1[i].vec[0] = b.vec[i].clone();
        }

        Self {
            a1_hat: a1,
            pk_bytes: *pk,
        }
    }
}

/// Verify HAETAE signature (standard API with empty context)
///
/// Verifies a signature by recomputing the challenge and checking norms.
/// Uses empty context (pre = [0x00]) per HAETAE v1.1.2 specification.
///
/// # Arguments
/// * `sig` - Signature (CRYPTO_BYTES bytes)
/// * `siglen` - Length of signature (must be CRYPTO_BYTES)
/// * `m` - Message that was signed
/// * `mlen` - Length of message
/// * `pk` - Public key (CRYPTO_PUBLICKEYBYTES bytes)
///
/// # Returns
/// * 0 if signature is valid
/// * -1 if signature is invalid
///
/// Transcopy from: int crypto_sign_verify(const uint8_t *sig, size_t siglen,
///                                          const uint8_t *m, size_t mlen,
///                                          const uint8_t *ctx, size_t ctxlen,
///                                          const uint8_t *pk)
pub fn crypto_sign_verify(
    sig: &[u8; CRYPTO_BYTES],
    siglen: usize,
    m: &[u8],
    mlen: usize,
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
) -> i32 {
    // Standard API: empty context → pre = [0x00]
    crypto_sign_verify_internal(sig, siglen, m, mlen, &[0u8], pk)
}

/// Verify HAETAE signature using pre-expanded A1 matrix (empty context).
///
/// Skips all hash expansion (K×M SHAKE128 calls), performing only
/// the message hash and challenge recomputation. ~30-40% faster
/// for repeated verification with the same public key.
pub fn crypto_sign_verify_expanded(
    sig: &[u8; CRYPTO_BYTES],
    siglen: usize,
    m: &[u8],
    mlen: usize,
    expanded: &ExpandedA1,
) -> i32 {
    crypto_sign_verify_expanded_internal(sig, siglen, m, mlen, &[0u8], expanded)
}

/// Verify HAETAE signature with explicit context prefix
///
/// Internal verification function matching the C reference's
/// `crypto_sign_verify_internal(sig, siglen, m, mlen, pre, prelen, vk)`.
///
/// The `pre` parameter is `[ctxlen] || ctx` where ctxlen is one byte.
/// For empty context: pre = [0x00].
///
/// # Arguments
/// * `sig` - Signature (CRYPTO_BYTES bytes)
/// * `siglen` - Length of signature (must be CRYPTO_BYTES)
/// * `m` - Message that was signed
/// * `mlen` - Length of message
/// * `pre` - Context prefix bytes: [ctxlen] || ctx
/// * `pk` - Public key (CRYPTO_PUBLICKEYBYTES bytes)
///
/// # Returns
/// * 0 if signature is valid
/// * -1 if signature is invalid
pub fn crypto_sign_verify_internal(
    sig: &[u8; CRYPTO_BYTES],
    siglen: usize,
    m: &[u8],
    mlen: usize,
    pre: &[u8],
    pk: &[u8; CRYPTO_PUBLICKEYBYTES],
) -> i32 {
    use crate::packing::{unpack_pk, unpack_sig};
    use crate::polymat::{polymatkl_expand, polymatkl_pointwise_montgomery, polymatkl_double};

    let mut buf = vec![0u8; POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES];
    let mut rhoprime = [0u8; SEEDBYTES];
    let mut mu = [0u8; SEEDBYTES];

    let mut a1: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
    let mut b = PolyVecK::new();
    let mut z1 = PolyVecL::new();
    let mut highbits = PolyVecK::new();
    let mut h = PolyVecK::new();
    let mut z2 = PolyVecK::new();
    let mut w = PolyVecK::new();

    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    let mut a = PolyVecK::new();

    let mut c = Poly::new();
    let mut cprime = Poly::new();
    let mut wprime = Poly::new();

    // Check signature length
    if siglen != CRYPTO_BYTES {
        return -1;
    }

    // Unpack public key
    unpack_pk(&mut b, &mut rhoprime, pk);

    // Temporary vector for lowbits
    let mut lowbits_z1 = PolyVecL::new();

    // Unpack signature
    if unpack_sig(&mut c, &mut lowbits_z1, &mut z1, &mut h, sig) != 0 {
        return -1;
    }

    // Compose z1 from HighBits(z1) and LowBits(z1)
    for i in 0..L {
        z1.vec[i].compose_inplace(&lowbits_z1.vec[i]);
    }

    /*------------------- 1. Recover A1 --------------------------------------*/
    // A1 = (-2b + qj || 2 * A0)
    polymatkl_expand(&mut a1, &rhoprime);
    polymatkl_double(&mut a1);

    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        // HAETAE-2/3: D = 1 (rounding mode)
        // Compute b = a - 2b, then double and NTT
        a.expand(&rhoprime);
        b.double();
        // b = a - b (reuse a as scratch since it's not needed after)
        for i in 0..K {
            for j in 0..N {
                b.vec[i].coeffs[j] = a.vec[i].coeffs[j] - b.vec[i].coeffs[j];
            }
        }
        b.double();
        b.ntt();
    }
    // HAETAE-5: D = 0, b already contains -2b in NTT domain (from keygen)

    // Set first column of A1 to b
    for i in 0..K {
        a1[i].vec[0] = b.vec[i].clone();
    }

    /*------------------- 2. Compute z2 ---------------------------------------*/
    // Compute squared norm of z1 and w' before NTT
    let sqnorm2 = z1.sqnorm2();

    wprime.sub(&z1.vec[0], &c);
    wprime.lsb_inplace();

    // A1 * z1 - qcj mod q
    z1.ntt();
    polymatkl_pointwise_montgomery(&mut highbits, &a1, &z1);
    highbits.invntt_tomont();

    // Recover A1 * z1 - qcj mod 2q
    highbits.poly_fromcrt_inplace(&wprime);
    highbits.freeze2q();

    // Recover w1 (original highbits before hint)
    w.highbits_hint(&highbits);
    w.add_assign(&h);
    w.csub_dq2alpha();

    // Recover z2 mod q: z2 = (w * ALPHA - highbits + w') / 2
    z2.mul_alpha(&w);
    z2.sub_assign(&highbits);
    z2.vec[0].add_assign(&wprime);
    z2.reduce2q();
    z2.div2();

    // Check final norm of z
    if sqnorm2 + z2.sqnorm2() > (B2SQ as u64) {
        return -1;
    }

    /*------------------- 3. Compute c' and Compare ---------------------------*/
    // Pack HighBits(A * z - qcj mod 2q) and w'
    let hb_buf: &mut [u8; POLYVECK_HIGHBITS_PACKEDBYTES] =
        (&mut buf[..POLYVECK_HIGHBITS_PACKEDBYTES]).try_into().unwrap();
    w.pack_highbits(hb_buf);
    let lsb_buf: &mut [u8; POLYC_PACKEDBYTES] =
        (&mut buf[POLYVECK_HIGHBITS_PACKEDBYTES..POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES]).try_into().unwrap();
    wprime.pack_lsb(lsb_buf);

    // Compute mu = H(pk || pre || m)
    // HAETAE v1.1.2: pre = [ctxlen] || ctx (context string protocol)
    let mut reader = crate::shake::shake256_multi(&[pk, pre, &m[..mlen]]);
    reader.read_into(&mut mu);

    // Compute challenge c' = H(w, w', mu)
    poly_challenge(&mut cprime, &buf, &mu);

    // Compare challenges (constant-time: XOR accumulation prevents
    // early-exit timing leak that could reveal mismatch position)
    let mut diff = 0i32;
    for i in 0..N {
        diff |= c.coeffs[i] ^ cprime.coeffs[i];
    }
    if diff != 0 {
        return -1;
    }

    0
}

/// Verify HAETAE signature using pre-expanded A1 matrix with explicit context.
///
/// This is the fast path: the A1 matrix expansion (K×M SHAKE128 calls) is
/// already done. Only the message hash and challenge recomputation remain.
pub fn crypto_sign_verify_expanded_internal(
    sig: &[u8; CRYPTO_BYTES],
    siglen: usize,
    m: &[u8],
    mlen: usize,
    pre: &[u8],
    expanded: &ExpandedA1,
) -> i32 {
    use crate::packing::unpack_sig;
    use crate::polymat::polymatkl_pointwise_montgomery;

    let mut buf = vec![0u8; POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES];
    let mut mu = [0u8; SEEDBYTES];

    let mut z1 = PolyVecL::new();
    let mut highbits = PolyVecK::new();
    let mut h = PolyVecK::new();
    let mut z2 = PolyVecK::new();
    let mut w = PolyVecK::new();

    let mut c = Poly::new();
    let mut cprime = Poly::new();
    let mut wprime = Poly::new();

    // Check signature length
    if siglen != CRYPTO_BYTES {
        return -1;
    }

    // Temporary vector for lowbits
    let mut lowbits_z1 = PolyVecL::new();

    // Unpack signature
    if unpack_sig(&mut c, &mut lowbits_z1, &mut z1, &mut h, sig) != 0 {
        return -1;
    }

    // Compose z1 from HighBits(z1) and LowBits(z1)
    for i in 0..L {
        z1.vec[i].compose_inplace(&lowbits_z1.vec[i]);
    }

    /*------------------- 1. A1 already expanded (SKIP hash calls) -----------*/
    // This is the key optimization: a1_hat is pre-computed from the PK.

    /*------------------- 2. Compute z2 ---------------------------------------*/
    // Compute squared norm of z1 and w' before NTT
    let sqnorm2 = z1.sqnorm2();

    wprime.sub(&z1.vec[0], &c);
    wprime.lsb_inplace();

    // A1 * z1 - qcj mod q
    z1.ntt();
    polymatkl_pointwise_montgomery(&mut highbits, &expanded.a1_hat, &z1);
    highbits.invntt_tomont();

    // Recover A1 * z1 - qcj mod 2q
    highbits.poly_fromcrt_inplace(&wprime);
    highbits.freeze2q();

    // Recover w1 (original highbits before hint)
    w.highbits_hint(&highbits);
    w.add_assign(&h);
    w.csub_dq2alpha();

    // Recover z2 mod q: z2 = (w * ALPHA - highbits + w') / 2
    z2.mul_alpha(&w);
    z2.sub_assign(&highbits);
    z2.vec[0].add_assign(&wprime);
    z2.reduce2q();
    z2.div2();

    // Check final norm of z
    if sqnorm2 + z2.sqnorm2() > (B2SQ as u64) {
        return -1;
    }

    /*------------------- 3. Compute c' and Compare ---------------------------*/
    // Pack HighBits(A * z - qcj mod 2q) and w'
    let hb_buf: &mut [u8; POLYVECK_HIGHBITS_PACKEDBYTES] =
        (&mut buf[..POLYVECK_HIGHBITS_PACKEDBYTES]).try_into().unwrap();
    w.pack_highbits(hb_buf);
    let lsb_buf: &mut [u8; POLYC_PACKEDBYTES] =
        (&mut buf[POLYVECK_HIGHBITS_PACKEDBYTES..POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES]).try_into().unwrap();
    wprime.pack_lsb(lsb_buf);

    // Compute mu = H(pk || pre || m)
    let mut reader = crate::shake::shake256_multi(&[&expanded.pk_bytes, pre, &m[..mlen]]);
    reader.read_into(&mut mu);

    // Compute challenge c' = H(w, w', mu)
    poly_challenge(&mut cprime, &buf, &mu);

    // Compare challenges (constant-time)
    let mut diff = 0i32;
    for i in 0..N {
        diff |= c.coeffs[i] ^ cprime.coeffs[i];
    }
    if diff != 0 {
        return -1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_keypair() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

        let result = crypto_sign_keypair(&mut pk, &mut sk);
        assert_eq!(result, 0);

        // Check that keys are not all zeros
        assert!(pk.iter().any(|&b| b != 0));
        assert!(sk.iter().any(|&b| b != 0));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_keypair_different_keys() {
        let mut pk1 = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk1 = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut pk2 = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk2 = [0u8; CRYPTO_SECRETKEYBYTES];

        crypto_sign_keypair(&mut pk1, &mut sk1);
        crypto_sign_keypair(&mut pk2, &mut sk2);

        // Different keys should be generated
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_keypair_pack_unpack() {
        use crate::packing::{unpack_pk, unpack_sk};

        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

        crypto_sign_keypair(&mut pk, &mut sk);

        // Unpack public key
        let mut b_unpacked = PolyVecK::new();
        let mut seed = [0u8; SEEDBYTES];
        unpack_pk(&mut b_unpacked, &mut seed, &pk);

        // Verify seed is not all zeros
        assert!(seed.iter().any(|&x| x != 0));

        // Unpack secret key
        let mut mat_a: [crate::polyvec::PolyVecL; K] = core::array::from_fn(|_| crate::polyvec::PolyVecL::new());
        let mut s0 = PolyVecM::new();
        let mut s1 = PolyVecK::new();
        let mut key = [0u8; SEEDBYTES];
        unpack_sk(&mut mat_a, &mut s0, &mut s1, &mut key, &sk);

        // Verify key is not all zeros
        assert!(key.iter().any(|&x| x != 0));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_signature() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut sig = [0u8; CRYPTO_BYTES];
        let mut siglen = 0usize;

        // Generate keypair
        let result = crypto_sign_keypair(&mut pk, &mut sk);
        assert_eq!(result, 0);

        // Sign a test message
        let message = b"Test message for HAETAE signature";
        let result = crypto_sign_signature(&mut sig, &mut siglen, message, message.len(), &sk);
        assert_eq!(result, 0);
        assert_eq!(siglen, CRYPTO_BYTES);

        // Check that signature is not all zeros
        assert!(sig.iter().any(|&b| b != 0));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_verify_valid() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut sig = [0u8; CRYPTO_BYTES];
        let mut siglen = 0usize;

        // Generate keypair
        crypto_sign_keypair(&mut pk, &mut sk);

        // Sign a test message
        let message = b"Test message for HAETAE verification";
        let result = crypto_sign_signature(&mut sig, &mut siglen, message, message.len(), &sk);
        assert_eq!(result, 0);

        // Verify the signature
        let result = crypto_sign_verify(&sig, CRYPTO_BYTES, message, message.len(), &pk);
        assert_eq!(result, 0, "Valid signature should verify successfully");
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_verify_invalid_signature() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut sig = [0u8; CRYPTO_BYTES];
        let mut siglen = 0usize;

        // Generate keypair
        crypto_sign_keypair(&mut pk, &mut sk);

        // Sign a test message
        let message = b"Original message";
        crypto_sign_signature(&mut sig, &mut siglen, message, message.len(), &sk);

        // Corrupt the signature
        sig[0] ^= 1;

        // Verification should fail
        let result = crypto_sign_verify(&sig, CRYPTO_BYTES, message, message.len(), &pk);
        assert_eq!(result, -1, "Corrupted signature should fail verification");
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_verify_wrong_message() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let mut sig = [0u8; CRYPTO_BYTES];
        let mut siglen = 0usize;

        // Generate keypair
        crypto_sign_keypair(&mut pk, &mut sk);

        // Sign a message
        let message1 = b"First message";
        crypto_sign_signature(&mut sig, &mut siglen, message1, message1.len(), &sk);

        // Try to verify with different message
        let message2 = b"Second message";
        let result = crypto_sign_verify(&sig, CRYPTO_BYTES, message2, message2.len(), &pk);
        assert_eq!(result, -1, "Signature should not verify for different message");
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_crypto_sign_verify_multiple_messages() {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

        // Generate keypair once
        crypto_sign_keypair(&mut pk, &mut sk);

        // Sign and verify multiple messages
        let messages = [
            b"Message 1" as &[u8],
            b"Message 2",
            b"A longer test message for HAETAE",
            b"",  // Empty message
        ];

        for message in &messages {
            let mut sig = [0u8; CRYPTO_BYTES];
            let mut siglen = 0usize;

            // Sign
            let result = crypto_sign_signature(&mut sig, &mut siglen, message, message.len(), &sk);
            assert_eq!(result, 0);

            // Verify
            let result = crypto_sign_verify(&sig, CRYPTO_BYTES, message, message.len(), &pk);
            assert_eq!(result, 0, "Signature should verify for message: {:?}", message);
        }
    }
}

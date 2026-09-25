//! KEM operations for NTRU+ — a port of `kem.c` from the ntruplus.org
//! reference implementation (commit 621c667, spec dated 2026-02-02).
//!
//! - keygen: f = 3·CBD1(SHAKE-256(coins)) + 1 and g = 3·CBD1(SHAKE-256(coins))
//!   are sampled in NTT form, each retried until invertible; h = g·f^{-1},
//!   h^{-1} = f·g^{-1}; sk = f ‖ h^{-1} ‖ hash_f(pk)
//! - encaps: c = h·r + m with r from hash_h and m the SOTP encoding of the
//!   message; ss is the first 32 bytes of hash_h
//! - decaps: recover m = crepmod3(f·c), re-derive r, compare without a secret-dependent branch,
//!   and zero the shared secret on failure

use crate::error::NtruPlusError;
use crate::params::NtruPlusParams;
use crate::poly::{self, Poly};
use crate::symmetric;
use alloc::vec;
use alloc::vec::Vec;

/// Public key: serialized h = g · f^{-1} (NTT domain).
#[derive(Clone)]
pub struct PublicKey {
    pub h: Vec<u8>,
}

/// Secret key in the reference wire layout:
/// `tobytes(f) ‖ tobytes(h^{-1}) ‖ hash_f(pk)`.
#[derive(Clone)]
pub struct SecretKey {
    pub f: Vec<u8>,
    pub hinv: Vec<u8>,
    pub pkh: [u8; 32],
}

/// Ciphertext: serialized c = h·r + m (NTT domain).
#[derive(Clone)]
pub struct Ciphertext {
    pub c: Vec<u8>,
}

/// Shared secret (32 bytes).
#[derive(Clone)]
pub struct SharedSecret {
    pub ss: [u8; 32],
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.ss
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.h.clone()
    }

    pub fn from_bytes<P: NtruPlusParams>(bytes: &[u8]) -> Result<Self, NtruPlusError> {
        if bytes.len() != P::PUBLIC_KEY_SIZE {
            return Err(NtruPlusError::InvalidKeySize);
        }
        Ok(Self { h: bytes.to_vec() })
    }
}

impl SecretKey {
    /// The reference's `CRYPTO_SECRETKEYBYTES` layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.f.len() + self.hinv.len() + 32);
        v.extend_from_slice(&self.f);
        v.extend_from_slice(&self.hinv);
        v.extend_from_slice(&self.pkh);
        v
    }

    pub fn from_bytes<P: NtruPlusParams>(bytes: &[u8]) -> Result<Self, NtruPlusError> {
        if bytes.len() != P::SECRET_KEY_SIZE {
            return Err(NtruPlusError::InvalidKeySize);
        }
        let pb = P::POLYBYTES;
        let mut pkh = [0u8; 32];
        pkh.copy_from_slice(&bytes[2 * pb..2 * pb + 32]);
        Ok(Self {
            f: bytes[..pb].to_vec(),
            hinv: bytes[pb..2 * pb].to_vec(),
            pkh,
        })
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.c.clone()
    }

    pub fn from_bytes<P: NtruPlusParams>(bytes: &[u8]) -> Result<Self, NtruPlusError> {
        if bytes.len() != P::CIPHERTEXT_SIZE {
            return Err(NtruPlusError::InvalidCiphertext);
        }
        Ok(Self { c: bytes.to_vec() })
    }
}

/// Upper bound on keygen retries. The reference loops until the sampled
/// polynomial is invertible (each attempt fails with probability far below
/// 2^-10); the bound only turns a broken `randombytes` into an error instead
/// of a hang.
const KEYGEN_MAX_ATTEMPTS: usize = 1000;

/// f = 3·CBD1(SHAKE-256(coins)) + 1 in NTT form, and f^{-1}.
/// Returns 0 on success, 1 if f is not invertible.
fn genf_derand<P: NtruPlusParams>(f: &mut Poly, finv: &mut Poly, coins: &[u8; 32]) -> i32 {
    let mut buf = vec![0u8; P::N / 4];
    symmetric::prf_keygen::<P>(&mut buf, coins);
    let mut t = Poly::zero(P::N);
    poly::poly_cbd1::<P>(&mut t, &buf);
    poly::poly_triple(f, &t);
    f.coeffs[0] = f.coeffs[0].wrapping_add(1);
    poly::poly_ntt::<P>(f);
    poly::poly_baseinv::<P>(finv, f)
}

/// g = 3·CBD1(SHAKE-256(coins)) in NTT form, and g^{-1}.
/// Returns 0 on success, 1 if g is not invertible.
fn geng_derand<P: NtruPlusParams>(g: &mut Poly, ginv: &mut Poly, coins: &[u8; 32]) -> i32 {
    let mut buf = vec![0u8; P::N / 4];
    symmetric::prf_keygen::<P>(&mut buf, coins);
    let mut t = Poly::zero(P::N);
    poly::poly_cbd1::<P>(&mut t, &buf);
    poly::poly_triple(g, &t);
    poly::poly_ntt::<P>(g);
    poly::poly_baseinv::<P>(ginv, g)
}

/// pk = tobytes(g·f^{-1}); sk = tobytes(f) ‖ tobytes(f·g^{-1}) ‖ hash_f(pk).
fn keypair_from_polys<P: NtruPlusParams>(f: &Poly, finv: &Poly, g: &Poly, ginv: &Poly) -> (PublicKey, SecretKey) {
    let n = P::N;
    let mut h = Poly::zero(n);
    poly::poly_basemul::<P>(&mut h, g, finv);
    let mut hinv = Poly::zero(n);
    poly::poly_basemul::<P>(&mut hinv, f, ginv);

    let mut pk = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut pk, &h);
    let mut f_bytes = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut f_bytes, f);
    let mut hinv_bytes = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut hinv_bytes, &hinv);
    let mut pkh = [0u8; 32];
    symmetric::hash_f(&mut pkh, &pk);

    (PublicKey { h: pk }, SecretKey { f: f_bytes, hinv: hinv_bytes, pkh })
}

/// Deterministic keygen: every 32-byte `coins` draw (one per attempt, f then
/// g) comes from `randombytes`, in the reference's draw order. This is the
/// entry point the upstream-KAT gate replays the NIST DRBG through; an
/// application generates keys with `generate_keypair`, which draws from the
/// operating system.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
#[cfg(feature = "kat-internal")]
pub fn generate_keypair_det<P: NtruPlusParams, F: FnMut(&mut [u8])>(
    randombytes: F,
) -> Result<(PublicKey, SecretKey), NtruPlusError> {
    keypair_from_randombytes::<P, F>(randombytes)
}

/// Body of `generate_keypair_det`; `generate_keypair` feeds it the operating
/// system's `getrandom`.
pub(crate) fn keypair_from_randombytes<P: NtruPlusParams, F: FnMut(&mut [u8])>(
    mut randombytes: F,
) -> Result<(PublicKey, SecretKey), NtruPlusError> {
    let n = P::N;
    let mut coins = [0u8; 32];

    let mut f = Poly::zero(n);
    let mut finv = Poly::zero(n);
    let mut ok = false;
    for _ in 0..KEYGEN_MAX_ATTEMPTS {
        randombytes(&mut coins);
        if genf_derand::<P>(&mut f, &mut finv, &coins) == 0 {
            ok = true;
            break;
        }
    }
    if !ok {
        return Err(NtruPlusError::KeyGenerationFailed);
    }

    let mut g = Poly::zero(n);
    let mut ginv = Poly::zero(n);
    let mut ok = false;
    for _ in 0..KEYGEN_MAX_ATTEMPTS {
        randombytes(&mut coins);
        if geng_derand::<P>(&mut g, &mut ginv, &coins) == 0 {
            ok = true;
            break;
        }
    }
    if !ok {
        return Err(NtruPlusError::KeyGenerationFailed);
    }

    Ok(keypair_from_polys::<P>(&f, &finv, &g, &ginv))
}

/// Generate a keypair from OS randomness.
pub fn generate_keypair<P: NtruPlusParams>() -> Result<(PublicKey, SecretKey), NtruPlusError> {
    let mut rng_failed = false;
    let result = keypair_from_randombytes::<P, _>(|buf| {
        if getrandom::getrandom(buf).is_err() {
            rng_failed = true;
        }
    });
    if rng_failed {
        return Err(NtruPlusError::RngError);
    }
    result
}

/// Encapsulate with an explicit N/8-byte message `coins`. Refuses a public key
/// with a coefficient `>= q`, as the reference's `crypto_kem_enc_derand` does.
fn encapsulate_derand<P: NtruPlusParams>(
    pk: &PublicKey,
    coins: &[u8],
) -> Result<(Ciphertext, SharedSecret), NtruPlusError> {
    let n = P::N;

    let mut h = Poly::zero(n);
    if poly::poly_frombytes::<P>(&mut h, &pk.h) != 0 {
        return Err(NtruPlusError::InvalidPublicKey);
    }

    let mut msg = vec![0u8; n / 8 + P::SYMBYTES];
    msg[..n / 8].copy_from_slice(&coins[..n / 8]);
    symmetric::hash_f(&mut msg[n / 8..], &pk.h);

    let mut buf1 = vec![0u8; P::SSBYTES + n / 4];
    symmetric::hash_h::<P>(&mut buf1, &msg);

    let mut r = Poly::zero(n);
    poly::poly_cbd1::<P>(&mut r, &buf1[P::SSBYTES..]);
    poly::poly_ntt::<P>(&mut r);

    let mut r_bytes = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut r_bytes, &r);
    let mut buf2 = vec![0u8; n / 4];
    symmetric::hash_g::<P>(&mut buf2, &r_bytes);

    let mut m = Poly::zero(n);
    poly::poly_sotp_encode::<P>(&mut m, &msg[..n / 8], &buf2);
    poly::poly_ntt::<P>(&mut m);

    let mut c = Poly::zero(n);
    poly::poly_basemul_add::<P>(&mut c, &h, &r, &m);

    let mut ct = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut ct, &c);

    let mut ss = SharedSecret { ss: [0u8; 32] };
    ss.ss.copy_from_slice(&buf1[..P::SSBYTES]);

    Ok((Ciphertext { c: ct }, ss))
}

/// Deterministic encapsulation: the N/8-byte message is drawn from
/// `randombytes`, matching the reference's single `randombytes(coins, N/8)`.
/// An application encapsulates with `encapsulate`, which draws from the
/// operating system.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
#[cfg(feature = "kat-internal")]
pub fn encapsulate_det<P: NtruPlusParams, F: FnMut(&mut [u8])>(
    pk: &PublicKey,
    randombytes: F,
) -> Result<(Ciphertext, SharedSecret), NtruPlusError> {
    encapsulate_from_randombytes::<P, F>(pk, randombytes)
}

/// Body of `encapsulate_det`; `encapsulate` feeds it the operating system's
/// `getrandom`.
pub(crate) fn encapsulate_from_randombytes<P: NtruPlusParams, F: FnMut(&mut [u8])>(
    pk: &PublicKey,
    mut randombytes: F,
) -> Result<(Ciphertext, SharedSecret), NtruPlusError> {
    if pk.h.len() != P::PUBLIC_KEY_SIZE {
        return Err(NtruPlusError::InvalidKeySize);
    }
    let mut coins = vec![0u8; P::N / 8];
    randombytes(&mut coins);
    encapsulate_derand::<P>(pk, &coins)
}

/// Encapsulate with OS randomness.
pub fn encapsulate<P: NtruPlusParams>(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), NtruPlusError> {
    let mut rng_failed = false;
    let result = encapsulate_from_randombytes::<P, _>(pk, |buf| {
        if getrandom::getrandom(buf).is_err() {
            rng_failed = true;
        }
    });
    if rng_failed {
        return Err(NtruPlusError::RngError);
    }
    result
}

/// Decapsulate.
///
/// NTRU+ uses explicit rejection (FO⊥): the reference's `crypto_kem_dec`
/// returns 1 with an all-zero ss when the ciphertext or secret key carries a
/// coefficient `>= q` or the re-encryption check fails. That return code is
/// the failure signal, so this returns `Err(DecapsulationFailed)` in exactly
/// those cases. (It used to return `Ok` with the zero ss, which left every
/// caller that did not compare against zeros agreeing on the key 0^32 with
/// whoever sent the junk ciphertext.)
pub fn decapsulate<P: NtruPlusParams>(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, NtruPlusError> {
    let n = P::N;
    if ct.c.len() != P::CIPHERTEXT_SIZE {
        return Err(NtruPlusError::InvalidCiphertext);
    }
    if sk.f.len() != P::POLYBYTES || sk.hinv.len() != P::POLYBYTES {
        return Err(NtruPlusError::InvalidKeySize);
    }

    // Canonical-encoding checks (specification 2026-07-10 §6.3). The
    // reference also stops early here; which input was malformed is not
    // secret-dependent.
    let mut c = Poly::zero(n);
    let mut f = Poly::zero(n);
    let mut hinv = Poly::zero(n);
    if poly::poly_frombytes::<P>(&mut c, &ct.c) != 0
        || poly::poly_frombytes::<P>(&mut f, &sk.f) != 0
        || poly::poly_frombytes::<P>(&mut hinv, &sk.hinv) != 0
    {
        return Err(NtruPlusError::DecapsulationFailed);
    }

    // m1 = crepmod3(INTT(c · f))
    let mut m1 = Poly::zero(n);
    poly::poly_basemul::<P>(&mut m1, &c, &f);
    poly::poly_invntt::<P>(&mut m1);
    let m1_raw = m1.clone();
    poly::poly_crepmod3(&mut m1, &m1_raw);

    // r2 = h^{-1} · (c - NTT(m1))
    let mut m2 = m1.clone();
    poly::poly_ntt::<P>(&mut m2);
    let c_in = c.clone();
    poly::poly_sub(&mut c, &c_in, &m2);
    let mut r2 = Poly::zero(n);
    poly::poly_basemul::<P>(&mut r2, &c, &hinv);

    let mut buf1 = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut buf1, &r2);
    let mut buf2 = vec![0u8; n / 4];
    symmetric::hash_g::<P>(&mut buf2, &buf1);

    let mut msg = vec![0u8; n / 8 + P::SYMBYTES];
    let mut fail = poly::poly_sotp_decode::<P>(&mut msg[..n / 8], &m1, &buf2);
    msg[n / 8..].copy_from_slice(&sk.pkh);

    let mut buf3 = vec![0u8; P::SSBYTES + n / 4];
    symmetric::hash_h::<P>(&mut buf3, &msg);

    let mut r1 = Poly::zero(n);
    poly::poly_cbd1::<P>(&mut r1, &buf3[P::SSBYTES..]);
    poly::poly_ntt::<P>(&mut r1);
    let mut r1_bytes = vec![0u8; P::POLYBYTES];
    poly::poly_tobytes::<P>(&mut r1_bytes, &r1);

    fail |= poly::verify(&buf1, &r1_bytes);

    // The masked copy stays branch-free, as in the reference; only the final
    // verdict — which the caller learns either way — is a branch.
    let mask: u8 = !((fail as u8).wrapping_neg());
    let mut ss = SharedSecret { ss: [0u8; 32] };
    for i in 0..P::SSBYTES {
        ss.ss[i] = buf3[i] & mask;
    }
    if fail != 0 {
        return Err(NtruPlusError::DecapsulationFailed);
    }
    Ok(ss)
}

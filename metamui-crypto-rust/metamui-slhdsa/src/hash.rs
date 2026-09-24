//! Hash functions for SLH-DSA
//!
//! This module provides the hash function abstractions used throughout SLH-DSA,
//! supporting both SHAKE256 and SHA-2 variants, over MetaMUI's own
//! `metamui-shake` and `metamui-sha2` (no RustCrypto crate is in this crate's
//! closure — CLAUDE.md, #199).

use crate::{Parameters, address::Address};
use metamui_sha2::{Sha256Hasher, Sha512Hasher};
use metamui_shake::{Shake256, Shake256Reader};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Hash function trait for SLH-DSA
pub trait HashFunction {
    /// PRF: Pseudorandom function (Algorithm 7 in FIPS 205)
    /// Hashes: pk_seed || addr || sk_seed
    fn prf(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], addr: &Address);

    /// PRF_msg: Pseudorandom function for message
    fn prf_msg(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]);
    
    /// H_msg: Hash function for message
    fn h_msg(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8]);
    
    /// F: Tweakable hash function
    fn f(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8]);
    
    /// H: Tweakable hash function for two inputs
    fn h(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8], m2: &[u8]);
    
    /// T_l: Tweakable hash function for l inputs
    fn t_l(out: &mut [u8], pk_seed: &[u8], addr: &Address, ml: &[u8]);
}

/// SHAKE256 over the concatenation of `parts`, in its squeeze phase.
fn shake256(parts: &[&[u8]]) -> Shake256Reader {
    let mut hasher = Shake256::new();
    for part in parts {
        hasher
            .update(part)
            .expect("SHAKE-256 state is absorbing until finalize_xof");
    }
    hasher.finalize_xof()
}

/// SHAKE256-based hash functions
pub struct Shake256Hash;

impl HashFunction for Shake256Hash {
    fn prf(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], addr: &Address) {
        // FIPS 205: PRF hashes pk_seed || addr || sk_seed
        shake256(&[pk_seed, &addr.to_bytes(), sk_seed]).read_into(out);
    }
    
    fn prf_msg(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) {
        shake256(&[sk_prf, opt_rand, msg]).read_into(out);
    }
    
    fn h_msg(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8]) {
        shake256(&[r, pk_seed, pk_root, msg]).read_into(out);
    }
    
    fn f(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8]) {
        shake256(&[pk_seed, &addr.to_bytes(), m1]).read_into(out);
    }
    
    fn h(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8], m2: &[u8]) {
        shake256(&[pk_seed, &addr.to_bytes(), m1, m2]).read_into(out);
    }
    
    fn t_l(out: &mut [u8], pk_seed: &[u8], addr: &Address, ml: &[u8]) {
        shake256(&[pk_seed, &addr.to_bytes(), ml]).read_into(out);
    }
}

/// The two fixed-output SHA-2 hashes FIPS 205 §11.2 instantiates with, seen
/// through one streaming shape so MGF1, HMAC and the tweakable hashes can be
/// written once.
trait Sha2Stream {
    /// Block size in bytes (`B` in §11.2): 64 for SHA-256, 128 for SHA-512.
    const BLOCK: usize;
    fn init() -> Self;
    fn absorb(&mut self, data: &[u8]);
    fn digest(self) -> Vec<u8>;
}

impl Sha2Stream for Sha256Hasher {
    const BLOCK: usize = 64;
    fn init() -> Self { Self::new() }
    fn absorb(&mut self, data: &[u8]) { self.update(data); }
    fn digest(self) -> Vec<u8> { self.finalize().to_vec() }
}

impl Sha2Stream for Sha512Hasher {
    const BLOCK: usize = 128;
    fn init() -> Self { Self::new() }
    fn absorb(&mut self, data: &[u8]) { self.update(data); }
    fn digest(self) -> Vec<u8> { self.finalize().to_vec() }
}

fn sha2_parts<H: Sha2Stream>(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = H::init();
    for p in parts {
        h.absorb(p);
    }
    h.digest()
}

/// SHA-2-based hash functions (FIPS 205 §11.2).
///
/// The SHA-2 instantiation is *category-tiered*:
///
/// * Security category 1 (`n == 16`): every function uses SHA-256.
/// * Categories 3 & 5 (`n == 24` / `n == 32`): the short-input functions `F`
///   and `PRF` stay on SHA-256, while the variable/long-input functions `H`,
///   `T_l`, `H_msg` and `PRF_msg` switch to SHA-512.
///
/// `PRF` and `F` always use SHA-256 with a `toByte(0, 64 − n)` zero pad after
/// `PK.seed`; `H`/`T_l` pad with `toByte(0, B − n)` where `B` is the block size
/// of the chosen hash (64 for SHA-256, 128 for SHA-512). All tweakable hashes
/// consume the 22-byte *compressed* address `ADRSc`, never the full 32-byte
/// `ADRS`.
pub struct Sha256Hash;

/// Compressed address (`ADRSc`) per FIPS 205 §11.2:
/// `ADRSc = ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32]` (22 bytes).
fn adrs_c(addr: &Address) -> [u8; 22] {
    let a = addr.to_bytes();
    let mut c = [0u8; 22];
    c[0] = a[3];                       // low byte of the 4-byte layer address
    c[1..9].copy_from_slice(&a[8..16]); // low 8 bytes of the 12-byte tree address
    c[9] = a[19];                      // low byte of the 4-byte type
    c[10..22].copy_from_slice(&a[20..32]); // remaining 12 address bytes
    c
}

/// MGF1 (RFC 8017) over an arbitrary fixed-output hash `H`.
fn mgf1<H: Sha2Stream>(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while output.len() < out_len {
        output.extend_from_slice(&sha2_parts::<H>(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    output.truncate(out_len);
    output
}

fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    mgf1::<Sha256Hasher>(seed, out_len)
}

fn mgf1_sha512(seed: &[u8], out_len: usize) -> Vec<u8> {
    mgf1::<Sha512Hasher>(seed, out_len)
}

/// HMAC (RFC 2104) over a fixed-output hash with its block size.
fn hmac<H: Sha2Stream>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // Keys longer than the block size are first hashed; SLH-DSA keys (n ≤ 32)
    // are always shorter, but handle the general case for correctness.
    let mut k = if key.len() > H::BLOCK {
        sha2_parts::<H>(&[key])
    } else {
        key.to_vec()
    };
    k.resize(H::BLOCK, 0);

    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();

    let inner_digest = sha2_parts::<H>(&[&ipad, msg]);
    sha2_parts::<H>(&[&opad, &inner_digest])
}

impl HashFunction for Sha256Hash {
    fn prf(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], addr: &Address) {
        // FIPS 205 §11.2: PRF = Trunc_n(SHA-256(PK.seed ‖ toByte(0,64−n) ‖ ADRSc ‖ SK.seed))
        let n = pk_seed.len();
        let hash = sha2_parts::<Sha256Hasher>(&[pk_seed, &vec![0u8; 64 - n], &adrs_c(addr), sk_seed]);
        out.copy_from_slice(&hash[..out.len()]);
    }

    fn prf_msg(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) {
        // FIPS 205 §11.2: PRF_msg = Trunc_n(HMAC-SHA-X(SK.prf, opt_rand ‖ M))
        let n = sk_prf.len();
        let mut data = Vec::with_capacity(opt_rand.len() + msg.len());
        data.extend_from_slice(opt_rand);
        data.extend_from_slice(msg);
        let mac = if n > 16 {
            hmac::<Sha512Hasher>(sk_prf, &data)
        } else {
            hmac::<Sha256Hasher>(sk_prf, &data)
        };
        out.copy_from_slice(&mac[..out.len()]);
    }

    fn h_msg(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8]) {
        // FIPS 205 §11.2:
        //   H_msg = MGF1-SHA-X(R ‖ PK.seed ‖ SHA-X(R ‖ PK.seed ‖ PK.root ‖ M), m)
        let n = pk_seed.len();
        let mut inner_input = Vec::with_capacity(r.len() + pk_seed.len() + pk_root.len() + msg.len());
        inner_input.extend_from_slice(r);
        inner_input.extend_from_slice(pk_seed);
        inner_input.extend_from_slice(pk_root);
        inner_input.extend_from_slice(msg);

        if n > 16 {
            let inner = sha2_parts::<Sha512Hasher>(&[&inner_input]);
            let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + inner.len());
            seed.extend_from_slice(r);
            seed.extend_from_slice(pk_seed);
            seed.extend_from_slice(&inner);
            out.copy_from_slice(&mgf1_sha512(&seed, out.len()));
        } else {
            let inner = sha2_parts::<Sha256Hasher>(&[&inner_input]);
            let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + inner.len());
            seed.extend_from_slice(r);
            seed.extend_from_slice(pk_seed);
            seed.extend_from_slice(&inner);
            out.copy_from_slice(&mgf1_sha256(&seed, out.len()));
        }
    }

    fn f(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8]) {
        // FIPS 205 §11.2: F = Trunc_n(SHA-256(PK.seed ‖ toByte(0,64−n) ‖ ADRSc ‖ M_1))
        let n = pk_seed.len();
        let hash = sha2_parts::<Sha256Hasher>(&[pk_seed, &vec![0u8; 64 - n], &adrs_c(addr), m1]);
        out.copy_from_slice(&hash[..out.len()]);
    }

    fn h(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8], m2: &[u8]) {
        // FIPS 205 §11.2: H = Trunc_n(SHA-X(PK.seed ‖ toByte(0,B−n) ‖ ADRSc ‖ M_1 ‖ M_2))
        sha2_tweak(out, pk_seed, addr, &[m1, m2]);
    }

    fn t_l(out: &mut [u8], pk_seed: &[u8], addr: &Address, ml: &[u8]) {
        // FIPS 205 §11.2: T_l = Trunc_n(SHA-X(PK.seed ‖ toByte(0,B−n) ‖ ADRSc ‖ M_l))
        sha2_tweak(out, pk_seed, addr, &[ml]);
    }
}

/// Shared body for the multi-input tweakable hashes `H` and `T_l`: SHA-256 at
/// category 1 (block 64), SHA-512 at categories 3/5 (block 128), padded with
/// `toByte(0, B − n)` and truncated to `n`.
fn sha2_tweak(out: &mut [u8], pk_seed: &[u8], addr: &Address, parts: &[&[u8]]) {
    let n = pk_seed.len();
    let adrsc = adrs_c(addr);
    let hash = if n > 16 {
        let mut hasher = Sha512Hasher::new();
        hasher.update(pk_seed);
        hasher.update(&vec![0u8; 128 - n]);
        hasher.update(&adrsc);
        for p in parts {
            hasher.update(p);
        }
        hasher.finalize().to_vec()
    } else {
        let mut hasher = Sha256Hasher::new();
        hasher.update(pk_seed);
        hasher.update(&vec![0u8; 64 - n]);
        hasher.update(&adrsc);
        for p in parts {
            hasher.update(p);
        }
        hasher.finalize().to_vec()
    };
    out.copy_from_slice(&hash[..out.len()]);
}

/// Generic hash wrapper that selects the appropriate hash function
pub struct Hash<P: Parameters> {
    _phantom: core::marker::PhantomData<P>,
}

impl<P: Parameters> Hash<P> {
    /// PRF function (Algorithm 7 in FIPS 205)
    pub fn prf(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], addr: &Address) {
        if P::USE_SHAKE {
            Shake256Hash::prf(out, pk_seed, sk_seed, addr);
        } else {
            Sha256Hash::prf(out, pk_seed, sk_seed, addr);
        }
    }
    
    /// PRF_msg function
    pub fn prf_msg(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) {
        if P::USE_SHAKE {
            Shake256Hash::prf_msg(out, sk_prf, opt_rand, msg);
        } else {
            Sha256Hash::prf_msg(out, sk_prf, opt_rand, msg);
        }
    }
    
    /// H_msg function
    pub fn h_msg(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8]) {
        if P::USE_SHAKE {
            Shake256Hash::h_msg(out, r, pk_seed, pk_root, msg);
        } else {
            Sha256Hash::h_msg(out, r, pk_seed, pk_root, msg);
        }
    }
    
    /// F function (tweakable hash)
    pub fn f(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8]) {
        if P::USE_SHAKE {
            Shake256Hash::f(out, pk_seed, addr, m1);
        } else {
            Sha256Hash::f(out, pk_seed, addr, m1);
        }
    }
    
    /// H function (tweakable hash for two inputs)
    pub fn h(out: &mut [u8], pk_seed: &[u8], addr: &Address, m1: &[u8], m2: &[u8]) {
        if P::USE_SHAKE {
            Shake256Hash::h(out, pk_seed, addr, m1, m2);
        } else {
            Sha256Hash::h(out, pk_seed, addr, m1, m2);
        }
    }
    
    /// T_l function (tweakable hash for l inputs)
    pub fn t_l(out: &mut [u8], pk_seed: &[u8], addr: &Address, ml: &[u8]) {
        if P::USE_SHAKE {
            Shake256Hash::t_l(out, pk_seed, addr, ml);
        } else {
            Sha256Hash::t_l(out, pk_seed, addr, ml);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;
    
    #[test]
    fn test_shake256_hash() {
        let pk_seed = vec![0x01; 16];
        let addr = Address::new();
        let m1 = vec![0x02; 16];
        let mut out = vec![0u8; 16];
        
        Shake256Hash::f(&mut out, &pk_seed, &addr, &m1);
        
        // Output should be deterministic
        let mut out2 = vec![0u8; 16];
        Shake256Hash::f(&mut out2, &pk_seed, &addr, &m1);
        assert_eq!(out, out2);
    }
    
    #[test]
    fn test_sha256_mgf1() {
        let seed = b"test seed";
        let out32 = mgf1_sha256(seed, 32);
        let out64 = mgf1_sha256(seed, 64);
        
        assert_eq!(out32.len(), 32);
        assert_eq!(out64.len(), 64);
        
        // First 32 bytes should match
        assert_eq!(&out32[..], &out64[..32]);
    }
    
    #[test]
    fn test_generic_hash() {
        type P = SlhDsa128s;
        
        let pk_seed = vec![0x01; P::N];
        let addr = Address::new();
        let m1 = vec![0x02; P::N];
        let mut out = vec![0u8; P::N];
        
        Hash::<P>::f(&mut out, &pk_seed, &addr, &m1);
        
        // Output should not be all zeros
        assert!(!out.iter().all(|&b| b == 0));
    }
}
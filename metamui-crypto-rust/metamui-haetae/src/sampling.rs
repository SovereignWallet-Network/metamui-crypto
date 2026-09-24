//! Sampling operations for HAETAE
//!
//! This module implements rejection sampling for uniform and bounded
//! distributions, as well as Gaussian sampling for hyperball generation.
//!
//! Transcopy from: metamui-haetae/src/sampler.c
//!
//! Same write-through-out-parameter pattern as sign.rs — some initial
//! `Fp96_76::default()` assignments are "unused" because the first read
//! happens through a function that writes before reading.

#![allow(unused_assignments)]

use crate::params::{ETA, Q, CRHBYTES, N};
use crate::fixpoint::{Fp96_76, fixpoint_square};
use crate::shake::{Shake256Stream, SHAKE256_RATE};

/// Rejection sampling for uniform distribution in [0, Q-1]
///
/// Samples uniformly random coefficients by performing rejection sampling
/// on array of random bytes. Reads 2 bytes per sample and accepts if < Q.
///
/// # Arguments
/// * `a` - Output array for sampled coefficients
/// * `buf` - Array of random bytes
///
/// # Returns
/// Number of coefficients successfully sampled (may be less than a.len())
///
/// Transcopy from: unsigned int rej_uniform(int32_t *a, unsigned int len, ...)
pub fn rej_uniform(a: &mut [i32], buf: &[u8]) -> usize {
    let len = a.len();
    let buflen = buf.len();
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < len && pos + 2 <= buflen {
        // Read 16-bit value (little-endian)
        let t = buf[pos] as u32 | ((buf[pos + 1] as u32) << 8);
        pos += 2;

        // Accept if less than Q
        if t < Q as u32 {
            a[ctr] = t as i32;
            ctr += 1;
        }
    }

    ctr
}

/// Helper: Reduce modulo 3 for general case
#[inline]
fn mod3(t: u8) -> i32 {
    let mut r = ((t >> 4) + (t & 0xf)) as i32;
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    r - (3 * (r >> 1))
}

/// Helper: Reduce modulo 3 for values <= 26
#[inline]
fn mod3_leq26(t: u8) -> i32 {
    let mut r = ((t >> 4) + (t & 0xf)) as i32;
    r = (r >> 2) + (r & 3);
    r = (r >> 2) + (r & 3);
    r - (3 * (r >> 1))
}

/// Helper: Reduce modulo 3 for values <= 8
#[inline]
fn mod3_leq8(t: u8) -> i32 {
    let mut r = ((t >> 2) + (t & 3)) as i32;
    r = (r >> 2) + (r & 3);
    r - (3 * (r >> 1))
}

/// Rejection sampling for uniform distribution in [-ETA, ETA]
///
/// Samples uniformly random coefficients in the range [-ETA, ETA] by
/// performing rejection sampling on array of random bytes.
///
/// For ETA=1: Uses mod3 reduction with 5 samples per byte
/// For ETA=2: Uses mod5 reduction with 2 samples per nibble
///
/// # Arguments
/// * `a` - Output array for sampled coefficients
/// * `buf` - Array of random bytes
///
/// # Returns
/// Number of coefficients successfully sampled
///
/// Transcopy from: unsigned int rej_eta(int32_t *a, unsigned int len, ...)
pub fn rej_eta(a: &mut [i32], buf: &[u8]) -> usize {
    let len = a.len();
    let buflen = buf.len();
    let mut ctr = 0;
    let mut pos = 0;

    #[cfg(not(any(feature = "haetae2", feature = "haetae3", feature = "haetae5")))]
    compile_error!("Must enable one of: haetae2, haetae3, or haetae5");

    while ctr < len && pos < buflen {
        #[cfg(any(feature = "haetae2", feature = "haetae3", feature = "haetae5"))]
        {
            if ETA == 1 {
                // ETA=1: Extract 5 coefficients from one byte
                let mut t = buf[pos] as u32;
                pos += 1;

                if t < 243 {
                    // First coefficient
                    a[ctr] = mod3(t as u8);
                    ctr += 1;
                    if ctr >= len {
                        break;
                    }

                    // Second coefficient
                    t = t.wrapping_mul(171); // 171*3 = 1 mod 256
                    t >>= 9;
                    a[ctr] = mod3(t as u8);
                    ctr += 1;
                    if ctr >= len {
                        break;
                    }

                    // Third coefficient
                    t = t.wrapping_mul(171);
                    t >>= 9;
                    a[ctr] = mod3_leq26(t as u8);
                    ctr += 1;
                    if ctr >= len {
                        break;
                    }

                    // Fourth coefficient
                    t = t.wrapping_mul(171);
                    t >>= 9;
                    a[ctr] = mod3_leq8(t as u8);
                    ctr += 1;
                    if ctr >= len {
                        break;
                    }

                    // Fifth coefficient
                    t = t.wrapping_mul(171);
                    t >>= 9;
                    a[ctr] = (t as i32) - 3 * ((t >> 1) as i32);
                    ctr += 1;
                }
            } else if ETA == 2 {
                // ETA=2: Extract 2 coefficients from one byte (nibbles)
                let byte = buf[pos];
                pos += 1;

                let t0 = (byte & 0x0F) as u32;
                let t1 = (byte >> 4) as u32;

                // First nibble
                if t0 < 15 {
                    let t0_mod5 = t0 - ((205 * t0) >> 10) * 5;
                    a[ctr] = 2 - (t0_mod5 as i32);
                    ctr += 1;
                }

                // Second nibble
                if t1 < 15 && ctr < len {
                    let t1_mod5 = t1 - ((205 * t1) >> 10) * 5;
                    a[ctr] = 2 - (t1_mod5 as i32);
                    ctr += 1;
                }
            }
        }
    }

    ctr
}

// ===========================================================================
// Gaussian Sampling for Hyperball
// ===========================================================================

/// 83-bit CDT for the D_{Z,16} half-Gaussian, rho(k) = exp(-k^2/512), k >= 0:
/// CDT83[k] = floor(CDF(k) * 2^83), split into an upper 19-bit and a lower
/// 64-bit table. Reference v1.2.0 `sampler.c` (replaces the 64-entry 16-bit
/// CDT of 1.1.2).
const CDTLEN: usize = 166;
const CDTHILEN: usize = 76;
const CDT83_HI: [u32; CDTHILEN] = [
    0x063a5, 0x0c718, 0x129f6, 0x18bdf,
    0x1ec73, 0x24b59, 0x2a83a, 0x302c6,
    0x35ab6, 0x3afc7, 0x401be, 0x4506a,
    0x49ba1, 0x4e343, 0x52736, 0x5676c,
    0x5a3dc, 0x5dc86, 0x61172, 0x642ad,
    0x6704c, 0x69a68, 0x6c120, 0x6e496,
    0x704ef, 0x72255, 0x73cf1, 0x754f0,
    0x76a7c, 0x77dc4, 0x78ef2, 0x79e32,
    0x7abaf, 0x7b78f, 0x7c1fb, 0x7cb17,
    0x7d304, 0x7d9e4, 0x7dfd4, 0x7e4f0,
    0x7e950, 0x7ed0d, 0x7f03b, 0x7f2ec,
    0x7f531, 0x7f71a, 0x7f8b3, 0x7fa08,
    0x7fb24, 0x7fc0e, 0x7fccf, 0x7fd6e,
    0x7fdf0, 0x7fe5a, 0x7feaf, 0x7fef5,
    0x7ff2c, 0x7ff59, 0x7ff7d, 0x7ff99,
    0x7ffb0, 0x7ffc2, 0x7ffd0, 0x7ffdb,
    0x7ffe3, 0x7ffea, 0x7ffef, 0x7fff3,
    0x7fff6, 0x7fff8, 0x7fffa, 0x7fffb,
    0x7fffd, 0x7fffd, 0x7fffe, 0x7fffe,
];
const CDT83_LO: [u64; CDTLEN] = [
    0x0aa572bc88db1e28, 0x4f3820e69064b2ee,
    0xd68dc44dd1418704, 0x6587a04d9b97b1dd,
    0x9b843ce0a65d0050, 0x02b62cb869003e7d,
    0x0d44f194f8bf43c6, 0xfaa0c7acb211b4db,
    0xa11387f7f524be80, 0x18526ca6f2ceb77f,
    0x42a01a906b7dad17, 0x32e5337a1966b9a7,
    0x6f00f7ac9735f58a, 0x0e6c48f40642ba60,
    0xb6192fa1afb5e4ec, 0x7339dba8ffc2fcf5,
    0x7746cbe1ac90c9eb, 0xb83004341d78466f,
    0x781dcca572bb3d8a, 0xb880376cc82a5384,
    0x9c68a5c477dfecb9, 0xbe45ceb02a25fef3,
    0x7d1a8ccd208dbaa1, 0x452c002b9085e7db,
    0xd7ef361c5551378d, 0x96b4ff49d9e5a8bb,
    0xd337c94ede732d83, 0x28c75b8d3fe83c38,
    0xe05d7bd130fe20e0, 0x6170e60b76d85108,
    0xb0e59892414901ff, 0xff05cf70b911f3de,
    0x4501460fdfd508c9, 0xf20b1303a2a54906,
    0xa7d3badbeb04b20c, 0x05ce666b741b666d,
    0x826e689fded20430, 0x5155d1354fcf6ff6,
    0x55469226a1d318f6, 0x1c8d3820cfa9cabc,
    0xe68d83bbf700fc40, 0xb1152d8944042803,
    0x4c1e741aabe53700, 0x72b94c56e0f9a967,
    0xe7e5a80a79e4539c, 0x9641c5d11feb4d12,
    0xb18b71598b73dde0, 0xd9112fb5a7904d7e,
    0x3a4f57cbefabc820, 0xb314025fd5022976,
    0xf2a2b228aab1981b, 0x996ce1e60378cd98,
    0x570ec64b38e3ca90, 0x0657269615dcd7c6,
    0xc7360038bdc85312, 0x167fa02a57a8ae1a,
    0xe380fab2ea9b2bef, 0xa36e6abd6509b5a2,
    0x62bfcf1d6ba81c37, 0xd4946e8bf96caa93,
    0x603e6262ea8cda2d, 0x2d18c8b333ae9203,
    0x2ccdedb5a7718d61, 0x24333ecab8497c0a,
    0xb2e06eb33bf2b7d9, 0x59a5f6c550dfe7e2,
    0x800548f3927f906e, 0x78cac146b573bc40,
    0x85e6dadec4b6aff1, 0xdba17dfa17def8ec,
    0xa33f84d06ce20a93, 0xfd2fe967c5186746,
    0x02d37ecd7e9b180f, 0xc7efafa8bd33f0bb,
    0x5bda826341e791cc, 0xca6c1c6ce045599f,
    0x1cc02c0faa9a526e, 0x59d002901a4a4e52,
    0x86ecbd139ce07540, 0xa81f9f15ffb47f4c,
    0xc075b17481687af0, 0xd23ad13e68301c65,
    0xdf27955fae1c84cb, 0xe884cdb07368c266,
    0xef46d4f897fc83f6, 0xf4227e46663ec049,
    0xf79d091c1b5aff07, 0xfa183c533c3890a6,
    0xfbdb8a602066b0f2, 0xfd1af06df3db86b7,
    0xfdfc1a818587e2aa, 0xfe9a37a348ac2a93,
    0xff08d0797970dbfe, 0xff55df73fd7a00bc,
    0xff8b5aa573bca5ce, 0xffb053c109f51681,
    0xffc9c9bd39a036ec, 0xffdb40bd4ee1f846,
    0xffe72fa859b20a4a, 0xffef4edda93d266d,
    0xfff4d07a9fb0d4e0, 0xfff88868ef31b1cc,
    0xfffb08c16a3f5f0c, 0xfffcb5d30be5cabf,
    0xfffdd43465d95fe6, 0xfffe929a538ad2fa,
    0xffff10b1c2119732, 0xffff63df8795a2c9,
    0xffff9a87a0a9f2af, 0xffffbe4df6f0f4a9,
    0xffffd5a10f204910, 0xffffe4c6f1668b32,
    0xffffee939680bfaf, 0xfffff4e4216290db,
    0xfffff8f1c044613e, 0xfffffb892dc2b174,
    0xfffffd2fb4188608, 0xfffffe3bc0a56eba,
    0xfffffee523b218c6, 0xffffff4fc31097e3,
    0xffffff929d76dbeb, 0xffffffbc5e7c0350,
    0xffffffd6586c6684, 0xffffffe6716865f7,
    0xfffffff0613c76e2, 0xfffffff67d62ab64,
    0xfffffffa3b6664c0, 0xfffffffc83e13d66,
    0xfffffffde713ef71, 0xfffffffebe18936f,
    0xffffffff3fbfc997, 0xffffffff8d9fa29a,
    0xffffffffbc372590, 0xffffffffd7fb7dfd,
    0xffffffffe87747f9, 0xfffffffff2368b89,
    0xfffffffff7f44d88, 0xfffffffffb52a49b,
    0xfffffffffd4a9ffb, 0xfffffffffe700579,
    0xffffffffff1a287f, 0xffffffffff7c6f06,
    0xffffffffffb4fa99, 0xffffffffffd56300,
    0xffffffffffe7e364, 0xfffffffffff268d7,
    0xfffffffffff85e8e, 0xfffffffffffbbb6f,
    0xfffffffffffd9f49, 0xfffffffffffeae2c,
    0xffffffffffff453d, 0xffffffffffff9928,
    0xffffffffffffc797, 0xffffffffffffe12f,
    0xffffffffffffef3c, 0xfffffffffffff6eb,
    0xfffffffffffffb1b, 0xfffffffffffffd60,
    0xfffffffffffffe9a, 0xffffffffffffff43,
    0xffffffffffffff9e, 0xffffffffffffffce,
    0xffffffffffffffe7, 0xfffffffffffffff4,
    0xfffffffffffffffb, 0xfffffffffffffffe,
];

/// Signed multiply high 48-bit, ceiling — reference v1.2.0 `fixpoint.h`
/// `smulh48` (1.1.2 rounded with `+ 2^47`).
#[inline]
fn smulh48(a: i64, b: u64) -> i64 {
    (((a as i128) * (b as i128) + (1i128 << 48) - 1) >> 48) as i64
}

/// GALACTICS degree-10 polynomial for exp(-z), z = x / 2^48, with the
/// constant term lifted by one unit so the approximation is a ceiling
/// everywhere. Coefficients are ceil(c_k * 2^48) from reference v1.2.0
/// `sampler.c` `approx_exp`.
fn approx_exp(xi: u64) -> u64 {
    let mut r: i64 = 55_868_746; // c_10
    r = smulh48(r, xi) - 743_564_434; // c_9
    r = smulh48(r, xi) + 6_953_427_278; // c_8
    r = smulh48(r, xi) - 55_833_338_892; // c_7
    r = smulh48(r, xi) + 390_932_311_155; // c_6
    r = smulh48(r, xi) - 2_345_623_661_771; // c_5
    r = smulh48(r, xi) + 11_728_123_872_951; // c_4
    r = smulh48(r, xi) - 46_912_496_106_200; // c_3
    r = smulh48(r, xi) + 140_737_488_354_861; // c_2
    r = smulh48(r, xi) - 281_474_976_710_650; // c_1
    r = smulh48(r, xi) + 281_474_976_710_657; // c_0 (2^48 + 1)
    r as u64
}

/// Sample from the half-Gaussian by an 83-bit CDT walk: `rand_lo` is the
/// lower 64 bits and `rand_hi` the upper 19 bits of the 83-bit random input.
/// Reference v1.2.0 `sample_gauss83` (Algorithm 17).
fn sample_gauss83(rand_lo: u64, rand_hi: u32) -> u64 {
    let rnd: u128 = ((rand_hi as u128) << 64) | rand_lo as u128;
    let mut r = 0u64;
    for i in 0..CDTHILEN {
        let cdt: u128 = ((CDT83_HI[i] as u128) << 64) | CDT83_LO[i] as u128;
        r += (cdt.wrapping_sub(rnd) >> 127) as u64;
    }
    for i in CDTHILEN..CDTLEN {
        let cdt: u128 = (0x7ffffu128 << 64) | CDT83_LO[i] as u128;
        r += (cdt.wrapping_sub(rnd) >> 127) as u64;
    }
    r
}

/// Gaussian random bits needed per sample: 72 (y noise) + 83 (CDT) + 48 (rejection).
const GAUSS_RAND: usize = 72 + 83 + 48;
const GAUSS_RAND_BYTES: usize = (GAUSS_RAND + 7) / 8; // 26

/// Sample single Gaussian value with standard deviation σ=√76
///
/// Returns true if accepted, updates r and sqr
///
/// Transcopy from: static int sample_gauss_sigma76(...) (reference v1.2.0,
/// Algorithm 16). Byte layout: rand[0..11] 83-bit CDT random, rand[11..17]
/// 48-bit rejection random, rand[17..26] 72-bit y noise.
fn sample_gauss_sigma76(r: &mut u64, sqr: &mut Fp96_76, rand: &[u8; GAUSS_RAND_BYTES]) -> bool {
    let rand_gauss83_lo = u64::from_le_bytes([rand[0], rand[1], rand[2], rand[3], rand[4], rand[5], rand[6], rand[7]]);
    let rand_gauss83_hi = ((rand[8] as u32) | ((rand[9] as u32) << 8) | ((rand[10] as u32) << 16)) & 0x7FFFF;
    let rand_rej = (rand[11] as u64)
        | ((rand[12] as u64) << 8)
        | ((rand[13] as u64) << 16)
        | ((rand[14] as u64) << 24)
        | ((rand[15] as u64) << 32)
        | ((rand[16] as u64) << 40);

    // Sample x from the discrete Gaussian
    let x = sample_gauss83(rand_gauss83_lo, rand_gauss83_hi);

    // Construct y with fractional part; leave 16 bits for carries
    let y = Fp96_76 {
        limb48: [
            (rand[17] as u64)
                | ((rand[18] as u64) << 8)
                | ((rand[19] as u64) << 16)
                | ((rand[20] as u64) << 24)
                | ((rand[21] as u64) << 32)
                | ((rand[22] as u64) << 40),
            (rand[23] as u64) | ((rand[24] as u64) << 8) | ((rand[25] as u64) << 16) | (x << 24),
        ],
    };

    // r := round y. limb48[1] can reach 166 * 2^24, so the two halves are
    // rounded separately (a single << 33 would overflow for x >= 128).
    *r = ((y.limb48[0] >> 15) + 1) >> 1;
    *r = r.wrapping_add(y.limb48[1] << 32);

    // Compute y²
    *sqr = fixpoint_square(&y);

    // Compute exp_in = y² - x²*2^68
    let mut exp_in = sqr.limb48[1].wrapping_sub((x * x) << (68 - 48));
    exp_in <<= 20;
    exp_in |= sqr.limb48[0] >> 28;
    exp_in = (exp_in + 1) >> 1; // Rounding

    // Rejection sampling
    let accept = ((((rand_rej ^ (rand_rej & 1)) as i64 - approx_exp(exp_in) as i64) >> 63)
        & ((((*r | r.wrapping_neg()) >> 63) | rand_rej) as i64))
        & 1;

    accept != 0
}

/// Sample N Gaussian values
///
/// # Arguments
/// * `r` - Output array for samples
/// * `signs` - Output array for sign bits
/// * `sqsum` - Running sum of squared values
/// * `seed` - SHAKE256 seed
/// * `nonce` - Nonce for domain separation
/// * `len` - Number of samples to generate
///
/// Sample Gaussian coefficients from a fixed randomness buffer, accumulating
/// each accepted sample's square into `sqsum`. Returns the number of
/// coefficients produced; stops early (returning < `len`) when fewer than
/// `GAUSS_RAND_BYTES` bytes remain so the caller can refill and resume.
///
/// `dont_write_last` mirrors the reference's `len % N` flag: when set, the
/// final coefficient of the run is the extra hyperball Gaussian — it is
/// sampled and contributes to `sqsum` but is NOT written to `r` (which would
/// be out of bounds for the N+1-length runs).
///
/// Transcopy from: int sample_gauss(uint64_t *r, fp96_76 *sqsum,
///   const uint8_t *buf, size_t buflen, size_t len, int dont_write_last)
fn sample_gauss(
    r: &mut [u64],
    sqsum: &mut Fp96_76,
    buf: &[u8],
    buflen: usize,
    len: usize,
    dont_write_last: bool,
) -> usize {
    let mut pos = 0usize;
    let mut bytecnt = buflen;
    let mut coefcnt = 0usize;

    while coefcnt < len {
        if bytecnt < GAUSS_RAND_BYTES {
            sqsum.renormalize();
            return coefcnt;
        }

        let mut rand_bytes = [0u8; GAUSS_RAND_BYTES];
        rand_bytes.copy_from_slice(&buf[pos..pos + GAUSS_RAND_BYTES]);

        let mut sqr = Fp96_76::new();
        let mut dummy = 0u64;
        let accepted = if dont_write_last && coefcnt == len - 1 {
            sample_gauss_sigma76(&mut dummy, &mut sqr, &rand_bytes)
        } else {
            sample_gauss_sigma76(&mut r[coefcnt], &mut sqr, &rand_bytes)
        };

        pos += GAUSS_RAND_BYTES;
        bytecnt -= GAUSS_RAND_BYTES;

        if accepted {
            sqsum.limb48[0] += sqr.limb48[0];
            sqsum.limb48[1] += sqr.limb48[1];
            coefcnt += 1;
        }
    }

    sqsum.renormalize();
    len
}

/// Transcopy from: void sample_gauss_N(...)
///
/// CRITICAL: when rejection sampling exhausts the initial SHAKE256 buffer
/// before `len` coefficients are accepted, the reference squeezes additional
/// blocks (carrying over the unconsumed tail) and continues. Omitting this
/// refill silently under-samples the hyperball, shrinking `sqsum` and scaling
/// every `y` coefficient up by the wrong radius factor.
pub fn sample_gauss_n(
    r: &mut [u64],
    signs: &mut [u8],
    sqsum: &mut Fp96_76,
    seed: &[u8; CRHBYTES],
    nonce: u16,
    len: usize,
) {
    const POLY_HYPERBALL_NBLOCKS: usize = ((GAUSS_RAND_BYTES * N) + SHAKE256_RATE - 1) / SHAKE256_RATE;

    let mut buf = vec![0u8; POLY_HYPERBALL_NBLOCKS * SHAKE256_RATE];
    let mut state = Shake256Stream::new(seed, nonce);
    state.squeeze_blocks(&mut buf, POLY_HYPERBALL_NBLOCKS);

    // Extract sign bits from the head of the buffer.
    for i in 0..(len / 8) {
        signs[i] = buf[i];
    }

    let dont_write_last = (len % N) != 0;
    let mut bytecnt = POLY_HYPERBALL_NBLOCKS * SHAKE256_RATE - len / 8;

    // First pass consumes the bytes after the sign region.
    let mut coefcnt = sample_gauss(r, sqsum, &buf[len / 8..], bytecnt, len, dont_write_last);

    // Refill and resume until all `len` coefficients are produced.
    let mut firstflag = 1usize;
    while coefcnt < len {
        let off = bytecnt % GAUSS_RAND_BYTES;
        // Carry over the unconsumed tail to the front of the buffer.
        for i in 0..off {
            buf[i] = buf[bytecnt + (len / 8) * firstflag - off + i];
        }
        state.squeeze_blocks(&mut buf[off..off + SHAKE256_RATE], 1);
        bytecnt = SHAKE256_RATE + off;

        let got = sample_gauss(
            &mut r[coefcnt..],
            sqsum,
            &buf,
            bytecnt,
            len - coefcnt,
            dont_write_last,
        );
        coefcnt += got;
        firstflag = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rej_uniform_basic() {
        let mut a = [0i32; 10];
        // Create buffer with some values < Q and some >= Q
        let buf = vec![
            0x00, 0x00, // 0 < Q ✓
            0x01, 0xFC, // 64513 = Q ✗
            0xFF, 0x00, // 255 < Q ✓
            0x00, 0x01, // 256 < Q ✓
        ];

        let count = rej_uniform(&mut a, &buf);

        // Should accept 3 values (0, 255, 256)
        assert_eq!(count, 3);
        assert_eq!(a[0], 0);
        assert_eq!(a[1], 255);
        assert_eq!(a[2], 256);
    }

    #[test]
    fn test_rej_eta_range() {
        let mut a = [0i32; 100];
        let buf: Vec<u8> = (0..100).collect();

        let count = rej_eta(&mut a, &buf);

        // All sampled values should be in range [-ETA, ETA]
        for i in 0..count {
            assert!(
                a[i] >= -(ETA as i32) && a[i] <= ETA as i32,
                "Value {} out of range [-{}, {}]: {}",
                i,
                ETA,
                ETA,
                a[i]
            );
        }
    }

    #[test]
    fn test_mod3_helpers() {
        // Test mod3 reduces correctly
        assert_eq!(mod3(0), 0);
        assert_eq!(mod3(3), 0);
        assert_eq!(mod3(1), 1);
        assert_eq!(mod3(4), 1);
        assert_eq!(mod3(2), -1);
        assert_eq!(mod3(5), -1);
    }

    #[test]
    fn test_rej_eta_exhaustive_bounds() {
        // Feed all 256 byte values through rej_eta and verify bounds
        let mut a = [0i32; 1280]; // 5 coeffs/byte * 256 bytes
        let buf: Vec<u8> = (0..=255u8).collect();
        let count = rej_eta(&mut a, &buf);

        assert!(count > 0, "Should sample at least some coefficients");
        for i in 0..count {
            assert!(
                a[i] >= -(ETA as i32) && a[i] <= ETA as i32,
                "rej_eta coefficient {} = {} exceeds [-{}, {}]",
                i, a[i], ETA, ETA
            );
        }
    }
}

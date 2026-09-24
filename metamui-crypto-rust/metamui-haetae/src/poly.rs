//! Polynomial operations for HAETAE
//!
//! This module implements polynomial arithmetic operations in the ring
//! R_q = Z_q[X]/(X^N + 1) where N=256 and q=64513.
//!
//! Transcopy from: metamui-haetae/src/poly.c

use crate::params::*;
use crate::reduce::*;
use crate::sampling::{rej_uniform, rej_eta};
use crate::shake::{Shake128Stream, Shake256Stream, SHAKE128_RATE, SHAKE256_RATE};
use zeroize::Zeroize;

/// Polynomial in R_q = Z_q[X]/(X^N + 1)
///
/// Represents a polynomial with N=256 coefficients modulo Q=64513.
/// This is the portable C layout: simple array of i32 coefficients.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Poly {
    /// Coefficients array: coeffs[i] is the coefficient of X^i
    pub coeffs: [i32; N],
}

impl Poly {
    /// Create a new zero polynomial
    pub const fn new() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create polynomial from coefficient array
    pub const fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Add two polynomials: c = a + b (mod q)
    ///
    /// Transcopy from: void poly_add(poly *c, const poly *a, const poly *b)
    pub fn add(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] + b.coeffs[i];
        }
    }

    /// In-place add: self += b
    pub fn add_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] += b.coeffs[i];
        }
    }

    /// Subtract two polynomials: c = a - b (mod q)
    ///
    /// Transcopy from: void poly_sub(poly *c, const poly *a, const poly *b)
    pub fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }

    /// In-place subtract: self -= b
    pub fn sub_assign(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] -= b.coeffs[i];
        }
    }

    /// Pointwise Montgomery multiplication: c = a * b (mod q)
    ///
    /// Assumes input is in Montgomery form (NTT domain).
    ///
    /// Transcopy from: void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b)
    pub fn pointwise_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
        }
    }

    /// Reduce all coefficients modulo 2Q
    ///
    /// For coefficients c with |c| < 2Q, this ensures 0 <= c < 2Q.
    ///
    /// Transcopy from: void poly_reduce2q(poly *a)
    pub fn reduce2q(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce2q(self.coeffs[i]);
        }
    }

    /// Freeze coefficients to canonical form [0, Q)
    ///
    /// Reduces coefficients modulo Q to range [0, Q).
    ///
    /// Transcopy from: void poly_freeze2q(poly *a) and poly_freeze(poly *a)
    pub fn freeze2q(&mut self) {
        for i in 0..N {
            self.coeffs[i] = freeze2q(self.coeffs[i]);
        }
    }

    /// Freeze coefficients to canonical form [0, Q)
    ///
    /// Transcopy from: void poly_freeze(poly *a)
    pub fn freeze(&mut self) {
        for i in 0..N {
            self.coeffs[i] = freeze(self.coeffs[i]);
        }
    }

    /// Extract high bits of decomposition
    ///
    /// For each coefficient c, compute c_high = ⌊c / ALPHA_HINT⌋.
    ///
    /// Transcopy from: void poly_highbits(poly *a2, const poly *a)
    pub fn highbits(&mut self, a: &Poly) {
        for i in 0..N {
            self.coeffs[i] = highbits(a.coeffs[i]);
        }
    }

    /// Extract low bits of decomposition
    ///
    /// For each coefficient c, compute c_low = c - c_high * ALPHA_HINT.
    ///
    /// Transcopy from: void poly_lowbits(poly *a1, const poly *a)
    pub fn lowbits(&mut self, a: &Poly) {
        for i in 0..N {
            self.coeffs[i] = lowbits(a.coeffs[i]);
        }
    }

    /// Compose polynomial from high and low bits
    ///
    /// Computes a = ha * ALPHA + la where ALPHA=256 (for z1 decomposition).
    ///
    /// Transcopy from: void poly_compose(poly *a, const poly *ha, const poly *la)
    /// Note: C reference uses 256, not ALPHA_HINT
    pub fn compose(&mut self, ha: &Poly, la: &Poly) {
        const ALPHA: i32 = 256;
        for i in 0..N {
            self.coeffs[i] = ha.coeffs[i] * ALPHA + la.coeffs[i];
        }
    }

    /// In-place compose: self = self * ALPHA + la (eliminates clone for self-aliasing)
    pub fn compose_inplace(&mut self, la: &Poly) {
        const ALPHA: i32 = 256;
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i] * ALPHA + la.coeffs[i];
        }
    }

    /// Extract least significant bit
    ///
    /// Transcopy from: void poly_lsb(poly *a0, const poly *a)
    pub fn lsb(&mut self, a: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] & 1;
        }
    }

    /// In-place LSB: self = self & 1 (eliminates clone for self-aliasing)
    pub fn lsb_inplace(&mut self) {
        for i in 0..N {
            self.coeffs[i] &= 1;
        }
    }

    /// Sample polynomial with uniformly random coefficients in [0, Q-1]
    ///
    /// Uses SHAKE128(seed||nonce) and rejection sampling to generate
    /// uniformly distributed coefficients.
    ///
    /// # Arguments
    /// * `seed` - Seed bytes for SHAKE128
    /// * `nonce` - 16-bit nonce for domain separation
    ///
    /// Transcopy from: void poly_uniform(poly *a, const uint8_t seed[SEEDBYTES], uint16_t nonce)
    pub fn uniform(&mut self, seed: &[u8; SEEDBYTES], nonce: u16) {
        // Number of SHAKE128 blocks needed (512 bytes / 168 bytes/block = 4 blocks)
        const NBLOCKS: usize = (512 + SHAKE128_RATE - 1) / SHAKE128_RATE;

        let mut stream = Shake128Stream::new(seed, nonce);
        let mut buf = vec![0u8; NBLOCKS * SHAKE128_RATE + 1];
        let buflen = NBLOCKS * SHAKE128_RATE;

        // Squeeze initial blocks
        stream.squeeze_blocks(&mut buf[..buflen], NBLOCKS);

        // Sample coefficients via rejection sampling
        let mut ctr = rej_uniform(&mut self.coeffs, &buf[..buflen]);

        // Continue until we have N coefficients
        while ctr < N {
            // Handle odd byte offset for 16-bit sampling alignment
            let off = buflen % 2;
            if off > 0 {
                buf[0] = buf[buflen - 1];
            }

            // Squeeze one more block
            stream.squeeze_blocks(&mut buf[off..off + SHAKE128_RATE], 1);
            let new_buflen = SHAKE128_RATE + off;

            // Sample more coefficients
            let new_samples = rej_uniform(
                &mut self.coeffs[ctr..],
                &buf[..new_buflen]
            );
            ctr += new_samples;
        }
    }

    /// Sample polynomial with uniformly random coefficients in [-ETA, ETA]
    ///
    /// Uses SHAKE256(seed||nonce) and rejection sampling to generate
    /// bounded coefficients for secret keys.
    ///
    /// # Arguments
    /// * `seed` - Seed bytes for SHAKE256
    /// * `nonce` - 16-bit nonce for domain separation
    ///
    /// Transcopy from: void poly_uniform_eta(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce)
    pub fn uniform_eta(&mut self, seed: &[u8; CRHBYTES], nonce: u16) {
        // Number of SHAKE256 blocks needed (136 bytes / 136 bytes/block = 1 block)
        const NBLOCKS: usize = (136 + SHAKE256_RATE - 1) / SHAKE256_RATE;

        let mut stream = Shake256Stream::new(seed, nonce);
        let mut buf = vec![0u8; NBLOCKS * SHAKE256_RATE];
        let buflen = NBLOCKS * SHAKE256_RATE;

        // Squeeze initial blocks
        stream.squeeze_blocks(&mut buf[..buflen], NBLOCKS);

        // Sample coefficients via rejection sampling
        let mut ctr = rej_eta(&mut self.coeffs, &buf[..buflen]);

        // Continue until we have N coefficients
        while ctr < N {
            stream.squeeze_blocks(&mut buf[..SHAKE256_RATE], 1);
            let new_samples = rej_eta(&mut self.coeffs[ctr..], &buf[..SHAKE256_RATE]);
            ctr += new_samples;
        }
    }

    // ========================================================================
    // Polynomial Packing Operations
    // ========================================================================

    /// Pack decomposed polynomial (simple byte packing)
    ///
    /// Transcopy from: void poly_decomposed_pack(uint8_t *buf, const poly *a)
    pub fn decomposed_pack(&self, buf: &mut [u8; N]) {
        for i in 0..N {
            buf[i] = self.coeffs[i] as u8;
        }
    }

    /// Unpack decomposed polynomial
    ///
    /// Transcopy from: void poly_decomposed_unpack(poly *a, const uint8_t *buf)
    pub fn decomposed_unpack(&mut self, buf: &[u8; N]) {
        for i in 0..N {
            self.coeffs[i] = buf[i] as i8 as i32;
        }
    }

    /// Pack polynomial with coefficients in [0, Q-1]
    ///
    /// Packs polynomial coefficients into POLYQ_PACKEDBYTES bytes.
    ///
    /// Transcopy from: void polyq_pack(uint8_t *r, const poly *a)
    pub fn polyq_pack(&self, r: &mut [u8; POLYQ_PACKEDBYTES]) {
        #[cfg(any(feature = "haetae2", feature = "haetae3"))]
        {
            // HAETAE-2 and HAETAE-3 both have POLYQ_PACKEDBYTES=480
            // Pack 8 coefficients into 15 bytes
            for i in 0..(N >> 3) {
                let b_idx = 15 * i;
                let d_idx = 8 * i;

                r[b_idx] = (self.coeffs[d_idx] & 0xff) as u8;
                r[b_idx + 1] = (((self.coeffs[d_idx] >> 8) & 0x7f) |
                               ((self.coeffs[d_idx + 1] & 0x1) << 7)) as u8;
                r[b_idx + 2] = ((self.coeffs[d_idx + 1] >> 1) & 0xff) as u8;
                r[b_idx + 3] = (((self.coeffs[d_idx + 1] >> 9) & 0x3f) |
                               ((self.coeffs[d_idx + 2] & 0x3) << 6)) as u8;
                r[b_idx + 4] = ((self.coeffs[d_idx + 2] >> 2) & 0xff) as u8;
                r[b_idx + 5] = (((self.coeffs[d_idx + 2] >> 10) & 0x1f) |
                               ((self.coeffs[d_idx + 3] & 0x7) << 5)) as u8;
                r[b_idx + 6] = ((self.coeffs[d_idx + 3] >> 3) & 0xff) as u8;
                r[b_idx + 7] = (((self.coeffs[d_idx + 3] >> 11) & 0xf) |
                               ((self.coeffs[d_idx + 4] & 0xf) << 4)) as u8;
                r[b_idx + 8] = ((self.coeffs[d_idx + 4] >> 4) & 0xff) as u8;
                r[b_idx + 9] = (((self.coeffs[d_idx + 4] >> 12) & 0x7) |
                               ((self.coeffs[d_idx + 5] & 0x1f) << 3)) as u8;
                r[b_idx + 10] = ((self.coeffs[d_idx + 5] >> 5) & 0xff) as u8;
                r[b_idx + 11] = (((self.coeffs[d_idx + 5] >> 13) & 0x3) |
                                ((self.coeffs[d_idx + 6] & 0x3f) << 2)) as u8;
                r[b_idx + 12] = ((self.coeffs[d_idx + 6] >> 6) & 0xff) as u8;
                r[b_idx + 13] = (((self.coeffs[d_idx + 6] >> 14) & 0x1) |
                                ((self.coeffs[d_idx + 7] & 0x7f) << 1)) as u8;
                r[b_idx + 14] = ((self.coeffs[d_idx + 7] >> 7) & 0xff) as u8;
            }
        }

        #[cfg(feature = "haetae5")]
        {
            // HAETAE-5 has POLYQ_PACKEDBYTES=512
            // Simple 16-bit packing: 2 bytes per coefficient
            for i in 0..N {
                r[2 * i + 0] = (self.coeffs[i] >> 0) as u8;
                r[2 * i + 1] = (self.coeffs[i] >> 8) as u8;
            }
        }
    }

    /// Unpack polynomial with coefficients in [0, Q-1]
    ///
    /// Transcopy from: void polyq_unpack(poly *r, const uint8_t *a)
    pub fn polyq_unpack(&mut self, a: &[u8; POLYQ_PACKEDBYTES]) {
        #[cfg(any(feature = "haetae2", feature = "haetae3"))]
        {
            // HAETAE-2 and HAETAE-3 both have POLYQ_PACKEDBYTES=480
            // Unpack 8 coefficients from 15 bytes
            for i in 0..(N >> 3) {
                let b_idx = 15 * i;
                let d_idx = 8 * i;

                self.coeffs[d_idx] = (a[b_idx] as i32 & 0xff) | ((a[b_idx + 1] as i32 & 0x7f) << 8);
                self.coeffs[d_idx + 1] = ((a[b_idx + 1] as i32 >> 7) & 0x1) |
                                         ((a[b_idx + 2] as i32 & 0xff) << 1) |
                                         ((a[b_idx + 3] as i32 & 0x3f) << 9);
                self.coeffs[d_idx + 2] = ((a[b_idx + 3] as i32 >> 6) & 0x3) |
                                         ((a[b_idx + 4] as i32 & 0xff) << 2) |
                                         ((a[b_idx + 5] as i32 & 0x1f) << 10);
                self.coeffs[d_idx + 3] = ((a[b_idx + 5] as i32 >> 5) & 0x7) |
                                         ((a[b_idx + 6] as i32 & 0xff) << 3) |
                                         ((a[b_idx + 7] as i32 & 0xf) << 11);
                self.coeffs[d_idx + 4] = ((a[b_idx + 7] as i32 >> 4) & 0xf) |
                                         ((a[b_idx + 8] as i32 & 0xff) << 4) |
                                         ((a[b_idx + 9] as i32 & 0x7) << 12);
                self.coeffs[d_idx + 5] = ((a[b_idx + 9] as i32 >> 3) & 0x1f) |
                                         ((a[b_idx + 10] as i32 & 0xff) << 5) |
                                         ((a[b_idx + 11] as i32 & 0x3) << 13);
                self.coeffs[d_idx + 6] = ((a[b_idx + 11] as i32 >> 2) & 0x3f) |
                                         ((a[b_idx + 12] as i32 & 0xff) << 6) |
                                         ((a[b_idx + 13] as i32 & 0x1) << 14);
                self.coeffs[d_idx + 7] = ((a[b_idx + 13] as i32 >> 1) & 0x7f) |
                                         ((a[b_idx + 14] as i32 & 0xff) << 7);
            }
        }

        #[cfg(feature = "haetae5")]
        {
            // HAETAE-5 has POLYQ_PACKEDBYTES=512
            // Simple 16-bit unpacking: 2 bytes per coefficient
            for i in 0..N {
                self.coeffs[i] = (a[2 * i + 0] as i32 >> 0) |
                                 ((a[2 * i + 1] as u16) << 8) as i32;
                self.coeffs[i] &= 0xffff;
            }
        }
    }

    /// Pack polynomial with coefficients in [-ETA, ETA]
    ///
    /// Transcopy from: void polyeta_pack(uint8_t *r, const poly *a)
    pub fn polyeta_pack(&self, r: &mut [u8; POLYETA_PACKEDBYTES]) {
        // All security levels: ETA=1, POLYETA_PACKEDBYTES=64
        // 2 bits per coefficient, 4 coefficients per byte
        for i in 0..(N / 4) {
            let t0 = (ETA as i32 - self.coeffs[4 * i + 0]) as u8;
            let t1 = (ETA as i32 - self.coeffs[4 * i + 1]) as u8;
            let t2 = (ETA as i32 - self.coeffs[4 * i + 2]) as u8;
            let t3 = (ETA as i32 - self.coeffs[4 * i + 3]) as u8;
            r[i] = (t0 >> 0) | (t1 << 2) | (t2 << 4) | (t3 << 6);
        }
    }

    /// Unpack polynomial with coefficients in [-ETA, ETA]
    ///
    /// Transcopy from: void polyeta_unpack(poly *r, const uint8_t *a)
    pub fn polyeta_unpack(&mut self, a: &[u8; POLYETA_PACKEDBYTES]) {
        // All security levels: ETA=1, POLYETA_PACKEDBYTES=64
        // 2 bits per coefficient, 4 coefficients per byte
        for i in 0..(N / 4) {
            self.coeffs[4 * i + 0] = ((a[i] >> 0) & 0x3) as i32;
            self.coeffs[4 * i + 1] = ((a[i] >> 2) & 0x3) as i32;
            self.coeffs[4 * i + 2] = ((a[i] >> 4) & 0x3) as i32;
            self.coeffs[4 * i + 3] = ((a[i] >> 6) & 0x3) as i32;

            self.coeffs[4 * i + 0] = ETA as i32 - self.coeffs[4 * i + 0];
            self.coeffs[4 * i + 1] = ETA as i32 - self.coeffs[4 * i + 1];
            self.coeffs[4 * i + 2] = ETA as i32 - self.coeffs[4 * i + 2];
            self.coeffs[4 * i + 3] = ETA as i32 - self.coeffs[4 * i + 3];
        }
    }

    /// Pack polynomial with coefficients in [-2*ETA, 2*ETA]
    /// Only used for HAETAE-2 and HAETAE-3 (D=1)
    ///
    /// Transcopy from: void poly2eta_pack(uint8_t *r, const poly *a)
    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    pub fn poly2eta_pack(&self, r: &mut [u8; POLY2ETA_PACKEDBYTES]) {
        // HAETAE-2 and HAETAE-3 both have ETA=1, D=1
        // Pack 8 coefficients into 3 bytes (3 bits per coefficient)
        for i in 0..(N / 8) {
            let t0 = (2 * ETA as i32 - self.coeffs[8 * i + 0]) as u8;
            let t1 = (2 * ETA as i32 - self.coeffs[8 * i + 1]) as u8;
            let t2 = (2 * ETA as i32 - self.coeffs[8 * i + 2]) as u8;
            let t3 = (2 * ETA as i32 - self.coeffs[8 * i + 3]) as u8;
            let t4 = (2 * ETA as i32 - self.coeffs[8 * i + 4]) as u8;
            let t5 = (2 * ETA as i32 - self.coeffs[8 * i + 5]) as u8;
            let t6 = (2 * ETA as i32 - self.coeffs[8 * i + 6]) as u8;
            let t7 = (2 * ETA as i32 - self.coeffs[8 * i + 7]) as u8;

            r[3 * i + 0] = (t0 >> 0) | (t1 << 3) | (t2 << 6);
            r[3 * i + 1] = (t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7);
            r[3 * i + 2] = (t5 >> 1) | (t6 << 2) | (t7 << 5);
        }
    }

    /// Unpack polynomial with coefficients in [-2*ETA, 2*ETA]
    /// Only used for HAETAE-2 and HAETAE-3 (D=1)
    ///
    /// Transcopy from: void poly2eta_unpack(poly *r, const uint8_t *a)
    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    pub fn poly2eta_unpack(&mut self, a: &[u8; POLY2ETA_PACKEDBYTES]) {
        // HAETAE-2 and HAETAE-3 both have ETA=1, D=1
        // Unpack 8 coefficients from 3 bytes (3 bits per coefficient)
        for i in 0..(N / 8) {
            self.coeffs[8 * i + 0] = ((a[3 * i + 0] >> 0) & 7) as i32;
            self.coeffs[8 * i + 1] = ((a[3 * i + 0] >> 3) & 7) as i32;
            self.coeffs[8 * i + 2] = (((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7) as i32;
            self.coeffs[8 * i + 3] = ((a[3 * i + 1] >> 1) & 7) as i32;
            self.coeffs[8 * i + 4] = ((a[3 * i + 1] >> 4) & 7) as i32;
            self.coeffs[8 * i + 5] = (((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7) as i32;
            self.coeffs[8 * i + 6] = ((a[3 * i + 2] >> 2) & 7) as i32;
            self.coeffs[8 * i + 7] = ((a[3 * i + 2] >> 5) & 7) as i32;

            for j in 0..8 {
                self.coeffs[8 * i + j] = 2 * ETA as i32 - self.coeffs[8 * i + j];
            }
        }
    }

    /// Pack LSB of each coefficient into bit-packed bytes
    ///
    /// Packs the least significant bit of all N coefficients into N/8 bytes.
    /// Bit i%8 of byte i/8 gets the LSB of coefficient i.
    ///
    /// Transcopy from: void pack_poly_lsb(uint8_t *buf, const poly *a)
    pub fn pack_lsb(&self, buf: &mut [u8; POLYC_PACKEDBYTES]) {
        for i in 0..N {
            if i % 8 == 0 {
                buf[i / 8] = 0;
            }
            buf[i / 8] |= ((self.coeffs[i] & 1) as u8) << (i % 8);
        }
    }

    /// CRT reconstruction with parity check
    ///
    /// For polynomials u (mod q) and v (mod 2), compute w (mod 2q)
    /// such that w ≡ u (mod q) and w ≡ v (mod 2).
    ///
    /// Transcopy from: void poly_fromcrt(poly *w, const poly *u, const poly *v)
    pub fn fromcrt(&mut self, u: &Poly, v: &Poly) {
        for i in 0..N {
            let xq = u.coeffs[i];
            let x2 = v.coeffs[i];
            self.coeffs[i] = xq + (Q & -((xq ^ x2) & 1));
        }
    }

    /// CRT reconstruction with parity 0
    ///
    /// For polynomial u (mod q), compute w (mod 2q) such that
    /// w ≡ u (mod q) and w ≡ 0 (mod 2).
    ///
    /// Transcopy from: void poly_fromcrt0(poly *w, const poly *u)
    pub fn fromcrt0(&mut self, u: &Poly) {
        for i in 0..N {
            let xq = u.coeffs[i];
            self.coeffs[i] = xq + (Q & -(xq & 1));
        }
    }

    /// Pack high bits for challenge hash computation
    ///
    /// HAETAE-2/3: 8-bit packing (1 byte per coefficient, coeffs fit in [0,252))
    /// HAETAE-5:   9-bit packing (9 bytes per 8 coefficients, coeffs in [0,504))
    ///
    /// Transcopy from: void pack_poly_highbits(uint8_t *buf, const poly *a)
    pub fn pack_highbits(&self, buf: &mut [u8; POLY_HIGHBITS_PACKEDBYTES]) {
        #[cfg(any(feature = "haetae2", feature = "haetae3"))]
        {
            // 8-bit packing: each coefficient fits in one byte
            // Remaining bytes (288-256=32) stay zero (caller zero-inits buffer)
            for i in 0..N {
                buf[i] = self.coeffs[i] as u8;
            }
        }

        #[cfg(feature = "haetae5")]
        {
            // 9-bit packing: 8 coefficients → 9 bytes
            for i in 0..(N / 8) {
                buf[9 * i + 0] = (self.coeffs[8 * i + 0] & 0xff) as u8;

                buf[9 * i + 1] = ((self.coeffs[8 * i + 0] >> 8) & 0x01) as u8;
                buf[9 * i + 1] |= ((self.coeffs[8 * i + 1] << 1) & 0xff) as u8;

                buf[9 * i + 2] = ((self.coeffs[8 * i + 1] >> 7) & 0x03) as u8;
                buf[9 * i + 2] |= ((self.coeffs[8 * i + 2] << 2) & 0xff) as u8;

                buf[9 * i + 3] = ((self.coeffs[8 * i + 2] >> 6) & 0x07) as u8;
                buf[9 * i + 3] |= ((self.coeffs[8 * i + 3] << 3) & 0xff) as u8;

                buf[9 * i + 4] = ((self.coeffs[8 * i + 3] >> 5) & 0x0f) as u8;
                buf[9 * i + 4] |= ((self.coeffs[8 * i + 4] << 4) & 0xff) as u8;

                buf[9 * i + 5] = ((self.coeffs[8 * i + 4] >> 4) & 0x1f) as u8;
                buf[9 * i + 5] |= ((self.coeffs[8 * i + 5] << 5) & 0xff) as u8;

                buf[9 * i + 6] = ((self.coeffs[8 * i + 5] >> 3) & 0x3f) as u8;
                buf[9 * i + 6] |= ((self.coeffs[8 * i + 6] << 6) & 0xff) as u8;

                buf[9 * i + 7] = ((self.coeffs[8 * i + 6] >> 2) & 0x7f) as u8;
                buf[9 * i + 7] |= ((self.coeffs[8 * i + 7] << 7) & 0xff) as u8;

                buf[9 * i + 8] = ((self.coeffs[8 * i + 7] >> 1) & 0xff) as u8;
            }
        }
    }
}

/// Hamming weight of 8-bit value
///
/// Transcopy from: uint8_t hammingWeight_8(uint8_t x).
/// Kept as a reference helper even though the live path uses
/// `u8::count_ones()` (which compiles to POPCNT when available).
#[inline]
#[allow(dead_code)]
fn hamming_weight_8(x: u8) -> u8 {
    let mut x = x;
    x = (x & 0x55) + (x >> 1 & 0x55);
    x = (x & 0x33) + (x >> 2 & 0x33);
    x = (x & 0x0F) + (x >> 4 & 0x0F);
    x
}

/// Generate challenge polynomial from hash
///
/// Creates sparse polynomial with TAU ones for HAETAE-2/3, or
/// fixed Hamming weight for HAETAE-5.
///
/// # Arguments
/// * `c` - Output challenge polynomial
/// * `highbits_lsb` - Commitment bytes (highbits || LSB)
/// * `mu` - Message hash (uses first SEEDBYTES bytes if longer)
///
/// Transcopy from: void poly_challenge(poly *c, const uint8_t highbits_lsb[], const uint8_t mu[])
pub fn poly_challenge(
    c: &mut Poly,
    highbits_lsb: &[u8],
    mu: &[u8]
) {

    // Use first SEEDBYTES bytes of mu (C code passes CRHBYTES array but uses SEEDBYTES)
    let mu_seed = &mu[..SEEDBYTES.min(mu.len())];

    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    {
        let mut pos = 0;
        let mut buf = [0u8; SHAKE256_RATE];

        // H(HighBits(A * y mod 2q), LSB(round(y0) * j), M)
        let mut reader = crate::shake::shake256_multi(&[highbits_lsb, mu_seed]);
        reader.read_into(&mut buf);

        for i in 0..N {
            c.coeffs[i] = 0;
        }

        for i in (N - TAU)..N {
            let mut b: usize;
            loop {
                if pos >= SHAKE256_RATE {
                    reader.read_into(&mut buf);
                    pos = 0;
                }

                b = buf[pos] as usize;
                pos += 1;

                if b <= i {
                    break;
                }
            }

            c.coeffs[i] = c.coeffs[b];
            c.coeffs[b] = 1;
        }
    }

    #[cfg(feature = "haetae5")]
    {
        let mut buf = [0u8; 32];

        // H(HighBits(A * y mod 2q), LSB(round(y0) * j), M)
        let mut reader = crate::shake::shake256_multi(&[highbits_lsb, mu_seed]);
        reader.read_into(&mut buf);

        let mut hwt = 0u32;
        for i in 0..32 {
            hwt += hamming_weight_8(buf[i]) as u32;
        }

        let cond = 128u32.wrapping_sub(hwt); // Use wrapping subtraction like C's unsigned arithmetic
        let mask = 0xff & (cond >> 8) as u8;
        let w0 = (-((buf[0] & 1) as i8)) as u8;
        let mask = w0 ^ ((-((cond != 0) as i8 & 1)) as u8 & (mask ^ w0));

        for i in 0..32 {
            buf[i] ^= mask;
            c.coeffs[8 * i] = (buf[i] & 1) as i32;
            c.coeffs[8 * i + 1] = ((buf[i] >> 1) & 1) as i32;
            c.coeffs[8 * i + 2] = ((buf[i] >> 2) & 1) as i32;
            c.coeffs[8 * i + 3] = ((buf[i] >> 3) & 1) as i32;
            c.coeffs[8 * i + 4] = ((buf[i] >> 4) & 1) as i32;
            c.coeffs[8 * i + 5] = ((buf[i] >> 5) & 1) as i32;
            c.coeffs[8 * i + 6] = ((buf[i] >> 6) & 1) as i32;
            c.coeffs[8 * i + 7] = ((buf[i] >> 7) & 1) as i32;
        }
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Poly {
    fn eq(&self, other: &Self) -> bool {
        self.coeffs[..] == other.coeffs[..]
    }
}

impl Eq for Poly {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_new() {
        let p = Poly::new();
        for i in 0..N {
            assert_eq!(p.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_add() {
        let mut a = Poly::new();
        let mut b = Poly::new();
        let mut c = Poly::new();

        a.coeffs[0] = 10;
        a.coeffs[1] = 20;
        b.coeffs[0] = 5;
        b.coeffs[1] = 15;

        c.add(&a, &b);

        assert_eq!(c.coeffs[0], 15);
        assert_eq!(c.coeffs[1], 35);
    }

    #[test]
    fn test_poly_sub() {
        let mut a = Poly::new();
        let mut b = Poly::new();
        let mut c = Poly::new();

        a.coeffs[0] = 10;
        a.coeffs[1] = 20;
        b.coeffs[0] = 5;
        b.coeffs[1] = 15;

        c.sub(&a, &b);

        assert_eq!(c.coeffs[0], 5);
        assert_eq!(c.coeffs[1], 5);
    }

    #[test]
    fn test_poly_equality() {
        let a = Poly::from_coeffs([1; N]);
        let b = Poly::from_coeffs([1; N]);
        let mut c = Poly::new();
        c.coeffs[0] = 2;

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_poly_lsb() {
        let mut a = Poly::new();
        let mut result = Poly::new();

        a.coeffs[0] = 15; // Binary: 1111, LSB = 1
        a.coeffs[1] = 22; // Binary: 10110, LSB = 0
        a.coeffs[2] = 7;  // Binary: 111, LSB = 1

        result.lsb(&a);

        assert_eq!(result.coeffs[0], 1);
        assert_eq!(result.coeffs[1], 0);
        assert_eq!(result.coeffs[2], 1);
    }

    #[test]
    fn test_decomposed_pack_unpack() {
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = (i as i8) as i32; // -128..127 range
        }

        let mut packed = [0u8; N];
        p.decomposed_pack(&mut packed);

        let mut unpacked = Poly::new();
        unpacked.decomposed_unpack(&packed);

        for i in 0..N {
            assert_eq!(unpacked.coeffs[i], p.coeffs[i]);
        }
    }

    #[test]
    fn test_polyq_pack_unpack_simple() {
        // Test with simple values first
        // Note: For HAETAE-2 (D=1), values must fit in 15 bits (< 32768)
        // For HAETAE-3/5 (D=0), values can use full 16 bits
        let mut p = Poly::new();
        p.coeffs[0] = 12345;
        p.coeffs[1] = 23456;  // Changed to fit in 15 bits
        p.coeffs[2] = 1000;

        let mut packed = [0u8; POLYQ_PACKEDBYTES];
        p.polyq_pack(&mut packed);

        let mut unpacked = Poly::new();
        unpacked.polyq_unpack(&packed);

        assert_eq!(unpacked.coeffs[0], 12345, "First coefficient mismatch");
        assert_eq!(unpacked.coeffs[1], 23456, "Second coefficient mismatch");
        assert_eq!(unpacked.coeffs[2], 1000, "Third coefficient mismatch");
    }

    #[test]
    fn test_polyq_pack_unpack() {
        let mut p = Poly::new();
        for i in 0..N {
            // HAETAE-2 and HAETAE-3 have POLYQ_PACKEDBYTES=480, values fit in 15 bits
            // HAETAE-5 has POLYQ_PACKEDBYTES=512, values can use full 16 bits
            #[cfg(any(feature = "haetae2", feature = "haetae3"))]
            {
                p.coeffs[i] = ((i * 127) % 32768) as i32;
            }
            #[cfg(feature = "haetae5")]
            {
                p.coeffs[i] = ((i * 251) % (Q as usize)) as i32;
            }
        }

        let mut packed = [0u8; POLYQ_PACKEDBYTES];
        p.polyq_pack(&mut packed);

        let mut unpacked = Poly::new();
        unpacked.polyq_unpack(&packed);

        for i in 0..N {
            if unpacked.coeffs[i] != p.coeffs[i] {
                eprintln!("Mismatch at index {}: packed={}, unpacked={}", i, p.coeffs[i], unpacked.coeffs[i]);
            }
            assert_eq!(unpacked.coeffs[i], p.coeffs[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_polyeta_pack_unpack() {
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = ((i % (2 * ETA + 1)) as i32) - (ETA as i32); // Values in [-ETA, ETA]
        }

        let mut packed = [0u8; POLYETA_PACKEDBYTES];
        p.polyeta_pack(&mut packed);

        let mut unpacked = Poly::new();
        unpacked.polyeta_unpack(&packed);

        for i in 0..N {
            assert_eq!(unpacked.coeffs[i], p.coeffs[i]);
        }
    }

    #[cfg(feature = "haetae2")]
    #[test]
    fn test_poly2eta_pack_unpack() {
        let mut p = Poly::new();
        for i in 0..N {
            p.coeffs[i] = ((i % (4 * ETA + 1)) as i32) - (2 * ETA as i32); // Values in [-2*ETA, 2*ETA]
        }

        let mut packed = [0u8; POLY2ETA_PACKEDBYTES];
        p.poly2eta_pack(&mut packed);

        let mut unpacked = Poly::new();
        unpacked.poly2eta_unpack(&packed);

        for i in 0..N {
            assert_eq!(unpacked.coeffs[i], p.coeffs[i]);
        }
    }
}

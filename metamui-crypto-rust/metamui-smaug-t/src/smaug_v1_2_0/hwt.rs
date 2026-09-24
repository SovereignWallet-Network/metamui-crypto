// SPDX-License-Identifier: MIT
//
// Fixed-weight ternary polynomial sampler — port of `src/hwt.c` v1.2.0.
//
// Reference:
//   Décio Luiz Gazzoni Filho, Tomás S. R. Silva, Julio López,
//   "Efficient isochronous fixed-weight sampling with applications to
//   NTRU," IACR ePrint 2024/548 (eprint.iacr.org/2024/548).
//
// The sampler returns -1 if all SHAKE-256 randomness is exhausted (which
// happens with negligible probability — upstream notes "only executed
// once with overwhelming probability"). `expand_s` retries with a new
// counter byte if `hwt` rejects.

use super::hash::Shake256State;
use super::params::{Params, CRYPTO_BYTES, HWTSEEDBYTES, N};

#[inline(always)]
fn load16_le(out: &mut [u16], inb: &[u8]) {
    for i in 0..out.len() {
        out[i] = (inb[2 * i] as u16) | ((inb[2 * i + 1] as u16) << 8);
    }
}

/// `rej_sample_mod` — for each `i` in `[0, N)`, sample `s[i]` uniformly
/// in `[0, N - i)` using rejection on the upper 16 bits of `rand[k] * (N-i)`.
/// Returns `Err` if `rand` is exhausted, else fills `si`.
fn rej_sample_mod(si: &mut [i16], rand: &[u16]) -> Result<(), ()> {
    let mut j = N;
    for i in 0..N {
        let s = (N - i) as u32;            // upper bound on s[i], in [1, N]
        let t = 65536u32 % s;              // rejection threshold

        let mut m: u32 = (rand[i] as u32) * s;
        let mut l = m as u16;

        while (l as u32) < t {
            if j >= HWTSEEDBYTES / 2 {
                return Err(());
            }
            m = (rand[j] as u32) * s;
            j += 1;
            l = m as u16;
        }

        si[i] = (m >> 16) as i16;
    }
    Ok(())
}

/// `hwt` — sample a sparse ternary polynomial with Hamming weight
/// `SMAUGT_HS` and N=256 coefficients. Seed length is
/// `CRYPTO_BYTES + 2 = 34` bytes.
///
/// Returns `false` on rejection (caller increments counter and retries).
pub fn hwt(p: &Params, res: &mut [i16; N], seed: &[u8]) -> bool {
    debug_assert_eq!(seed.len(), CRYPTO_BYTES + 2);

    let mut state = Shake256State::new();
    state.absorb(seed);

    // First squeeze: HWTSEEDBYTES (616) bytes → 308 u16 words for indices.
    let mut buf = vec![0u8; HWTSEEDBYTES];
    let mut reader = state.squeeze_into(&mut buf);

    let mut rand_words = vec![0u16; HWTSEEDBYTES / 2];
    load16_le(&mut rand_words, &buf);

    let mut si = [0i16; N];
    if rej_sample_mod(&mut si, &rand_words).is_err() {
        return false;
    }

    // Second squeeze: N/4 bytes → 64 bytes of sign decision bits.
    let mut sign = vec![0u8; N / 4];
    reader.squeeze(&mut sign);

    // Convert (si, sign) into the ternary polynomial.
    // The first pass: res[i] = 1 + t0 where t0 = ((si[i] - c0) >> 15).
    // c0 starts at (N - HS), tracking the residual indices.
    let c0_init: i16 = (N - p.hs) as i16;
    let mut c0 = c0_init;
    for i in 0..N {
        let t0 = (si[i].wrapping_sub(c0)) >> 15;   // arithmetic shift: 0 or -1
        c0 = c0.wrapping_add(t0);
        res[i] = 1i16.wrapping_add(t0);             // 1 or 0

        // Sign extraction: complicated bit-shuffle.
        //   sign index: ((i >> 4) >> 3) * 16 + (i & 0x0F)
        //   shift:      (i >> 4) & 0x07
        let sign_byte_idx = ((i >> 4) >> 3) * 16 + (i & 0x0F);
        let sign_shift = (i >> 4) & 0x07;
        let sign_bit = ((sign[sign_byte_idx] as i16) >> sign_shift) & 0x01;

        // res[i] = (-res[i]) & ((sign_bit << 1) & 0x02) - 1
        // Decode: if res[i] was 0 → output 0
        //         if res[i] was 1 → output 1 or -1 depending on sign_bit
        let mask = (((sign_bit << 1) & 0x02).wrapping_sub(1)) as i16;
        res[i] = ((0i16).wrapping_sub(res[i])) & mask;
    }
    true
}

// SPDX-License-Identifier: MIT
//
// SMAUG-T v1.2.0 — clean-room Rust port of the CryptoLab reference
// implementation v1.2.0 (specification v260521, 2026-05-21, MIT-licensed),
// vendored at `metamui-crypto-reference/c/cryptoLabInc-SMAUG-T-v1.2.0/`.
// Byte-exact to the authors' own `kat/PQCkemKAT_smaugt_mode*.rsp`
// (`test-vectors/smaug-t/v1.2.0-kat/`). v1.2.0 differs from v1.1.1 only by
// the `dg.c` tape-unpacking fix and two memset sizes, but that fix changes
// every key and ciphertext byte.
//
// File layout — one Rust submodule per upstream C source file:
//
//   params      ← params.h, config.h          (compile-time params + Mode enum)
//   poly_types  ← poly.h                      (Poly / PolyVec / Matrix types)
//   hash        ← hash.c, fips202.h           (SHAKE / SHA-3 wrappers)
//   cbd         ← cbd.c                       (sp_cbd dispatch + variants)
//   dg          ← dg.c                        (constant-time discrete Gaussian)
//   hwt         ← hwt.c                       (fixed-weight ternary sampler)
//   poly_ops    ← poly.c                      (vec_vec_mult, matrix_vec_mult_*)
//   pack        ← pack.c                      (pack_enck/deck/ct + s-poly codec)
//   key         ← key.c                       (expand_A / expand_b / expand_s)
//   ciphertext  ← ciphertext.c                (computeC1 / computeC2 + rounding)
//   indcpa      ← indcpa.c                    (expand_r + indcpa_keypair/enc/dec)
//   kem         ← kem.c                       (KEM API + _internal variants)
//
// The Toom-Cook 4-way multiplier is unchanged between v1.0 and v1.2.0
// (verified by `diff`); this module re-exports the existing
// `smaug_canonical::poly_mul_acc` instead of re-porting toomcook.c.

pub mod params;
pub mod poly_types;
pub mod hash;
pub mod cbd;
pub mod dg;
pub mod hwt;
pub mod poly_ops;
pub mod pack_ring;
pub mod pack;
pub mod key;
pub mod ciphertext;
pub mod indcpa;
pub mod kem;
pub mod api;

pub use params::{Mode, Params, MODE1, MODE3, MODE5, MODET};
pub use api::{SmaugTV1, SmaugV1Error};
pub use kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
#[cfg(feature = "kat-internal")]
pub use kem::{crypto_kem_dec_internal, crypto_kem_enc_internal, crypto_kem_keypair_internal};

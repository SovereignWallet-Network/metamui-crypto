//! rANS entropy coding for HAETAE signature compression
//!
//! This module implements range Asymmetric Numeral Systems (rANS) encoding for
//! compressing HAETAE signatures. It provides parameter-specific probability
//! tables optimized for the distribution of hint vectors and highbits(z1).
//!
//! Key compression targets:
//! - Hint vector h: Sparse polynomial indicating high-bit corrections
//! - HighBits(z1): High bits of z1 decomposition
//!
//! Compression achieves ~30-40% size reduction over raw encoding, enabling
//! practical deployment of HAETAE signatures in blockchain systems.
//!
//! Transcopy from: encoding.c

use crate::params::{K, L, N};
use crate::rans_byte::{
    rans_dec_advance_symbol, rans_dec_get, rans_dec_init, rans_dec_verify, rans_enc_flush,
    rans_enc_init, rans_enc_put_symbol, RansDecSymbol, RansEncSymbol, RansState,
};

/// Scale bits for rANS probability distribution
const SCALE_BITS: u32 = 10;

/// Scale factor: 2^SCALE_BITS. Kept as a named constant for audit
/// clarity alongside `SCALE_BITS`; the live rANS path uses inline
/// `1u32 << SCALE_BITS` where needed.
#[allow(dead_code)]
const SCALE: u32 = 1u32 << SCALE_BITS;

// ============================================================================
// HAETAE-2 Parameter-Specific Tables
// ============================================================================

#[cfg(feature = "haetae2")]
mod tables {
    use super::*;

    pub const M_H: usize = 13;
    pub const OFFSET_H: i32 = 239;
    pub const M_HB_Z1: usize = 13;
    pub const OFFSET_HB_Z1: i32 = 6;

    pub static ESYMS_H: [RansEncSymbol; M_H] = [
        RansEncSymbol { x_max: 801112064, rcp_freq: 4294967295 - 1416664605 + 1, bias: 0, cmpl_freq: 642, rcp_shift: 8 },
        RansEncSymbol { x_max: 515899392, rcp_freq: 4294967295 - 2060187564 + 1, bias: 382, cmpl_freq: 778, rcp_shift: 7 },
        RansEncSymbol { x_max: 136314880, rcp_freq: 4294967295 - 66076419 + 1, bias: 628, cmpl_freq: 959, rcp_shift: 6 },
        RansEncSymbol { x_max: 14680064, rcp_freq: 4294967295 - 1840700269 + 1, bias: 693, cmpl_freq: 1017, rcp_shift: 2 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1723, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1724, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1725, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1726, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1727, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1728, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 14680064, rcp_freq: 4294967295 - 1840700269 + 1, bias: 706, cmpl_freq: 1017, rcp_shift: 2 },
        RansEncSymbol { x_max: 136314880, rcp_freq: 4294967295 - 66076419 + 1, bias: 713, cmpl_freq: 959, rcp_shift: 6 },
        RansEncSymbol { x_max: 515899392, rcp_freq: 4294967295 - 2060187564 + 1, bias: 778, cmpl_freq: 778, rcp_shift: 7 },
    ];

    pub static DSYMS_H: [RansDecSymbol; M_H] = [
        RansDecSymbol { start: 0, freq: 382 },
        RansDecSymbol { start: 382, freq: 246 },
        RansDecSymbol { start: 628, freq: 65 },
        RansDecSymbol { start: 693, freq: 7 },
        RansDecSymbol { start: 700, freq: 1 },
        RansDecSymbol { start: 701, freq: 1 },
        RansDecSymbol { start: 702, freq: 1 },
        RansDecSymbol { start: 703, freq: 1 },
        RansDecSymbol { start: 704, freq: 1 },
        RansDecSymbol { start: 705, freq: 1 },
        RansDecSymbol { start: 706, freq: 7 },
        RansDecSymbol { start: 713, freq: 65 },
        RansDecSymbol { start: 778, freq: 246 },
    ];

    pub static SYMBOL_H: [u16; 1024] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12];

    pub static ESYMS_HB_Z1: [RansEncSymbol; M_HB_Z1] = [
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1023, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1024, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1025, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 10485760, rcp_freq: 4294967295 - 858993459 + 1, bias: 3, cmpl_freq: 1019, rcp_shift: 2 },
        RansEncSymbol { x_max: 121634816, rcp_freq: 4294967295 - 1925330167 + 1, bias: 8, cmpl_freq: 966, rcp_shift: 5 },
        RansEncSymbol { x_max: 515899392, rcp_freq: 4294967295 - 2060187564 + 1, bias: 66, cmpl_freq: 778, rcp_shift: 7 },
        RansEncSymbol { x_max: 834666496, rcp_freq: 4294967295 - 1532375266 + 1, bias: 312, cmpl_freq: 626, rcp_shift: 8 },
        RansEncSymbol { x_max: 517996544, rcp_freq: 4294967295 - 2069235255 + 1, bias: 710, cmpl_freq: 777, rcp_shift: 7 },
        RansEncSymbol { x_max: 123731968, rcp_freq: 4294967295 - 1965493508 + 1, bias: 957, cmpl_freq: 965, rcp_shift: 5 },
        RansEncSymbol { x_max: 10485760, rcp_freq: 4294967295 - 858993459 + 1, bias: 1016, cmpl_freq: 1019, rcp_shift: 2 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2044, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2045, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2046, cmpl_freq: 1023, rcp_shift: 0 },
    ];

    pub static DSYMS_HB_Z1: [RansDecSymbol; M_HB_Z1] = [
        RansDecSymbol { start: 0, freq: 1 },
        RansDecSymbol { start: 1, freq: 1 },
        RansDecSymbol { start: 2, freq: 1 },
        RansDecSymbol { start: 3, freq: 5 },
        RansDecSymbol { start: 8, freq: 58 },
        RansDecSymbol { start: 66, freq: 246 },
        RansDecSymbol { start: 312, freq: 398 },
        RansDecSymbol { start: 710, freq: 247 },
        RansDecSymbol { start: 957, freq: 59 },
        RansDecSymbol { start: 1016, freq: 5 },
        RansDecSymbol { start: 1021, freq: 1 },
        RansDecSymbol { start: 1022, freq: 1 },
        RansDecSymbol { start: 1023, freq: 1 },
    ];

    pub static SYMBOL_HB_Z1: [u16; 1024] = [0, 1, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 10, 11, 12];
}

// ============================================================================
// HAETAE-3 Parameter-Specific Tables
// ============================================================================

#[cfg(feature = "haetae3")]
mod tables {
    use super::*;

    pub const M_H: usize = 17;
    pub const OFFSET_H: i32 = 235;
    pub const M_HB_Z1: usize = 17;
    pub const OFFSET_HB_Z1: i32 = 8;

    pub static ESYMS_H: [RansEncSymbol; M_H] = [
        RansEncSymbol { x_max: 557842432, rcp_freq: 4294967295 - 161464935 + 1, bias: 0, cmpl_freq: 758, rcp_shift: 8 },
        RansEncSymbol { x_max: 446693376, rcp_freq: 4294967295 - 1713954085 + 1, bias: 266, cmpl_freq: 811, rcp_shift: 7 },
        RansEncSymbol { x_max: 236978176, rcp_freq: 4294967295 - 1862419446 + 1, bias: 479, cmpl_freq: 911, rcp_shift: 6 },
        RansEncSymbol { x_max: 83886080, rcp_freq: 4294967295 - 858993459 + 1, bias: 592, cmpl_freq: 984, rcp_shift: 5 },
        RansEncSymbol { x_max: 18874368, rcp_freq: 4294967295 - 477218588 + 1, bias: 632, cmpl_freq: 1015, rcp_shift: 3 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1664, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1665, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1666, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1667, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1668, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1669, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1670, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1671, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 18874368, rcp_freq: 4294967295 - 477218588 + 1, bias: 649, cmpl_freq: 1015, rcp_shift: 3 },
        RansEncSymbol { x_max: 83886080, rcp_freq: 4294967295 - 858993459 + 1, bias: 658, cmpl_freq: 984, rcp_shift: 5 },
        RansEncSymbol { x_max: 236978176, rcp_freq: 4294967295 - 1862419446 + 1, bias: 698, cmpl_freq: 911, rcp_shift: 6 },
        RansEncSymbol { x_max: 446693376, rcp_freq: 4294967295 - 1713954085 + 1, bias: 811, cmpl_freq: 811, rcp_shift: 7 },
    ];

    pub static DSYMS_H: [RansDecSymbol; M_H] = [
        RansDecSymbol { start: 0, freq: 266 },
        RansDecSymbol { start: 266, freq: 213 },
        RansDecSymbol { start: 479, freq: 113 },
        RansDecSymbol { start: 592, freq: 40 },
        RansDecSymbol { start: 632, freq: 9 },
        RansDecSymbol { start: 641, freq: 1 },
        RansDecSymbol { start: 642, freq: 1 },
        RansDecSymbol { start: 643, freq: 1 },
        RansDecSymbol { start: 644, freq: 1 },
        RansDecSymbol { start: 645, freq: 1 },
        RansDecSymbol { start: 646, freq: 1 },
        RansDecSymbol { start: 647, freq: 1 },
        RansDecSymbol { start: 648, freq: 1 },
        RansDecSymbol { start: 649, freq: 9 },
        RansDecSymbol { start: 658, freq: 40 },
        RansDecSymbol { start: 698, freq: 113 },
        RansDecSymbol { start: 811, freq: 213 },
    ];

    pub static SYMBOL_H: [u16; 1024] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16];

    pub static ESYMS_HB_Z1: [RansEncSymbol; M_HB_Z1] = [
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1023, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1024, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1025, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1026, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 16777216, rcp_freq: 4294967295 - 2147483648u32 + 1, bias: 4, cmpl_freq: 1016, rcp_shift: 2 },
        RansEncSymbol { x_max: 77594624, rcp_freq: 4294967295 - 580400985 + 1, bias: 12, cmpl_freq: 987, rcp_shift: 5 },
        RansEncSymbol { x_max: 234881024, rcp_freq: 4294967295 - 1840700269 + 1, bias: 49, cmpl_freq: 912, rcp_shift: 6 },
        RansEncSymbol { x_max: 452984832, rcp_freq: 4294967295 - 1749801490 + 1, bias: 161, cmpl_freq: 808, rcp_shift: 7 },
        RansEncSymbol { x_max: 564133888, rcp_freq: 4294967295 - 207563475 + 1, bias: 377, cmpl_freq: 755, rcp_shift: 8 },
        RansEncSymbol { x_max: 452984832, rcp_freq: 4294967295 - 1749801490 + 1, bias: 646, cmpl_freq: 808, rcp_shift: 7 },
        RansEncSymbol { x_max: 234881024, rcp_freq: 4294967295 - 1840700269 + 1, bias: 862, cmpl_freq: 912, rcp_shift: 6 },
        RansEncSymbol { x_max: 79691776, rcp_freq: 4294967295 - 678152730 + 1, bias: 974, cmpl_freq: 986, rcp_shift: 5 },
        RansEncSymbol { x_max: 16777216, rcp_freq: 4294967295 - 2147483648u32 + 1, bias: 1012, cmpl_freq: 1016, rcp_shift: 2 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2043, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2044, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2045, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2046, cmpl_freq: 1023, rcp_shift: 0 },
    ];

    pub static DSYMS_HB_Z1: [RansDecSymbol; M_HB_Z1] = [
        RansDecSymbol { start: 0, freq: 1 },
        RansDecSymbol { start: 1, freq: 1 },
        RansDecSymbol { start: 2, freq: 1 },
        RansDecSymbol { start: 3, freq: 1 },
        RansDecSymbol { start: 4, freq: 8 },
        RansDecSymbol { start: 12, freq: 37 },
        RansDecSymbol { start: 49, freq: 112 },
        RansDecSymbol { start: 161, freq: 216 },
        RansDecSymbol { start: 377, freq: 269 },
        RansDecSymbol { start: 646, freq: 216 },
        RansDecSymbol { start: 862, freq: 112 },
        RansDecSymbol { start: 974, freq: 38 },
        RansDecSymbol { start: 1012, freq: 8 },
        RansDecSymbol { start: 1020, freq: 1 },
        RansDecSymbol { start: 1021, freq: 1 },
        RansDecSymbol { start: 1022, freq: 1 },
        RansDecSymbol { start: 1023, freq: 1 },
    ];

    pub static SYMBOL_HB_Z1: [u16; 1024] = [0, 1, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 13, 14, 15, 16];
}

// ============================================================================
// HAETAE-5 Parameter-Specific Tables
// ============================================================================

#[cfg(feature = "haetae5")]
mod tables {
    use super::*;

    pub const M_H: usize = 33;
    pub const OFFSET_H: i32 = 471;
    pub const M_HB_Z1: usize = 19;
    pub const OFFSET_HB_Z1: i32 = 9;

    pub static ESYMS_H: [RansEncSymbol; M_H] = [
        RansEncSymbol { x_max: 255852544, rcp_freq: 4294967295 - 2041869698 + 1, bias: 0, cmpl_freq: 902, rcp_shift: 6 },
        RansEncSymbol { x_max: 245366784, rcp_freq: 4294967295 - 1945583475 + 1, bias: 122, cmpl_freq: 907, rcp_shift: 6 },
        RansEncSymbol { x_max: 213909504, rcp_freq: 4294967295 - 1600085855 + 1, bias: 239, cmpl_freq: 922, rcp_shift: 6 },
        RansEncSymbol { x_max: 169869312, rcp_freq: 4294967295 - 901412889 + 1, bias: 341, cmpl_freq: 943, rcp_shift: 6 },
        RansEncSymbol { x_max: 123731968, rcp_freq: 4294967295 - 1965493508 + 1, bias: 422, cmpl_freq: 965, rcp_shift: 5 },
        RansEncSymbol { x_max: 81788928, rcp_freq: 4294967295 - 770891565 + 1, bias: 481, cmpl_freq: 985, rcp_shift: 5 },
        RansEncSymbol { x_max: 48234496, rcp_freq: 4294967295 - 1307163959 + 1, bias: 520, cmpl_freq: 1001, rcp_shift: 4 },
        RansEncSymbol { x_max: 27262976, rcp_freq: 4294967295 - 1651910498 + 1, bias: 543, cmpl_freq: 1011, rcp_shift: 3 },
        RansEncSymbol { x_max: 12582912, rcp_freq: 4294967295 - 1431655765 + 1, bias: 556, cmpl_freq: 1018, rcp_shift: 2 },
        RansEncSymbol { x_max: 6291456, rcp_freq: 4294967295 - 1431655765 + 1, bias: 562, cmpl_freq: 1021, rcp_shift: 1 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1588, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1589, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1590, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1591, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1592, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1593, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1594, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1595, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1596, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1597, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1598, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1599, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1600, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1601, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 6291456, rcp_freq: 4294967295 - 1431655765 + 1, bias: 579, cmpl_freq: 1021, rcp_shift: 1 },
        RansEncSymbol { x_max: 12582912, rcp_freq: 4294967295 - 1431655765 + 1, bias: 582, cmpl_freq: 1018, rcp_shift: 2 },
        RansEncSymbol { x_max: 27262976, rcp_freq: 4294967295 - 1651910498 + 1, bias: 588, cmpl_freq: 1011, rcp_shift: 3 },
        RansEncSymbol { x_max: 50331648, rcp_freq: 4294967295 - 1431655765 + 1, bias: 601, cmpl_freq: 1000, rcp_shift: 4 },
        RansEncSymbol { x_max: 81788928, rcp_freq: 4294967295 - 770891565 + 1, bias: 625, cmpl_freq: 985, rcp_shift: 5 },
        RansEncSymbol { x_max: 123731968, rcp_freq: 4294967295 - 1965493508 + 1, bias: 664, cmpl_freq: 965, rcp_shift: 5 },
        RansEncSymbol { x_max: 169869312, rcp_freq: 4294967295 - 901412889 + 1, bias: 723, cmpl_freq: 943, rcp_shift: 6 },
        RansEncSymbol { x_max: 213909504, rcp_freq: 4294967295 - 1600085855 + 1, bias: 804, cmpl_freq: 922, rcp_shift: 6 },
        RansEncSymbol { x_max: 247463936, rcp_freq: 4294967295 - 1965493508 + 1, bias: 906, cmpl_freq: 906, rcp_shift: 6 },
    ];

    pub static DSYMS_H: [RansDecSymbol; M_H] = [
        RansDecSymbol { start: 0, freq: 122 },
        RansDecSymbol { start: 122, freq: 117 },
        RansDecSymbol { start: 239, freq: 102 },
        RansDecSymbol { start: 341, freq: 81 },
        RansDecSymbol { start: 422, freq: 59 },
        RansDecSymbol { start: 481, freq: 39 },
        RansDecSymbol { start: 520, freq: 23 },
        RansDecSymbol { start: 543, freq: 13 },
        RansDecSymbol { start: 556, freq: 6 },
        RansDecSymbol { start: 562, freq: 3 },
        RansDecSymbol { start: 565, freq: 1 },
        RansDecSymbol { start: 566, freq: 1 },
        RansDecSymbol { start: 567, freq: 1 },
        RansDecSymbol { start: 568, freq: 1 },
        RansDecSymbol { start: 569, freq: 1 },
        RansDecSymbol { start: 570, freq: 1 },
        RansDecSymbol { start: 571, freq: 1 },
        RansDecSymbol { start: 572, freq: 1 },
        RansDecSymbol { start: 573, freq: 1 },
        RansDecSymbol { start: 574, freq: 1 },
        RansDecSymbol { start: 575, freq: 1 },
        RansDecSymbol { start: 576, freq: 1 },
        RansDecSymbol { start: 577, freq: 1 },
        RansDecSymbol { start: 578, freq: 1 },
        RansDecSymbol { start: 579, freq: 3 },
        RansDecSymbol { start: 582, freq: 6 },
        RansDecSymbol { start: 588, freq: 13 },
        RansDecSymbol { start: 601, freq: 24 },
        RansDecSymbol { start: 625, freq: 39 },
        RansDecSymbol { start: 664, freq: 59 },
        RansDecSymbol { start: 723, freq: 81 },
        RansDecSymbol { start: 804, freq: 102 },
        RansDecSymbol { start: 906, freq: 118 },
    ];

    pub static SYMBOL_H: [u16; 1024] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 9, 9, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 24, 24, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32];

    pub static ESYMS_HB_Z1: [RansEncSymbol; M_HB_Z1] = [
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1023, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1024, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1025, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 1026, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 4194304, rcp_freq: 4294967295 - 2147483648u32 + 1, bias: 4, cmpl_freq: 1022, rcp_shift: 0 },
        RansEncSymbol { x_max: 27262976, rcp_freq: 4294967295 - 1651910498 + 1, bias: 6, cmpl_freq: 1011, rcp_shift: 3 },
        RansEncSymbol { x_max: 100663296, rcp_freq: 4294967295 - 1431655765 + 1, bias: 19, cmpl_freq: 976, rcp_shift: 5 },
        RansEncSymbol { x_max: 247463936, rcp_freq: 4294967295 - 1965493508 + 1, bias: 67, cmpl_freq: 906, rcp_shift: 6 },
        RansEncSymbol { x_max: 427819008, rcp_freq: 4294967295 - 1600085855 + 1, bias: 185, cmpl_freq: 820, rcp_shift: 7 },
        RansEncSymbol { x_max: 513802240, rcp_freq: 4294967295 - 2051066014 + 1, bias: 389, cmpl_freq: 779, rcp_shift: 7 },
        RansEncSymbol { x_max: 427819008, rcp_freq: 4294967295 - 1600085855 + 1, bias: 634, cmpl_freq: 820, rcp_shift: 7 },
        RansEncSymbol { x_max: 247463936, rcp_freq: 4294967295 - 1965493508 + 1, bias: 838, cmpl_freq: 906, rcp_shift: 6 },
        RansEncSymbol { x_max: 100663296, rcp_freq: 4294967295 - 1431655765 + 1, bias: 956, cmpl_freq: 976, rcp_shift: 5 },
        RansEncSymbol { x_max: 29360128, rcp_freq: 4294967295 - 1840700269 + 1, bias: 1004, cmpl_freq: 1010, rcp_shift: 3 },
        RansEncSymbol { x_max: 4194304, rcp_freq: 4294967295 - 2147483648u32 + 1, bias: 1018, cmpl_freq: 1022, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2043, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2044, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2045, cmpl_freq: 1023, rcp_shift: 0 },
        RansEncSymbol { x_max: 2097152, rcp_freq: u32::MAX, bias: 2046, cmpl_freq: 1023, rcp_shift: 0 },
    ];

    pub static DSYMS_HB_Z1: [RansDecSymbol; M_HB_Z1] = [
        RansDecSymbol { start: 0, freq: 1 },
        RansDecSymbol { start: 1, freq: 1 },
        RansDecSymbol { start: 2, freq: 1 },
        RansDecSymbol { start: 3, freq: 1 },
        RansDecSymbol { start: 4, freq: 2 },
        RansDecSymbol { start: 6, freq: 13 },
        RansDecSymbol { start: 19, freq: 48 },
        RansDecSymbol { start: 67, freq: 118 },
        RansDecSymbol { start: 185, freq: 204 },
        RansDecSymbol { start: 389, freq: 245 },
        RansDecSymbol { start: 634, freq: 204 },
        RansDecSymbol { start: 838, freq: 118 },
        RansDecSymbol { start: 956, freq: 48 },
        RansDecSymbol { start: 1004, freq: 14 },
        RansDecSymbol { start: 1018, freq: 2 },
        RansDecSymbol { start: 1020, freq: 1 },
        RansDecSymbol { start: 1021, freq: 1 },
        RansDecSymbol { start: 1022, freq: 1 },
        RansDecSymbol { start: 1023, freq: 1 },
    ];

    pub static SYMBOL_HB_Z1: [u16; 1024] = [0, 1, 2, 3, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 15, 16, 17, 18];
}

// ============================================================================
// Import parameter-specific tables based on feature flags
// ============================================================================

use tables::*;

/// H_CUT: Mid-point for symbol mapping
const H_CUT: usize = (M_H - 1) >> 1;

// ============================================================================
// Encoding Functions
// ============================================================================

/// Encode hint vector h using rANS
///
/// Compresses the hint polynomial vector using entropy coding. The hint vector
/// indicates which coefficients need high-bit corrections during verification.
///
/// # Arguments
/// * `buf` - Output buffer for encoded data
/// * `h` - Hint polynomial vector coefficients (K*N values)
///
/// # Returns
/// Number of bytes written, or 0 if encoding fails
///
/// Transcopy from: encode_h (encoding.c:59-96)
pub fn encode_h(buf: &mut [u8], h: &[i32]) -> u16 {
    let size_h = N * K;
    let mut encoding = vec![0u8; size_h]; // size_h is a loose upper bound

    let mut rans: RansState = 0;
    rans_enc_init(&mut rans);

    let mut ptr = encoding.as_mut_ptr();
    unsafe {
        ptr = ptr.add(size_h); // end of encoding buffer
    }

    // Encode symbols in REVERSE order (rANS encodes like a stack)
    for i in (0..size_h).rev() {
        let mut tmp = h[i] as u32;

        // Check for very unlikely values that we do not encode
        // to make the encoding cheaper:
        if (H_CUT as u32) < tmp && tmp <= (H_CUT as u32) + (OFFSET_H as u32) {
            return 0;
        }

        // Map the upper likely part of symbols next to the lower part
        // to have a dense and compact distribution:
        tmp = if tmp > (H_CUT as u32) + (OFFSET_H as u32) {
            tmp - (OFFSET_H as u32)
        } else {
            tmp
        };

        let s = tmp as u8;
        if (s as usize) >= M_H {
            return 0;
        }

        rans_enc_put_symbol(&mut rans, &mut ptr, &ESYMS_H[s as usize]);

        // Check that at least 4 bytes remain for memory safety:
        unsafe {
            if ptr < encoding.as_mut_ptr().add(4) {
                return 0;
            }
        }
    }

    rans_enc_flush(&rans, &mut ptr);

    let size_encoded = unsafe { encoding.as_ptr().add(size_h).offset_from(ptr) as usize };
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size_encoded);
    }

    size_encoded as u16
}

/// Decode hint vector h using rANS
///
/// Decompresses the hint polynomial vector from entropy-coded data.
///
/// # Arguments
/// * `h` - Output buffer for hint coefficients (K*N values)
/// * `buf` - Encoded input data
/// * `size_in` - Size of encoded data in bytes
///
/// # Returns
/// 0 on success, 1 on failure
///
/// Transcopy from: decode_h (encoding.c:106-139)
pub fn decode_h(h: &mut [i32], buf: &[u8], size_in: u16) -> i32 {
    let size_h = N * K;
    let mut rans: RansState = 0;

    let mut ptr = buf.as_ptr();
    let buf_start = buf.as_ptr();
    let buf_end = unsafe { buf.as_ptr().add(size_in as usize) };

    if rans_dec_init(&mut rans, &mut ptr) != 0 {
        return 1; // corrupted initial state
    }

    for i in 0..size_h {
        let s = SYMBOL_H[rans_dec_get(&rans, SCALE_BITS) as usize];
        let mut tmp = s as u32;

        if (tmp as usize) >= M_H {
            return 1; // invalid symbol
        }

        tmp = if (H_CUT as u32) < tmp {
            tmp + (OFFSET_H as u32)
        } else {
            tmp
        };

        h[i] = tmp as i32;

        rans_dec_advance_symbol(&mut rans, &mut ptr, buf_end, &DSYMS_H[s as usize], SCALE_BITS);
    }

    if rans_dec_verify(&rans) != 0 {
        return 1; // final state not correct
    }

    let size_used = unsafe { ptr.offset_from(buf_start) as usize };
    if size_used != size_in as usize {
        return 1; // size does not match
    }

    0
}

/// Encode highbits(z1) polynomial vector using rANS
///
/// Compresses the high bits of z1 decomposition using entropy coding.
///
/// # Arguments
/// * `buf` - Output buffer for encoded data
/// * `hb_z1` - HighBits(z1) polynomial vector coefficients (L*N values)
///
/// # Returns
/// Number of bytes written, or 0 if encoding fails
///
/// Transcopy from: encode_hb_z1 (encoding.c:150-184)
pub fn encode_hb_z1(buf: &mut [u8], hb_z1: &[i32]) -> u16 {
    let size_hb_z1 = N * L;
    let mut encoding = vec![0u8; size_hb_z1]; // size_hb_z1 is a loose upper bound

    let mut rans: RansState = 0;
    rans_enc_init(&mut rans);

    let mut ptr = encoding.as_mut_ptr();
    unsafe {
        ptr = ptr.add(size_hb_z1); // end of output buffer
    }

    // Encode symbols in REVERSE order
    for i in (0..size_hb_z1).rev() {
        // From centered to positive representation:
        let tmp = hb_z1[i] + OFFSET_HB_Z1;

        // Check for very unlikely values that we do not encode
        // to make the encoding cheaper:
        if tmp < 0 || (tmp as usize) >= M_HB_Z1 {
            return 0;
        }

        let s = tmp as u8;

        rans_enc_put_symbol(&mut rans, &mut ptr, &ESYMS_HB_Z1[s as usize]);

        // Check that at least 4 bytes remain for memory safety:
        unsafe {
            if ptr < encoding.as_mut_ptr().add(4) {
                return 0;
            }
        }
    }

    rans_enc_flush(&rans, &mut ptr);

    let size_encoded = unsafe { encoding.as_ptr().add(size_hb_z1).offset_from(ptr) as usize };
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size_encoded);
    }

    size_encoded as u16
}

/// Decode highbits(z1) polynomial vector using rANS
///
/// Decompresses the high bits of z1 decomposition from entropy-coded data.
///
/// # Arguments
/// * `hb_z1` - Output buffer for highbits(z1) coefficients (L*N values)
/// * `buf` - Encoded input data
/// * `size_in` - Size of encoded data in bytes
///
/// # Returns
/// 0 on success, 1 on failure
///
/// Transcopy from: decode_hb_z1 (encoding.c:194-227)
pub fn decode_hb_z1(hb_z1: &mut [i32], buf: &[u8], size_in: u16) -> i32 {
    let size_hb_z1 = N * L;
    let mut rans: RansState = 0;

    let mut ptr = buf.as_ptr();
    let buf_start = buf.as_ptr();
    let buf_end = unsafe { buf.as_ptr().add(size_in as usize) };

    if rans_dec_init(&mut rans, &mut ptr) != 0 {
        return 1; // corrupted initial state
    }

    for i in 0..size_hb_z1 {
        let s = SYMBOL_HB_Z1[rans_dec_get(&rans, SCALE_BITS) as usize];
        let tmp = s as u32;

        if (tmp as usize) >= M_HB_Z1 {
            return 1; // invalid symbol
        }

        // From positive to centered representation:
        hb_z1[i] = (tmp as i32) - OFFSET_HB_Z1;

        rans_dec_advance_symbol(&mut rans, &mut ptr, buf_end, &DSYMS_HB_Z1[s as usize], SCALE_BITS);
    }

    if rans_dec_verify(&rans) != 0 {
        return 1; // final state not correct
    }

    let size_used = unsafe { ptr.offset_from(buf_start) as usize };
    if size_used != size_in as usize {
        return 1; // size does not match
    }

    0
}


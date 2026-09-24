// SPDX-License-Identifier: MIT
//
// Ported from SMAUG-T reference implementation `packring.c` (unchanged
// between v1.1.1 and v1.2.0 apart from a memset size).
//
// The v1.1.1 reference replaced the precision-losing `bytes_to_Rq` /
// `Rq_to_bytes` packing in `pack.c` with this cleaner "R2_q" bit-packing
// scheme: q bits per coefficient packed contiguously into bytes. The
// fix addressed the Finding #29 root cause: divergence between the
// upstream reference and the optimized implementation.
//
// Coefficient storage conventions:
//   - For ciphertext-domain encodings (q in {3,4,5,7,8,9}) the
//     coefficient values are unsigned in [0, 2^q) and stored DIRECTLY
//     in the lower q bits of `coeffs[i]`. The pack/unpack functions
//     just mask `& ((1<<q)-1)`.
//   - For module-domain encodings (q in {10, 11}) the coefficient
//     values are unsigned in [0, 2^q) but stored LEFT-ALIGNED in i16,
//     i.e. as `value << (16-q)`. The pack functions extract the q
//     bits via `>> (16-q)`; unpack restores via `<< (16-q)`. This
//     matches the in-memory representation used by the matrix multiply.
//
// Test fixtures captured from the C reference live in
// `test-vectors/smaug-t/v1.1.1-packring/` and are verified byte-for-byte
// by `tests/pack_ring_v1_2_0.rs`.

use super::poly_types::Poly;

const LWE_N: usize = 256;

// ============================================================================
// q = 3 (used by modet / TiMER: p' = 2^3)
// ============================================================================

/// `pack_R2_3` — pack 8 coefficients (3 bits each) into 3 bytes.
/// Output buffer length: LWE_N * 3 / 8 = 96 bytes.
pub fn pack_r2_3(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u32 = 0;
        for i in 0..8 {
            packed |= ((data.coeffs[data_idx + i] as u16 & 0x0007) as u32) << (3 * i);
        }
        bytes[bytes_idx] = (packed & 0xff) as u8;
        bytes[bytes_idx + 1] = ((packed >> 8) & 0xff) as u8;
        bytes[bytes_idx + 2] = ((packed >> 16) & 0xff) as u8;
        bytes_idx += 3;
        data_idx += 8;
    }
}

pub fn unpack_r2_3(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u32 = 0;
        packed |= bytes[bytes_idx] as u32;
        packed |= (bytes[bytes_idx + 1] as u32) << 8;
        packed |= (bytes[bytes_idx + 2] as u32) << 16;
        bytes_idx += 3;
        for i in 0..8 {
            data.coeffs[data_idx + i] = ((packed >> (3 * i)) & 0x07) as i16;
        }
        data_idx += 8;
    }
}

// ============================================================================
// q = 4 (used by mode3: p' = 2^4)
// ============================================================================

/// `pack_R2_4` — pack 2 coefficients (4 bits each) per byte.
/// Output buffer length: LWE_N * 4 / 8 = 128 bytes.
pub fn pack_r2_4(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let lo = (data.coeffs[data_idx] as u16 & 0x000f) as u8;
        let hi = ((data.coeffs[data_idx + 1] as u16 & 0x000f) << 4) as u8;
        bytes[bytes_idx] = lo | hi;
        bytes_idx += 1;
        data_idx += 2;
    }
}

pub fn unpack_r2_4(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        data.coeffs[data_idx] = (bytes[bytes_idx] & 0x0f) as i16;
        data.coeffs[data_idx + 1] = ((bytes[bytes_idx] >> 4) & 0x0f) as i16;
        bytes_idx += 1;
        data_idx += 2;
    }
}

// ============================================================================
// q = 5 (used by mode1: p' = 2^5)
// ============================================================================

/// `pack_R2_5` — pack 8 coefficients (5 bits each) into 5 bytes.
/// Output buffer length: LWE_N * 5 / 8 = 160 bytes.
pub fn pack_r2_5(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for i in 0..8 {
            packed |= ((data.coeffs[data_idx + i] as u16 & 0x001f) as u64) << (5 * i);
        }
        for s in 0..5 {
            bytes[bytes_idx + s] = ((packed >> (8 * s)) & 0xff) as u8;
        }
        bytes_idx += 5;
        data_idx += 8;
    }
}

pub fn unpack_r2_5(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for s in 0..5 {
            packed |= (bytes[bytes_idx + s] as u64) << (8 * s);
        }
        bytes_idx += 5;
        for i in 0..8 {
            data.coeffs[data_idx + i] = ((packed >> (5 * i)) & 0x1f) as i16;
        }
        data_idx += 8;
    }
}

// ============================================================================
// q = 7 (used by mode5: p' = 2^7)
// ============================================================================

/// `pack_R2_7` — pack 8 coefficients (7 bits each) into 7 bytes.
/// Output buffer length: LWE_N * 7 / 8 = 224 bytes.
pub fn pack_r2_7(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for i in 0..8 {
            packed |= ((data.coeffs[data_idx + i] as u16 & 0x007f) as u64) << (7 * i);
        }
        for s in 0..7 {
            bytes[bytes_idx + s] = ((packed >> (8 * s)) & 0xff) as u8;
        }
        bytes_idx += 7;
        data_idx += 8;
    }
}

pub fn unpack_r2_7(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for s in 0..7 {
            packed |= (bytes[bytes_idx + s] as u64) << (8 * s);
        }
        bytes_idx += 7;
        for i in 0..8 {
            data.coeffs[data_idx + i] = ((packed >> (7 * i)) & 0x7f) as i16;
        }
        data_idx += 8;
    }
}

// ============================================================================
// q = 8 (used by mode1 and modet: p = 2^8)
// ============================================================================

/// `pack_R2_8` — 8 bits per coefficient = 1 byte.
/// Output buffer length: LWE_N = 256 bytes.
pub fn pack_r2_8(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    for i in 0..LWE_N {
        bytes[i] = (data.coeffs[i] as u16 & 0x00ff) as u8;
    }
}

pub fn unpack_r2_8(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    for i in 0..LWE_N {
        data.coeffs[i] = bytes[i] as i16;
    }
}

// ============================================================================
// q = 9 (used by mode3 and mode5: p = 2^9)
// ============================================================================

/// `pack_R2_9` — pack 8 coefficients (9 bits each) into 9 bytes.
/// Output buffer length: LWE_N * 9 / 8 = 288 bytes.
///
/// The encoding splits each 8-coefficient group across a u64 (the
/// first 7 full coefficients + the low bit of coefficient 7) and an
/// 8-bit overflow (the upper 8 bits of coefficient 7). This matches
/// the upstream C reference exactly — see `packring.c::pack_R2_9`.
pub fn pack_r2_9(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for i in 0..7 {
            packed |= ((data.coeffs[data_idx + i] as u16 & 0x01ff) as u64) << (9 * i);
        }
        packed |= ((data.coeffs[data_idx + 7] as u16 & 0x0001) as u64) << 63;
        let packed2: u8 = ((data.coeffs[data_idx + 7] as u16 >> 1) & 0xff) as u8;

        for s in 0..8 {
            bytes[bytes_idx + s] = ((packed >> (8 * s)) & 0xff) as u8;
        }
        bytes[bytes_idx + 8] = packed2;
        bytes_idx += 9;
        data_idx += 8;
    }
}

pub fn unpack_r2_9(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for s in 0..8 {
            packed |= (bytes[bytes_idx + s] as u64) << (8 * s);
        }
        let packed2 = bytes[bytes_idx + 8];
        bytes_idx += 9;

        for i in 0..7 {
            data.coeffs[data_idx + i] = ((packed >> (9 * i)) & 0x01ff) as i16;
        }
        // coefficient 7: low bit from packed[63], high 8 bits from packed2
        let c7_low = ((packed >> 63) & 0x0001) as i16;
        let c7_high = ((packed2 as i16) << 1) & 0x01fe;
        data.coeffs[data_idx + 7] = c7_low | c7_high;
        data_idx += 8;
    }
}

// ============================================================================
// q = 10 (used by mode1 and modet: q = 2^10, public-key polynomials)
// ============================================================================

/// `pack_R2_10` — pack 4 left-aligned coefficients (10 bits each) into 5 bytes.
/// Output buffer length: LWE_N * 10 / 8 = 320 bytes.
///
/// Coefficients are expected to be stored as `value << 6` in i16
/// (in-memory format for the matrix multiply). The pack function
/// extracts the upper 10 bits via `>> 6`.
pub fn pack_r2_10(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for i in 0..4 {
            let v = (data.coeffs[data_idx + i] as u16 >> 6) & 0x03ff;
            packed |= (v as u64) << (10 * i);
        }
        for s in 0..5 {
            bytes[bytes_idx + s] = ((packed >> (8 * s)) & 0xff) as u8;
        }
        bytes_idx += 5;
        data_idx += 4;
    }
}

pub fn unpack_r2_10(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for s in 0..5 {
            packed |= (bytes[bytes_idx + s] as u64) << (8 * s);
        }
        bytes_idx += 5;
        for i in 0..4 {
            // Use u16 wrapping shift so that values >= 512 (which shift
            // into the sign bit) don't panic in Rust debug mode.
            let v = ((packed >> (10 * i)) & 0x03ff) as u16;
            data.coeffs[data_idx + i] = v.wrapping_shl(6) as i16;
        }
        data_idx += 4;
    }
}

// ============================================================================
// q = 11 (used by mode3 and mode5: q = 2^11, public-key polynomials)
// ============================================================================

/// `pack_R2_11` — pack 8 left-aligned coefficients (11 bits each) into 11 bytes.
/// Output buffer length: LWE_N * 11 / 8 = 352 bytes.
///
/// Coefficients are expected to be stored as `value << 5` in i16. The
/// pack function extracts the upper 11 bits via `>> 5`. The encoding
/// splits each 8-coefficient group across a u64 (first 5 full coeffs +
/// the low bit of coeff 5) and a u32 (the upper 10 bits of coeff 5 +
/// coeffs 6 and 7).
pub fn pack_r2_11(bytes: &mut [u8], data: &Poly) {
    for b in bytes.iter_mut() { *b = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for i in 0..5 {
            let v = (data.coeffs[data_idx + i] as u16 >> 5) & 0x07ff;
            packed |= (v as u64) << (11 * i);
        }
        let c5 = (data.coeffs[data_idx + 5] as u16 >> 5) & 0x07ff;
        packed |= ((c5 as u64) & 0x0001) << 55;

        let mut packed2: u32 = ((c5 >> 1) & 0x03ff) as u32;
        for i in 0..2 {
            let v = (data.coeffs[data_idx + 6 + i] as u16 >> 5) & 0x07ff;
            packed2 |= (v as u32) << (10 + 11 * i);
        }

        for s in 0..7 {
            bytes[bytes_idx + s] = ((packed >> (8 * s)) & 0xff) as u8;
        }
        for s in 0..4 {
            bytes[bytes_idx + 7 + s] = ((packed2 >> (8 * s)) & 0xff) as u8;
        }
        bytes_idx += 11;
        data_idx += 8;
    }
}

pub fn unpack_r2_11(data: &mut Poly, bytes: &[u8]) {
    for c in data.coeffs.iter_mut() { *c = 0; }
    let mut bytes_idx = 0;
    let mut data_idx = 0;
    while data_idx < LWE_N {
        let mut packed: u64 = 0;
        for s in 0..7 {
            packed |= (bytes[bytes_idx + s] as u64) << (8 * s);
        }
        let mut packed2: u32 = 0;
        for s in 0..4 {
            packed2 |= (bytes[bytes_idx + 7 + s] as u32) << (8 * s);
        }
        bytes_idx += 11;

        for i in 0..5 {
            let v = ((packed >> (11 * i)) & 0x07ff) as u16;
            data.coeffs[data_idx + i] = v.wrapping_shl(5) as i16;
        }
        // coefficient 5: low bit from packed[55] (→ i16 bit 5),
        // high 10 bits from packed2[0..10] (→ i16 bits 6..15).
        // Compute in u16 with wrapping shift so bit 15 is preserved
        // when packed2 supplies a value with its high bit set.
        let c5_low_u: u16 = (((packed >> 55) & 0x0001) as u16).wrapping_shl(5);
        let c5_high_u: u16 = ((packed2 & 0x03ff) as u16).wrapping_shl(6);
        data.coeffs[data_idx + 5] = (c5_low_u | c5_high_u) as i16;
        for i in 0..2 {
            let v = ((packed2 >> (10 + 11 * i)) & 0x07ff) as u16;
            data.coeffs[data_idx + 6 + i] = v.wrapping_shl(5) as i16;
        }
        data_idx += 8;
    }
}

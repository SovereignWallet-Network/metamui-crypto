//! NIST-compliant encoding and decoding functions for Falcon-512
//!
//! This module implements the encoding functions from the NIST reference
//! implementation, specifically from codec.c in the falcon-round3 submission.
//!
//! Key formats:
//! - Public key:  1 byte header + 14-bit packed coefficients (897 bytes for n=512)
//! - Private key: 1 byte header + trim-encoded f, g, F (1281 bytes NIST ref; 2305 bytes tree format)
//! - Signature:   Golomb-Rice compressed s2 coefficients (variable, ~666 bytes avg)

use crate::constants::Q;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

// ================================================================
// Public key encoding: 14-bit packed coefficients
// ================================================================

/// Encode polynomial modulo q into bytes (NIST format).
///
/// Each coefficient is in [0, q-1] where q = 12289.
/// Uses 14 bits per coefficient, big-endian bit packing (NIST codec.c).
/// Output size: ceil(n * 14 / 8) bytes.
pub fn modq_encode(h: &[i16], logn: usize) -> Vec<u8> {
    let n = 1 << logn;
    assert_eq!(h.len(), n);

    let out_len = (n * 14 + 7) / 8;
    let mut out = Vec::with_capacity(out_len);

    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;

    for &coeff in h {
        // Normalize to [0, q-1]
        let c = if coeff < 0 {
            ((coeff as i32 + Q as i32) as u16) % Q
        } else {
            (coeff as u16) % Q
        };

        acc = (acc << 14) | (c as u32);
        acc_len += 14;

        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    // Flush remaining bits (left-aligned in final byte)
    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    out
}

/// Decode bytes to polynomial modulo q (NIST format).
///
/// Big-endian bit packing matching NIST codec.c.
pub fn modq_decode(data: &[u8], logn: usize) -> Result<Vec<i16>> {
    let n = 1 << logn;
    let expected_len = (n * 14 + 7) / 8;

    if data.len() != expected_len {
        return Err(Falcon512Error::InvalidPublicKey);
    }

    let mut coeffs = vec![0i16; n];
    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;
    let mut data_pos = 0;
    let mut i = 0;

    while i < n {
        acc = (acc << 8) | (data[data_pos] as u32);
        data_pos += 1;
        acc_len += 8;

        if acc_len >= 14 {
            acc_len -= 14;
            let c = ((acc >> acc_len) & 0x3FFF) as u16;

            if c >= Q {
                return Err(Falcon512Error::InvalidPublicKey);
            }

            coeffs[i] = c as i16;
            i += 1;
        }
    }

    // Verify unused trailing bits are zero
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return Err(Falcon512Error::InvalidPublicKey);
    }

    Ok(coeffs)
}

// ================================================================
// Private key encoding: trim encoding with per-logn bit widths
// ================================================================

/// Encode trim with i16 coefficients and variable bit widths.
///
/// Used for encoding f, g, F polynomials with per-logn bit widths:
/// - logn=9 (Falcon-512): f_bits=6, g_bits=6, F_bits=8
/// - logn=10 (Falcon-1024): f_bits=5, g_bits=5, F_bits=8
///
/// This is the reference `trim_i8_encode` layout: MSB-first two's complement.
/// Like the reference, a coefficient outside `-(2^(bits-1) - 1) ..= 2^(bits-1) - 1`
/// is refused (`InvalidPrivateKey`) — including the forbidden `-2^(bits-1)`,
/// which the decoder rejects. Masking it would encode a *different* key (#341).
pub fn trim_i16_encode(x: &[i16], bits: usize) -> Result<Vec<u8>> {
    let n = x.len();
    let out_len = (n * bits + 7) / 8;
    let mut out = Vec::with_capacity(out_len);

    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;
    let mask = (1u32 << bits) - 1;
    let limit = (1i32 << (bits - 1)) - 1;

    for &coeff in x {
        if (coeff as i32) < -limit || (coeff as i32) > limit {
            return Err(Falcon512Error::InvalidPrivateKey);
        }
        // NIST: store as unsigned with sign folded into low bit range
        acc = (acc << bits) | ((coeff as u16) as u32 & mask);
        acc_len += bits;

        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    Ok(out)
}

/// Decode trim encoding with i16 output (NIST big-endian bit packing).
pub fn trim_i16_decode(data: &[u8], n: usize, bits: usize) -> Result<Vec<i16>> {
    let expected_len = (n * bits + 7) / 8;
    if data.len() < expected_len {
        return Err(Falcon512Error::InvalidPrivateKey);
    }

    let mut coeffs = vec![0i16; n];
    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;
    let mut data_pos = 0;

    let mask1 = (1u32 << bits) - 1;
    let mask2 = 1u32 << (bits - 1);

    let mut i = 0;
    while i < n {
        acc = (acc << 8) | (data[data_pos] as u32);
        data_pos += 1;
        acc_len += 8;

        while acc_len >= bits && i < n {
            acc_len -= bits;
            let w = (acc >> acc_len) & mask1;
            // Sign-extend: if high bit set, extend to negative
            let signed = if w & mask2 != 0 {
                w | !mask1
            } else {
                w
            };
            // The -2^(bits-1) value is forbidden
            if signed == (!mask1 | mask2) {
                return Err(Falcon512Error::InvalidPrivateKey);
            }
            coeffs[i] = signed as i32 as i16;
            i += 1;
        }
    }

    Ok(coeffs)
}

// ================================================================
// Signature compression: Golomb-Rice encoding
//
// Each coefficient s of the signature polynomial is encoded as:
//   1. Sign bit: 0 = positive, 1 = negative
//   2. Low bits: |s| & ((1 << LOW_BITS) - 1), using LOW_BITS bits
//   3. High bits: |s| >> LOW_BITS, encoded in unary (that many 0-bits + 1-bit)
//
// For Falcon-512, LOW_BITS = 8 (empirically optimal).
// This matches the C reference falcon_comp_encode/decode.
// ================================================================

/// Number of low bits in the Golomb-Rice encoding
// NIST comp encoding uses 7 low bits + sign bit = 8 bits per coefficient,
// plus unary high-part encoding. The constant is built into comp_encode/decode.

/// Compress signature using Golomb-Rice encoding (NIST format).
///
/// Encodes each coefficient as: sign(1) | lo(LOW_BITS) | unary_hi | terminator(1)
/// This produces variable-length output (~666 bytes average for Falcon-512).
pub fn comp_encode(s: &[i16], logn: usize) -> Vec<u8> {
    let n = 1 << logn;
    assert_eq!(s.len(), n);

    let mut out = Vec::with_capacity(700);
    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;

    for &coeff in s {
        // Push sign bit (1 = negative) and low 7 bits = 8 bits total (big-endian)
        acc <<= 1;
        let t = if coeff < 0 {
            acc |= 1;
            (-coeff) as u32
        } else {
            coeff as u32
        };
        acc <<= 7;
        acc |= t & 127;
        let w = t >> 7;
        acc_len += 8;

        // Push w zeros + one 1-bit (unary high encoding, big-endian)
        acc <<= w + 1;
        acc |= 1;
        acc_len += (w + 1) as usize;

        // Flush full bytes
        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
        }
    }

    // Flush remaining bits (left-aligned)
    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }

    out
}

/// Decompress signature from Golomb-Rice encoding (NIST format, big-endian).
///
/// Strict: every byte of `data` must belong to the encoding. Trailing bytes are
/// rejected (`InvalidSignature`) so a signature has exactly one byte
/// representation — the reference `comp_decode` reports the consumed length and
/// its callers reject `v != sig_len`; accepting trailing bytes would make
/// signature bytes malleable.
pub fn comp_decode(data: &[u8], logn: usize) -> Result<Vec<i16>> {
    let (coeffs, consumed) = comp_decode_consumed(data, logn)?;
    if consumed != data.len() {
        return Err(Falcon512Error::InvalidSignature);
    }
    Ok(coeffs)
}

/// Decompress `2^logn` coefficients and report how many bytes were consumed
/// (the reference `comp_decode` return value). The padded profile uses the
/// count to check that everything after the body is zero.
pub fn comp_decode_consumed(data: &[u8], logn: usize) -> Result<(Vec<i16>, usize)> {
    let n = 1 << logn;
    let mut coeffs = vec![0i16; n];

    if data.is_empty() {
        return Err(Falcon512Error::InvalidSignature);
    }

    let mut acc: u32 = 0;
    let mut acc_len: usize = 0;
    let mut pos: usize = 0;

    for i in 0..n {
        // Read next 8 bits: sign (1 bit) + low 7 bits of absolute value
        if pos >= data.len() {
            return Err(Falcon512Error::DecompressionFailed);
        }
        acc = (acc << 8) | (data[pos] as u32);
        pos += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;

        // Read unary high bits: count zero-bits until we see a 1-bit
        loop {
            if acc_len == 0 {
                if pos >= data.len() {
                    return Err(Falcon512Error::DecompressionFailed);
                }
                acc = (acc << 8) | (data[pos] as u32);
                pos += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return Err(Falcon512Error::DecompressionFailed);
            }
        }

        // "-0" is forbidden
        if s != 0 && m == 0 {
            return Err(Falcon512Error::InvalidSignature);
        }

        coeffs[i] = if s != 0 {
            -(m as i16)
        } else {
            m as i16
        };
    }

    // Verify unused bits in last byte are zero
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return Err(Falcon512Error::InvalidSignature);
    }

    Ok((coeffs, pos))
}

// ================================================================
// Full key encoding with NIST headers
// ================================================================

/// Encode public key in NIST format: [header(1)] [14-bit packed h]
///
/// Header byte: 0x00 | logn (0x09 for Falcon-512, 0x0A for Falcon-1024)
/// Total size: 897 bytes for Falcon-512, 1793 bytes for Falcon-1024
pub fn encode_public_key(h: &[i16], logn: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(logn as u8); // header = 0x00 | logn
    out.extend(modq_encode(h, logn));
    out
}

/// Decode public key from NIST format
pub fn decode_public_key(data: &[u8], logn: usize) -> Result<Vec<i16>> {
    let n = 1usize << logn;
    let expected_len = 1 + (n * 14 + 7) / 8;

    if data.len() < expected_len {
        return Err(Falcon512Error::InvalidPublicKey);
    }

    // Check header
    if data[0] != logn as u8 {
        return Err(Falcon512Error::InvalidPublicKey);
    }

    modq_decode(&data[1..], logn)
}

/// Decode the legacy headerless raw public key: `2^logn` little-endian i16
/// coefficients (1024 bytes for Falcon-512, 2048 for Falcon-1024).
///
/// Kept for keys stored by consumers before the NIST form was the only
/// output. It used to take any i16, so h[i], h[i] ± q and so on were distinct
/// byte strings for one key mod q (M-19). Like `modq_decode`, it now accepts
/// only the canonical representative in [0, q) — what every writer of this
/// form (`h` from keygen or from the NIST decoder) produces.
pub fn decode_raw_public_key(data: &[u8], logn: usize) -> Result<Vec<i16>> {
    let n = 1usize << logn;
    if data.len() != n * 2 {
        return Err(Falcon512Error::InvalidPublicKey);
    }
    data.chunks_exact(2)
        .map(|b| {
            let c = i16::from_le_bytes([b[0], b[1]]);
            if (0..Q as i16).contains(&c) {
                Ok(c)
            } else {
                Err(Falcon512Error::InvalidPublicKey)
            }
        })
        .collect()
}

/// Encode private key in NIST format: [header(1)] [f] [g] [F]
///
/// Header byte: 0x50 | logn (0x59 for Falcon-512, 0x5A for Falcon-1024)
/// Bit widths per logn:
///   logn=9:  f_bits=6, g_bits=6, F_bits=8 → 1 + 512*20/8 = 1281
///   logn=10: f_bits=5, g_bits=5, F_bits=8 → 1 + 1024*18/8 = 2305
///
/// Refuses a key whose coefficients do not fit the encoding (see
/// `trim_i16_encode`); keys from keygen and from `decode_private_key` always fit.
pub fn encode_private_key(f: &[i16], g: &[i16], big_f: &[i16], logn: usize) -> Result<Vec<u8>> {
    let f_bits = if logn >= 10 { 5 } else { 6 };
    let g_bits = if logn >= 10 { 5 } else { 6 };
    let f_bits_large = 8;

    let mut out = Vec::new();
    out.push(0x50 | logn as u8); // header

    out.extend(trim_i16_encode(f, f_bits)?);
    out.extend(trim_i16_encode(g, g_bits)?);
    out.extend(trim_i16_encode(big_f, f_bits_large)?);

    Ok(out)
}

/// Decode private key from NIST format
pub fn decode_private_key(data: &[u8], logn: usize) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>)> {
    let n = 1usize << logn;
    let f_bits = if logn >= 10 { 5 } else { 6 };
    let g_bits = if logn >= 10 { 5 } else { 6 };
    let f_bits_large = 8;

    let expected_len = 1 + (n * (f_bits + g_bits + f_bits_large) + 7) / 8;
    if data.len() < expected_len {
        return Err(Falcon512Error::InvalidPrivateKey);
    }

    // Check header
    if data[0] != (0x50 | logn as u8) {
        return Err(Falcon512Error::InvalidPrivateKey);
    }

    let mut pos = 1;

    // Decode f
    let f_len = (n * f_bits + 7) / 8;
    let f = trim_i16_decode(&data[pos..pos + f_len], n, f_bits)?;
    pos += f_len;

    // Decode g
    let g_len = (n * g_bits + 7) / 8;
    let g = trim_i16_decode(&data[pos..pos + g_len], n, g_bits)?;
    pos += g_len;

    // Decode F
    let big_f_len = (n * f_bits_large + 7) / 8;
    let big_f = trim_i16_decode(&data[pos..pos + big_f_len], n, f_bits_large)?;

    Ok((f, g, big_f))
}

// ================================================================
// Signature encoding with NIST header
// ================================================================

/// Encode signature in NIST format: [header(1)] [nonce(40)] [compressed s2]
///
/// Header byte: 0x30 | logn (0x39 for Falcon-512, 0x3A for Falcon-1024)
pub fn encode_signature(s2: &[i16], nonce: &[u8], logn: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30 | logn as u8); // header
    out.extend_from_slice(nonce); // 40-byte nonce
    out.extend(comp_encode(s2, logn)); // compressed s2
    out
}

/// Decode signature from NIST format.
///
/// Returns (nonce, s2) where s2 is the decompressed signature polynomial.
pub fn decode_signature(data: &[u8], logn: usize) -> Result<(Vec<u8>, Vec<i16>)> {
    if data.len() < 42 {
        // Need at least header + 40 nonce + 1 byte compressed
        return Err(Falcon512Error::InvalidSignature);
    }

    // Check header
    let expected_header = 0x30 | logn as u8;
    if data[0] != expected_header {
        return Err(Falcon512Error::InvalidSignature);
    }

    let nonce = data[1..41].to_vec();
    // Strict: the body must be exactly the Golomb-Rice encoding, no trailing bytes.
    let s2 = comp_decode(&data[41..], logn)?;

    Ok((nonce, s2))
}

// ================================================================
// Padded profile (Round-3 falcon.h FALCON_SIG_PADDED / PQClean falcon-padded-*)
// ================================================================

/// Encode a signature in the **padded** profile: `[0x30|logn] [nonce(40)]
/// [comp(s2)] [zero padding]`, exactly `sizes::sig_padded(logn)` bytes.
///
/// Returns `SignatureTooLong` when the compressed body does not fit; the caller
/// must retry with a fresh nonce (the reference does the same), never truncate.
pub fn encode_signature_padded(s2: &[i16], nonce: &[u8], logn: usize) -> Result<Vec<u8>> {
    let total = crate::sizes::sig_padded(logn as u32).ok_or(Falcon512Error::InvalidParameter)?;
    if nonce.len() != crate::sizes::NONCE_LEN {
        return Err(Falcon512Error::InvalidNonce);
    }
    let body = comp_encode(s2, logn);
    let prefix = crate::sizes::SIG_PREFIX_LEN;
    if prefix + body.len() > total {
        return Err(Falcon512Error::SignatureTooLong);
    }
    let mut out = Vec::with_capacity(total);
    out.push(0x30 | logn as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&body);
    out.resize(total, 0u8);
    Ok(out)
}

/// Decode a **padded**-profile signature. The total length must be exactly
/// `sizes::sig_padded(logn)`, the header `0x30|logn`, and every byte after the
/// compressed body must be zero (`InvalidPadding` otherwise).
///
/// Returns `(nonce, s2)`.
pub fn decode_signature_padded(data: &[u8], logn: usize) -> Result<(Vec<u8>, Vec<i16>)> {
    let total = crate::sizes::sig_padded(logn as u32).ok_or(Falcon512Error::InvalidParameter)?;
    if data.len() != total {
        return Err(Falcon512Error::InvalidPadding);
    }
    if data[0] != (0x30 | logn as u8) {
        return Err(Falcon512Error::InvalidSignature);
    }
    let prefix = crate::sizes::SIG_PREFIX_LEN;
    let nonce = data[1..prefix].to_vec();
    let (s2, consumed) = comp_decode_consumed(&data[prefix..], logn)?;
    if data[prefix + consumed..].iter().any(|&b| b != 0) {
        return Err(Falcon512Error::InvalidPadding);
    }
    Ok((nonce, s2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modq_encode_decode() {
        let mut h = vec![0i16; 512];
        for i in 0..512 {
            h[i] = ((i * 17 + 42) % Q as usize) as i16;
        }

        let encoded = modq_encode(&h, 9);
        assert_eq!(encoded.len(), 896); // 512 * 14 / 8

        let decoded = modq_decode(&encoded, 9).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn test_trim_i16_encode_decode() {
        let mut f = vec![0i16; 512];
        for i in 0..512 {
            f[i] = ((i as i32 - 256) % 30) as i16; // fits in 6 bits
        }

        let encoded = trim_i16_encode(&f, 6).unwrap();
        let decoded = trim_i16_decode(&encoded, 512, 6).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn test_trim_i16_encode_refuses_what_it_cannot_represent() {
        // #341: 6 bits hold -31..=31; 32 used to be masked into another value
        // and -32 is the forbidden pattern the decoder rejects.
        let mut f = vec![0i16; 512];
        f[7] = 31;
        f[8] = -31;
        assert!(trim_i16_encode(&f, 6).is_ok());
        for bad in [32i16, -32, 127, -300] {
            f[9] = bad;
            assert!(trim_i16_encode(&f, 6).is_err(), "coefficient {bad} must be refused");
        }
        f[9] = 127;
        assert!(trim_i16_encode(&f, 8).is_ok());
        f[9] = -128;
        assert!(trim_i16_encode(&f, 8).is_err());
    }

    #[test]
    fn test_comp_encode_decode_roundtrip() {
        // Test with small coefficients (typical signature range)
        let mut s = vec![0i16; 512];
        for i in 0..512 {
            s[i] = ((i as i32 - 256) % 100) as i16;
        }

        let encoded = comp_encode(&s, 9);
        let decoded = comp_decode(&encoded, 9).unwrap();
        assert_eq!(decoded.len(), 512);

        for i in 0..512 {
            assert_eq!(
                decoded[i], s[i],
                "Mismatch at index {}: got {}, expected {}",
                i, decoded[i], s[i]
            );
        }
    }

    #[test]
    fn test_comp_encode_zeros() {
        // All-zero signature should still roundtrip
        let s = vec![0i16; 512];
        let encoded = comp_encode(&s, 9);
        let decoded = comp_decode(&encoded, 9).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn test_comp_encode_size() {
        // Typical signature coefficients should compress well
        let mut s = vec![0i16; 512];
        for i in 0..512 {
            // Typical Falcon-512 signature coefficients are small
            s[i] = ((i as i32 * 7 - 200) % 50) as i16;
        }

        let encoded = comp_encode(&s, 9);
        // Should be much less than 512 * 2 = 1024 bytes (uncompressed)
        assert!(
            encoded.len() < 900,
            "Compressed size {} is too large",
            encoded.len()
        );
    }

    #[test]
    fn test_public_key_nist_format() {
        let mut h = vec![0i16; 512];
        for i in 0..512 {
            h[i] = ((i * 23 + 7) % Q as usize) as i16;
        }

        let encoded = encode_public_key(&h, 9);
        assert_eq!(encoded.len(), 897); // 1 header + 896 data
        assert_eq!(encoded[0], 0x09); // header for logn=9

        let decoded = decode_public_key(&encoded, 9).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn test_private_key_nist_format() {
        let mut f = vec![0i16; 512];
        let mut g = vec![0i16; 512];
        let mut big_f = vec![0i16; 512];

        for i in 0..512 {
            f[i] = ((i as i32 - 256) % 30) as i16; // fits in 6 bits
            g[i] = ((i as i32 - 200) % 30) as i16;
            big_f[i] = ((i as i32 - 256) % 120) as i16; // fits in 8 bits
        }

        let encoded = encode_private_key(&f, &g, &big_f, 9).unwrap();
        assert_eq!(encoded.len(), 1281); // 1 + 512*20/8
        assert_eq!(encoded[0], 0x59); // header for logn=9

        let (df, dg, dbf) = decode_private_key(&encoded, 9).unwrap();
        assert_eq!(df, f);
        assert_eq!(dg, g);
        assert_eq!(dbf, big_f);
    }

    #[test]
    fn test_signature_nist_format() {
        let mut s2 = vec![0i16; 512];
        for i in 0..512 {
            s2[i] = ((i as i32 - 256) % 50) as i16;
        }
        let nonce = vec![0xABu8; 40];

        let encoded = encode_signature(&s2, &nonce, 9);
        assert_eq!(encoded[0], 0x39); // header for logn=9
        assert_eq!(&encoded[1..41], &nonce[..]);

        let (dec_nonce, dec_s2) = decode_signature(&encoded, 9).unwrap();
        assert_eq!(dec_nonce, nonce);
        assert_eq!(dec_s2, s2);
    }
}

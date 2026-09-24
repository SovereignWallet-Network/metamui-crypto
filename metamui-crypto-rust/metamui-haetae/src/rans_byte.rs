//! Byte-aligned rANS encoder/decoder for HAETAE
//!
//! Simple byte-aligned rANS (range Asymmetric Numeral Systems) implementation
//! for entropy coding in HAETAE signatures. This achieves near-optimal
//! compression by encoding symbols according to their probability distribution.
//!
//! Public domain - Fabian 'ryg' Giesen 2014
//!
//! Key properties:
//! - Encode data in REVERSE order (last symbol first) - rANS works like a stack
//! - Encoder outputs bytes in REVERSE - pointer starts at end of buffer
//! - Can interleave multiple independent rANS streams without extra signaling
//!
//! Transcopy from: rans_byte.h

/// Lower bound of normalization interval (2^23)
///
/// We use 31 bits (not 32!) intentionally because exact reciprocals for
/// 31-bit uints fit in 32-bit uints, permitting encoding optimizations.
pub const RANS_BYTE_L: u32 = 1u32 << 23;

/// rANS encoder/decoder state (just a u32!)
pub type RansState = u32;

// ============================================================================
// Encoder
// ============================================================================

/// Initialize rANS encoder
#[inline]
pub fn rans_enc_init(r: &mut RansState) {
    *r = RANS_BYTE_L;
}

/// Renormalize encoder (internal)
///
/// Ensures state stays within normalization interval by emitting bytes.
#[inline]
fn rans_enc_renorm(x: RansState, pptr: &mut *mut u8, freq: u32, scale_bits: u32) -> RansState {
    let x_max = ((RANS_BYTE_L >> scale_bits) << 8) * freq;
    let mut x = x;

    if x >= x_max {
        unsafe {
            let mut ptr = *pptr;
            while x >= x_max {
                ptr = ptr.sub(1);
                *ptr = (x & 0xff) as u8;
                x >>= 8;
            }
            *pptr = ptr;
        }
    }

    x
}

/// Encode a single symbol
///
/// Encodes symbol with range start "start" and frequency "freq".
/// All frequencies sum to "1 << scale_bits".
///
/// NOTE: Encode symbols in REVERSE order! Output bytestream is backwards!
#[inline]
pub fn rans_enc_put(r: &mut RansState, pptr: &mut *mut u8, start: u32, freq: u32, scale_bits: u32) {
    // Renormalize
    let x = rans_enc_renorm(*r, pptr, freq, scale_bits);

    // x = C(s,x)
    *r = ((x / freq) << scale_bits) + (x % freq) + start;
}

/// Flush rANS encoder
///
/// Writes final 4 bytes of state to output.
#[inline]
pub fn rans_enc_flush(r: &RansState, pptr: &mut *mut u8) {
    let x = *r;

    unsafe {
        let ptr = *pptr;
        let ptr = ptr.sub(4);
        *ptr.add(0) = (x >> 0) as u8;
        *ptr.add(1) = (x >> 8) as u8;
        *ptr.add(2) = (x >> 16) as u8;
        *ptr.add(3) = (x >> 24) as u8;
        *pptr = ptr;
    }
}

// ============================================================================
// Decoder
// ============================================================================

/// Initialize rANS decoder
///
/// Returns 0 on success, 1 if initial state is out of range.
#[inline]
pub fn rans_dec_init(r: &mut RansState, pptr: &mut *const u8) -> i32 {
    unsafe {
        let ptr = *pptr;
        let x = (*ptr.add(0) as u32) << 0
              | (*ptr.add(1) as u32) << 8
              | (*ptr.add(2) as u32) << 16
              | (*ptr.add(3) as u32) << 24;

        if x < RANS_BYTE_L || (RANS_BYTE_L << 8) <= x {
            return 1; // Initial state out of range
        }

        *pptr = ptr.add(4);
        *r = x;
    }
    0
}

/// Get current cumulative frequency
///
/// Returns the value to map to a symbol via lookup table.
#[inline]
pub fn rans_dec_get(r: &RansState, scale_bits: u32) -> u32 {
    *r & ((1u32 << scale_bits) - 1)
}

/// Advance decoder by one symbol
///
/// "Pops" a single symbol with range start "start" and frequency "freq".
#[inline]
pub fn rans_dec_advance(
    r: &mut RansState,
    pptr: &mut *const u8,
    end: *const u8,
    start: u32,
    freq: u32,
    scale_bits: u32
) {
    let mask = (1u32 << scale_bits) - 1;

    // s, x = D(x)
    let mut x = *r;
    x = freq * (x >> scale_bits) + (x & mask) - start;

    // Renormalize
    unsafe {
        if x < RANS_BYTE_L && *pptr < end {
            let mut ptr = *pptr;
            while x < RANS_BYTE_L && ptr < end {
                x = (x << 8) | (*ptr as u32);
                ptr = ptr.add(1);
            }
            *pptr = ptr;
        }
    }

    *r = x;
}

/// Verify final decoder state
///
/// Returns 0 if final state matches initial state, 1 otherwise.
#[inline]
pub fn rans_dec_verify(r: &RansState) -> i32 {
    if *r != RANS_BYTE_L {
        return 1; // Final state inconsistent with initial state
    }
    0
}

// ============================================================================
// Symbol descriptions for optimized encoding/decoding
// ============================================================================

/// Encoder symbol description
///
/// Precomputed parameters for fast encoding without division.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RansEncSymbol {
    pub x_max: u32,      // (Exclusive) upper bound of pre-normalization interval
    pub rcp_freq: u32,   // Fixed-point reciprocal frequency
    pub bias: u32,       // Bias
    pub cmpl_freq: u16,  // Complement of frequency: (1 << scale_bits) - freq
    pub rcp_shift: u16,  // Reciprocal shift
}

/// Decoder symbol description
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RansDecSymbol {
    pub start: u16,  // Start of range
    pub freq: u16,   // Symbol frequency
}

/// Encode symbol using precomputed parameters (faster than RansEncPut)
#[inline]
pub fn rans_enc_put_symbol(r: &mut RansState, pptr: &mut *mut u8, sym: &RansEncSymbol) {
    debug_assert!(sym.x_max != 0); // Can't encode symbol with freq=0

    // Renormalize
    let mut x = *r;
    let x_max = sym.x_max;

    if x >= x_max {
        unsafe {
            let mut ptr = *pptr;
            while x >= x_max {
                ptr = ptr.sub(1);
                *ptr = (x & 0xff) as u8;
                x >>= 8;
            }
            *pptr = ptr;
        }
    }

    // x = C(s,x)
    // Written to get 32-bit "multiply high" when available
    let q = (((x as u64) * (sym.rcp_freq as u64)) >> 32) as u32 >> sym.rcp_shift;
    *r = x + sym.bias + q * (sym.cmpl_freq as u32);
}

/// Advance decoder using symbol description
#[inline]
pub fn rans_dec_advance_symbol(
    r: &mut RansState,
    pptr: &mut *const u8,
    end: *const u8,
    sym: &RansDecSymbol,
    scale_bits: u32
) {
    rans_dec_advance(r, pptr, end, sym.start as u32, sym.freq as u32, scale_bits);
}

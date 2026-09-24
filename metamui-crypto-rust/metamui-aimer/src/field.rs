//! GF(2^n) field arithmetic for AIM
//!
//! Supports GF(2^128), GF(2^192), GF(2^256) with the following irreducible polynomials:
//! - GF(2^128): x^128 + x^7 + x^2 + x + 1
//! - GF(2^192): x^192 + x^7 + x^2 + x + 1
//! - GF(2^256): x^256 + x^10 + x^5 + x^2 + 1
//!
//! Elements are stored as little-endian byte arrays (byte 0 = lowest coefficients).
//! Internally uses u64 limbs for efficient arithmetic.

use alloc::vec;
use alloc::vec::Vec;

/// Add two field elements (XOR). Result written to `result`.
pub fn gf_add(a: &[u8], b: &[u8], result: &mut [u8]) {
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
}

/// Add two field elements, returning a new Vec.
pub fn gf_add_alloc(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; a.len()];
    gf_add(a, b, &mut result);
    result
}

/// Check if a field element is zero.
pub fn gf_is_zero(a: &[u8]) -> bool {
    a.iter().all(|&b| b == 0)
}

/// Multiply two field elements in GF(2^n).
pub fn gf_mul(a: &[u8], b: &[u8], field_size: usize) -> Vec<u8> {
    let a_limbs = bytes_to_limbs(a);
    let b_limbs = bytes_to_limbs(b);
    let mut product = poly_mul(&a_limbs, &b_limbs);
    reduce(&mut product, field_size);
    limbs_to_bytes(&product, field_size)
}

/// Square a field element in GF(2^n).
/// Squaring is a linear operation (Frobenius endomorphism) and can be optimized.
pub fn gf_square(a: &[u8], field_size: usize) -> Vec<u8> {
    let a_limbs = bytes_to_limbs(a);
    let n_limbs = a_limbs.len();
    let mut product = vec![0u64; 2 * n_limbs];

    // Square each limb: expand bits so bit k -> bit 2k
    for i in 0..n_limbs {
        let (lo, hi) = square_u64(a_limbs[i]);
        product[2 * i] ^= lo;
        product[2 * i + 1] ^= hi;
    }

    reduce(&mut product, field_size);
    limbs_to_bytes(&product, field_size)
}

/// Compute the multiplicative inverse in GF(2^n) using Fermat's little theorem.
/// a^(-1) = a^(2^n - 2) for a != 0.
///
/// Uses the identity: 2^n - 2 = sum of 2^i for i = 1 to n-1.
/// So a^(2^n-2) = a^2 * a^4 * a^8 * ... * a^(2^(n-1)).
pub fn gf_inverse(a: &[u8], field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }

    let n = field_size * 8; // number of bits

    // result = a^2
    let mut result = gf_square(a, field_size);
    // power tracks a^(2^i), starting at a^2
    let mut power = result.clone();

    // Multiply in a^(2^i) for i = 2, 3, ..., n-1
    for _ in 2..n {
        power = gf_square(&power, field_size);
        result = gf_mul(&result, &power, field_size);
    }

    result
}

/// Compute a^(2^e - 1) in GF(2^n) — the forward Mersenne power map.
///
/// Uses the identity: 2^e - 1 = 1 + 2 + 4 + ... + 2^(e-1), so
/// a^(2^e - 1) = a^1 * a^2 * a^4 * ... * a^(2^(e-1))
///             = product of a^(2^i) for i = 0 to e-1.
///
/// Returns zero for zero input (convention: 0^k = 0).
pub fn gf_power_mersenne(a: &[u8], exponent_e: usize, field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }
    assert!(exponent_e >= 1, "Mersenne exponent must be >= 1");

    // result starts at a^(2^0) = a
    let mut result = a.to_vec();
    // power tracks a^(2^i), starting at a^(2^0) = a
    let mut power = a.to_vec();

    for _ in 1..exponent_e {
        power = gf_square(&power, field_size);
        result = gf_mul(&result, &power, field_size);
    }

    result
}

/// Compute a^exp in GF(2^n) where exp is a big integer in little-endian byte form.
///
/// Uses left-to-right square-and-multiply. Returns 1 (identity) for exp=0.
pub fn gf_power_exp(a: &[u8], exp: &[u8], field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }

    // Find the highest set bit in exp
    let mut highest_bit: Option<usize> = None;
    for i in (0..exp.len()).rev() {
        if exp[i] != 0 {
            highest_bit = Some(i * 8 + 7 - exp[i].leading_zeros() as usize);
            break;
        }
    }

    let highest_bit = match highest_bit {
        Some(b) => b,
        None => {
            // exp == 0, return 1
            let mut one = vec![0u8; field_size];
            one[0] = 1;
            return one;
        }
    };

    // Square-and-multiply from highest bit down
    let mut result = vec![0u8; field_size];
    result[0] = 1; // multiplicative identity

    for bit in (0..=highest_bit).rev() {
        result = gf_square(&result, field_size);
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        if exp[byte_idx] & (1 << bit_idx) != 0 {
            result = gf_mul(&result, a, field_size);
        }
    }

    result
}

/// Compute a^((2^e - 1)^(-1) mod (2^n - 1)) in GF(2^n) — the inverse Mersenne power map.
///
/// This is the functional inverse of `gf_power_mersenne`: if y = x^(2^e - 1),
/// then x = gf_power_mersenne_inverse(y, e, field_size).
///
/// The inverse exponent d satisfies d * (2^e - 1) ≡ 1 (mod 2^n - 1).
/// It exists when gcd(2^e - 1, 2^n - 1) = 1, i.e., when gcd(e, n) = 1.
/// (For AIM2, all n are powers of 2 and all e are odd, so gcd(e, n) = 1 always holds.)
pub fn gf_power_mersenne_inverse(a: &[u8], exponent_e: usize, field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }
    let n = field_size * 8;
    assert!(exponent_e >= 1, "Mersenne exponent must be >= 1");

    // Compute the inverse exponent d = modinv(2^e - 1, 2^n - 1)
    let d = mersenne_inverse_exponent(exponent_e, n);
    gf_power_exp(a, &d, field_size)
}

// ============================================================================
// Big-integer helpers for Mersenne inverse exponent computation
// ============================================================================

/// Compute d = (2^e - 1)^(-1) mod (2^n - 1) as a little-endian byte array.
///
/// Uses the binary extended GCD (Stein's algorithm variant) which only requires
/// shifts, additions, subtractions, and comparisons on big integers.
/// Handles arbitrary exponent sizes (e up to n-1).
fn mersenne_inverse_exponent(e: usize, n: usize) -> Vec<u8> {
    let n_bytes = (n + 7) / 8;
    let n_limbs = (n + 63) / 64;

    // Build a = 2^e - 1 as limbs
    let a_limbs = make_mersenne(e, n_limbs);
    // Build m = 2^n - 1 as limbs
    let m_limbs = make_mersenne(n, n_limbs);

    // Use binary extended GCD to compute a^(-1) mod m
    // Algorithm: adapted Stein's algorithm for modular inverse
    //
    // We maintain: u, v (working towards gcd)
    //              x1 ≡ a^(-1) * u (mod m), x2 ≡ a^(-1) * v (mod m)
    // but we track x1 and x2 directly where:
    //   x1 starts at 1 (since u starts at a, and a^(-1)*a = 1 mod m)
    //   x2 starts at 0 (since v starts at m, and a^(-1)*m = 0 mod m)

    let mut u = a_limbs.clone();
    let mut v = m_limbs.clone();
    let mut x1 = vec![0u64; n_limbs + 1]; x1[0] = 1;
    let mut x2 = vec![0u64; n_limbs + 1];

    while !big_is_zero(&u) && !big_is_zero(&v) {
        // While u is even
        while u[0] & 1 == 0 {
            big_shr1(&mut u);
            if x1[0] & 1 == 0 {
                big_shr1(&mut x1);
            } else {
                big_add_inplace(&mut x1, &m_limbs);
                big_shr1(&mut x1);
            }
        }

        // While v is even
        while v[0] & 1 == 0 {
            big_shr1(&mut v);
            if x2[0] & 1 == 0 {
                big_shr1(&mut x2);
            } else {
                big_add_inplace(&mut x2, &m_limbs);
                big_shr1(&mut x2);
            }
        }

        // Subtract the smaller from the larger
        match big_cmp(&u, &v) {
            core::cmp::Ordering::Greater | core::cmp::Ordering::Equal => {
                big_sub_inplace(&mut u, &v);
                // x1 = x1 - x2 mod m
                if big_cmp(&x1, &x2) != core::cmp::Ordering::Less {
                    big_sub_inplace(&mut x1, &x2);
                } else {
                    big_add_inplace(&mut x1, &m_limbs);
                    big_sub_inplace(&mut x1, &x2);
                }
            }
            core::cmp::Ordering::Less => {
                big_sub_inplace(&mut v, &u);
                if big_cmp(&x2, &x1) != core::cmp::Ordering::Less {
                    big_sub_inplace(&mut x2, &x1);
                } else {
                    big_add_inplace(&mut x2, &m_limbs);
                    big_sub_inplace(&mut x2, &x1);
                }
            }
        }
    }

    // The GCD is whichever of u, v is non-zero (should be 1)
    let result = if big_is_zero(&u) { &x2 } else { &x1 };

    // Reduce mod m if needed
    let mut d = result.to_vec();
    while big_cmp(&d, &m_limbs) != core::cmp::Ordering::Less {
        big_sub_inplace(&mut d, &m_limbs);
    }

    // Convert limbs to bytes
    let mut bytes = vec![0u8; n_bytes];
    for i in 0..n_bytes {
        let limb_idx = i / 8;
        let byte_idx = i % 8;
        if limb_idx < d.len() {
            bytes[i] = (d[limb_idx] >> (byte_idx * 8)) as u8;
        }
    }

    bytes
}

/// Build the Mersenne number 2^e - 1 as little-endian u64 limbs.
fn make_mersenne(e: usize, min_limbs: usize) -> Vec<u64> {
    let n_limbs = core::cmp::max((e + 63) / 64, min_limbs);
    let mut limbs = vec![0u64; n_limbs];

    // Set all bits below position e to 1
    let full_limbs = e / 64;
    let remaining_bits = e % 64;

    for i in 0..full_limbs {
        if i < n_limbs {
            limbs[i] = u64::MAX;
        }
    }
    if remaining_bits > 0 && full_limbs < n_limbs {
        limbs[full_limbs] = (1u64 << remaining_bits) - 1;
    }

    limbs
}

/// Right-shift a big number by 1 bit in place.
fn big_shr1(a: &mut [u64]) {
    let mut carry = 0u64;
    for i in (0..a.len()).rev() {
        let new_carry = a[i] & 1;
        a[i] = (a[i] >> 1) | (carry << 63);
        carry = new_carry;
    }
}

/// Add b to a in place: a += b
fn big_add_inplace(a: &mut Vec<u64>, b: &[u64]) {
    let len = core::cmp::max(a.len(), b.len());
    while a.len() < len + 1 {
        a.push(0);
    }
    let mut carry: u64 = 0;
    for i in 0..len {
        let bi = if i < b.len() { b[i] } else { 0 };
        let sum = a[i] as u128 + bi as u128 + carry as u128;
        a[i] = sum as u64;
        carry = (sum >> 64) as u64;
    }
    if carry > 0 && len < a.len() {
        a[len] = a[len].wrapping_add(carry);
    }
}

/// Subtract b from a in place: a -= b (assumes a >= b)
fn big_sub_inplace(a: &mut [u64], b: &[u64]) {
    let mut borrow: u64 = 0;
    for i in 0..a.len() {
        let bi = if i < b.len() { b[i] } else { 0 };
        let (diff, borrow1) = a[i].overflowing_sub(bi);
        let (diff2, borrow2) = diff.overflowing_sub(borrow);
        a[i] = diff2;
        borrow = (borrow1 as u64) + (borrow2 as u64);
    }
}

/// Compare two unsigned big numbers (little-endian limbs).
fn big_cmp(a: &[u64], b: &[u64]) -> core::cmp::Ordering {
    let a_len = a.iter().rposition(|&x| x != 0).map(|i| i + 1).unwrap_or(0);
    let b_len = b.iter().rposition(|&x| x != 0).map(|i| i + 1).unwrap_or(0);

    if a_len != b_len {
        return a_len.cmp(&b_len);
    }

    for i in (0..a_len).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }

    core::cmp::Ordering::Equal
}

/// Check if a big number is zero.
fn big_is_zero(a: &[u64]) -> bool {
    a.iter().all(|&x| x == 0)
}

/// Multiply a binary (GF(2)) matrix by a field element (treated as a bit vector).
/// The matrix is stored row-major: matrix[row] is a byte-array of length field_size.
/// Output bit i = parity of (matrix_row_i AND input).
pub fn binary_matrix_mul(matrix: &[Vec<u8>], input: &[u8], field_size: usize) -> Vec<u8> {
    let n_bits = field_size * 8;
    let mut output = vec![0u8; field_size];

    for i in 0..n_bits {
        let row = &matrix[i];
        // Compute parity of (row AND input)
        let mut parity = 0u8;
        for j in 0..field_size {
            parity ^= row[j] & input[j];
        }
        // parity now has XOR of all matched bits in each byte position
        // We need the overall parity (XOR of all bits)
        parity = byte_parity(parity);

        // Set bit i of output
        if parity != 0 {
            output[i / 8] |= 1 << (i % 8);
        }
    }

    output
}

/// Binary matrix-vector multiply using u64 word operations and popcount parity.
///
/// 8x fewer operations than byte-level version (u64 AND vs u8 AND), plus
/// hardware popcount for parity computation. Zero allocation.
///
/// `matrix_limbs` must be precomputed: each row is [u64; 4] (max 256 bits).
pub fn binary_matrix_mul_limbs(
    matrix_limbs: &[[u64; 4]],
    input_limbs: &[u64; 4],
    n_limbs: usize,
    output: &mut [u64; 4],
) {
    let n_bits = n_limbs * 64;
    *output = [0u64; 4];

    for i in 0..n_bits {
        // Dot product: AND each limb pair, XOR results, popcount for parity
        let mut dot = 0u64;
        for k in 0..n_limbs {
            dot ^= matrix_limbs[i][k] & input_limbs[k];
        }
        // Parity = XOR of all bits in dot = popcount mod 2
        if dot.count_ones() & 1 != 0 {
            output[i / 64] |= 1u64 << (i % 64);
        }
    }
}

/// Precompute matrix rows as [u64; 4] limb arrays for binary_matrix_mul_limbs.
pub fn precompute_matrix_limbs(matrix: &[Vec<u8>], n_bits: usize) -> Vec<[u64; 4]> {
    let mut result = Vec::with_capacity(n_bits);
    for i in 0..n_bits {
        let limbs = bytes_to_limbs(&matrix[i]);
        let mut arr = [0u64; 4];
        for k in 0..limbs.len().min(4) {
            arr[k] = limbs[k];
        }
        result.push(arr);
    }
    result
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Convert bytes (little-endian) to u64 limbs (little-endian).
fn bytes_to_limbs(bytes: &[u8]) -> Vec<u64> {
    let n_limbs = (bytes.len() + 7) / 8;
    let mut limbs = vec![0u64; n_limbs];
    for i in 0..bytes.len() {
        limbs[i / 8] |= (bytes[i] as u64) << ((i % 8) * 8);
    }
    limbs
}

/// Convert u64 limbs back to bytes, truncating to field_size bytes.
fn limbs_to_bytes(limbs: &[u64], field_size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; field_size];
    let n_limbs = (field_size + 7) / 8;
    for i in 0..field_size {
        if i / 8 < n_limbs && i / 8 < limbs.len() {
            bytes[i] = (limbs[i / 8] >> ((i % 8) * 8)) as u8;
        }
    }
    bytes
}

/// Software carry-less multiply of two u64 values -> (lo, hi).
///
/// This is the only carry-less multiply in this crate: portable scalar
/// shifts and XORs, the same on every target. There is no PCLMULQDQ or
/// PMULL path and no CPU-feature detection. It is also the oracle a
/// hardware implementation maintained elsewhere is measured against.
pub fn clmul_u64_soft(a: u64, b: u64) -> (u64, u64) {
    let mut lo: u64 = 0;
    let mut hi: u64 = 0;

    if b & 1 != 0 {
        lo ^= a;
    }
    for i in 1..64 {
        if b & (1u64 << i) != 0 {
            lo ^= a << i;
            hi ^= a >> (64 - i);
        }
    }
    (lo, hi)
}

/// Carry-less multiply: [`clmul_u64_soft`], the software implementation.
/// This is the inner operation of every field multiplication here.
#[inline(always)]
fn clmul_u64(a: u64, b: u64) -> (u64, u64) {
    clmul_u64_soft(a, b)
}

/// Polynomial multiplication of two multi-limb polynomials over GF(2).
fn poly_mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    let na = a.len();
    let nb = b.len();
    let mut result = vec![0u64; na + nb];

    for i in 0..na {
        if a[i] == 0 {
            continue;
        }
        for j in 0..nb {
            if b[j] == 0 {
                continue;
            }
            let (lo, hi) = clmul_u64(a[i], b[j]);
            result[i + j] ^= lo;
            result[i + j + 1] ^= hi;
        }
    }
    result
}

/// Square a u64: expand bits so bit k -> bit 2k. Returns (lo, hi).
fn square_u64(a: u64) -> (u64, u64) {
    let lo = expand_bits(a as u32);
    let hi = expand_bits((a >> 32) as u32);
    (lo, hi)
}

/// Expand 32 bits into 64 bits by inserting a zero after each bit.
fn expand_bits(a: u32) -> u64 {
    let mut x: u64 = a as u64;
    x = (x | (x << 16)) & 0x0000FFFF0000FFFF;
    x = (x | (x << 8)) & 0x00FF00FF00FF00FF;
    x = (x | (x << 4)) & 0x0F0F0F0F0F0F0F0F;
    x = (x | (x << 2)) & 0x3333333333333333;
    x = (x | (x << 1)) & 0x5555555555555555;
    x
}

/// Reduce a polynomial modulo the irreducible polynomial for the given field size.
fn reduce(product: &mut Vec<u64>, field_size: usize) {
    match field_size {
        16 => reduce_128(product),
        24 => reduce_192(product),
        32 => reduce_256(product),
        _ => panic!("Unsupported field size: {}", field_size),
    }
    // Truncate to the correct number of limbs
    let n_limbs = (field_size + 7) / 8;
    product.truncate(n_limbs);
}

/// Reduce modulo x^128 + x^7 + x^2 + x + 1.
fn reduce_128(p: &mut Vec<u64>) {
    // Ensure we have at least 4 limbs
    while p.len() < 4 {
        p.push(0);
    }

    // Process limb 3 (bits 192-255): x^(192+j) -> x^(64+j) ^ x^(65+j) ^ x^(66+j) ^ x^(71+j)
    let t = p[3];
    if t != 0 {
        p[1] ^= t;
        p[1] ^= t << 1;
        p[2] ^= t >> 63;
        p[1] ^= t << 2;
        p[2] ^= t >> 62;
        p[1] ^= t << 7;
        p[2] ^= t >> 57;
        p[3] = 0;
    }

    // Process limb 2 (bits 128-191): x^(128+j) -> x^j ^ x^(j+1) ^ x^(j+2) ^ x^(j+7)
    let t = p[2];
    if t != 0 {
        p[0] ^= t;
        p[0] ^= t << 1;
        p[1] ^= t >> 63;
        p[0] ^= t << 2;
        p[1] ^= t >> 62;
        p[0] ^= t << 7;
        p[1] ^= t >> 57;
        p[2] = 0;
    }
}

/// Reduce modulo x^192 + x^7 + x^2 + x + 1.
fn reduce_192(p: &mut Vec<u64>) {
    while p.len() < 6 {
        p.push(0);
    }

    // Process limb 5 (bits 320-383): fold into limbs 2-3
    let t = p[5];
    if t != 0 {
        p[2] ^= t;
        p[2] ^= t << 1;
        p[3] ^= t >> 63;
        p[2] ^= t << 2;
        p[3] ^= t >> 62;
        p[2] ^= t << 7;
        p[3] ^= t >> 57;
        p[5] = 0;
    }

    // Process limb 4 (bits 256-319): fold into limbs 1-2
    let t = p[4];
    if t != 0 {
        p[1] ^= t;
        p[1] ^= t << 1;
        p[2] ^= t >> 63;
        p[1] ^= t << 2;
        p[2] ^= t >> 62;
        p[1] ^= t << 7;
        p[2] ^= t >> 57;
        p[4] = 0;
    }

    // Process limb 3 (bits 192-255): fold into limbs 0-1
    let t = p[3];
    if t != 0 {
        p[0] ^= t;
        p[0] ^= t << 1;
        p[1] ^= t >> 63;
        p[0] ^= t << 2;
        p[1] ^= t >> 62;
        p[0] ^= t << 7;
        p[1] ^= t >> 57;
        p[3] = 0;
    }
}

/// Reduce modulo x^256 + x^10 + x^5 + x^2 + 1.
fn reduce_256(p: &mut Vec<u64>) {
    while p.len() < 8 {
        p.push(0);
    }

    // Process from highest limb down to limb 4
    // x^(256+k) = x^k ^ x^(k+2) ^ x^(k+5) ^ x^(k+10)
    for i in (4..8).rev() {
        let t = p[i];
        if t == 0 {
            continue;
        }
        let base = i - 4;
        p[base] ^= t;
        p[base] ^= t << 2;
        p[base + 1] ^= t >> 62;
        p[base] ^= t << 5;
        p[base + 1] ^= t >> 59;
        p[base] ^= t << 10;
        p[base + 1] ^= t >> 54;
        p[i] = 0;
    }
}

/// Compute the parity (XOR of all bits) of a byte.
fn byte_parity(mut b: u8) -> u8 {
    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    b & 1
}

// ============================================================================
// Allocation-free field operations for hot paths
//
// These operate on u64 limb slices in-place, avoiding the ~4.7M heap
// allocations per AIM2er-I signature from the byte-based API.
// ============================================================================

/// Public wrappers for allocation-free limb operations (used by signing hot path).
pub fn bytes_to_limbs_pub(bytes: &[u8]) -> Vec<u64> { bytes_to_limbs(bytes) }
pub fn limbs_to_bytes_pub(limbs: &[u64], field_size: usize) -> Vec<u8> { limbs_to_bytes(limbs, field_size) }
pub fn square_limbs_pub(a: &[u64], product: &mut [u64], field_size: usize) { square_limbs(a, product, field_size) }

/// Fused GF(2^128) multiply: schoolbook 2×2 limbs + inline reduction, zero allocation.
/// Uses 4 CLMUL instructions (Karatsuba's 3 is not faster due to low PMULL latency
/// on Apple Silicon — the XOR overhead for cross-terms exceeds the saved CLMUL).
#[inline(always)]
pub fn gf128_mul_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    let mut p = [0u64; 4];
    // Schoolbook 2×2: 4 CLMUL instructions
    let (lo, hi) = clmul_u64(a[0], b[0]); p[0] ^= lo; p[1] ^= hi;
    let (lo, hi) = clmul_u64(a[0], b[1]); p[1] ^= lo; p[2] ^= hi;
    let (lo, hi) = clmul_u64(a[1], b[0]); p[1] ^= lo; p[2] ^= hi;
    let (lo, hi) = clmul_u64(a[1], b[1]); p[2] ^= lo; p[3] ^= hi;

    // Inline reduction mod x^128 + x^7 + x^2 + x + 1
    let t = p[3];
    if t != 0 {
        p[1] ^= t; p[1] ^= t << 1; p[2] ^= t >> 63;
        p[1] ^= t << 2; p[2] ^= t >> 62;
        p[1] ^= t << 7; p[2] ^= t >> 57;
    }
    let t = p[2];
    if t != 0 {
        p[0] ^= t; p[0] ^= t << 1; p[1] ^= t >> 63;
        p[0] ^= t << 2; p[1] ^= t >> 62;
        p[0] ^= t << 7; p[1] ^= t >> 57;
    }
    out[0] = p[0];
    out[1] = p[1];
}

/// Fused GF(2^192) multiply: schoolbook 3×3 limbs + inline reduction, zero allocation.
#[inline(always)]
pub fn gf192_mul_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    let mut p = [0u64; 6];
    for i in 0..3 {
        if a[i] == 0 { continue; }
        for j in 0..3 {
            if b[j] == 0 { continue; }
            let (lo, hi) = clmul_u64(a[i], b[j]);
            p[i + j] ^= lo;
            p[i + j + 1] ^= hi;
        }
    }
    // Reduce mod x^192 + x^7 + x^2 + x + 1
    reduce_192_slice(&mut p);
    out[0] = p[0]; out[1] = p[1]; out[2] = p[2];
}

/// Fused GF(2^256) multiply: schoolbook 4×4 limbs + inline reduction, zero allocation.
#[inline(always)]
pub fn gf256_mul_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    let mut p = [0u64; 8];
    for i in 0..4 {
        if a[i] == 0 { continue; }
        for j in 0..4 {
            if b[j] == 0 { continue; }
            let (lo, hi) = clmul_u64(a[i], b[j]);
            p[i + j] ^= lo;
            p[i + j + 1] ^= hi;
        }
    }
    reduce_256_slice(&mut p);
    out[0] = p[0]; out[1] = p[1]; out[2] = p[2]; out[3] = p[3];
}

/// Dispatch fused multiply by field size (zero-allocation, limb-native).
pub fn gf_mul_limbs(a: &[u64], b: &[u64], out: &mut [u64], field_size: usize) {
    match field_size {
        16 => gf128_mul_limbs(a, b, out),
        24 => gf192_mul_limbs(a, b, out),
        32 => gf256_mul_limbs(a, b, out),
        _ => panic!("Unsupported field size: {}", field_size),
    }
}

/// Square a field element in-place on limbs (no allocation).
/// Overwrites `product` (must be 2*n_limbs long), then reduces in-place.
fn square_limbs(a: &[u64], product: &mut [u64], field_size: usize) {
    let n_limbs = a.len();
    for i in 0..product.len() {
        product[i] = 0;
    }
    for i in 0..n_limbs {
        let (lo, hi) = square_u64(a[i]);
        product[2 * i] = lo;
        product[2 * i + 1] = hi;
    }
    reduce_slice(product, field_size);
}


/// Reduce a mutable limb slice in-place (no Vec required).
fn reduce_slice(p: &mut [u64], field_size: usize) {
    match field_size {
        16 => reduce_128_slice(p),
        24 => reduce_192_slice(p),
        32 => reduce_256_slice(p),
        _ => panic!("Unsupported field size: {}", field_size),
    }
}

fn reduce_128_slice(p: &mut [u64]) {
    if p.len() >= 4 {
        let t = p[3];
        if t != 0 {
            p[1] ^= t; p[1] ^= t << 1; p[2] ^= t >> 63;
            p[1] ^= t << 2; p[2] ^= t >> 62;
            p[1] ^= t << 7; p[2] ^= t >> 57;
            p[3] = 0;
        }
    }
    if p.len() >= 3 {
        let t = p[2];
        if t != 0 {
            p[0] ^= t; p[0] ^= t << 1; p[1] ^= t >> 63;
            p[0] ^= t << 2; p[1] ^= t >> 62;
            p[0] ^= t << 7; p[1] ^= t >> 57;
            p[2] = 0;
        }
    }
}

fn reduce_192_slice(p: &mut [u64]) {
    if p.len() >= 6 {
        let t = p[5];
        if t != 0 {
            p[2] ^= t; p[2] ^= t << 1; p[3] ^= t >> 63;
            p[2] ^= t << 2; p[3] ^= t >> 62;
            p[2] ^= t << 7; p[3] ^= t >> 57;
            p[5] = 0;
        }
    }
    if p.len() >= 5 {
        let t = p[4];
        if t != 0 {
            p[1] ^= t; p[1] ^= t << 1; p[2] ^= t >> 63;
            p[1] ^= t << 2; p[2] ^= t >> 62;
            p[1] ^= t << 7; p[2] ^= t >> 57;
            p[4] = 0;
        }
    }
    if p.len() >= 4 {
        let t = p[3];
        if t != 0 {
            p[0] ^= t; p[0] ^= t << 1; p[1] ^= t >> 63;
            p[0] ^= t << 2; p[1] ^= t >> 62;
            p[0] ^= t << 7; p[1] ^= t >> 57;
            p[3] = 0;
        }
    }
}

fn reduce_256_slice(p: &mut [u64]) {
    for i in (4..core::cmp::min(p.len(), 8)).rev() {
        let t = p[i];
        if t == 0 { continue; }
        let base = i - 4;
        p[base] ^= t;
        p[base] ^= t << 2; p[base + 1] ^= t >> 62;
        p[base] ^= t << 5; p[base + 1] ^= t >> 59;
        p[base] ^= t << 10; p[base + 1] ^= t >> 54;
        p[i] = 0;
    }
}

/// Compute a^(2^e - 1) in GF(2^n) using allocation-free limb operations.
///
/// This is the hot-path optimization for gf_power_mersenne. Instead of
/// allocating ~6e Vec<u64> per call, uses fixed-size stack buffers.
/// For AIM2er-I with e=91, this eliminates ~546 heap allocations per S-box.
pub fn gf_power_mersenne_fast(a: &[u8], exponent_e: usize, field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }
    assert!(exponent_e >= 1);

    let n_limbs = (field_size + 7) / 8;
    let product_limbs = 2 * n_limbs;

    let a_limbs = bytes_to_limbs(a);

    // Working buffers on the stack (max 8 limbs for GF(2^256))
    let mut result = [0u64; 8];
    let mut power = [0u64; 8];
    let mut scratch = [0u64; 16]; // product buffer

    // Initialize result = a, power = a
    for i in 0..n_limbs {
        result[i] = a_limbs[i];
        power[i] = a_limbs[i];
    }

    for _ in 1..exponent_e {
        // power = power^2 (in-place via scratch)
        square_limbs(&power[..n_limbs], &mut scratch[..product_limbs], field_size);
        for i in 0..n_limbs {
            power[i] = scratch[i];
        }

        // result = result * power using fused Karatsuba (no intermediate alloc)
        let mut mul_out = [0u64; 8];
        gf_mul_limbs(&result[..n_limbs], &power[..n_limbs], &mut mul_out[..n_limbs], field_size);
        for i in 0..n_limbs {
            result[i] = mul_out[i];
        }
    }

    limbs_to_bytes(&result[..n_limbs], field_size)
}

/// Compute a^exp (big-integer exponent) using allocation-free limb operations.
pub fn gf_power_exp_fast(a: &[u8], exp: &[u8], field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }

    let n_limbs = (field_size + 7) / 8;
    let product_limbs = 2 * n_limbs;

    // Find the highest set bit in exp
    let mut highest_bit: Option<usize> = None;
    for i in (0..exp.len()).rev() {
        if exp[i] != 0 {
            for b in (0..8).rev() {
                if exp[i] & (1u8 << b) != 0 {
                    highest_bit = Some(i * 8 + b);
                    break;
                }
            }
            break;
        }
    }
    let highest_bit = match highest_bit {
        Some(b) => b,
        None => return { let mut one = vec![0u8; field_size]; one[0] = 1; one },
    };

    let a_limbs = bytes_to_limbs(a);
    let mut result = [0u64; 8];
    let mut base = [0u64; 8];
    let mut scratch = [0u64; 16];

    // Initialize result = 1, base = a
    result[0] = 1;
    for i in 0..n_limbs {
        base[i] = a_limbs[i];
    }

    // Left-to-right square-and-multiply
    for bit_pos in (0..=highest_bit).rev() {
        // result = result^2
        square_limbs(&result[..n_limbs], &mut scratch[..product_limbs], field_size);
        for i in 0..n_limbs {
            result[i] = scratch[i];
        }

        // If bit is set, result *= base
        let byte_idx = bit_pos / 8;
        let bit_idx = bit_pos % 8;
        if exp[byte_idx] & (1u8 << bit_idx) != 0 {
            let mut mul_out = [0u64; 8];
            gf_mul_limbs(&result[..n_limbs], &base[..n_limbs], &mut mul_out[..n_limbs], field_size);
            for i in 0..n_limbs {
                result[i] = mul_out[i];
            }
        }
    }

    limbs_to_bytes(&result[..n_limbs], field_size)
}

/// Compute the inverse Mersenne map using allocation-free operations.
pub fn gf_power_mersenne_inverse_fast(a: &[u8], exponent_e: usize, field_size: usize) -> Vec<u8> {
    if gf_is_zero(a) {
        return vec![0u8; field_size];
    }
    let n = field_size * 8;
    assert!(exponent_e >= 1);

    let d = mersenne_inverse_exponent(exponent_e, n);
    gf_power_exp_fast(a, &d, field_size)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf128_add() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        let mut c = [0u8; 16];
        gf_add(&a, &b, &mut c);
        assert_eq!(c, [3u8; 16]);
    }

    #[test]
    fn test_gf128_mul_by_zero() {
        let a = [0x42u8; 16];
        let zero = [0u8; 16];
        let result = gf_mul(&a, &zero, 16);
        assert_eq!(result, vec![0u8; 16]);
    }

    #[test]
    fn test_gf128_mul_by_one() {
        let a = [0x42u8; 16];
        // Multiplicative identity in GF(2^128) is the polynomial 1,
        // which is byte 0 = 0x01, rest = 0x00
        let mut one = [0u8; 16];
        one[0] = 1;
        let result = gf_mul(&a, &one, 16);
        assert_eq!(&result[..], &a[..]);
    }

    #[test]
    fn test_gf128_square_of_one() {
        let mut one = [0u8; 16];
        one[0] = 1;
        let result = gf_square(&one, 16);
        assert_eq!(&result[..], &one[..]);
    }

    #[test]
    fn test_gf128_inverse() {
        // Test that a * a^(-1) = 1 for a non-trivial element
        let a = [0x42u8; 16];
        let inv = gf_inverse(&a, 16);

        let product = gf_mul(&a, &inv, 16);
        let mut expected_one = vec![0u8; 16];
        expected_one[0] = 1;
        assert_eq!(product, expected_one, "a * a^(-1) should equal 1 in GF(2^128)");
    }

    #[test]
    fn test_gf128_inverse_of_zero() {
        let zero = [0u8; 16];
        let inv = gf_inverse(&zero, 16);
        assert_eq!(inv, vec![0u8; 16]);
    }

    #[test]
    fn test_gf256_mul_by_one() {
        let a = [0x42u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        let result = gf_mul(&a, &one, 32);
        assert_eq!(&result[..], &a[..]);
    }

    #[test]
    fn test_gf256_inverse() {
        let a = [0x37u8; 32];
        let inv = gf_inverse(&a, 32);
        let product = gf_mul(&a, &inv, 32);
        let mut expected_one = vec![0u8; 32];
        expected_one[0] = 1;
        assert_eq!(product, expected_one, "a * a^(-1) should equal 1 in GF(2^256)");
    }

    #[test]
    fn test_gf192_inverse() {
        let a = [0x13u8; 24];
        let inv = gf_inverse(&a, 24);
        let product = gf_mul(&a, &inv, 24);
        let mut expected_one = vec![0u8; 24];
        expected_one[0] = 1;
        assert_eq!(product, expected_one, "a * a^(-1) should equal 1 in GF(2^192)");
    }

    #[test]
    fn test_gf128_mul_commutative() {
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();
        let b: Vec<u8> = (0..16).map(|i| (i * 31 + 7) as u8).collect();
        let ab = gf_mul(&a, &b, 16);
        let ba = gf_mul(&b, &a, 16);
        assert_eq!(ab, ba, "GF(2^128) multiplication should be commutative");
    }

    #[test]
    fn test_gf128_mul_associative() {
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();
        let b: Vec<u8> = (0..16).map(|i| (i * 31 + 7) as u8).collect();
        let c: Vec<u8> = (0..16).map(|i| (i * 43 + 11) as u8).collect();
        let ab = gf_mul(&a, &b, 16);
        let ab_c = gf_mul(&ab, &c, 16);
        let bc = gf_mul(&b, &c, 16);
        let a_bc = gf_mul(&a, &bc, 16);
        assert_eq!(ab_c, a_bc, "GF(2^128) multiplication should be associative");
    }

    #[test]
    fn test_square_equals_self_mul() {
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();
        let sq = gf_square(&a, 16);
        let mul = gf_mul(&a, &a, 16);
        assert_eq!(sq, mul, "a^2 should equal a * a");
    }

    #[test]
    fn test_expand_bits() {
        // 0b1010 = 10 -> expand -> 0b01000100 = 0x44
        assert_eq!(expand_bits(0b1010), 0b01000100);
        // 0b1111 = 15 -> expand -> 0b01010101
        assert_eq!(expand_bits(0b1111), 0b01010101);
        // 0b1 -> 0b1
        assert_eq!(expand_bits(1), 1);
        // 0 -> 0
        assert_eq!(expand_bits(0), 0);
    }

    #[test]
    fn test_byte_parity() {
        assert_eq!(byte_parity(0), 0);
        assert_eq!(byte_parity(1), 1);
        assert_eq!(byte_parity(0b11), 0);
        assert_eq!(byte_parity(0b111), 1);
        assert_eq!(byte_parity(0xFF), 0);
    }

    // ========================================================================
    // Mersenne power map tests (for AIM2)
    // ========================================================================

    #[test]
    fn test_mersenne_forward_e1_is_identity() {
        // x^(2^1 - 1) = x^1 = x
        let a = [0x42u8; 16];
        let result = gf_power_mersenne(&a, 1, 16);
        assert_eq!(&result[..], &a[..], "x^(2^1-1) should be x");
    }

    #[test]
    fn test_mersenne_forward_e_equals_n_relation() {
        // x^(2^n - 1) = x * x^(2^n - 2) = x * x^(-1) = 1 for non-zero x
        let a = [0x42u8; 16];
        let result = gf_power_mersenne(&a, 128, 16);
        let mut one = vec![0u8; 16];
        one[0] = 1;
        assert_eq!(result, one, "x^(2^n - 1) should equal 1 for non-zero x");
    }

    #[test]
    fn test_mersenne_forward_zero_input() {
        let zero = [0u8; 16];
        let result = gf_power_mersenne(&zero, 3, 16);
        assert_eq!(result, vec![0u8; 16], "0^k should be 0");
    }

    #[test]
    fn test_mersenne_roundtrip_e3_gf128() {
        // gcd(3, 128) = 1, so inverse uses modinv(7, 2^128-1)
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();

        let forward = gf_power_mersenne(&a, 3, 16);
        let recovered = gf_power_mersenne_inverse(&forward, 3, 16);
        assert_eq!(recovered, a, "inverse(forward(x)) should be x for e=3 in GF(2^128)");

        let inv_first = gf_power_mersenne_inverse(&a, 3, 16);
        let recovered2 = gf_power_mersenne(&inv_first, 3, 16);
        assert_eq!(recovered2, a, "forward(inverse(x)) should be x for e=3 in GF(2^128)");
    }

    #[test]
    fn test_mersenne_roundtrip_e5_gf192() {
        // gcd(5, 192) = 1, so inverse uses modinv(31, 2^192-1)
        let a: Vec<u8> = (0..24).map(|i| (i * 13 + 7) as u8).collect();

        let forward = gf_power_mersenne(&a, 5, 24);
        let recovered = gf_power_mersenne_inverse(&forward, 5, 24);
        assert_eq!(recovered, a, "roundtrip for e=5 in GF(2^192)");
    }

    #[test]
    fn test_mersenne_roundtrip_e7_gf256() {
        // gcd(7, 256) = 1, so inverse uses modinv(127, 2^256-1)
        let a: Vec<u8> = (0..32).map(|i| (i * 11 + 5) as u8).collect();

        let forward = gf_power_mersenne(&a, 7, 32);
        let recovered = gf_power_mersenne_inverse(&forward, 7, 32);
        assert_eq!(recovered, a, "roundtrip for e=7 in GF(2^256)");
    }

    #[test]
    fn test_mersenne_forward_e33_deterministic() {
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();
        let r1 = gf_power_mersenne(&a, 33, 16);
        let r2 = gf_power_mersenne(&a, 33, 16);
        assert_eq!(r1, r2, "Mersenne power should be deterministic");
    }

    #[test]
    fn test_mersenne_inverse_zero_input() {
        let zero = [0u8; 24];
        let result = gf_power_mersenne_inverse(&zero, 5, 24);
        assert_eq!(result, vec![0u8; 24], "0^k should be 0");
    }

    #[test]
    fn test_mersenne_roundtrip_e3_gf192() {
        // gcd(3, 192) = 3, but 2^gcd(3,192)-1 = 7, and gcd(7, 2^192-1) = 7 != 1
        // So the inverse of x^7 does NOT exist in GF(2^192)!
        // However, gcd(3, 192) = 3, and since 3 | 192, the map x^7 is NOT a bijection.
        // Skip: this parameter combination is not used in AIM2.
    }

    #[test]
    fn test_mersenne_roundtrip_e3_gf256() {
        // gcd(3, 256) = 1 — valid for AIM2-256
        let a: Vec<u8> = (0..32).map(|i| (i * 19 + 3) as u8).collect();
        let forward = gf_power_mersenne(&a, 3, 32);
        let recovered = gf_power_mersenne_inverse(&forward, 3, 32);
        assert_eq!(recovered, a, "roundtrip for e=3 in GF(2^256)");
    }

    #[test]
    fn test_gf_power_exp_identity() {
        // x^1 = x
        let a = [0x42u8; 16];
        let exp = [1u8]; // exponent = 1
        let result = gf_power_exp(&a, &exp, 16);
        assert_eq!(&result[..], &a[..], "x^1 should be x");
    }

    #[test]
    fn test_gf_power_exp_matches_inverse() {
        // x^(2^n-2) should equal gf_inverse(x)
        let a: Vec<u8> = (0..16).map(|i| (i * 17 + 3) as u8).collect();

        // 2^128 - 2 in little-endian bytes: all 0xFF except byte 0 = 0xFE
        let mut exp = vec![0xFFu8; 16];
        exp[0] = 0xFE;

        let via_power = gf_power_exp(&a, &exp, 16);
        let via_inverse = gf_inverse(&a, 16);
        assert_eq!(via_power, via_inverse, "x^(2^n-2) should equal gf_inverse(x)");
    }
}

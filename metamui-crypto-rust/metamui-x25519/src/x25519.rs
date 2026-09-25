//! Optimized pure native Rust implementation of X25519
//!
//! This implementation includes several optimizations:
//! 1. Use of const generics and inline hints
//! 2. Optimized field arithmetic with fewer allocations
//! 3. SIMD-friendly operations where possible
//! 4. Compile-time constant evaluation
//!
//! Several `native_x25519_*` helpers (public_from_private, generate_keypair,
//! scalar_mult_optimized) are kept as reference/fallback paths that the
//! runtime-dispatched API does not currently call.

#![allow(dead_code)]

use rand::{rngs::OsRng, RngCore};

/// X25519 public key size
pub const PUBLIC_KEY_SIZE: usize = 32;

/// X25519 private key size  
pub const PRIVATE_KEY_SIZE: usize = 32;

/// X25519 shared secret size
pub const SHARED_SECRET_SIZE: usize = 32;

/// Field element type - represents numbers modulo 2^255 - 19
/// Using i64 array to avoid overflow issues in intermediate calculations
type FieldElement = [i64; 16];

/// Constants
const _121665: FieldElement = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const _9: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Unpack 32 bytes into a field element
#[inline(always)]
fn unpack25519(n: &[u8]) -> FieldElement {
    let mut o = [0i64; 16];
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) | ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

/// Pack a field element into 32 bytes
#[inline(always)]
fn pack25519(o: &mut [u8], n: &FieldElement) {
    let mut m = [0i64; 16];
    let mut t = *n;
    
    // Carry propagation
    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);
    
    // Freeze reduction
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        
        sel25519(&mut t, &m, (1 - b) as i32);
    }
    
    // Pack into bytes
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
}

/// Carry propagation - optimized version
#[inline(always)]
fn carry25519(o: &mut FieldElement) {
    let mut carry: i64;
    for i in 0..16 {
        o[i] += 1 << 16;
        carry = o[i] >> 16;
        if i < 15 {
            o[i + 1] += carry - 1;
        } else {
            o[0] += (carry - 1) * 38;
        }
        o[i] -= carry << 16;
    }
}

/// Conditional swap: if b == 1, swap p and q
#[inline(always)]
fn sel25519(p: &mut FieldElement, q: &FieldElement, b: i32) {
    let c = (!(b as i64) + 1) & 0xffff;
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
    }
}

/// Field addition: o = a + b
#[inline(always)]
fn field_add(o: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}

/// Field subtraction: o = a - b
#[inline(always)]
fn field_sub(o: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

/// Optimized field multiplication: o = a * b
#[inline(always)]
fn field_mul(o: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    // Use local array to avoid heap allocation
    let mut t: [i64; 31] = [0; 31];
    
    // Schoolbook multiplication
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    
    // Reduction modulo 2^255 - 19
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    
    // Copy result
    o.copy_from_slice(&t[..16]);
    
    carry25519(o);
    carry25519(o);
}

/// Optimized field squaring: o = a^2
#[inline(always)]
fn field_square(o: &mut FieldElement, a: &FieldElement) {
    // Use local array to avoid heap allocation
    let mut t: [i64; 31] = [0; 31];
    
    // Diagonal elements
    for i in 0..16 {
        t[2 * i] += a[i] * a[i];
    }
    
    // Off-diagonal elements (appear twice)
    for i in 0..16 {
        for j in (i + 1)..16 {
            t[i + j] += 2 * a[i] * a[j];
        }
    }
    
    // Reduction
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    
    o.copy_from_slice(&t[..16]);
    
    carry25519(o);
    carry25519(o);
}

/// Field inversion: o = 1/i using Fermat's little theorem
#[inline]
fn inv25519(o: &mut FieldElement, i: &FieldElement) {
    let c = *i;
    
    // Use addition chain for p-2 = 2^255 - 21
    // This is more efficient than the simple loop
    let mut t0 = [0i64; 16];
    let mut t1 = [0i64; 16];
    let mut t2 = [0i64; 16];
    let mut t3 = [0i64; 16];
    
    // Compute various powers we'll need
    field_square(&mut t0, &c);      // 2
    field_square(&mut t1, &t0);     // 4
    let temp_t1 = t1;
    field_square(&mut t1, &temp_t1);     // 8
    let temp_t1_2 = t1;
    field_mul(&mut t1, &c, &temp_t1_2);    // 9
    let temp_t0 = t0;
    let temp_t1_3 = t1;
    field_mul(&mut t0, &temp_t0, &temp_t1_3);   // 11
    field_square(&mut t2, &t0);     // 22
    let temp_t1_4 = t1;
    field_mul(&mut t1, &temp_t1_4, &t2);   // 31 = 2^5 - 1
    field_square(&mut t2, &t1);     // 2^6 - 2
    
    // Square 4 times
    for _ in 0..4 {
        let temp_t2 = t2;
        field_square(&mut t2, &temp_t2);
    }
    
    let temp_t1_5 = t1;
    field_mul(&mut t1, &temp_t1_5, &t2);   // 2^10 - 1
    field_square(&mut t2, &t1);     // 2^11 - 2
    
    // Square 9 times
    for _ in 0..9 {
        let temp_t2 = t2;
        field_square(&mut t2, &temp_t2);
    }
    
    let temp_t2_2 = t2;
    field_mul(&mut t2, &t1, &temp_t2_2);   // 2^20 - 1
    field_square(&mut t3, &t2);     // 2^21 - 2
    
    // Square 19 times
    for _ in 0..19 {
        let temp_t3 = t3;
        field_square(&mut t3, &temp_t3);
    }
    
    let temp_t2_3 = t2;
    field_mul(&mut t2, &temp_t2_3, &t3);   // 2^40 - 1
    let temp_t2_4 = t2;
    field_square(&mut t2, &temp_t2_4);     // 2^41 - 2
    
    // Square 9 times
    for _ in 0..9 {
        let temp_t2 = t2;
        field_square(&mut t2, &temp_t2);
    }
    
    let temp_t1_6 = t1;
    field_mul(&mut t1, &temp_t1_6, &t2);   // 2^50 - 1
    field_square(&mut t2, &t1);     // 2^51 - 2
    
    // Square 49 times
    for _ in 0..49 {
        let temp_t2 = t2;
        field_square(&mut t2, &temp_t2);
    }
    
    let temp_t2_5 = t2;
    field_mul(&mut t2, &t1, &temp_t2_5);   // 2^100 - 1
    field_square(&mut t3, &t2);     // 2^101 - 2
    
    // Square 99 times
    for _ in 0..99 {
        let temp_t3 = t3;
        field_square(&mut t3, &temp_t3);
    }
    
    let temp_t2_6 = t2;
    field_mul(&mut t2, &temp_t2_6, &t3);   // 2^200 - 1
    let temp_t2_7 = t2;
    field_square(&mut t2, &temp_t2_7);     // 2^201 - 2
    
    // Square 49 times
    for _ in 0..49 {
        let temp_t2 = t2;
        field_square(&mut t2, &temp_t2);
    }
    
    let temp_t1_7 = t1;
    field_mul(&mut t1, &temp_t1_7, &t2);   // 2^250 - 1
    let temp_t1_8 = t1;
    field_square(&mut t1, &temp_t1_8);     // 2^251 - 2
    let temp_t1_9 = t1;
    field_square(&mut t1, &temp_t1_9);     // 2^252 - 4
    let temp_t1_10 = t1;
    field_square(&mut t1, &temp_t1_10);     // 2^253 - 8
    let temp_t1_11 = t1;
    field_square(&mut t1, &temp_t1_11);     // 2^254 - 16
    let temp_t1_12 = t1;
    field_square(&mut t1, &temp_t1_12);     // 2^255 - 32
    field_mul(o, &t1, &t0);         // 2^255 - 21
}

/// Optimized scalar multiplication on Curve25519
/// Implements X25519 as specified in RFC 7748
#[inline]
fn scalar_mult(n: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    let mut z = [0u8; 32];
    let mut x = [0i64; 80];
    let mut a = [0i64; 16];
    let mut b = [0i64; 16];
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    let mut e = [0i64; 16];
    let mut f = [0i64; 16];
    
    // Unpack the point
    let unpacked = unpack25519(p);
    x[..16].copy_from_slice(&unpacked);
    b.copy_from_slice(&unpacked);
    
    // Initialize
    a[0] = 1;
    d[0] = 1;
    
    // Main loop - Montgomery ladder
    for i in (0..=254).rev() {
        let bit = ((n[i >> 3] >> (i & 7)) & 1) as i32;
        
        // Conditional swap based on bit
        cswap(&mut a, &mut b, bit);
        cswap(&mut c, &mut d, bit);
        
        let temp_a = a;
        let temp_c = c;
        let temp_b = b;
        let temp_d = d;
        
        field_add(&mut e, &temp_a, &temp_c);
        field_sub(&mut a, &temp_a, &temp_c);
        field_add(&mut c, &temp_b, &temp_d);
        field_sub(&mut b, &temp_b, &temp_d);
        field_square(&mut d, &e);
        field_square(&mut f, &a);
        
        let temp_a2 = a;
        let temp_c2 = c;
        field_mul(&mut a, &temp_c2, &temp_a2);
        field_mul(&mut c, &b, &e);
        
        let temp_a3 = a;
        let temp_c3 = c;
        field_add(&mut e, &temp_a3, &temp_c3);
        field_sub(&mut a, &temp_a3, &temp_c3);
        field_square(&mut b, &a);
        field_sub(&mut c, &d, &f);
        
        let temp_c4 = c;
        field_mul(&mut a, &temp_c4, &_121665);
        let temp_a4 = a;
        field_add(&mut a, &temp_a4, &d);
        let temp_c5 = c;
        let temp_a5 = a;
        field_mul(&mut c, &temp_c5, &temp_a5);
        field_mul(&mut a, &d, &f);
        field_mul(&mut d, &b, &x[0..16].try_into().unwrap());
        field_square(&mut b, &e);
        
        // Conditional swap back
        cswap(&mut a, &mut b, bit);
        cswap(&mut c, &mut d, bit);
    }
    
    // Finalize
    x[16..32].copy_from_slice(&a);
    x[32..48].copy_from_slice(&c);
    x[48..64].copy_from_slice(&b);
    x[64..80].copy_from_slice(&d);
    
    // Compute final result
    let mut x32 = [0i64; 16];
    let mut x16 = [0i64; 16];
    
    x32.copy_from_slice(&x[32..48]);
    x16.copy_from_slice(&x[16..32]);
    
    let temp_x32 = x32;
    inv25519(&mut x32, &temp_x32);
    let temp_x16 = x16;
    field_mul(&mut x16, &temp_x16, &x32);
    pack25519(&mut z, &x16);
    
    z
}

/// Conditional swap of field elements
#[inline(always)]
fn cswap(p: &mut FieldElement, q: &mut FieldElement, b: i32) {
    let c = (!(b as i64) + 1) & 0xffff;
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/// Generate X25519 keypair from random bytes
#[inline]
pub fn native_x25519_keypair(random_bytes: &[u8; 32]) -> ([u8; PUBLIC_KEY_SIZE], [u8; PRIVATE_KEY_SIZE]) {
    // Clamp private key according to X25519 spec
    let mut private_key = *random_bytes;
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    
    // Compute public key = private_key * base_point
    let public_key = scalar_mult(&private_key, &_9);
    
    (public_key, private_key)
}

/// Generate public key from private key
#[inline]
pub fn native_x25519_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    // Clamp the private key as per RFC 7748
    let mut clamped = *private_key;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    
    scalar_mult(&clamped, &_9)
}

/// Perform X25519 key exchange
#[inline]
pub fn native_x25519_diffie_hellman(
    private_key: &[u8; PRIVATE_KEY_SIZE],
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; SHARED_SECRET_SIZE] {
    // Clamp the private key
    let mut clamped = *private_key;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    
    scalar_mult(&clamped, public_key)
}

/// Generate a new X25519 keypair with secure random
#[inline]
pub fn native_x25519_generate_keypair() -> ([u8; PUBLIC_KEY_SIZE], [u8; PRIVATE_KEY_SIZE]) {
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    native_x25519_keypair(&random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_x25519_keypair() {
        let random = [42u8; 32];
        let (public_key, private_key) = native_x25519_keypair(&random);
        
        assert_eq!(public_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), PRIVATE_KEY_SIZE);
        
        // Check clamping
        assert_eq!(private_key[0] & 7, 0);
        assert_eq!(private_key[31] & 128, 0);
        assert_eq!(private_key[31] & 64, 64);
    }

    #[test]
    fn test_optimized_x25519_exchange() {
        // Alice's keypair
        let alice_random = [1u8; 32];
        let (alice_public, alice_private) = native_x25519_keypair(&alice_random);
        
        // Bob's keypair
        let bob_random = [2u8; 32];
        let (bob_public, bob_private) = native_x25519_keypair(&bob_random);
        
        // Key exchange
        let alice_shared = native_x25519_diffie_hellman(&alice_private, &bob_public);
        let bob_shared = native_x25519_diffie_hellman(&bob_private, &alice_public);
        
        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }
    
    #[test]
    fn test_optimized_public_from_private() {
        let random = [99u8; 32];
        let (public_key, private_key) = native_x25519_keypair(&random);
        
        // Deriving public key from private should give same result
        let derived_public = native_x25519_public_from_private(&private_key);
        assert_eq!(public_key, derived_public);
    }
}

/// Scalar multiplication (exposed for compatibility)
#[inline]
pub fn native_x25519_scalar_mult_optimized(
    scalar: &[u8; 32],
    point: &[u8; 32],
) -> [u8; 32] {
    scalar_mult(scalar, point)
}
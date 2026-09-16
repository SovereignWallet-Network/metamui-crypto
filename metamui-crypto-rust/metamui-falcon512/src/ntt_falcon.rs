//! Negacyclic Number Theoretic Transform (NTT) for Falcon-512 and Falcon-1024
//!
//! Implements polynomial multiplication in Z_q[x]/(x^n+1) where q = 12289.
//! Uses the pre-twist method: apply ψ^i twist, then cyclic Cooley-Tukey NTT with ω = ψ².
//!
//! For Falcon-512:  n=512,  ψ=10302 (ψ^1024=1, ψ^512=-1 mod q)
//! For Falcon-1024: n=1024, ψ=1945  (ψ^2048=1, ψ^1024=-1 mod q)

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Primitive 2N-th root of unity mod Q.
/// Verified: PSI^N = Q-1 = -1 (mod Q), PSI^{2N} = 1 (mod Q).
const PSI: u64 = 10302;

/// Precomputed twiddle factors for forward cyclic NTT (powers of ω = ψ²)
static mut OMEGA_POWERS: [u32; N] = [0; N];
/// Precomputed twiddle factors for inverse cyclic NTT (powers of ω⁻¹)
static mut OMEGA_INV_POWERS: [u32; N] = [0; N];
/// Pre-twist factors (powers of ψ)
static mut PSI_POWERS: [u32; N] = [0; N];
/// Post-twist factors (powers of ψ⁻¹)
static mut PSI_INV_POWERS: [u32; N] = [0; N];
/// N⁻¹ mod Q for inverse NTT scaling
static mut N_INV_MOD_Q: u32 = 0;
/// Initialization flag
static mut TABLES_INITIALIZED: bool = false;

// ================================================================
// Falcon-1024 twiddle factor tables
// ================================================================

/// Primitive 2N-th root of unity mod Q for Falcon-1024.
/// ψ₁₀₂₄^1024 = Q-1 = -1 (mod Q), ψ₁₀₂₄^2048 = 1 (mod Q).
const PSI_1024: u64 = 1945;
const N_1024: usize = 1024;

static mut OMEGA_POWERS_1024: [u32; N_1024] = [0; N_1024];
static mut OMEGA_INV_POWERS_1024: [u32; N_1024] = [0; N_1024];
static mut PSI_POWERS_1024: [u32; N_1024] = [0; N_1024];
static mut PSI_INV_POWERS_1024: [u32; N_1024] = [0; N_1024];
static mut N_INV_MOD_Q_1024: u32 = 0;
static mut TABLES_1024_INITIALIZED: bool = false;

/// Modular exponentiation: base^exp mod Q
fn mod_pow_q(mut base: u64, mut exp: u64) -> u32 {
    let q = Q as u64;
    let mut result = 1u64;
    base %= q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        exp >>= 1;
    }
    result as u32
}

/// Initialize precomputed twiddle factor tables.
///
/// Must be called before any NTT operation.
/// Uses lazy initialization — safe to call multiple times.
pub fn init_ntt_tables() {
    unsafe {
        if TABLES_INITIALIZED {
            return;
        }

        let q = Q as u64;

        // ω = ψ² mod q — primitive N-th root of unity
        let omega = PSI * PSI % q;
        let omega_inv = mod_pow_q(omega, Q as u64 - 2) as u64;
        let psi_inv = mod_pow_q(PSI, Q as u64 - 2) as u64;
        N_INV_MOD_Q = mod_pow_q(N as u64, Q as u64 - 2);

        OMEGA_POWERS[0] = 1;
        OMEGA_INV_POWERS[0] = 1;
        PSI_POWERS[0] = 1;
        PSI_INV_POWERS[0] = 1;

        for i in 1..N {
            OMEGA_POWERS[i] = (OMEGA_POWERS[i - 1] as u64 * omega % q) as u32;
            OMEGA_INV_POWERS[i] = (OMEGA_INV_POWERS[i - 1] as u64 * omega_inv % q) as u32;
            PSI_POWERS[i] = (PSI_POWERS[i - 1] as u64 * PSI % q) as u32;
            PSI_INV_POWERS[i] = (PSI_INV_POWERS[i - 1] as u64 * psi_inv % q) as u32;
        }

        TABLES_INITIALIZED = true;
    }
}

/// Bit-reversal permutation for Cooley-Tukey NTT
fn bit_reverse(data: &mut [i32]) {
    let n = data.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j >= bit {
            j -= bit;
            bit >>= 1;
        }
        j += bit;
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Forward negacyclic NTT.
///
/// Transforms a polynomial from coefficient domain to NTT domain.
/// Uses pre-twist with ψ followed by cyclic Cooley-Tukey DIT butterfly.
///
/// Output values are in [0, Q-1].
pub fn ntt_forward(poly: &[i16]) -> Vec<i16> {
    init_ntt_tables();

    let q = Q as i64;
    let mut data = vec![0i32; N];

    // Pre-twist: data[i] = poly[i] * ψ^i mod q
    // This transforms the negacyclic problem into a cyclic one.
    unsafe {
        for i in 0..N {
            let val = if poly[i] < 0 {
                poly[i] as i64 + q
            } else {
                poly[i] as i64
            };
            data[i] = (val * PSI_POWERS[i] as i64 % q) as i32;
        }
    }

    // Bit-reversal permutation
    bit_reverse(&mut data);

    // Cooley-Tukey DIT butterfly with ω (cyclic NTT)
    let mut len = 2;
    while len <= N {
        let half = len / 2;
        let table_step = N / len;

        for i in (0..N).step_by(len) {
            let mut table_idx = 0;
            for j in 0..half {
                let twiddle = unsafe { OMEGA_POWERS[table_idx] as i64 };
                let u = data[i + j] as i64;
                let v = data[i + j + half] as i64 * twiddle % q;

                data[i + j] = ((u + v) % q) as i32;
                data[i + j + half] = ((u - v + q) % q) as i32;

                table_idx += table_step;
            }
        }

        len *= 2;
    }

    data.iter().map(|&x| x as i16).collect()
}

/// Inverse negacyclic NTT.
///
/// Transforms from NTT domain back to coefficient domain.
/// Applies cyclic inverse DIT butterfly, scales by N⁻¹, then post-twists by ψ⁻ⁱ.
///
/// Output values are in signed representation [-Q/2, Q/2).
pub fn ntt_inverse(poly: &[i16]) -> Vec<i16> {
    init_ntt_tables();

    let q = Q as i64;

    // Normalize input to [0, Q-1]
    let mut data: Vec<i32> = poly
        .iter()
        .map(|&x| {
            let v = x as i32;
            if v < 0 { v + Q as i32 } else { v }
        })
        .collect();

    // Bit-reversal permutation
    bit_reverse(&mut data);

    // Cooley-Tukey DIT butterfly with ω⁻¹ (cyclic inverse NTT)
    let mut len = 2;
    while len <= N {
        let half = len / 2;
        let table_step = N / len;

        for i in (0..N).step_by(len) {
            let mut table_idx = 0;
            for j in 0..half {
                let twiddle = unsafe { OMEGA_INV_POWERS[table_idx] as i64 };
                let u = data[i + j] as i64;
                let v = data[i + j + half] as i64 * twiddle % q;

                data[i + j] = ((u + v) % q) as i32;
                data[i + j + half] = ((u - v + q) % q) as i32;

                table_idx += table_step;
            }
        }

        len *= 2;
    }

    // Scale by N⁻¹ and post-twist by ψ⁻ⁱ (combined in one pass)
    unsafe {
        let n_inv = N_INV_MOD_Q as i64;
        for i in 0..N {
            let scaled = data[i] as i64 * n_inv % q;
            data[i] = (scaled * PSI_INV_POWERS[i] as i64 % q) as i32;
        }
    }

    // Convert to signed representation [-Q/2, Q/2)
    data.iter()
        .map(|&x| {
            if x > (Q / 2) as i32 {
                (x - Q as i32) as i16
            } else {
                x as i16
            }
        })
        .collect()
}

/// Multiply two polynomials in Z_q[x]/(x^n+1) using negacyclic NTT.
///
/// This is the core operation: transform both operands, pointwise multiply
/// in NTT domain, then inverse transform.
pub fn multiply_ntt(a: &[i16], b: &[i16]) -> Vec<i16> {
    let a_ntt = ntt_forward(a);
    let b_ntt = ntt_forward(b);

    let q = Q as u64;
    let mut c_ntt = vec![0i16; N];
    for i in 0..N {
        let ai = if a_ntt[i] < 0 {
            (a_ntt[i] as i32 + Q as i32) as u64
        } else {
            a_ntt[i] as u64
        };
        let bi = if b_ntt[i] < 0 {
            (b_ntt[i] as i32 + Q as i32) as u64
        } else {
            b_ntt[i] as u64
        };
        c_ntt[i] = (ai * bi % q) as i16;
    }

    ntt_inverse(&c_ntt)
}

/// Modular inverse using extended GCD.
pub fn mod_inverse(a: u16, m: u16) -> Option<u16> {
    let (gcd, x, _) = extended_gcd(a as i32, m as i32);
    if gcd != 1 {
        return None;
    }
    Some((((x % m as i32) + m as i32) % m as i32) as u16)
}

/// Extended GCD: returns (gcd, x, y) such that a*x + b*y = gcd.
fn extended_gcd(a: i32, b: i32) -> (i32, i32, i32) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    (gcd, y1, x1 - (a / b) * y1)
}

/// Compute public key h = g * f⁻¹ mod q in Z_q[x]/(x^n+1) using NTT.
pub fn compute_public_key_ntt(f: &[i16], g: &[i16]) -> Result<Vec<i16>> {
    let f_inv = inverse_ntt(f)?;
    let h = multiply_ntt(g, &f_inv);
    // Normalize to [0, q) for public key representation
    let h_normalized: Vec<i16> = h.iter().map(|&c| {
        if c < 0 { (c as i32 + Q as i32) as i16 } else { c }
    }).collect();
    Ok(h_normalized)
}

/// Compute polynomial inverse in Z_q[x]/(x^n+1) using NTT.
///
/// In the NTT domain, inversion is simply pointwise modular inverse.
/// The polynomial is invertible iff all NTT evaluations are non-zero.
pub fn inverse_ntt(poly: &[i16]) -> Result<Vec<i16>> {
    init_ntt_tables();

    // Forward NTT
    let poly_ntt = ntt_forward(poly);

    // Pointwise inverse in NTT domain
    let mut inv_ntt = vec![0i16; N];
    for i in 0..N {
        let val = if poly_ntt[i] < 0 {
            (poly_ntt[i] as i32 + Q as i32) as u16
        } else {
            poly_ntt[i] as u16
        };
        if val == 0 {
            return Err(Falcon512Error::NotInvertible);
        }
        match mod_inverse(val, Q) {
            Some(inv) => inv_ntt[i] = inv as i16,
            None => return Err(Falcon512Error::NotInvertible),
        }
    }

    // Inverse NTT to get the polynomial inverse
    Ok(ntt_inverse(&inv_ntt))
}

// ================================================================
// Falcon-1024 NTT support — parameterized functions
// ================================================================

/// Initialize precomputed twiddle factor tables for Falcon-1024 (n=1024, ψ=1945).
pub fn init_ntt_tables_1024() {
    unsafe {
        if TABLES_1024_INITIALIZED {
            return;
        }

        let n = N_1024;
        let q = Q as u64;

        let omega = PSI_1024 * PSI_1024 % q;
        let omega_inv = mod_pow_q(omega, Q as u64 - 2) as u64;
        let psi_inv = mod_pow_q(PSI_1024, Q as u64 - 2) as u64;
        N_INV_MOD_Q_1024 = mod_pow_q(n as u64, Q as u64 - 2);

        OMEGA_POWERS_1024[0] = 1;
        OMEGA_INV_POWERS_1024[0] = 1;
        PSI_POWERS_1024[0] = 1;
        PSI_INV_POWERS_1024[0] = 1;

        for i in 1..n {
            OMEGA_POWERS_1024[i] = (OMEGA_POWERS_1024[i - 1] as u64 * omega % q) as u32;
            OMEGA_INV_POWERS_1024[i] = (OMEGA_INV_POWERS_1024[i - 1] as u64 * omega_inv % q) as u32;
            PSI_POWERS_1024[i] = (PSI_POWERS_1024[i - 1] as u64 * PSI_1024 % q) as u32;
            PSI_INV_POWERS_1024[i] = (PSI_INV_POWERS_1024[i - 1] as u64 * psi_inv % q) as u32;
        }

        TABLES_1024_INITIALIZED = true;
    }
}

/// Initialize NTT tables for the given degree n (512 or 1024).
pub fn init_ntt_tables_n(n: usize) {
    match n {
        512 => init_ntt_tables(),
        1024 => init_ntt_tables_1024(),
        _ => panic!("Unsupported NTT degree: {}", n),
    }
}

/// Returns (omega_powers, omega_inv_powers, psi_powers, psi_inv_powers, n_inv_mod_q)
/// for the given degree n. Initializes tables if needed.
///
/// # Safety
/// Returns references to static mut arrays, safe because tables are write-once.
unsafe fn get_ntt_tables(n: usize) -> (&'static [u32], &'static [u32], &'static [u32], &'static [u32], u32) {
    match n {
        512 => {
            init_ntt_tables();
            (&OMEGA_POWERS[..], &OMEGA_INV_POWERS[..], &PSI_POWERS[..], &PSI_INV_POWERS[..], N_INV_MOD_Q)
        }
        1024 => {
            init_ntt_tables_1024();
            (&OMEGA_POWERS_1024[..], &OMEGA_INV_POWERS_1024[..], &PSI_POWERS_1024[..], &PSI_INV_POWERS_1024[..], N_INV_MOD_Q_1024)
        }
        _ => panic!("Unsupported NTT degree: {}", n),
    }
}

/// Forward negacyclic NTT for degree n (512 or 1024).
pub fn ntt_forward_n(poly: &[i16], n: usize) -> Vec<i16> {
    assert_eq!(poly.len(), n);
    let (omega_powers, _, psi_powers, _, _) = unsafe { get_ntt_tables(n) };

    let q = Q as i64;
    let mut data = vec![0i32; n];

    // Pre-twist: data[i] = poly[i] * ψ^i mod q
    for i in 0..n {
        let val = if poly[i] < 0 {
            poly[i] as i64 + q
        } else {
            poly[i] as i64
        };
        data[i] = (val * psi_powers[i] as i64 % q) as i32;
    }

    // Bit-reversal permutation
    bit_reverse(&mut data);

    // Cooley-Tukey DIT butterfly with ω
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let table_step = n / len;

        for i in (0..n).step_by(len) {
            let mut table_idx = 0;
            for j in 0..half {
                let twiddle = omega_powers[table_idx] as i64;
                let u = data[i + j] as i64;
                let v = data[i + j + half] as i64 * twiddle % q;

                data[i + j] = ((u + v) % q) as i32;
                data[i + j + half] = ((u - v + q) % q) as i32;

                table_idx += table_step;
            }
        }

        len *= 2;
    }

    data.iter().map(|&x| x as i16).collect()
}

/// Inverse negacyclic NTT for degree n (512 or 1024).
pub fn ntt_inverse_n(poly: &[i16], n: usize) -> Vec<i16> {
    assert_eq!(poly.len(), n);
    let (_, omega_inv_powers, _, psi_inv_powers, n_inv) = unsafe { get_ntt_tables(n) };

    let q = Q as i64;

    let mut data: Vec<i32> = poly
        .iter()
        .map(|&x| {
            let v = x as i32;
            if v < 0 { v + Q as i32 } else { v }
        })
        .collect();

    // Bit-reversal permutation
    bit_reverse(&mut data);

    // Cooley-Tukey DIT butterfly with ω⁻¹
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let table_step = n / len;

        for i in (0..n).step_by(len) {
            let mut table_idx = 0;
            for j in 0..half {
                let twiddle = omega_inv_powers[table_idx] as i64;
                let u = data[i + j] as i64;
                let v = data[i + j + half] as i64 * twiddle % q;

                data[i + j] = ((u + v) % q) as i32;
                data[i + j + half] = ((u - v + q) % q) as i32;

                table_idx += table_step;
            }
        }

        len *= 2;
    }

    // Scale by N⁻¹ and post-twist by ψ⁻ⁱ
    let n_inv_val = n_inv as i64;
    for i in 0..n {
        let scaled = data[i] as i64 * n_inv_val % q;
        data[i] = (scaled * psi_inv_powers[i] as i64 % q) as i32;
    }

    // Convert to signed representation [-Q/2, Q/2)
    data.iter()
        .map(|&x| {
            if x > (Q / 2) as i32 {
                (x - Q as i32) as i16
            } else {
                x as i16
            }
        })
        .collect()
}

/// Multiply two polynomials in Z_q[x]/(x^n+1) for degree n using negacyclic NTT.
pub fn multiply_ntt_n(a: &[i16], b: &[i16], n: usize) -> Vec<i16> {
    let a_ntt = ntt_forward_n(a, n);
    let b_ntt = ntt_forward_n(b, n);

    let q = Q as u64;
    let mut c_ntt = vec![0i16; n];
    for i in 0..n {
        let ai = if a_ntt[i] < 0 {
            (a_ntt[i] as i32 + Q as i32) as u64
        } else {
            a_ntt[i] as u64
        };
        let bi = if b_ntt[i] < 0 {
            (b_ntt[i] as i32 + Q as i32) as u64
        } else {
            b_ntt[i] as u64
        };
        c_ntt[i] = (ai * bi % q) as i16;
    }

    ntt_inverse_n(&c_ntt, n)
}

/// Compute polynomial inverse in Z_q[x]/(x^n+1) for degree n.
pub fn inverse_ntt_n(poly: &[i16], n: usize) -> Result<Vec<i16>> {
    let poly_ntt = ntt_forward_n(poly, n);

    let mut inv_ntt = vec![0i16; n];
    for i in 0..n {
        let val = if poly_ntt[i] < 0 {
            (poly_ntt[i] as i32 + Q as i32) as u16
        } else {
            poly_ntt[i] as u16
        };
        if val == 0 {
            return Err(Falcon512Error::NotInvertible);
        }
        match mod_inverse(val, Q) {
            Some(inv) => inv_ntt[i] = inv as i16,
            None => return Err(Falcon512Error::NotInvertible),
        }
    }

    Ok(ntt_inverse_n(&inv_ntt, n))
}

/// Compute public key h = g * f⁻¹ mod q in Z_q[x]/(x^n+1) for degree n.
pub fn compute_public_key_ntt_n(f: &[i16], g: &[i16], n: usize) -> Result<Vec<i16>> {
    let f_inv = inverse_ntt_n(f, n)?;
    let h = multiply_ntt_n(g, &f_inv, n);
    let h_normalized: Vec<i16> = h.iter().map(|&c| {
        if c < 0 { (c as i32 + Q as i32) as i16 } else { c }
    }).collect();
    Ok(h_normalized)
}

/// Recover G from the NTRU equation f·G − g·F = q.
///
/// Given f, g, F (from private key), computes G ≡ (q + g·F) · f⁻¹ (mod q).
/// The true integer G has small coefficients (bounded by ~q/2), so we
/// center-reduce the mod-q result to [−q/2, q/2).
pub fn recover_big_g(f: &[i16], g: &[i16], big_f: &[i16]) -> Result<Vec<i16>> {
    // Compute g·F mod q in Z_q[x]/(x^n+1)
    let gf = multiply_ntt(g, big_f);

    // Add q to constant term: (q + g·F)
    let mut q_plus_gf = gf.clone();
    q_plus_gf[0] = ((q_plus_gf[0] as i32 + Q as i32) % Q as i32) as i16;

    // Compute (q + g·F) · f⁻¹ mod q
    let f_inv = inverse_ntt(f)?;
    let big_g_mod_q = multiply_ntt(&q_plus_gf, &f_inv);

    // Center-reduce: map from [0, q) to [−q/2, q/2)
    let half_q = Q as i32 / 2;
    let big_g: Vec<i16> = big_g_mod_q.iter().map(|&c| {
        let v = if c < 0 { c as i32 + Q as i32 } else { c as i32 };
        if v > half_q { (v - Q as i32) as i16 } else { v as i16 }
    }).collect();

    Ok(big_g)
}

/// Recover G for arbitrary degree n (used by Falcon-1024).
pub fn recover_big_g_n(f: &[i16], g: &[i16], big_f: &[i16], n: usize) -> Result<Vec<i16>> {
    let gf = multiply_ntt_n(g, big_f, n);

    let mut q_plus_gf = gf.clone();
    q_plus_gf[0] = ((q_plus_gf[0] as i32 + Q as i32) % Q as i32) as i16;

    let f_inv = inverse_ntt_n(f, n)?;
    let big_g_mod_q = multiply_ntt_n(&q_plus_gf, &f_inv, n);

    let half_q = Q as i32 / 2;
    let big_g: Vec<i16> = big_g_mod_q.iter().map(|&c| {
        let v = if c < 0 { c as i32 + Q as i32 } else { c as i32 };
        if v > half_q { (v - Q as i32) as i16 } else { v as i16 }
    }).collect();

    Ok(big_g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::Poly;

    #[test]
    fn test_ntt_roundtrip() {
        init_ntt_tables();

        let mut poly = vec![0i16; N];
        for i in 0..N {
            poly[i] = (i % 100) as i16;
        }

        let ntt = ntt_forward(&poly);
        let recovered = ntt_inverse(&ntt);

        for i in 0..N {
            assert_eq!(poly[i], recovered[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_ntt_roundtrip_negative() {
        init_ntt_tables();

        let mut poly = vec![0i16; N];
        for i in 0..N {
            poly[i] = (i as i16 % 200) - 100;
        }

        let ntt = ntt_forward(&poly);
        let recovered = ntt_inverse(&ntt);

        for i in 0..N {
            assert_eq!(poly[i], recovered[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_negacyclic_multiplication() {
        // (2 + 3x)(5 + 7x) = 10 + 29x + 21x² in Z_q[x]/(x^n+1)
        let mut a = vec![0i16; N];
        let mut b = vec![0i16; N];
        a[0] = 2;
        a[1] = 3;
        b[0] = 5;
        b[1] = 7;

        let c = multiply_ntt(&a, &b);
        assert_eq!(c[0], 10);
        assert_eq!(c[1], 29);
        assert_eq!(c[2], 21);
    }

    #[test]
    fn test_negacyclic_property() {
        // X^{n-1} * X = X^n ≡ -1 (mod x^n + 1)
        let mut x_n_minus_1 = vec![0i16; N];
        x_n_minus_1[N - 1] = 1;

        let mut x = vec![0i16; N];
        x[1] = 1;

        let result = multiply_ntt(&x_n_minus_1, &x);
        assert_eq!(result[0], -1, "X^n should equal -1 mod (X^n+1)");
        for i in 1..N {
            assert_eq!(result[i], 0, "Non-zero at index {}", i);
        }
    }

    #[test]
    fn test_ntt_matches_direct_negacyclic() {
        let mut a_coeffs = vec![0i16; N];
        let mut b_coeffs = vec![0i16; N];
        a_coeffs[0] = 1;
        a_coeffs[1] = 2;
        a_coeffs[2] = 3;
        b_coeffs[0] = 4;
        b_coeffs[1] = 5;
        b_coeffs[2] = 6;

        let a = Poly::new(a_coeffs.clone());
        let b = Poly::new(b_coeffs.clone());

        let direct = a.mul(&b);
        let ntt_result = multiply_ntt(&a_coeffs, &b_coeffs);

        for i in 0..10 {
            assert_eq!(
                ntt_result[i], direct.coeffs[i],
                "Mismatch at index {}: NTT={}, direct={}",
                i, ntt_result[i], direct.coeffs[i]
            );
        }
    }

    #[test]
    fn test_polynomial_inverse() {
        let mut poly = vec![0i16; N];
        poly[0] = 2;

        let inv = inverse_ntt(&poly).expect("Should be invertible");
        let product = multiply_ntt(&poly, &inv);

        assert_eq!(product[0], 1, "product[0] should be 1, got {}", product[0]);
        for i in 1..N {
            assert_eq!(product[i], 0, "product[{}] should be 0, got {}", i, product[i]);
        }
    }

    #[test]
    fn test_polynomial_inverse_complex() {
        let mut poly = vec![0i16; N];
        poly[0] = 3;
        poly[1] = 1;
        poly[2] = -2;

        let inv = inverse_ntt(&poly).expect("Should be invertible");
        let product = multiply_ntt(&poly, &inv);

        assert_eq!(product[0], 1, "product[0] should be 1, got {}", product[0]);
        for i in 1..N {
            assert_eq!(product[i], 0, "product[{}] should be 0, got {}", i, product[i]);
        }
    }

    // ================================================================
    // Falcon-1024 NTT tests
    // ================================================================

    #[test]
    fn test_psi_1024_is_root_of_unity() {
        // Verify PSI_1024^1024 ≡ -1 (mod Q)
        let val = mod_pow_q(PSI_1024, 1024);
        assert_eq!(val, Q as u32 - 1, "PSI_1024^1024 should be -1 mod Q, got {}", val);

        // Verify PSI_1024^2048 ≡ 1 (mod Q)
        let val2 = mod_pow_q(PSI_1024, 2048);
        assert_eq!(val2, 1u32, "PSI_1024^2048 should be 1 mod Q, got {}", val2);
    }

    #[test]
    fn test_ntt_1024_roundtrip() {
        let n = 1024;
        let mut poly = vec![0i16; n];
        for i in 0..n {
            poly[i] = (i % 100) as i16;
        }

        let ntt = ntt_forward_n(&poly, n);
        let recovered = ntt_inverse_n(&ntt, n);

        for i in 0..n {
            assert_eq!(poly[i], recovered[i], "1024 roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn test_ntt_1024_roundtrip_negative() {
        let n = 1024;
        let mut poly = vec![0i16; n];
        for i in 0..n {
            poly[i] = (i as i16 % 200) - 100;
        }

        let ntt = ntt_forward_n(&poly, n);
        let recovered = ntt_inverse_n(&ntt, n);

        for i in 0..n {
            assert_eq!(poly[i], recovered[i], "1024 neg roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn test_ntt_1024_negacyclic_multiplication() {
        let n = 1024;
        // (2 + 3x)(5 + 7x) = 10 + 29x + 21x²
        let mut a = vec![0i16; n];
        let mut b = vec![0i16; n];
        a[0] = 2; a[1] = 3;
        b[0] = 5; b[1] = 7;

        let c = multiply_ntt_n(&a, &b, n);
        assert_eq!(c[0], 10);
        assert_eq!(c[1], 29);
        assert_eq!(c[2], 21);
    }

    #[test]
    fn test_ntt_1024_negacyclic_property() {
        let n = 1024;
        // X^{n-1} * X = X^n ≡ -1 (mod x^n + 1)
        let mut x_n_minus_1 = vec![0i16; n];
        x_n_minus_1[n - 1] = 1;

        let mut x = vec![0i16; n];
        x[1] = 1;

        let result = multiply_ntt_n(&x_n_minus_1, &x, n);
        assert_eq!(result[0], -1, "X^n should equal -1 mod (X^n+1)");
        for i in 1..n {
            assert_eq!(result[i], 0, "Non-zero at index {}", i);
        }
    }

    #[test]
    fn test_ntt_1024_polynomial_inverse() {
        let n = 1024;
        let mut poly = vec![0i16; n];
        poly[0] = 3;
        poly[1] = 1;
        poly[2] = -2;

        let inv = inverse_ntt_n(&poly, n).expect("Should be invertible");
        let product = multiply_ntt_n(&poly, &inv, n);

        assert_eq!(product[0], 1, "product[0] should be 1, got {}", product[0]);
        for i in 1..n {
            assert_eq!(product[i], 0, "product[{}] should be 0, got {}", i, product[i]);
        }
    }

    #[test]
    fn test_ntt_n_matches_existing_512() {
        // Verify that ntt_forward_n(poly, 512) matches ntt_forward(poly)
        let mut poly = vec![0i16; N];
        for i in 0..N {
            poly[i] = ((i * 7 + 3) % 100) as i16 - 50;
        }

        let ntt_old = ntt_forward(&poly);
        let ntt_new = ntt_forward_n(&poly, 512);

        for i in 0..N {
            assert_eq!(ntt_old[i], ntt_new[i], "512 forward mismatch at {}", i);
        }

        let inv_old = ntt_inverse(&ntt_old);
        let inv_new = ntt_inverse_n(&ntt_new, 512);

        for i in 0..N {
            assert_eq!(inv_old[i], inv_new[i], "512 inverse mismatch at {}", i);
        }
    }
}

use metamui_dilithium::{Dilithium2, operations::*, params::*, poly::*};

#[test]
fn test_key_generation_t_computation() {
    println!("\n=== Key Generation T Computation Test ===");
    
    // Generate keypair
    let (pk, sk) = Dilithium2::generate_keypair();
    
    // Unpack to get components
    let rho = &pk[0..32];
    let t1 = unpack_t1(&pk[32..], &DILITHIUM2_PARAMS);
    let (_rho_sk, _k_seed, _tr, s1, s2, t0) = unpack_sk(&sk, &DILITHIUM2_PARAMS);
    
    println!("Unpacked components");
    
    // Expand A
    let a_matrix = expand_a(rho, &DILITHIUM2_PARAMS);
    
    // Recompute t = As1 + s2
    let s1_ntt = s1.to_ntt();
    let as1_ntt = matrix_vector_mul_ntt(&a_matrix, &s1_ntt).unwrap();
    let as1 = as1_ntt.from_ntt();
    let t = as1.add(&s2).unwrap().reduce();
    
    println!("\nRecomputed t:");
    println!("  t[0] first 4 coeffs: {:?}", &t.polys[0].coeffs[..4]);
    
    // Decompose t to get t1 and t0
    let mut t1_recomputed = PolyVec::zero(DILITHIUM2_PARAMS.k);
    let mut t0_recomputed = PolyVec::zero(DILITHIUM2_PARAMS.k);
    
    for i in 0..DILITHIUM2_PARAMS.k {
        let (t1_poly, t0_poly) = t.polys[i].power2round(D);
        t1_recomputed.polys[i] = t1_poly;
        t0_recomputed.polys[i] = t0_poly;
    }
    
    println!("\nDecomposed t:");
    println!("  t1[0] first 4 coeffs: {:?}", &t1_recomputed.polys[0].coeffs[..4]);
    println!("  t0[0] first 4 coeffs: {:?}", &t0_recomputed.polys[0].coeffs[..4]);
    
    // Compare with stored values
    println!("\nStored values:");
    println!("  t1[0] first 4 coeffs: {:?}", &t1.polys[0].coeffs[..4]);
    println!("  t0[0] first 4 coeffs: {:?}", &t0.polys[0].coeffs[..4]);
    
    // Check if they match
    let mut t1_match = true;
    let mut t0_match = true;
    
    for i in 0..DILITHIUM2_PARAMS.k {
        for j in 0..N {
            if t1.polys[i].coeffs[j] != t1_recomputed.polys[i].coeffs[j] {
                t1_match = false;
            }
            if t0.polys[i].coeffs[j] != t0_recomputed.polys[i].coeffs[j] {
                t0_match = false;
            }
        }
    }
    
    println!("\nt1 matches: {}", t1_match);
    println!("t0 matches: {}", t0_match);
    
    // Test power2round correctness
    println!("\n=== Testing power2round ===");
    
    // Test some specific values
    let test_values = vec![
        0,
        1 << D,
        (1 << D) - 1,
        (1 << D) + 1,
        Q as i32 - 1,
        Q as i32 / 2,
        -(Q as i32) / 2,
    ];
    
    for val in test_values {
        let poly = Poly::from_coeffs([val; N]);
        let (r1, r0) = poly.power2round(D);
        let reconstructed = r1.coeffs[0] * (1 << D) + r0.coeffs[0];
        let reconstructed_mod = reconstructed.rem_euclid(Q as i32);
        let val_mod = val.rem_euclid(Q as i32);
        
        println!("  {} -> r1={}, r0={}, reconstructed={} (mod Q: {})",
                 val, r1.coeffs[0], r0.coeffs[0], reconstructed, reconstructed_mod);
        
        if reconstructed_mod != val_mod {
            println!("    ERROR: Reconstruction failed!");
        }
    }
}
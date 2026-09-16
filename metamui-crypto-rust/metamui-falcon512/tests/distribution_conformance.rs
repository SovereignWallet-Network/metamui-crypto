//! Falcon-512 signature norm DISTRIBUTION conformance (#139).
//!
//! The bound the verifier enforces is one-sided (`||(s0,s1)||^2 < BETA_SQUARED`),
//! so a signer emitting signatures far *narrower* than the specification passes
//! every correctness test and every KAT. Only a two-sided band around the design
//! expectation can tell a conformant sampler from a broken one.
//!
//! Before the Gaussian sampler landed, this measured 1,048,661 (0.037x design)
//! for Falcon-512, and 2,097,000-ish (2n·q/12) for Falcon-1024 (#143).

use metamui_falcon512::constants::{BETA_SQUARED, LOGN, N, Q, SIGMA};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Reconstruct `||(s0,s1)||^2` the way `verify_complete` does.
fn norm_sq(pk: &metamui_falcon512::PublicKey, msg: &[u8], sig: &[u8]) -> i64 {
    let (nonce, s1) = metamui_falcon512::nist_encoding::decode_signature(sig, LOGN)
        .expect("our own signature must decode");
    let c = metamui_falcon512::nist_hash::hash_to_point_nist(&nonce, msg);
    let s1h = metamui_falcon512::ntt_falcon::multiply_ntt(&s1, &pk.h.coeffs);

    let mut acc: i64 = 0;
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
        let s0 = if diff >= (Q as i32 + 1) / 2 {
            diff - Q as i32
        } else {
            diff
        };
        acc += (s0 as i64) * (s0 as i64) + (s1[i] as i64) * (s1[i] as i64);
    }
    acc
}

#[test]
fn signature_norms_match_the_design_gaussian() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);

    let mut norms = Vec::new();
    for k in 0..8 {
        let kp = metamui_falcon512::generate_keypair(&mut rng).expect("keygen");
        for m in 0..8 {
            let msg = format!("falcon/139/distribution/{k}/{m}");
            let sig =
                metamui_falcon512::sign(msg.as_bytes(), &kp.private_key, &mut rng).expect("sign");
            assert!(
                metamui_falcon512::verify(msg.as_bytes(), &sig, &kp.public_key).unwrap(),
                "signature must verify"
            );
            norms.push(norm_sq(&kp.public_key, msg.as_bytes(), &sig));
        }
    }

    let n = norms.len() as f64;
    let mean = norms.iter().map(|&x| x as f64).sum::<f64>() / n;
    let design = 2.0 * N as f64 * SIGMA * SIGMA;
    let ratio = mean / design;
    let sigma_eff = (mean / (2.0 * N as f64)).sqrt();

    println!("samples        = {}", norms.len());
    println!("mean ||s||^2   = {mean:.0}");
    println!("design 2n*s^2  = {design:.0}");
    println!("ratio          = {ratio:.4}x");
    println!("effective sigma= {sigma_eff:.2} (spec {SIGMA})");
    println!(
        "% of beta^2    = {:.1}%",
        100.0 * mean / BETA_SQUARED as f64
    );

    assert!(
        (0.90..=1.10).contains(&ratio),
        "norm distribution off-spec: mean {mean:.0} is {ratio:.4}x the design \
         {design:.0} (effective sigma {sigma_eff:.2} vs {SIGMA})"
    );
}

/// Falcon-1024 analogue (#143). Spec sigma = 1.17 · σ_min(1024) · √q; the old
/// SIGMA = 203.93 plus the Babai-rounding leaf made this unmeasurable-by-design:
/// rounding gave 2n·q/12 regardless of sigma.
#[test]
fn falcon1024_signature_norms_match_the_design_gaussian() {
    use metamui_falcon512::falcon1024::{generate_keypair_1024, sign_1024, verify_1024};

    const N1024: usize = 1024;
    const LOGN1024: usize = 10;
    const SIGMA_1024: f64 = 168.3885714457672;

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);

    let mut norms: Vec<i64> = Vec::new();
    for k in 0..4 {
        let kp = generate_keypair_1024(&mut rng).expect("keygen");
        for m in 0..8 {
            let msg = format!("falcon/143/distribution/{k}/{m}");
            let sig = sign_1024(msg.as_bytes(), &kp.private_key, &mut rng).expect("sign");
            assert!(
                verify_1024(msg.as_bytes(), &sig, &kp.public_key).unwrap(),
                "signature must verify"
            );

            // Reconstruct ||(s0,s1)||^2 the way verify_1024 does.
            let (nonce, s1) = metamui_falcon512::nist_encoding::decode_signature(&sig, LOGN1024)
                .expect("our own signature must decode");
            let c = metamui_falcon512::nist_hash::hash_to_point_nist_n(&nonce, msg.as_bytes(), N1024);
            let s1h = metamui_falcon512::ntt_falcon::multiply_ntt_n(&s1, &kp.public_key.h, N1024);
            let mut acc: i64 = 0;
            for i in 0..N1024 {
                let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
                let s0 = if diff >= (Q as i32 + 1) / 2 { diff - Q as i32 } else { diff };
                acc += (s0 as i64) * (s0 as i64) + (s1[i] as i64) * (s1[i] as i64);
            }
            norms.push(acc);
        }
    }

    let n = norms.len() as f64;
    let mean = norms.iter().map(|&x| x as f64).sum::<f64>() / n;
    let design = 2.0 * N1024 as f64 * SIGMA_1024 * SIGMA_1024;
    let ratio = mean / design;
    let sigma_eff = (mean / (2.0 * N1024 as f64)).sqrt();

    println!("samples        = {}", norms.len());
    println!("mean ||s||^2   = {mean:.0}");
    println!("design 2n*s^2  = {design:.0}");
    println!("ratio          = {ratio:.4}x");
    println!("effective sigma= {sigma_eff:.2} (spec {SIGMA_1024})");

    assert!(
        (0.90..=1.10).contains(&ratio),
        "Falcon-1024 norm distribution off-spec: mean {mean:.0} is {ratio:.4}x the \
         design {design:.0} (effective sigma {sigma_eff:.2} vs {SIGMA_1024})"
    );
}

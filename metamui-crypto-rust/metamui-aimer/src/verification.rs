//! Verification operations for AIMer
//!
//! Supports both AIM v1 (legacy) and AIM2 (spec v260130, Algorithm 13).

use crate::{
    params::AimerParams,
    error::AimerError,
    signing::{PublicKey, Signature},
    field,
};
use crate::aim2::Aim2;
use crate::signing::{
    h0_hash, h5_hash, h1_hash, h2_hash,
    expand_h1_challenges, expand_h2_indices,
    aim2_mpc_party, RepH1Data, RepH2Data,
};
use alloc::vec;
use alloc::vec::Vec;

/// Verify an AIM2 signature (spec v260130, Algorithm 13).
///
/// A signature carrying no per-repetition proofs is rejected outright. Until
/// 2026-09 that shape selected a legacy AIM v1 verifier; there is no longer
/// anything for it to select, and silently accepting it would be the weaker
/// of the two algorithms answering for the stronger one.
pub fn verify<P: AimerParams>(
    msg: &[u8],
    sig: &Signature,
    pk: &PublicKey,
) -> Result<bool, AimerError> {
    if !sig.is_well_formed() {
        return Err(AimerError::InvalidSignature);
    }
    verify_v2::<P>(msg, sig, pk)
}

// ============================================================================
// AIM2 v260130 verification (Algorithm 13)
// ============================================================================

fn verify_v2<P: AimerParams>(
    msg: &[u8],
    sig: &Signature,
    pk: &PublicKey,
) -> Result<bool, AimerError> {
    let fs = P::FIELD_SIZE;
    let lambda_bytes = P::SECURITY_BITS / 8;
    let l = P::AIM2_NUM_SBOXES;
    let tau = P::MPC_ROUNDS;
    let n = P::MPC_PARTIES;
    let iv = &pk.iv;
    let ct = &pk.ct;

    // Basic size checks
    if sig.salt.len() != lambda_bytes {
        return Ok(false);
    }
    if sig.h1.len() != 2 * lambda_bytes {
        return Ok(false);
    }
    if sig.h2.len() != 2 * lambda_bytes {
        return Ok(false);
    }
    if sig.proofs.len() != tau {
        return Ok(false);
    }

    // Step 1: μ = H₀(H0_PREFIX ‖ iv ‖ ct ‖ ctxlen=0x00 ‖ M') per genuine
    // samsungsds reference (spec v260130). See h0_hash for the pre-byte detail.
    let mu = h0_hash::<P>(iv, ct, msg);

    // Step 2: Generate affine layer
    let aim2 = Aim2::<P>::new();
    let (matrices, b_iv) = aim2.generate_affine_layer_public(iv);

    // Step 3: Expand challenges
    let epsilons = expand_h1_challenges::<P>(&sig.h1);
    let excluded = expand_h2_indices::<P>(&sig.h2);

    let mut h1_recomp_data = Vec::with_capacity(tau);
    let mut h2_recomp_data = Vec::with_capacity(tau);

    // Step 4: For each repetition k
    for k in 0..tau {
        let proof = &sig.proofs[k];
        let i_bar = excluded[k];

        // Reconstruct the seed tree (excluded party's seed = zeros)
        let party_seeds = crate::tree::reconstruct_tree::<P>(
            &sig.salt, &proof.path, k as u8, i_bar,
        );

        // Generate party materials via H₅ for all non-excluded parties
        let mut pt_shares: Vec<Vec<u8>> = vec![vec![0u8; fs]; n];
        let mut t_shares_all: Vec<Vec<Vec<u8>>> = vec![vec![vec![0u8; fs]; l]; n];
        let mut a_shares: Vec<Vec<u8>> = vec![vec![0u8; fs]; n];
        let mut c_shares: Vec<Vec<u8>> = vec![vec![0u8; fs]; n];
        let mut commitments: Vec<Vec<u8>> = Vec::with_capacity(n);

        for i in 0..n {
            if i == i_bar {
                commitments.push(proof.com_excluded.clone());
            } else {
                let m = h5_hash::<P>(&sig.salt, k as u8, i as u8, &party_seeds[i]);
                commitments.push(m.com_vec());
                pt_shares[i] = m.pt_share(fs);
                t_shares_all[i] = m.t_shares(l, fs);
                a_shares[i] = m.a_share(fs);
                c_shares[i] = m.c_share(fs);
            }
        }

        // Apply delta corrections to party N-1 (if not excluded)
        if (n - 1) != i_bar {
            pt_shares[n - 1] = field::gf_add_alloc(&pt_shares[n - 1], &proof.delta_pt);
            for j in 0..l {
                t_shares_all[n - 1][j] = field::gf_add_alloc(&t_shares_all[n - 1][j], &proof.delta_ts[j]);
            }
            c_shares[n - 1] = field::gf_add_alloc(&c_shares[n - 1], &proof.delta_c);
        }

        // Run AIM2_MPC for each non-excluded party
        let mut x_per_party: Vec<Vec<Vec<u8>>> = vec![vec![vec![0u8; fs]; l + 1]; n];
        let mut z_per_party: Vec<Vec<Vec<u8>>> = vec![vec![vec![0u8; fs]; l + 1]; n];

        for i in 0..n {
            if i != i_bar {
                let (x_vals, z_vals) = aim2_mpc_party::<P>(
                    &matrices, &b_iv, ct, &t_shares_all[i], i == n - 1,
                );
                x_per_party[i] = x_vals;
                z_per_party[i] = z_vals;
            }
        }

        // Compute individual alpha shares for all N parties.
        // Non-excluded: computed from H₅ material + epsilon challenges.
        // Excluded: taken directly from proof.alpha_excluded.
        let mut alpha_shares: Vec<Vec<u8>> = vec![vec![0u8; fs]; n];
        let mut alpha_total = vec![0u8; fs];
        for i in 0..n {
            if i == i_bar {
                alpha_shares[i] = proof.alpha_excluded.clone();
            } else {
                let mut alpha_i = a_shares[i].clone();
                for j in 0..(l + 1) {
                    let eps_x = field::gf_mul(&epsilons[k][j], &x_per_party[i][j], fs);
                    alpha_i = field::gf_add_alloc(&alpha_i, &eps_x);
                }
                alpha_shares[i] = alpha_i;
            }
            alpha_total = field::gf_add_alloc(&alpha_total, &alpha_shares[i]);
        }

        // Compute v shares for non-excluded parties
        let mut v_shares: Vec<Vec<u8>> = vec![vec![0u8; fs]; n];
        for i in 0..n {
            if i != i_bar {
                let mut v_i = c_shares[i].clone();
                for j in 0..(l + 1) {
                    let eps_z = field::gf_mul(&epsilons[k][j], &z_per_party[i][j], fs);
                    v_i = field::gf_add_alloc(&v_i, &eps_z);
                }
                let alpha_pt = field::gf_mul(&alpha_total, &pt_shares[i], fs);
                v_i = field::gf_add_alloc(&v_i, &alpha_pt);
                v_shares[i] = v_i;
            }
        }

        // Compute excluded party's v from zero-sum constraint: Σ_i v_i = 0
        let mut v_excluded = vec![0u8; fs];
        for i in 0..n {
            if i != i_bar {
                v_excluded = field::gf_add_alloc(&v_excluded, &v_shares[i]);
            }
        }
        v_shares[i_bar] = v_excluded;

        h1_recomp_data.push(RepH1Data {
            commitments,
            delta_pt: proof.delta_pt.clone(),
            delta_ts: proof.delta_ts.clone(),
            delta_c: proof.delta_c.clone(),
        });

        h2_recomp_data.push(RepH2Data {
            alpha_shares,
            v_shares,
        });
    }

    // Step 5: Recompute h₁' and compare
    let h1_prime = h1_hash::<P>(&mu, &sig.salt, &h1_recomp_data);
    if h1_prime != sig.h1 {
        return Ok(false);
    }

    // Step 6: Recompute h₂' and compare
    let h2_prime = h2_hash::<P>(&sig.h1, &sig.salt, &h2_recomp_data);
    if h2_prime != sig.h2 {
        return Ok(false);
    }

    Ok(true)
}

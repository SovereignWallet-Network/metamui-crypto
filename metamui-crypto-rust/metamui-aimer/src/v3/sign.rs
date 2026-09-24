//! AIMer v3 key generation, signing and verification (`sign.c` upstream),
//! laid out one-to-one against the reference so the KAT gate pinpoints any
//! divergence to a phase.

use super::aim3::{aim3, aim3_mpc, generate_linear, sbox_outputs, Linear, MultChk, Tape};
use super::backend;
use super::field::*;
use super::hash::{Hash, PREFIX_1, PREFIX_2, PREFIX_3, PREFIX_5};
use super::params::AimerV3Params;
use super::tree::{expand_tree, reconstruct_tree, reveal_all_but};
use super::V3Error;
use alloc::vec;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

/// `crypto_sign_keypair_internal`: `pk = iv ‖ ct`, `sk = pt ‖ iv ‖ ct`, or
/// `Err(ZeroSboxInput)` when this `(pt, iv)` must be discarded.
///
/// Runs on the installed [`super::backend`] when there is one,
/// which must produce the bytes of [`keypair_from_pt_iv_ref`]; otherwise,
/// and always with this crate alone, it is [`keypair_from_pt_iv_ref`].
pub fn keypair_from_pt_iv<P: AimerV3Params>(pt: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), V3Error> {
    if pt.len() != P::FB || iv.len() != P::FB {
        return Err(V3Error::InvalidLength);
    }
    if let Some(b) = backend::backend() {
        return b.keypair_from_pt_iv(P::SET, pt, iv);
    }
    keypair_from_pt_iv_ref::<P>(pt, iv)
}

/// [`keypair_from_pt_iv`] on the reference path, whatever backend is installed.
pub fn keypair_from_pt_iv_ref<P: AimerV3Params>(pt: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), V3Error> {
    if pt.len() != P::FB || iv.len() != P::FB {
        return Err(V3Error::InvalidLength);
    }
    let lin = generate_linear::<P>(iv);
    let pt_gf = gf_from_bytes::<P>(pt);
    let ct = aim3::<P>(&lin, &pt_gf).ok_or(V3Error::ZeroSboxInput)?;
    let mut pk = Vec::with_capacity(P::PK_BYTES);
    pk.extend_from_slice(iv);
    pk.extend_from_slice(&gf_bytes::<P>(&ct));
    let mut sk = Vec::with_capacity(P::SK_BYTES);
    sk.extend_from_slice(pt);
    sk.extend_from_slice(&pk);
    Ok((pk, sk))
}

/// `crypto_sign_keypair`: draws `pt` then `iv` from `rng` and retries on a
/// zero S-box input, exactly as the reference does.
pub fn generate_keypair_with<P: AimerV3Params, F: FnMut(&mut [u8]) -> Result<(), V3Error>>(
    mut rng: F,
) -> Result<(Vec<u8>, Vec<u8>), V3Error> {
    let mut pt = vec![0u8; P::FB];
    let mut iv = vec![0u8; P::FB];
    loop {
        rng(&mut pt)?;
        rng(&mut iv)?;
        match keypair_from_pt_iv::<P>(&pt, &iv) {
            Ok(kp) => return Ok(kp),
            Err(V3Error::ZeroSboxInput) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn commit_and_expand_tape<P: AimerV3Params>(salt: &[u8], rep: usize, party: usize, seed: &[u8]) -> (Vec<u8>, Tape) {
    let mut h = Hash::with_prefix::<P>(PREFIX_5);
    h.update(salt);
    h.update(&[rep as u8]);
    h.update(&[party as u8]);
    h.update(seed);
    let mut xof = h.finalize();
    let commit = xof.squeeze(P::COMMIT);
    let tape = Tape::from_bytes::<P>(&xof.squeeze(P::TAPE_BYTES));
    (commit, tape)
}

/// `pre = ctxlen ‖ ctx`
fn prefix(ctx: &[u8]) -> Result<Vec<u8>, V3Error> {
    if ctx.len() > 255 {
        return Err(V3Error::ContextTooLong);
    }
    let mut pre = Vec::with_capacity(1 + ctx.len());
    pre.push(ctx.len() as u8);
    pre.extend_from_slice(ctx);
    Ok(pre)
}

/// The per-repetition proof, in wire order.
///
/// Exposed, hidden from the documentation, so that a [`backend`] crate
/// serialises its proofs through the same code; not a stable API.
#[doc(hidden)]
pub struct Proof {
    pub reveal_path: Vec<Vec<u8>>,
    pub missing_commitment: Vec<u8>,
    pub delta_pt: Vec<u8>,
    pub delta_ys: Vec<Vec<u8>>,
    pub delta_c: Vec<u8>,
    pub missing_alpha: Vec<Vec<u8>>,
}

#[doc(hidden)]
impl Proof {
    pub fn empty<P: AimerV3Params>() -> Self {
        Proof {
            reveal_path: vec![vec![0u8; P::FB]; P::LOGN],
            missing_commitment: vec![0u8; P::COMMIT],
            delta_pt: vec![0u8; P::FB],
            delta_ys: vec![vec![0u8; P::FB]; P::L],
            delta_c: vec![0u8; P::FB],
            missing_alpha: vec![vec![0u8; P::FB]; P::L + 1],
        }
    }

    /// `delta_pt ‖ delta_ys[L] ‖ delta_c` — the `(L+2)` elements hashed into `h_1`.
    pub fn deltas(&self) -> Vec<u8> {
        let mut v = self.delta_pt.clone();
        for y in &self.delta_ys {
            v.extend_from_slice(y);
        }
        v.extend_from_slice(&self.delta_c);
        v
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        for s in &self.reveal_path {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(&self.missing_commitment);
        out.extend_from_slice(&self.deltas());
        for a in &self.missing_alpha {
            out.extend_from_slice(a);
        }
    }

    pub fn read<P: AimerV3Params>(bytes: &[u8]) -> Self {
        let mut off = 0usize;
        let mut take = |n: usize| {
            let v = bytes[off..off + n].to_vec();
            off += n;
            v
        };
        let reveal_path = (0..P::LOGN).map(|_| take(P::FB)).collect();
        let missing_commitment = take(P::COMMIT);
        let delta_pt = take(P::FB);
        let delta_ys = (0..P::L).map(|_| take(P::FB)).collect();
        let delta_c = take(P::FB);
        let missing_alpha = (0..=P::L).map(|_| take(P::FB)).collect();
        Proof { reveal_path, missing_commitment, delta_pt, delta_ys, delta_c, missing_alpha }
    }
}

/// Bytes of one [`Proof`] on the wire. Hidden: for a [`backend`] crate.
#[doc(hidden)]
pub const fn proof_bytes<P: AimerV3Params>() -> usize {
    P::LOGN * P::FB + P::COMMIT + (2 * P::L + 3) * P::FB
}

/// `crypto_sign_signature_internal` with an explicit `rnd` (λ/8 bytes) and
/// pre-built `pre`; returns the `SIG_BYTES`-byte detached signature.
///
/// Runs on the installed [`super::backend`] when there is one,
/// which must produce the bytes of [`sign_internal_ref`]; otherwise, and
/// always with this crate alone, it is [`sign_internal_ref`].
pub fn sign_internal<P: AimerV3Params>(m: &[u8], pre: &[u8], rnd: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error> {
    if sk.len() != P::SK_BYTES || rnd.len() != P::FB {
        return Err(V3Error::InvalidLength);
    }
    if let Some(b) = backend::backend() {
        return b.sign_internal(P::SET, m, pre, rnd, sk);
    }
    sign_internal_ref::<P>(m, pre, rnd, sk)
}

/// [`sign_internal`] on the reference path, whatever backend is installed.
pub fn sign_internal_ref<P: AimerV3Params>(m: &[u8], pre: &[u8], rnd: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error> {
    if sk.len() != P::SK_BYTES || rnd.len() != P::FB {
        return Err(V3Error::InvalidLength);
    }
    let pt = gf_from_bytes::<P>(&sk[..P::FB]);
    let iv = &sk[P::FB..2 * P::FB];
    let ct = gf_from_bytes::<P>(&sk[2 * P::FB..3 * P::FB]);

    // ---- Phase 1: commit to seeds and execution views ------------------
    let mut h = Hash::with_prefix::<P>(P::HASH_PREFIX_0);
    h.update(&sk[P::FB..3 * P::FB]); // iv ‖ ct
    h.update(pre);
    h.update(m);
    let mu = h.finalize().squeeze(P::COMMIT);

    let lin: Linear = generate_linear::<P>(iv);
    let sbox_out = sbox_outputs::<P>(&lin, &pt, &ct);

    let mut h = Hash::with_prefix::<P>(PREFIX_3);
    h.update(&sk[..P::FB]);
    h.update(&mu);
    h.update(rnd);
    let mut xof = h.finalize();
    let salt = xof.squeeze(P::FB);
    let root_seeds: Vec<Vec<u8>> = (0..P::T).map(|_| xof.squeeze(P::FB)).collect();

    let mut h1 = Hash::with_prefix::<P>(PREFIX_1);
    h1.update(&mu);
    h1.update(&salt);

    let mut proofs: Vec<Proof> = (0..P::T).map(|_| Proof::empty::<P>()).collect();
    let mut all_nodes: Vec<Vec<Vec<u8>>> = Vec::with_capacity(P::T);
    let mut all_commits: Vec<Vec<Vec<u8>>> = Vec::with_capacity(P::T);
    let mut mult_chk: Vec<Vec<MultChk>> = Vec::with_capacity(P::T);

    for rep in 0..P::T {
        let nodes = expand_tree::<P>(&salt, rep, &root_seeds[rep]);
        let mut delta = Tape::zero::<P>();
        let mut commits = Vec::with_capacity(P::N);
        let mut chks = Vec::with_capacity(P::N);
        for party in 0..P::N {
            let (commit, mut tape) = commit_and_expand_tape::<P>(&salt, rep, party, &nodes[party + P::N - 1]);
            gf_add_assign::<P>(&mut delta.pt_share, &tape.pt_share);
            for i in 0..P::L {
                gf_add_assign::<P>(&mut delta.y_shares[i], &tape.y_shares[i]);
            }
            for i in 0..=P::L {
                gf_add_assign::<P>(&mut delta.a_shares[i], &tape.a_shares[i]);
            }
            gf_add_assign::<P>(&mut delta.c_share, &tape.c_share);

            if party == P::N - 1 {
                // adjust_last_share
                let proof = &mut proofs[rep];
                gf_add_assign::<P>(&mut delta.pt_share, &pt);
                proof.delta_pt = gf_bytes::<P>(&delta.pt_share);
                tape.pt_share = gf_add::<P>(&delta.pt_share, &tape.pt_share);
                for i in 0..P::L {
                    gf_add_assign::<P>(&mut delta.y_shares[i], &sbox_out[i]);
                    proof.delta_ys[i] = gf_bytes::<P>(&delta.y_shares[i]);
                    tape.y_shares[i] = gf_add::<P>(&delta.y_shares[i], &tape.y_shares[i]);
                }
                for i in 0..=P::L {
                    gf_mul_add::<P>(&mut delta.c_share, &delta.a_shares[i], &sbox_out[i]);
                }
                proof.delta_c = gf_bytes::<P>(&delta.c_share);
                tape.c_share = gf_add::<P>(&delta.c_share, &tape.c_share);
            }
            chks.push(aim3_mpc::<P>(&lin, &tape, &ct, party));
            commits.push(commit);
        }
        for c in &commits {
            h1.update(c);
        }
        h1.update(&proofs[rep].deltas());
        all_nodes.push(nodes);
        all_commits.push(commits);
        mult_chk.push(chks);
    }
    let h_1 = h1.finalize().squeeze(P::COMMIT);

    // ---- Phases 2 and 3: challenge and commit to the multiplication check --
    let mut he = Hash::new::<P>();
    he.update(&h_1);
    let mut ctx_e = he.finalize();

    let mut h2 = Hash::with_prefix::<P>(PREFIX_2);
    h2.update(&h_1);
    h2.update(&salt);

    let mut alpha_shares: Vec<Vec<Vec<Gf>>> = Vec::with_capacity(P::T);
    for rep in 0..P::T {
        let eps_bytes = ctx_e.squeeze((P::L + 1) * P::FB);
        let epsilons: Vec<Gf> = (0..=P::L).map(|l| gf_from_bytes::<P>(&eps_bytes[l * P::FB..(l + 1) * P::FB])).collect();
        let mut alpha = vec![gf_zero(); P::L + 1];
        let mut shares = vec![vec![gf_zero(); P::L + 1]; P::N];
        let mut v_share = vec![gf_zero(); P::N];
        for party in 0..P::N {
            let mc = &mult_chk[rep][party];
            v_share[party] = mc.c_share;
            for ell in 0..=P::L {
                let mut a = mc.a_shares[ell];
                gf_mul_add::<P>(&mut a, &mc.x_shares[ell], &epsilons[ell]);
                gf_add_assign::<P>(&mut alpha[ell], &a);
                shares[party][ell] = a;
                gf_mul_add::<P>(&mut v_share[party], &mc.z_shares[ell], &epsilons[ell]);
            }
        }
        for party in 0..P::N {
            let mc = &mult_chk[rep][party];
            for ell in 0..=P::L {
                gf_mul_add::<P>(&mut v_share[party], &mc.b_shares[ell], &alpha[ell]);
            }
        }
        for party in 0..P::N {
            for ell in 0..=P::L {
                h2.update(&gf_bytes::<P>(&shares[party][ell]));
            }
        }
        for party in 0..P::N {
            h2.update(&gf_bytes::<P>(&v_share[party]));
        }
        alpha_shares.push(shares);
    }
    let h_2 = h2.finalize().squeeze(P::COMMIT);

    // ---- Phases 4 and 5: challenge and open the views ------------------
    let mut hi = Hash::new::<P>();
    hi.update(&h_2);
    let indices = hi.finalize().squeeze(P::T);
    for rep in 0..P::T {
        let i_bar = (indices[rep] as usize) & ((1 << P::LOGN) - 1);
        let proof = &mut proofs[rep];
        proof.reveal_path = reveal_all_but::<P>(&all_nodes[rep], i_bar);
        proof.missing_commitment = all_commits[rep][i_bar].clone();
        for ell in 0..=P::L {
            proof.missing_alpha[ell] = gf_bytes::<P>(&alpha_shares[rep][i_bar][ell]);
        }
    }

    let mut sig = Vec::with_capacity(P::SIG_BYTES);
    sig.extend_from_slice(&salt);
    sig.extend_from_slice(&h_1);
    sig.extend_from_slice(&h_2);
    for p in &proofs {
        p.write(&mut sig);
    }
    debug_assert_eq!(sig.len(), P::SIG_BYTES);
    Ok(sig)
}

/// `crypto_sign_signature`: context-bound detached signature with caller
/// randomness (`rnd`, λ/8 bytes — the reference draws it from `randombytes`).
pub fn sign_with_rnd<P: AimerV3Params>(m: &[u8], ctx: &[u8], rnd: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error> {
    let pre = prefix(ctx)?;
    sign_internal::<P>(m, &pre, rnd, sk)
}

/// `crypto_sign_verify_internal`
///
/// Runs on the installed [`super::backend`] when there is one,
/// which must return the verdict of [`verify_internal_ref`]; otherwise, and
/// always with this crate alone, it is [`verify_internal_ref`].
pub fn verify_internal<P: AimerV3Params>(sig: &[u8], m: &[u8], pre: &[u8], pk: &[u8]) -> bool {
    if sig.len() != P::SIG_BYTES || pk.len() != P::PK_BYTES {
        return false;
    }
    if let Some(b) = backend::backend() {
        return b.verify_internal(P::SET, sig, m, pre, pk);
    }
    verify_internal_ref::<P>(sig, m, pre, pk)
}

/// [`verify_internal`] on the reference path, whatever backend is installed.
pub fn verify_internal_ref<P: AimerV3Params>(sig: &[u8], m: &[u8], pre: &[u8], pk: &[u8]) -> bool {
    if sig.len() != P::SIG_BYTES || pk.len() != P::PK_BYTES {
        return false;
    }
    let iv = &pk[..P::FB];
    let ct = gf_from_bytes::<P>(&pk[P::FB..2 * P::FB]);
    let lin = generate_linear::<P>(iv);

    let salt = &sig[..P::FB];
    let h_1 = &sig[P::FB..P::FB + P::COMMIT];
    let h_2 = &sig[P::FB + P::COMMIT..P::FB + 2 * P::COMMIT];
    let mut off = P::FB + 2 * P::COMMIT;
    let proofs: Vec<Proof> = (0..P::T)
        .map(|_| {
            let p = Proof::read::<P>(&sig[off..off + proof_bytes::<P>()]);
            off += proof_bytes::<P>();
            p
        })
        .collect();

    let mut hi = Hash::new::<P>();
    hi.update(h_2);
    let indices = hi.finalize().squeeze(P::T);

    let mut he = Hash::new::<P>();
    he.update(h_1);
    let mut ctx_e = he.finalize();

    let mut h = Hash::with_prefix::<P>(P::HASH_PREFIX_0);
    h.update(pk);
    h.update(pre);
    h.update(m);
    let mu = h.finalize().squeeze(P::COMMIT);

    let mut ctx_h1 = Hash::with_prefix::<P>(PREFIX_1);
    ctx_h1.update(&mu);
    ctx_h1.update(salt);
    let mut ctx_h2 = Hash::with_prefix::<P>(PREFIX_2);
    ctx_h2.update(h_1);
    ctx_h2.update(salt);

    for rep in 0..P::T {
        let i_bar = (indices[rep] as usize) & ((1 << P::LOGN) - 1);
        let proof = &proofs[rep];
        let nodes = reconstruct_tree::<P>(salt, &proof.reveal_path, rep, i_bar);

        let eps_bytes = ctx_e.squeeze((P::L + 1) * P::FB);
        let epsilons: Vec<Gf> = (0..=P::L).map(|l| gf_from_bytes::<P>(&eps_bytes[l * P::FB..(l + 1) * P::FB])).collect();
        let mut alpha = vec![gf_zero(); P::L + 1];
        let mut alpha_shares = vec![vec![gf_zero(); P::L + 1]; P::N];
        let mut b_shares = vec![vec![gf_zero(); P::L + 1]; P::N];
        let mut v_shares = vec![gf_zero(); P::N];

        for party in 0..P::N {
            if party == i_bar {
                ctx_h1.update(&proof.missing_commitment);
                for ell in 0..=P::L {
                    alpha_shares[i_bar][ell] = gf_from_bytes::<P>(&proof.missing_alpha[ell]);
                    gf_add_assign::<P>(&mut alpha[ell], &alpha_shares[i_bar][ell]);
                }
                continue;
            }
            let (commit, mut tape) = commit_and_expand_tape::<P>(salt, rep, party, &nodes[P::N + party - 2]);
            ctx_h1.update(&commit);
            if party == P::N - 1 {
                gf_add_assign::<P>(&mut tape.pt_share, &gf_from_bytes::<P>(&proof.delta_pt));
                for ell in 0..P::L {
                    gf_add_assign::<P>(&mut tape.y_shares[ell], &gf_from_bytes::<P>(&proof.delta_ys[ell]));
                }
                gf_add_assign::<P>(&mut tape.c_share, &gf_from_bytes::<P>(&proof.delta_c));
            }
            let mc = aim3_mpc::<P>(&lin, &tape, &ct, party);
            v_shares[party] = mc.c_share;
            for ell in 0..=P::L {
                let mut a = mc.a_shares[ell];
                gf_mul_add::<P>(&mut a, &mc.x_shares[ell], &epsilons[ell]);
                gf_add_assign::<P>(&mut alpha[ell], &a);
                alpha_shares[party][ell] = a;
                b_shares[party][ell] = mc.b_shares[ell];
                gf_mul_add::<P>(&mut v_shares[party], &mc.z_shares[ell], &epsilons[ell]);
            }
        }

        // recompute_v_shares: the missing party's v is whatever makes the sum zero
        let mut v_bar = gf_zero();
        for party in 0..P::N {
            if party == i_bar {
                continue;
            }
            for ell in 0..=P::L {
                gf_mul_add::<P>(&mut v_shares[party], &b_shares[party][ell], &alpha[ell]);
            }
            gf_add_assign::<P>(&mut v_bar, &v_shares[party]);
        }
        v_shares[i_bar] = v_bar;

        for party in 0..P::N {
            for ell in 0..=P::L {
                ctx_h2.update(&gf_bytes::<P>(&alpha_shares[party][ell]));
            }
        }
        for party in 0..P::N {
            ctx_h2.update(&gf_bytes::<P>(&v_shares[party]));
        }
        ctx_h1.update(&proof.deltas());
    }

    let h_1_prime = ctx_h1.finalize().squeeze(P::COMMIT);
    let h_2_prime = ctx_h2.finalize().squeeze(P::COMMIT);
    bool::from(h_1_prime.ct_eq(h_1) & h_2_prime.ct_eq(h_2))
}

/// `crypto_sign_verify`
pub fn verify_with_ctx<P: AimerV3Params>(sig: &[u8], m: &[u8], ctx: &[u8], pk: &[u8]) -> bool {
    match prefix(ctx) {
        Ok(pre) => verify_internal::<P>(sig, m, &pre, pk),
        Err(_) => false,
    }
}

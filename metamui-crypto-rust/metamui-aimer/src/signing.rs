//! Signing operations for AIMer (AIM2, spec v260130, Algorithm 11).

use crate::{
    params::AimerParams,
    error::AimerError,
    field,
};
use crate::aim2::Aim2;
use metamui_shake::Shake128;
use metamui_shake::Shake256;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;
use getrandom::getrandom;

/// Public key for AIMer
#[derive(Clone)]
pub struct PublicKey {
    /// Initialization vector (used as key input to AIM)
    pub iv: Vec<u8>,
    /// Ciphertext = AIM(sk, iv) or AIM2(iv, sk)
    pub ct: Vec<u8>,
}

/// Secret key for AIMer
#[derive(Clone)]
pub struct SecretKey {
    pub sk: Vec<u8>,
    pub pk: PublicKey,
}

impl PublicKey {
    /// Serialize to the reference wire format: `iv ‖ ct`, each `FIELD_SIZE`
    /// bytes, `PUBLIC_KEY_SIZE` in total.
    ///
    /// This is the layout the genuine Samsung SDS KAT files carry — the
    /// upstream gate (`tests/aimer_upstream_kat.rs`) splits their `pk` field at
    /// exactly this boundary — so a binding that round-trips through it is
    /// interoperable rather than merely self-consistent.
    pub fn to_bytes<P: AimerParams>(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(P::PUBLIC_KEY_SIZE);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse the reference wire format. Rejects any length but
    /// `P::PUBLIC_KEY_SIZE`.
    pub fn from_bytes<P: AimerParams>(bytes: &[u8]) -> Result<Self, AimerError> {
        if bytes.len() != P::PUBLIC_KEY_SIZE {
            return Err(AimerError::InvalidKeySize);
        }
        Ok(Self {
            iv: bytes[..P::FIELD_SIZE].to_vec(),
            ct: bytes[P::FIELD_SIZE..].to_vec(),
        })
    }
}

impl SecretKey {
    /// Serialize to the reference wire format: `pt ‖ iv ‖ ct`, each
    /// `FIELD_SIZE` bytes, `SECRET_KEY_SIZE` in total (the secret key embeds
    /// its public key, as the NIST KAT `sk` field does).
    pub fn to_bytes<P: AimerParams>(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(P::SECRET_KEY_SIZE);
        out.extend_from_slice(&self.sk);
        out.extend_from_slice(&self.pk.iv);
        out.extend_from_slice(&self.pk.ct);
        out
    }

    /// Parse the reference wire format. Rejects any length but
    /// `P::SECRET_KEY_SIZE`.
    pub fn from_bytes<P: AimerParams>(bytes: &[u8]) -> Result<Self, AimerError> {
        if bytes.len() != P::SECRET_KEY_SIZE {
            return Err(AimerError::InvalidKeySize);
        }
        let fs = P::FIELD_SIZE;
        Ok(Self {
            sk: bytes[..fs].to_vec(),
            pk: PublicKey {
                iv: bytes[fs..2 * fs].to_vec(),
                ct: bytes[2 * fs..].to_vec(),
            },
        })
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.sk.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Per-repetition proof data in the compact signature format (spec v260130).
#[derive(Clone)]
pub struct RepProof {
    /// Sibling path: log₂N seeds, each lambda/8 bytes
    pub path: Vec<Vec<u8>>,
    /// Commitment of the excluded party, 2*lambda/8 bytes
    pub com_excluded: Vec<u8>,
    /// Correction for plaintext share: FIELD_SIZE bytes
    pub delta_pt: Vec<u8>,
    /// Corrections for S-box output shares: ℓ values, each FIELD_SIZE bytes
    pub delta_ts: Vec<Vec<u8>>,
    /// Correction for inner-product share: FIELD_SIZE bytes
    pub delta_c: Vec<u8>,
    /// Alpha of excluded party: FIELD_SIZE bytes
    pub alpha_excluded: Vec<u8>,
}

/// Signature for AIMer — the compact AIM2 (salt, h1, h2, proofs) format.
#[derive(Clone)]
pub struct Signature {
    pub salt: Vec<u8>,
    pub h1: Vec<u8>,
    pub h2: Vec<u8>,
    pub proofs: Vec<RepProof>,
}

impl Signature {
    /// Create a new AIM2 compact signature.
    fn new_v2(salt: Vec<u8>, h1: Vec<u8>, h2: Vec<u8>, proofs: Vec<RepProof>) -> Self {
        Self { salt, h1, h2, proofs }
    }

    /// Returns true if this signature carries the per-repetition proofs the
    /// AIM2 format requires. A signature that does not is structurally
    /// invalid — `verify` rejects it rather than falling back to anything.
    pub fn is_well_formed(&self) -> bool {
        !self.proofs.is_empty()
    }

    /// Deserialize a compact AIM2 signature from the reference wire format.
    ///
    /// Wire layout:
    /// `salt[SALT_SIZE] | h1[DIGEST_SIZE] | h2[DIGEST_SIZE] | proofs[MPC_ROUNDS × proof_size]`
    ///
    /// Each proof:
    /// `path[LOG_N × SEED_SIZE] | com_excluded[DIGEST_SIZE] | delta_pt[FIELD_SIZE] |
    ///  delta_ts[AIM2_NUM_SBOXES × FIELD_SIZE] | delta_c[FIELD_SIZE] | alpha_excluded[FIELD_SIZE]`
    pub fn from_bytes<P: AimerParams>(bytes: &[u8]) -> Result<Self, AimerError> {
        if bytes.len() != P::SIGNATURE_SIZE {
            return Err(AimerError::InvalidSignatureSize);
        }

        let mut pos = 0;

        let salt = bytes[pos..pos + P::SALT_SIZE].to_vec();
        pos += P::SALT_SIZE;

        let h1 = bytes[pos..pos + P::DIGEST_SIZE].to_vec();
        pos += P::DIGEST_SIZE;

        let h2 = bytes[pos..pos + P::DIGEST_SIZE].to_vec();
        pos += P::DIGEST_SIZE;

        let mut proofs = Vec::with_capacity(P::MPC_ROUNDS);
        for _ in 0..P::MPC_ROUNDS {
            // Sibling seeds on the reveal path
            let mut path = Vec::with_capacity(P::LOG_N);
            for _ in 0..P::LOG_N {
                path.push(bytes[pos..pos + P::SEED_SIZE].to_vec());
                pos += P::SEED_SIZE;
            }

            let com_excluded = bytes[pos..pos + P::DIGEST_SIZE].to_vec();
            pos += P::DIGEST_SIZE;

            let delta_pt = bytes[pos..pos + P::FIELD_SIZE].to_vec();
            pos += P::FIELD_SIZE;

            let mut delta_ts = Vec::with_capacity(P::AIM2_NUM_SBOXES);
            for _ in 0..P::AIM2_NUM_SBOXES {
                delta_ts.push(bytes[pos..pos + P::FIELD_SIZE].to_vec());
                pos += P::FIELD_SIZE;
            }

            let delta_c = bytes[pos..pos + P::FIELD_SIZE].to_vec();
            pos += P::FIELD_SIZE;

            let alpha_excluded = bytes[pos..pos + P::FIELD_SIZE].to_vec();
            pos += P::FIELD_SIZE;

            proofs.push(RepProof {
                path,
                com_excluded,
                delta_pt,
                delta_ts,
                delta_c,
                alpha_excluded,
            });
        }

        debug_assert_eq!(pos, P::SIGNATURE_SIZE);
        Ok(Self::new_v2(salt, h1, h2, proofs))
    }

    /// Serialize a compact AIM2 signature to the reference wire format.
    ///
    /// Mirror image of `from_bytes` — same field order, same sizes.
    pub fn to_bytes<P: AimerParams>(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(P::SIGNATURE_SIZE);

        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.h1);
        buf.extend_from_slice(&self.h2);

        for proof in &self.proofs {
            for seed in &proof.path {
                buf.extend_from_slice(seed);
            }
            buf.extend_from_slice(&proof.com_excluded);
            buf.extend_from_slice(&proof.delta_pt);
            for dt in &proof.delta_ts {
                buf.extend_from_slice(dt);
            }
            buf.extend_from_slice(&proof.delta_c);
            buf.extend_from_slice(&proof.alpha_excluded);
        }

        debug_assert_eq!(buf.len(), P::SIGNATURE_SIZE);
        buf
    }
}

/// Generate a keypair
pub fn generate_keypair<P: AimerParams>() -> Result<(PublicKey, SecretKey), AimerError> {
    let mut sk_bytes = vec![0u8; P::FIELD_SIZE];
    getrandom(&mut sk_bytes).map_err(|_| AimerError::RandomGenerationFailed)?;

    let mut iv = vec![0u8; P::FIELD_SIZE];
    getrandom(&mut iv).map_err(|_| AimerError::RandomGenerationFailed)?;

    let ct = Aim2::<P>::new().evaluate(&iv, &sk_bytes)?;

    let pk = PublicKey { iv, ct };
    let sk = SecretKey {
        sk: sk_bytes,
        pk: pk.clone(),
    };

    Ok((pk, sk))
}

/// Sign a message with AIM2 (spec v260130, Algorithm 11).
pub fn sign<P: AimerParams>(msg: &[u8], sk: &SecretKey) -> Result<Signature, AimerError> {
    sign_v2::<P>(msg, sk)
}

// ============================================================================
// AIM2 (spec v260130) signing — Algorithm 11
// ============================================================================

// SHAKE absorb trait for polymorphic hashing
trait ShakeAbsorb {
    fn absorb(&mut self, data: &[u8]);
}

struct ShakeAbsorber128<'a>(&'a mut Shake128);
struct ShakeAbsorber256<'a>(&'a mut Shake256);

impl<'a> ShakeAbsorb for ShakeAbsorber128<'a> {
    fn absorb(&mut self, data: &[u8]) { let _ = self.0.update(data); }
}
impl<'a> ShakeAbsorb for ShakeAbsorber256<'a> {
    fn absorb(&mut self, data: &[u8]) { let _ = self.0.update(data); }
}

macro_rules! shake_hash {
    ($security_bits:expr, $absorb:expr, $output_len:expr) => {{
        if $security_bits == 128 {
            let mut shake = Shake128::new();
            $absorb(&mut ShakeAbsorber128(&mut shake));
            let mut reader = shake.finalize_xof();
            reader.read($output_len)
        } else {
            let mut shake = Shake256::new();
            $absorb(&mut ShakeAbsorber256(&mut shake));
            let mut reader = shake.finalize_xof();
            reader.read($output_len)
        }
    }};
}

/// μ = H₀(iv, ct, M') = SHAKE_λ(H0_PREFIX ‖ iv ‖ ct ‖ pre ‖ M', 2λ).
///
/// Matches the genuine samsungsds AIMer reference (spec v260130, sign.c
/// `run_phase_1` / `crypto_sign_verify_internal`):
///   hash_init_prefix(&ctx, HASH_PREFIX_0)        // per-variant: 0x00/0x10/0x20/0x30/0x40/0x50
///   hash_update(&ctx, iv ‖ ct, AIM2_IV_SIZE + AIM2_NUM_BYTES_FIELD)
///   hash_update(&ctx, pre, prelen)               // pre = [ctxlen ‖ ctx]
///   hash_update(&ctx, m, mlen)
///
/// The public `verify`/`sign` API carries no context string, so `ctx` is empty
/// and `pre` is the single byte `ctxlen = 0x00` (`crypto_sign_signature` builds
/// `prefix[0] = ctxlen` and passes `prelen = 1 + ctxlen`). Two corrections vs
/// the older in-repo KPQC reference this port previously mirrored: (1) the
/// per-variant `H0_PREFIX` (was hardcoded 0x00 — wrong for 5 of 6 sets), and
/// (2) the `0x00` context byte between `ct` and the message (the spec adopted
/// the NIST-style context API; the old vintage omitted it).
pub(crate) fn h0_hash<P: AimerParams>(iv: &[u8], ct: &[u8], msg: &[u8]) -> Vec<u8> {
    let output_len = 2 * (P::SECURITY_BITS / 8);
    shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(&[P::H0_PREFIX]);
        s.absorb(iv);
        s.absorb(ct);
        s.absorb(&[0x00]); // pre = [ctxlen = 0] for the empty-context API path
        s.absorb(msg);
    }, output_len)
}

/// H₃(pt, μ, ρ) = SHAKE_λ(0x03 ‖ pt ‖ μ ‖ ρ, λ + τ·λ).
///
/// Matches KPQC C reference (sign.c, run_phase_1):
///   hash_init_prefix(&ctx, HASH_PREFIX_3)          // 0x03
///   hash_update(&ctx, sk, AIM2_NUM_BYTES_FIELD)    // pt FIRST
///   hash_update(&ctx, mu, AIMER_COMMIT_SIZE)       // then μ
///   hash_update(&ctx, random, SECURITY_BYTES)      // then ρ
///
/// Parameter labels remain `mu, pt, rho` for caller clarity; the internal
/// absorb order is `pt → μ → ρ` per the C reference.
fn h3<P: AimerParams>(mu: &[u8], pt: &[u8], rho: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let lambda_bytes = P::SECURITY_BITS / 8;
    let tau = P::MPC_ROUNDS;
    let output_len = lambda_bytes + tau * lambda_bytes;
    let output = shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(&[0x03]);
        s.absorb(pt);
        s.absorb(mu);
        s.absorb(rho);
    }, output_len);

    let salt = output[..lambda_bytes].to_vec();
    let mut seeds = Vec::with_capacity(tau);
    for k in 0..tau {
        let start = lambda_bytes + k * lambda_bytes;
        seeds.push(output[start..start + lambda_bytes].to_vec());
    }
    (salt, seeds)
}

/// Convert a byte slice to a fixed-size [u64; 4] limb array (stack-allocated).
#[inline(always)]
fn bytes_to_limbs4(bytes: &[u8]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..bytes.len() {
        limbs[i / 8] |= (bytes[i] as u64) << ((i % 8) * 8);
    }
    limbs
}

/// H₅(salt, k, i, seed) = SHAKE_λ(0x05 ‖ salt ‖ k ‖ i ‖ seed, 2λ + (ℓ+3)·λ/8·8)
/// Output: com (2*lambda_bytes), pt_share (fs), ℓ*t_share (fs each), a_share (fs), c_share (fs)
///
/// Returns a stack-allocated PartyMaterial — zero heap allocations.
pub(crate) fn h5_hash<P: AimerParams>(salt: &[u8], k: u8, i: u8, seed: &[u8]) -> PartyMaterial {
    let lambda_bytes = P::SECURITY_BITS / 8;
    let l = P::AIM2_NUM_SBOXES;
    let fs = P::FIELD_SIZE;
    let output_len = 2 * lambda_bytes + (l + 3) * fs;
    let output = shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(&[0x05]);
        s.absorb(salt);
        s.absorb(&[k]);
        s.absorb(&[i]);
        s.absorb(seed);
    }, output_len);

    let com_len = 2 * lambda_bytes;
    let mut mat = PartyMaterial {
        com: [0u8; 64],
        com_len,
        pt_share_limbs: [0u64; 4],
        t_shares_limbs: [[0u64; 4]; 3],
        a_share_limbs: [0u64; 4],
        c_share_limbs: [0u64; 4],
    };

    let mut off = 0;

    // com: copy bytes directly into fixed array
    mat.com[..com_len].copy_from_slice(&output[off..off + com_len]);
    off += com_len;

    // pt_share: parse to limbs
    mat.pt_share_limbs = bytes_to_limbs4(&output[off..off + fs]);
    off += fs;

    // t_shares: parse each to limbs (max ℓ=3)
    for j in 0..l {
        mat.t_shares_limbs[j] = bytes_to_limbs4(&output[off..off + fs]);
        off += fs;
    }

    // a_share, c_share: parse to limbs
    mat.a_share_limbs = bytes_to_limbs4(&output[off..off + fs]);
    off += fs;
    mat.c_share_limbs = bytes_to_limbs4(&output[off..off + fs]);

    mat
}

/// Material derived from H₅ for a single party.
/// Stack-allocated: eliminates ~67K heap allocations per signature.
pub(crate) struct PartyMaterial {
    /// Commitment bytes (max 2*lambda_bytes = 64 for L5)
    pub com: [u8; 64],
    /// Actual length of com used
    pub com_len: usize,
    /// Plaintext share as u64 limbs (max 4 for GF(2^256))
    pub pt_share_limbs: [u64; 4],
    /// S-box output shares as limbs (max ℓ=3)
    pub t_shares_limbs: [[u64; 4]; 3],
    /// a_share as limbs
    pub a_share_limbs: [u64; 4],
    /// c_share as limbs
    pub c_share_limbs: [u64; 4],
}

impl PartyMaterial {
    /// Convert com to Vec<u8> (for verification backward-compat)
    pub fn com_vec(&self) -> Vec<u8> { self.com[..self.com_len].to_vec() }
    /// Convert pt_share_limbs to Vec<u8> (for verification backward-compat)
    pub fn pt_share(&self, fs: usize) -> Vec<u8> {
        let n = (fs + 7) / 8;
        field::limbs_to_bytes_pub(&self.pt_share_limbs[..n], fs)
    }
    /// Convert t_shares_limbs to Vec<Vec<u8>> (for verification backward-compat)
    pub fn t_shares(&self, l: usize, fs: usize) -> Vec<Vec<u8>> {
        let n = (fs + 7) / 8;
        (0..l).map(|j| field::limbs_to_bytes_pub(&self.t_shares_limbs[j][..n], fs)).collect()
    }
    /// Convert a_share_limbs to Vec<u8> (for verification backward-compat)
    pub fn a_share(&self, fs: usize) -> Vec<u8> {
        let n = (fs + 7) / 8;
        field::limbs_to_bytes_pub(&self.a_share_limbs[..n], fs)
    }
    /// Convert c_share_limbs to Vec<u8> (for verification backward-compat)
    pub fn c_share(&self, fs: usize) -> Vec<u8> {
        let n = (fs + 7) / 8;
        field::limbs_to_bytes_pub(&self.c_share_limbs[..n], fs)
    }
}

/// H₁(μ, σ₁)
pub(crate) fn h1_hash<P: AimerParams>(
    mu: &[u8],
    salt: &[u8],
    rep_data: &[RepH1Data],
) -> Vec<u8> {
    let output_len = 2 * (P::SECURITY_BITS / 8);
    shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(&[0x01]);
        s.absorb(mu);
        s.absorb(salt);
        for rep in rep_data {
            for com in &rep.commitments {
                s.absorb(com);
            }
            s.absorb(&rep.delta_pt);
            for dt in &rep.delta_ts {
                s.absorb(dt);
            }
            s.absorb(&rep.delta_c);
        }
    }, output_len)
}

pub(crate) struct RepH1Data {
    pub commitments: Vec<Vec<u8>>,
    pub delta_pt: Vec<u8>,
    pub delta_ts: Vec<Vec<u8>>,
    pub delta_c: Vec<u8>,
}

/// H₂(h₁, σ₂)
///
/// σ₂ = (salt, ((α_k^(i))_{i∈[N]}, (v_k^(i))_{i∈[N]})_{k∈[τ]})
/// All N individual alpha shares per repetition, then all N v shares.
pub(crate) fn h2_hash<P: AimerParams>(
    h1_val: &[u8],
    salt: &[u8],
    rep_data: &[RepH2Data],
) -> Vec<u8> {
    let output_len = 2 * (P::SECURITY_BITS / 8);
    shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(&[0x02]);
        s.absorb(h1_val);
        s.absorb(salt);
        for rep in rep_data {
            for alpha in &rep.alpha_shares {
                s.absorb(alpha);
            }
            for v in &rep.v_shares {
                s.absorb(v);
            }
        }
    }, output_len)
}

pub(crate) struct RepH2Data {
    /// All N individual alpha shares in party order (index 0..N-1).
    pub alpha_shares: Vec<Vec<u8>>,
    pub v_shares: Vec<Vec<u8>>,
}

/// Expand h₁ into τ × (ℓ+1) field element challenges.
///
/// ExpandH1 has no domain separation prefix (spec §4.1.2).
pub(crate) fn expand_h1_challenges<P: AimerParams>(h1_val: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let tau = P::MPC_ROUNDS;
    let l = P::AIM2_NUM_SBOXES;
    let fs = P::FIELD_SIZE;
    let total = tau * (l + 1) * fs;

    let output = shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(h1_val);
    }, total);

    let mut result = Vec::with_capacity(tau);
    let mut off = 0;
    for _ in 0..tau {
        let mut eps = Vec::with_capacity(l + 1);
        for _ in 0..(l + 1) {
            eps.push(output[off..off + fs].to_vec());
            off += fs;
        }
        result.push(eps);
    }
    result
}

/// Expand h₂ into τ excluded party indices in [0, N-1].
///
/// ExpandH2 has no domain separation prefix (spec §4.1.2).
/// Formula: ī_k = SHAKE(h₂)[k] & ((1 << LOGN) - 1), range 0..N-1.
/// (Reference: `indices[rep] &= (1 << AIMER_LOGN) - 1`)
pub(crate) fn expand_h2_indices<P: AimerParams>(h2_val: &[u8]) -> Vec<usize> {
    let tau = P::MPC_ROUNDS;
    let mask = (1usize << P::LOG_N) - 1;

    // 1 byte per index, no prefix
    let output = shake_hash!(P::SECURITY_BITS, |s: &mut dyn ShakeAbsorb| {
        s.absorb(h2_val);
    }, tau);

    let mut indices = Vec::with_capacity(tau);
    for k in 0..tau {
        indices.push((output[k] as usize) & mask);
    }
    indices
}

/// Compute S-box outputs from plaintext.
/// Returns ℓ values t_j = Mer[e_j]^{-1}(pt + gamma_j).
pub(crate) fn aim2_sbox_outputs<P: AimerParams>(pt: &[u8]) -> Vec<Vec<u8>> {
    let l = P::AIM2_NUM_SBOXES;
    let fs = P::FIELD_SIZE;
    let mut t_values = Vec::with_capacity(l);

    for j in 0..l {
        let gamma_start = j * fs;
        let gamma_j = &P::AIM2_GAMMA[gamma_start..gamma_start + fs];
        let sbox_input = field::gf_add_alloc(pt, gamma_j);
        let e_j = P::AIM2_LAYER1_EXPONENTS[j];
        let t_j = field::gf_power_mersenne_inverse_fast(&sbox_input, e_j, fs);
        t_values.push(t_j);
    }

    t_values
}

/// Run AIM2_MPC per-party (spec Figure 3).
///
/// All linear operations (Frobenius, public-scalar multiply, matrix multiply)
/// are applied to every party's share. Only additive constants (b_iv) are
/// added to party N-1 alone (matches reference: `vector_b` set only for party AIMER_N-1).
pub(crate) fn aim2_mpc_party<P: AimerParams>(
    matrices: &[Vec<Vec<u8>>],
    b_iv: &[u8],
    ct: &[u8],
    t_shares: &[Vec<u8>],
    is_party_zero: bool,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let l = P::AIM2_NUM_SBOXES;
    let fs = P::FIELD_SIZE;
    let mut x_vals = Vec::with_capacity(l + 1);
    let mut z_vals = Vec::with_capacity(l + 1);

    // Layer-1 S-boxes: z_j = x_j^{2^{e_j}} + gamma_j * x_j
    // Both Frobenius and scalar-by-public-constant are linear per share.
    // Uses allocation-free gf_power_mersenne_fast for the Frobenius squaring chain.
    for j in 0..l {
        let x_j = t_shares[j].clone();
        let e_j = P::AIM2_LAYER1_EXPONENTS[j];

        // Frobenius chain: x_j^{2^{e_j}} = x_j^{2^e_j}
        // This is NOT gf_power_mersenne (which computes x^{2^e - 1}).
        // We need x^{2^e}, which is just e repeated squarings.
        // Use allocation-free limb-native squaring.
        let n_limbs = (fs + 7) / 8;
        let product_limbs = 2 * n_limbs;
        let a_limbs = field::bytes_to_limbs_pub(&x_j);
        let mut cur = [0u64; 8];
        let mut scratch = [0u64; 16];
        for i in 0..n_limbs { cur[i] = a_limbs[i]; }
        for _ in 0..e_j {
            field::square_limbs_pub(&cur[..n_limbs], &mut scratch[..product_limbs], fs);
            for i in 0..n_limbs { cur[i] = scratch[i]; }
        }
        // gamma_j * x_j using fused limb multiply (zero alloc)
        let gamma_start = j * fs;
        let gamma_j = &P::AIM2_GAMMA[gamma_start..gamma_start + fs];
        let gamma_limbs = field::bytes_to_limbs_pub(gamma_j);
        let x_limbs = field::bytes_to_limbs_pub(&x_j);
        let mut gamma_x_limbs = [0u64; 8];
        field::gf_mul_limbs(&gamma_limbs[..n_limbs], &x_limbs[..n_limbs], &mut gamma_x_limbs[..n_limbs], fs);

        // z_j = frobenius(x_j) + gamma_j * x_j — combine in limb domain
        let mut z_j_limbs = [0u64; 8];
        for i in 0..n_limbs {
            z_j_limbs[i] = cur[i] ^ gamma_x_limbs[i]; // XOR = GF(2) add
        }
        let z_j_final = field::limbs_to_bytes_pub(&z_j_limbs[..n_limbs], fs);

        x_vals.push(x_j);
        z_vals.push(z_j_final);
    }

    // Layer-2: x_ℓ = Σ_j A_j · x_j + b_iv
    let mut x_l = vec![0u8; fs];
    for j in 0..l {
        let a_j_x = field::binary_matrix_mul(&matrices[j], &x_vals[j], fs);
        x_l = field::gf_add_alloc(&x_l, &a_j_x);
    }
    if is_party_zero {
        x_l = field::gf_add_alloc(&x_l, b_iv);
    }

    // z_ℓ = x_ℓ^{2^{e_*}} + ct · x_ℓ — allocation-free squaring chain
    let e_star = P::AIM2_LAYER2_EXPONENT;
    let n_limbs = (fs + 7) / 8;
    let product_limbs = 2 * n_limbs;
    let xl_limbs = field::bytes_to_limbs_pub(&x_l);
    let mut cur = [0u64; 8];
    let mut scratch = [0u64; 16];
    for i in 0..n_limbs { cur[i] = xl_limbs[i]; }
    for _ in 0..e_star {
        field::square_limbs_pub(&cur[..n_limbs], &mut scratch[..product_limbs], fs);
        for i in 0..n_limbs { cur[i] = scratch[i]; }
    }
    // ct * x_l using fused limb multiply (zero alloc)
    let ct_limbs = field::bytes_to_limbs_pub(ct);
    let mut ct_x_limbs = [0u64; 8];
    field::gf_mul_limbs(&ct_limbs[..n_limbs], &xl_limbs[..n_limbs], &mut ct_x_limbs[..n_limbs], fs);
    // z_l = frobenius(x_l) XOR ct*x_l — combine in limb domain
    for i in 0..n_limbs { cur[i] ^= ct_x_limbs[i]; }
    let z_l = field::limbs_to_bytes_pub(&cur[..n_limbs], fs);

    x_vals.push(x_l);
    z_vals.push(z_l);

    (x_vals, z_vals)
}

/// MPC party computation entirely in limb domain. Zero heap allocation for field ops.
/// Output arrays x_out and z_out must have at least (ℓ+1) entries.
fn aim2_mpc_party_limbs<P: AimerParams>(
    matrix_limbs: &[Vec<[u64; 4]>],
    b_iv_limbs: &[u64; 4],
    ct_limbs: &[u64; 4],
    gamma_limbs: &[[u64; 4]],
    t_share_limbs: &[[u64; 4]],
    is_party_zero: bool,
    n_limbs: usize,
    x_out: &mut [[u64; 4]],
    z_out: &mut [[u64; 4]],
) {
    let l = P::AIM2_NUM_SBOXES;
    let fs = P::FIELD_SIZE;

    // Layer-1: for each S-box j
    for j in 0..l {
        // x_j = t_share[j]
        x_out[j] = t_share_limbs[j];

        // Frobenius: x_j^{2^{e_j}} — repeated squaring in limb domain
        let e_j = P::AIM2_LAYER1_EXPONENTS[j];
        let mut cur = t_share_limbs[j];
        let mut scratch = [0u64; 16];
        for _ in 0..e_j {
            field::square_limbs_pub(&cur[..n_limbs], &mut scratch[..2 * n_limbs], fs);
            for k in 0..n_limbs { cur[k] = scratch[k]; }
        }

        // z_j = frobenius(x_j) + gamma_j * x_j
        let mut gamma_x = [0u64; 4];
        field::gf_mul_limbs(
            &gamma_limbs[j][..n_limbs],
            &t_share_limbs[j][..n_limbs],
            &mut gamma_x[..n_limbs],
            fs,
        );
        for k in 0..n_limbs {
            z_out[j][k] = cur[k] ^ gamma_x[k];
        }
    }

    // Layer-2: x_ℓ = Σ_j A_j · x_j + b_iv — using precomputed limb matrices
    let mut x_l = [0u64; 4];
    for j in 0..l {
        let mut a_j_x = [0u64; 4];
        field::binary_matrix_mul_limbs(&matrix_limbs[j], &x_out[j], n_limbs, &mut a_j_x);
        for k in 0..n_limbs {
            x_l[k] ^= a_j_x[k];
        }
    }
    if is_party_zero {
        for k in 0..n_limbs {
            x_l[k] ^= b_iv_limbs[k];
        }
    }
    x_out[l] = x_l;

    // z_ℓ = x_ℓ^{2^{e_*}} + ct · x_ℓ
    let e_star = P::AIM2_LAYER2_EXPONENT;
    let mut cur = x_l;
    let mut scratch = [0u64; 16];
    for _ in 0..e_star {
        field::square_limbs_pub(&cur[..n_limbs], &mut scratch[..2 * n_limbs], fs);
        for k in 0..n_limbs { cur[k] = scratch[k]; }
    }
    let mut ct_x = [0u64; 4];
    field::gf_mul_limbs(
        &ct_limbs[..n_limbs],
        &x_l[..n_limbs],
        &mut ct_x[..n_limbs],
        fs,
    );
    for k in 0..n_limbs {
        z_out[l][k] = cur[k] ^ ct_x[k];
    }
}

// ============================================================================
// AIM2 v260130 sign (Algorithm 11)
// ============================================================================

fn sign_v2_with_rho<P: AimerParams>(msg: &[u8], sk: &SecretKey, rho: &[u8]) -> Result<Signature, AimerError> {
    let fs = P::FIELD_SIZE;
    let l = P::AIM2_NUM_SBOXES;
    let tau = P::MPC_ROUNDS;
    let n = P::MPC_PARTIES;
    let n_limbs = (fs + 7) / 8;
    let pt = &sk.sk;
    let iv = &sk.pk.iv;
    let ct = &sk.pk.ct;
    let pt_limbs = field::bytes_to_limbs_pub(pt);

    // Step 1: μ ← H₀(iv, ct, M')
    let mu = h0_hash::<P>(iv, ct, msg);

    // Step 2: Compute S-box outputs
    let t_values = aim2_sbox_outputs::<P>(pt);

    // Step 3: Generate affine layer
    let aim2 = Aim2::<P>::new();
    let (matrices, b_iv) = aim2.generate_affine_layer_public(iv);

    // Step 4: Derive salt + root seeds from the caller-supplied randomness ρ
    let (salt, root_seeds) = h3::<P>(&mu, pt, rho);

    // Precomputed limb-domain constants (computed once per signing)
    let ct_limbs_arr = {
        let v = field::bytes_to_limbs_pub(ct);
        let mut a = [0u64; 4];
        for i in 0..n_limbs { a[i] = v[i]; }
        a
    };
    let gamma_limbs_arr: Vec<[u64; 4]> = (0..l).map(|j| {
        let start = j * fs;
        let v = field::bytes_to_limbs_pub(&P::AIM2_GAMMA[start..start + fs]);
        let mut a = [0u64; 4];
        for i in 0..n_limbs { a[i] = v[i]; }
        a
    }).collect();
    let b_iv_limbs_arr = {
        let v = field::bytes_to_limbs_pub(&b_iv);
        let mut a = [0u64; 4];
        for i in 0..n_limbs { a[i] = v[i]; }
        a
    };
    // Precompute matrix rows as limb arrays for SIMD matrix-vector multiply
    let matrix_limbs_precomputed: Vec<Vec<[u64; 4]>> = matrices.iter()
        .map(|m| field::precompute_matrix_limbs(m, n_limbs * 64))
        .collect();

    // Per-repetition MPC data
    struct RepMpcData {
        materials: Vec<PartyMaterial>,
        nodes: Vec<Vec<u8>>,
        x_per_party_limbs: Vec<[[u64; 4]; 4]>,
        z_per_party_limbs: Vec<[[u64; 4]; 4]>,
        delta_pt: Vec<u8>,
        delta_ts: Vec<Vec<u8>>,
        delta_c: Vec<u8>,
    }

    // Step 5: For each repetition k — parallelizable across τ independent reps
    let compute_rep = |k: usize| -> (RepH1Data, RepMpcData) {
        // Expand seed tree
        let nodes = crate::tree::expand_tree::<P>(&salt, k as u8, &root_seeds[k]);
        let leaf_start = n - 1;

        // Generate party materials from H₅
        let mut materials: Vec<PartyMaterial> = Vec::with_capacity(n);
        for i in 0..n {
            materials.push(h5_hash::<P>(&salt, k as u8, i as u8, &nodes[leaf_start + i]));
        }

        // Compute Δpt = pt ⊕ Σ_i pt_k^i — limb-domain XOR accumulation
        let mut sum_pt_limbs = [0u64; 4];
        for m in &materials {
            for kk in 0..n_limbs { sum_pt_limbs[kk] ^= m.pt_share_limbs[kk]; }
        }
        let mut delta_pt_limbs = [0u64; 4];
        for kk in 0..n_limbs { delta_pt_limbs[kk] = pt_limbs[kk] ^ sum_pt_limbs[kk]; }
        for kk in 0..n_limbs { materials[n - 1].pt_share_limbs[kk] ^= delta_pt_limbs[kk]; }
        let delta_pt = field::limbs_to_bytes_pub(&delta_pt_limbs[..n_limbs], fs);

        // Compute Δt_{k,j} for each S-box j — limb-domain XOR accumulation
        let mut delta_ts = Vec::with_capacity(l);
        for j in 0..l {
            let mut sum_t_limbs = [0u64; 4];
            for m in &materials {
                for kk in 0..n_limbs { sum_t_limbs[kk] ^= m.t_shares_limbs[j][kk]; }
            }
            let t_val_limbs = bytes_to_limbs4(&t_values[j]);
            let mut dt_limbs = [0u64; 4];
            for kk in 0..n_limbs { dt_limbs[kk] = t_val_limbs[kk] ^ sum_t_limbs[kk]; }
            for kk in 0..n_limbs { materials[n - 1].t_shares_limbs[j][kk] ^= dt_limbs[kk]; }
            delta_ts.push(field::limbs_to_bytes_pub(&dt_limbs[..n_limbs], fs));
        }

        // Compute Δc = Σ_i(a_k^i · pt) ⊕ Σ_i(c_k^i) — fused limb-domain, zero alloc
        let mut sum_a_pt_limbs = [0u64; 8];
        let mut sum_c_limbs = [0u64; 8];
        for m in &materials {
            let mut a_pt_limbs = [0u64; 8];
            field::gf_mul_limbs(&m.a_share_limbs[..n_limbs], &pt_limbs[..n_limbs], &mut a_pt_limbs[..n_limbs], fs);
            for i in 0..n_limbs { sum_a_pt_limbs[i] ^= a_pt_limbs[i]; }
            for i in 0..n_limbs { sum_c_limbs[i] ^= m.c_share_limbs[i]; }
        }
        for i in 0..n_limbs { sum_a_pt_limbs[i] ^= sum_c_limbs[i]; }
        let delta_c = field::limbs_to_bytes_pub(&sum_a_pt_limbs[..n_limbs], fs);
        // Adjust last party's c_share in limbs
        let delta_c_limbs = bytes_to_limbs4(&delta_c);
        for kk in 0..n_limbs { materials[n - 1].c_share_limbs[kk] ^= delta_c_limbs[kk]; }

        // Run AIM2_MPC for each party — limb-domain fast path
        // The 256 party MPC simulations are independent (after delta correction).
        // Parallelize with Rayon for nested parallelism (reps × parties).
        let compute_party = |i: usize| -> ([[u64; 4]; 4], [[u64; 4]; 4]) {
            // t_shares already in limbs — use directly from PartyMaterial
            let mut x_out = [[0u64; 4]; 4];
            let mut z_out = [[0u64; 4]; 4];
            aim2_mpc_party_limbs::<P>(
                &matrix_limbs_precomputed, &b_iv_limbs_arr, &ct_limbs_arr, &gamma_limbs_arr,
                &materials[i].t_shares_limbs[..l], i == n - 1, n_limbs,
                &mut x_out, &mut z_out,
            );
            (x_out, z_out)
        };

        #[cfg(feature = "parallel")]
        let party_results: Vec<_> = {
            use rayon::prelude::*;
            (0..n).into_par_iter().map(compute_party).collect()
        };
        #[cfg(not(feature = "parallel"))]
        let party_results: Vec<_> = (0..n).map(compute_party).collect();

        let (x_per_party_limbs, z_per_party_limbs): (Vec<_>, Vec<_>) =
            party_results.into_iter().unzip();

        let commitments: Vec<Vec<u8>> = materials.iter()
            .map(|m| m.com[..m.com_len].to_vec())
            .collect();

        let h1d = RepH1Data {
            commitments,
            delta_pt: delta_pt.clone(),
            delta_ts: delta_ts.clone(),
            delta_c: delta_c.clone(),
        };

        let rmd = RepMpcData {
            materials,
            nodes,
            x_per_party_limbs,
            z_per_party_limbs,
            delta_pt,
            delta_ts,
            delta_c,
        };
        (h1d, rmd)
    };

    // Dispatch: parallel (Rayon) or sequential
    #[cfg(feature = "parallel")]
    let results: Vec<(RepH1Data, RepMpcData)> = {
        use rayon::prelude::*;
        (0..tau).into_par_iter().map(|k| compute_rep(k)).collect()
    };
    #[cfg(not(feature = "parallel"))]
    let results: Vec<(RepH1Data, RepMpcData)> = {
        (0..tau).map(|k| compute_rep(k)).collect()
    };

    let (h1_data, rep_mpc): (Vec<_>, Vec<_>) = results.into_iter().unzip();

    // Step 6: h₁ ← H₁(μ, σ₁)
    let h1_val = h1_hash::<P>(&mu, &salt, &h1_data);

    // Step 7: Expand h₁ challenges
    let epsilons = expand_h1_challenges::<P>(&h1_val);

    // Precompute epsilon limbs: reused across all parties in each repetition
    let eps_limbs: Vec<Vec<[u64; 8]>> = epsilons.iter().map(|rep_eps| {
        rep_eps.iter().map(|e| {
            let raw = field::bytes_to_limbs_pub(e);
            let mut arr = [0u64; 8];
            for i in 0..n_limbs { arr[i] = raw[i]; }
            arr
        }).collect()
    }).collect();

    // Step 8: Compute α and v for each repetition — fused limb-domain
    //         Uses precomputed x/z limb arrays to avoid bytes_to_limbs_pub calls
    let mut h2_data = Vec::with_capacity(tau);
    // Store per-party alphas for extracting excluded party's alpha later
    let mut all_alpha_per_party: Vec<Vec<Vec<u8>>> = Vec::with_capacity(tau);

    for k in 0..tau {
        let rd = &rep_mpc[k];

        let mut alpha_per_party_limbs: Vec<[u64; 8]> = Vec::with_capacity(n);
        let mut alpha_total_limbs = [0u64; 8];

        for i in 0..n {
            let mut alpha_i_limbs = [0u64; 8];
            for idx in 0..n_limbs { alpha_i_limbs[idx] = rd.materials[i].a_share_limbs[idx]; }

            for j in 0..(l + 1) {
                // Use precomputed limb-domain x values directly
                let mut eps_x_limbs = [0u64; 8];
                field::gf_mul_limbs(&eps_limbs[k][j][..n_limbs], &rd.x_per_party_limbs[i][j][..n_limbs], &mut eps_x_limbs[..n_limbs], fs);
                for idx in 0..n_limbs { alpha_i_limbs[idx] ^= eps_x_limbs[idx]; }
            }
            for idx in 0..n_limbs { alpha_total_limbs[idx] ^= alpha_i_limbs[idx]; }
            alpha_per_party_limbs.push(alpha_i_limbs);
        }

        // Convert per-party alphas to bytes for proof extraction
        let alpha_per_party: Vec<Vec<u8>> = alpha_per_party_limbs.iter()
            .map(|a| field::limbs_to_bytes_pub(&a[..n_limbs], fs))
            .collect();

        // v_k^i = c_k^i + Σ_j ε_{k,j} · z_{k,j}^i − α_k · pt_k^i
        let mut v_shares = Vec::with_capacity(n);
        for i in 0..n {
            let mut v_i_limbs = [0u64; 8];
            for idx in 0..n_limbs { v_i_limbs[idx] = rd.materials[i].c_share_limbs[idx]; }

            for j in 0..(l + 1) {
                // Use precomputed limb-domain z values directly
                let mut eps_z_limbs = [0u64; 8];
                field::gf_mul_limbs(&eps_limbs[k][j][..n_limbs], &rd.z_per_party_limbs[i][j][..n_limbs], &mut eps_z_limbs[..n_limbs], fs);
                for idx in 0..n_limbs { v_i_limbs[idx] ^= eps_z_limbs[idx]; }
            }

            let mut alpha_pt_limbs = [0u64; 8];
            field::gf_mul_limbs(&alpha_total_limbs[..n_limbs], &rd.materials[i].pt_share_limbs[..n_limbs], &mut alpha_pt_limbs[..n_limbs], fs);
            for idx in 0..n_limbs { v_i_limbs[idx] ^= alpha_pt_limbs[idx]; }

            v_shares.push(field::limbs_to_bytes_pub(&v_i_limbs[..n_limbs], fs));
        }

        h2_data.push(RepH2Data {
            alpha_shares: alpha_per_party.clone(),
            v_shares,
        });
        all_alpha_per_party.push(alpha_per_party);
    }

    // Step 9: h₂ ← H₂(h₁, σ₂)
    let h2_val = h2_hash::<P>(&h1_val, &salt, &h2_data);

    // Step 10: Expand h₂ to get excluded parties
    let excluded = expand_h2_indices::<P>(&h2_val);

    // Step 11-12: Build proofs
    let mut proofs = Vec::with_capacity(tau);
    for k in 0..tau {
        let i_bar = excluded[k];
        let path = crate::tree::reveal_all_but::<P>(&rep_mpc[k].nodes, i_bar);

        proofs.push(RepProof {
            path,
            com_excluded: rep_mpc[k].materials[i_bar].com[..rep_mpc[k].materials[i_bar].com_len].to_vec(),
            delta_pt: rep_mpc[k].delta_pt.clone(),
            delta_ts: rep_mpc[k].delta_ts.clone(),
            delta_c: rep_mpc[k].delta_c.clone(),
            alpha_excluded: all_alpha_per_party[k][i_bar].clone(),
        });
    }

    Ok(Signature::new_v2(salt, h1_val, h2_val, proofs))
}

/// AIM2 (v2) signing with a fresh OS-random ρ. Thin wrapper over
/// `sign_v2_with_rho`; the deterministic core lives there so KAT byte-equality
/// can inject ρ from a NIST DRBG.
fn sign_v2<P: AimerParams>(msg: &[u8], sk: &SecretKey) -> Result<Signature, AimerError> {
    let mut rho = vec![0u8; P::SECURITY_BITS / 8];
    getrandom(&mut rho).map_err(|_| AimerError::RandomGenerationFailed)?;
    sign_v2_with_rho::<P>(msg, sk, &rho)
}

/// Deterministic AIM2 keypair from explicit `(pt, iv)` — the secret plaintext
/// and initial vector. Mirrors upstream `crypto_sign_keypair_internal`:
/// `ct = AIM2(iv, pt)`, `pk = iv ‖ ct`, `sk = pt ‖ iv ‖ ct`. For reproducible /
/// KAT keygen, draw `pt` then `iv` (each FIELD_SIZE bytes) from a NIST DRBG.
pub fn keypair_from_pt_iv<P: AimerParams>(
    pt: &[u8],
    iv: &[u8],
) -> Result<(PublicKey, SecretKey), AimerError> {
    let aim2 = Aim2::<P>::new();
    let ct = aim2.evaluate(iv, pt)?;
    let pk = PublicKey { iv: iv.to_vec(), ct };
    let sk = SecretKey { sk: pt.to_vec(), pk: pk.clone() };
    Ok((pk, sk))
}

/// Deterministic AIM2 signing with a caller-supplied randomness ρ
/// (SECURITY_BITS/8 bytes). For reproducible / KAT signing; the public `sign`
/// path draws ρ from the OS RNG. ρ feeds H₃ to derive the salt and root seeds.
pub fn sign_with_rho<P: AimerParams>(
    msg: &[u8],
    sk: &SecretKey,
    rho: &[u8],
) -> Result<Signature, AimerError> {
    sign_v2_with_rho::<P>(msg, sk, rho)
}

//! The Ascon permutation (NIST SP 800-232 §3) and the little-endian word I/O
//! every Ascon mode shares.
//!
//! One implementation feeds all four SP 800-232 functions in this crate:
//! Ascon-AEAD128 (`aead128`), Ascon-Hash256 (`hash256`), Ascon-XOF128
//! (`xof128`) and Ascon-CXOF128 (`cxof128`). Keeping it in one place means the
//! AEAD KATs, which exercise both the 12-round and the 8-round schedules, vouch
//! for the permutation the hash functions use.

/// 64-bit right rotation.
#[inline]
const fn rotr64(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// One round of the Ascon permutation with the given round constant.
fn ascon_round(state: &mut [u64; 5], round_const: u8) {
    // Addition of round constant.
    state[2] ^= round_const as u64;

    // Substitution layer (5-bit S-box, bitsliced).
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];

    let mut t = [0u64; 5];
    t[0] = state[0] ^ ((!state[1]) & state[2]);
    t[1] = state[1] ^ ((!state[2]) & state[3]);
    t[2] = state[2] ^ ((!state[3]) & state[4]);
    t[3] = state[3] ^ ((!state[4]) & state[0]);
    t[4] = state[4] ^ ((!state[0]) & state[1]);

    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];
    t[2] = !t[2];

    // Linear diffusion layer.
    state[0] = t[0] ^ rotr64(t[0], 19) ^ rotr64(t[0], 28);
    state[1] = t[1] ^ rotr64(t[1], 61) ^ rotr64(t[1], 39);
    state[2] = t[2] ^ rotr64(t[2], 1) ^ rotr64(t[2], 6);
    state[3] = t[3] ^ rotr64(t[3], 10) ^ rotr64(t[3], 17);
    state[4] = t[4] ^ rotr64(t[4], 7) ^ rotr64(t[4], 41);
}

/// Apply the last `rounds` rounds of the 12-round Ascon permutation
/// (`rounds` = 12 for p^a, 8 for p^b).
pub(crate) fn ascon_permutation(state: &mut [u64; 5], rounds: u8) {
    for i in (12 - rounds)..12 {
        let round_const = (0xf0u8.wrapping_sub(i * 0x10).wrapping_add(i)) & 0xFF;
        ascon_round(state, round_const);
    }
}

/// Load a 64-bit little-endian word from an 8-byte slice (SP 800-232 §2.2).
#[inline]
pub(crate) fn load64_le(src: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&src[..8]);
    u64::from_le_bytes(buf)
}

/// Store a 64-bit word as 8 little-endian bytes.
#[inline]
pub(crate) fn store64_le(val: u64) -> [u8; 8] {
    val.to_le_bytes()
}

/// Load up to 8 little-endian bytes from `src[..n]` into a `u64`
/// (the reference's `LOADBYTES(in, n)`).
#[inline]
pub(crate) fn load64_le_partial(src: &[u8], n: usize) -> u64 {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < n {
        x |= (src[i] as u64) << (8 * i);
        i += 1;
    }
    x
}

/// Store the low `n` little-endian bytes of `val` into `dst[..n]`
/// (the reference's `STOREBYTES(out, x, n)`).
#[inline]
pub(crate) fn store64_le_partial(dst: &mut [u8], val: u64, n: usize) {
    let mut i = 0;
    while i < n {
        dst[i] = (val >> (8 * i)) as u8;
        i += 1;
    }
}

/// The 10* padding word for a partial block of `n` bytes (`PAD(n)`).
#[inline]
pub(crate) const fn pad(n: usize) -> u64 {
    0x01u64 << (8 * n)
}

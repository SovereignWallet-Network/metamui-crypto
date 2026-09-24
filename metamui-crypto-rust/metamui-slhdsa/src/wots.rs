//! WOTS+ (Winternitz One-Time Signature Plus) implementation for SLH-DSA
//!
//! WOTS+ is a hash-based one-time signature scheme that forms the foundation
//! of the SLH-DSA signature scheme. It uses a Winternitz parameter W to trade
//! signature size for computation time.

use crate::{Parameters, address::Address};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// WOTS+ chain function - iteratively hashes a value
pub fn wots_chain<P: Parameters>(
    input: &[u8],
    start: u32,
    steps: u32,
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    let mut result = input.to_vec();
    let mut addr = *addr;

    for i in start..(start + steps) {
        addr.set_hash_addr(i);
        result = wots_hash::<P>(&result, pk_seed, &addr);
    }

    result
}

/// WOTS+ hash function using the tweakable hash
fn wots_hash<P: Parameters>(
    input: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    use crate::hash::Hash;
    let mut output = vec![0u8; P::N];
    Hash::<P>::f(&mut output, pk_seed, addr, input);
    output
}

/// Generate a WOTS+ public key from a secret seed
/// Algorithm 6 from FIPS 205
pub fn wots_gen_pk<P: Parameters>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    let len = wots_len::<P>();
    let mut pk = Vec::with_capacity(len * P::N);

    // Create separate address for secret key generation (WOTS_PRF)
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(5); // WOTS_PRF
    let keypair_val = addr.keypair;
    sk_addr.set_keypair(keypair_val);

    // Use main address for chaining (WOTS_HASH)
    let mut chain_addr = *addr;
    chain_addr.set_type_wots();

    for i in 0..len {
        // Generate secret key element with WOTS_PRF address
        sk_addr.set_chain_addr(i as u32);
        let sk_i = wots_gen_sk::<P>(pk_seed, sk_seed, &sk_addr);

        // Chain with WOTS_HASH address
        chain_addr.set_chain_addr(i as u32);
        let pk_i = wots_chain::<P>(&sk_i, 0, P::W as u32 - 1, pk_seed, &chain_addr);
        pk.extend_from_slice(&pk_i);
    }

    // Compress the public key with WOTS_PK address
    let mut wotspk_addr = *addr;
    wotspk_addr.set_type_and_clear(1); // WOTS_PK
    wotspk_addr.set_keypair(keypair_val);
    wots_pk_compress::<P>(&pk, pk_seed, &wotspk_addr)
}

/// Generate a WOTS+ secret key element
fn wots_gen_sk<P: Parameters>(
    pk_seed: &[u8],
    sk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    use crate::hash::Hash;
    let mut output = vec![0u8; P::N];
    Hash::<P>::prf(&mut output, pk_seed, sk_seed, addr);
    output
}

/// Compress a WOTS+ public key
fn wots_pk_compress<P: Parameters>(
    pk: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    use crate::hash::Hash;
    let mut output = vec![0u8; P::N];
    Hash::<P>::t_l(&mut output, pk_seed, addr, pk);
    output
}

/// Sign a message using WOTS+ (FIPS 205 Algorithm 7)
pub fn wots_sign<P: Parameters>(
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    let len = wots_len::<P>();
    let mut sig = Vec::with_capacity(len * P::N);

    // Compute full message + checksum in base-w
    let msg_full = wots_msg_and_checksum::<P>(msg);

    // Create separate address for secret key generation (WOTS_PRF)
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(5); // WOTS_PRF
    let keypair_val = addr.keypair;
    sk_addr.set_keypair(keypair_val);

    // Use main address for chaining (WOTS_HASH)
    let mut chain_addr = *addr;
    chain_addr.set_type_wots();

    // Generate signature
    for i in 0..len {
        // Generate secret key element with WOTS_PRF address
        sk_addr.set_chain_addr(i as u32);
        let sk_i = wots_gen_sk::<P>(pk_seed, sk_seed, &sk_addr);

        // Chain with WOTS_HASH address
        chain_addr.set_chain_addr(i as u32);
        let sig_i = wots_chain::<P>(&sk_i, 0, msg_full[i], pk_seed, &chain_addr);
        sig.extend_from_slice(&sig_i);
    }

    sig
}

/// Verify a WOTS+ signature and recover the public key (FIPS 205 Algorithm 8)
pub fn wots_pk_from_sig<P: Parameters>(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    let len = wots_len::<P>();
    let mut pk = Vec::with_capacity(len * P::N);

    // Compute full message + checksum in base-w
    let msg_full = wots_msg_and_checksum::<P>(msg);

    let mut addr = *addr;
    let _keypair_val = addr.keypair;

    // Set address type once before loop
    addr.set_type_wots();

    // Recover public key from signature
    for i in 0..len {
        addr.set_chain_addr(i as u32);

        // Get signature element
        let sig_i = &sig[i * P::N..(i + 1) * P::N];

        // Chain to recover public key element
        let pk_i = wots_chain::<P>(
            sig_i,
            msg_full[i],
            P::W as u32 - 1 - msg_full[i],
            pk_seed,
            &addr,
        );
        pk.extend_from_slice(&pk_i);
    }

    // Compress the public key
    let mut wotspk_addr = addr;
    wotspk_addr.set_type_and_clear(1); // WOTS_PK
    wotspk_addr.set_keypair(addr.keypair);
    wots_pk_compress::<P>(&pk, pk_seed, &wotspk_addr)
}

/// Calculate the WOTS+ length parameters
pub(crate) fn wots_len<P: Parameters>() -> usize {
    wots_len1::<P>() + wots_len2::<P>()
}

/// Calculate len1 (message chains)
fn wots_len1<P: Parameters>() -> usize {
    // FIPS 205 standard formula: (8 * N + lg(W) - 1) / lg(W)
    (8 * P::N as usize + lg(P::W) - 1) / lg(P::W)
}

/// Calculate len2 (checksum chains)
fn wots_len2<P: Parameters>() -> usize {
    let len1 = wots_len1::<P>();
    let max_csum = len1 * (P::W - 1);

    if max_csum == 0 {
        return 1;
    }

    // NIST FIPS 205 formula: floor((floor(log2(len1*(w-1))) + lg(w)) / lg(w))
    let log2_max_csum = (usize::BITS - max_csum.leading_zeros() - 1) as usize;
    let numerator = log2_max_csum + lg(P::W);
    numerator / lg(P::W)
}

/// Compute base-w message + checksum (FIPS 205 Algorithm 7 steps 1-7)
fn wots_msg_and_checksum<P: Parameters>(msg: &[u8]) -> Vec<u32> {
    let len1 = wots_len1::<P>();
    let len2 = wots_len2::<P>();
    let lgw = lg(P::W) as u32;

    // 2: msg ← base_2b(M, lgw, len1)
    let mut result = Vec::with_capacity(len1 + len2);
    base_2b_into(msg, lgw, len1, &mut result);

    // 3-5: Compute checksum
    let mut csum = 0u32;
    for i in 0..len1 {
        csum += P::W as u32 - 1 - result[i];
    }

    // 6: csum ← csum << ((8 − ((len2·lgw) mod 8)) mod 8)
    let shift = (8 - ((len2 as u32 * lgw) & 0x07)) & 0x07;
    csum <<= shift;

    // 7: msg ← msg ∥ base_2b(toByte(csum, ceil(len2·lgw/8)), lgw, len2)
    let csum_bytes_len = (len2 as u32 * lgw + 7) / 8;
    let csum_be = csum.to_be_bytes();
    let csum_slice = &csum_be[(4 - csum_bytes_len as usize)..];
    base_2b_into(csum_slice, lgw, len2, &mut result);

    result
}

/// base_2b: Convert byte string to base 2^b representation (FIPS 205 Algorithm 4)
/// Appends out_len values to the output vector.
fn base_2b_into(x: &[u8], b: u32, out_len: usize, output: &mut Vec<u32>) {
    let mut inn = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;

    for _ in 0..out_len {
        while bits < b {
            if inn < x.len() {
                total = (total << 8) + (x[inn] as u32);
            } else {
                total = total << 8;
            }
            inn += 1;
            bits += 8;
        }
        bits -= b;
        output.push((total >> bits) & ((1u32 << b) - 1));
    }
}

/// Compute logarithm base 2 (floor)
fn lg(x: usize) -> usize {
    if x == 0 {
        0
    } else {
        (usize::BITS - x.leading_zeros() - 1) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;

    #[test]
    fn test_wots_len() {
        type P = SlhDsa128s;
        let len1 = wots_len1::<P>();
        let len2 = wots_len2::<P>();
        let total = wots_len::<P>();

        assert_eq!(len1, 32);
        assert_eq!(len2, 3);
        assert_eq!(total, 35);
    }

    #[test]
    fn test_base_2b_conversion() {
        let input = vec![0xFF, 0x00, 0xAB];
        let mut output = Vec::new();
        base_2b_into(&input, 4, 6, &mut output);

        assert_eq!(output.len(), 6);
        assert_eq!(output, vec![0xF, 0xF, 0x0, 0x0, 0xA, 0xB]);
    }

    #[test]
    fn test_lg() {
        assert_eq!(lg(1), 0);
        assert_eq!(lg(2), 1);
        assert_eq!(lg(4), 2);
        assert_eq!(lg(8), 3);
        assert_eq!(lg(16), 4);
        assert_eq!(lg(15), 3);
        assert_eq!(lg(17), 4);
    }

    #[test]
    fn test_msg_and_checksum() {
        type P = SlhDsa128s;
        // N=16 bytes message, all zeros
        let msg = vec![0u8; P::N];
        let result = wots_msg_and_checksum::<P>(&msg);

        // len1=32, len2=3, total=35
        assert_eq!(result.len(), 35);

        // All zero message -> all zero base-w digits
        for i in 0..32 {
            assert_eq!(result[i], 0);
        }

        // Checksum = 32 * 15 = 480 = 0x1E0
        // Shifted: 480 << 4 = 7680 = 0x1E00
        // to_byte(7680, 2) = [0x1E, 0x00]
        // base_2b = [1, 14, 0]
        assert_eq!(result[32], 1);
        assert_eq!(result[33], 14);
        assert_eq!(result[34], 0);
    }
}
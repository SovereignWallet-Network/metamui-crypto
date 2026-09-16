//! Keccak-f[1600] and a bit-granular sponge (FIPS 202 §3, §4).
//!
//! `keccak_f1600` is the one permutation every function in this crate uses.
//! `KeccakSponge` absorbs bit strings in FIPS 202 Appendix B.1 (`h2b`) order —
//! the valid bits of a trailing partial byte sit in its LOW positions — so
//! SP 800-185 constructions can concatenate a non-byte-aligned message with
//! the byte strings that follow it (`right_encode(L)` in KMAC, the `00`
//! domain suffix in cSHAKE) without any caller-side bit shuffling.

use alloc::vec;
use alloc::vec::Vec;

const KECCAK_ROUNDS: usize = 24;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const RHO_OFFSETS: [[u32; 5]; 5] = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

#[inline(always)]
fn rotate_left(value: u64, amount: u32) -> u64 {
    if amount == 0 { value } else { (value << amount) | (value >> (64 - amount)) }
}

/// The Keccak-f[1600] permutation over 25 little-endian lanes.
pub fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..KECCAK_ROUNDS {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ rotate_left(c[(x + 1) % 5], 1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        // ρ and π
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(state[x + 5 * y], RHO_OFFSETS[x][y]);
            }
        }
        // χ
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Absorb side of a Keccak sponge with a byte rate `rate` (168 for the
/// 128-bit-security functions, 136 for the 256-bit ones).
#[derive(Clone)]
pub struct KeccakSponge {
    state: [u64; 25],
    rate: usize,
    buf: [u8; 200],
    /// Bits of the current block already filled (0..rate*8).
    bit_pos: usize,
}

impl KeccakSponge {
    /// A fresh sponge with the given byte rate.
    pub fn new(rate: usize) -> Self {
        assert!(rate > 0 && rate <= 200 && rate % 8 == 0, "invalid Keccak rate {rate}");
        Self { state: [0u64; 25], rate, buf: [0u8; 200], bit_pos: 0 }
    }

    /// Rate in bytes.
    pub fn rate(&self) -> usize {
        self.rate
    }

    fn absorb_block(&mut self) {
        for (i, lane) in self.buf[..self.rate].chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        keccak_f1600(&mut self.state);
        self.buf[..self.rate].fill(0);
        self.bit_pos = 0;
    }

    /// Absorb whole bytes.
    pub fn absorb(&mut self, mut data: &[u8]) {
        if self.bit_pos % 8 != 0 {
            // A partial byte is pending: everything after it is bit-shifted.
            self.absorb_bits(data, data.len() * 8);
            return;
        }
        while !data.is_empty() {
            let pos = self.bit_pos / 8;
            let take = core::cmp::min(self.rate - pos, data.len());
            self.buf[pos..pos + take].copy_from_slice(&data[..take]);
            self.bit_pos += take * 8;
            data = &data[take..];
            if self.bit_pos == self.rate * 8 {
                self.absorb_block();
            }
        }
    }

    /// Absorb the first `nbits` bits of `data` (LSB-first within each byte,
    /// FIPS 202 `h2b`); `data` must hold at least `ceil(nbits / 8)` bytes.
    pub fn absorb_bits(&mut self, data: &[u8], nbits: usize) {
        assert!(nbits <= data.len() * 8, "absorb_bits: {nbits} bits requested from {} bytes", data.len());
        let mut i = 0;
        if self.bit_pos % 8 == 0 {
            let full = nbits / 8;
            self.absorb(&data[..full]);
            i = full * 8;
        }
        while i < nbits {
            let bit = (data[i / 8] >> (i % 8)) & 1;
            self.buf[self.bit_pos / 8] |= bit << (self.bit_pos % 8);
            self.bit_pos += 1;
            i += 1;
            if self.bit_pos == self.rate * 8 {
                self.absorb_block();
            }
        }
    }

    /// Append the `suffix_bits` low bits of `suffix` (the domain-separation
    /// suffix: `1111` for SHAKE, `00` for cSHAKE), apply `pad10*1`, and switch
    /// to squeezing.
    pub fn finalize(mut self, suffix: u8, suffix_bits: usize) -> KeccakReader {
        assert!(suffix_bits <= 8);
        self.absorb_bits(&[suffix], suffix_bits);
        // pad10*1: a 1 bit, zeros, and a final 1 at the end of the block. If
        // the first 1 fills the block, the closing 1 opens a new block.
        self.buf[self.bit_pos / 8] |= 1 << (self.bit_pos % 8);
        self.bit_pos += 1;
        if self.bit_pos == self.rate * 8 {
            self.absorb_block();
        }
        self.buf[self.rate - 1] |= 0x80;
        self.absorb_block();
        KeccakReader { state: self.state, rate: self.rate, block: [0u8; 200], pos: self.rate, started: false }
    }
}

/// Squeeze side of a Keccak sponge. Successive reads continue one output
/// stream: the state is permuted between rate blocks, never after the last.
#[derive(Clone)]
pub struct KeccakReader {
    state: [u64; 25],
    rate: usize,
    block: [u8; 200],
    /// Bytes of `block` already handed out; `rate` means "refill first".
    pos: usize,
    /// Whether the first block has been produced (later blocks permute first).
    started: bool,
}

impl KeccakReader {
    fn next_block(&mut self) {
        if self.started {
            keccak_f1600(&mut self.state);
        }
        for (i, lane) in self.block[..self.rate].chunks_exact_mut(8).enumerate() {
            lane.copy_from_slice(&self.state[i].to_le_bytes());
        }
        self.pos = 0;
        self.started = true;
    }

    /// Fill `out` with the next output bytes.
    pub fn read_into(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == self.rate {
                self.next_block();
            }
            let take = core::cmp::min(self.rate - self.pos, out.len() - done);
            out[done..done + take].copy_from_slice(&self.block[self.pos..self.pos + take]);
            self.pos += take;
            done += take;
        }
    }

    /// Return the next `len` output bytes.
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.read_into(&mut out);
        out
    }

    /// Return the next `nbits` output bits as `ceil(nbits / 8)` bytes, the
    /// last byte holding its valid bits in the LOW positions (FIPS 202 `b2h`).
    pub fn read_bits(&mut self, nbits: usize) -> Vec<u8> {
        let mut out = self.read(nbits.div_ceil(8));
        if nbits % 8 != 0 {
            let last = out.len() - 1;
            out[last] &= (1u8 << (nbits % 8)) - 1;
        }
        out
    }
}

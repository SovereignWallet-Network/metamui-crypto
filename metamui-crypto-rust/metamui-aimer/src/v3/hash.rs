//! `hash.c` upstream: SHAKE128 for λ = 128, SHAKE256 otherwise, used as an
//! incremental absorb → finalize → squeeze XOF with one-byte domain prefixes.

use super::params::AimerV3Params;
use alloc::vec::Vec;
use metamui_shake::{Shake128, Shake128Reader, Shake256, Shake256Reader};

pub const PREFIX_1: u8 = 1;
pub const PREFIX_2: u8 = 2;
pub const PREFIX_3: u8 = 3;
pub const PREFIX_4: u8 = 4;
pub const PREFIX_5: u8 = 5;

pub enum Hash {
    S128(Shake128),
    S256(Shake256),
}

pub enum Xof {
    S128(Shake128Reader),
    S256(Shake256Reader),
}

impl Hash {
    pub fn new<P: AimerV3Params>() -> Self {
        if P::SECURITY_BITS == 128 {
            Hash::S128(Shake128::new())
        } else {
            Hash::S256(Shake256::new())
        }
    }

    pub fn with_prefix<P: AimerV3Params>(prefix: u8) -> Self {
        let mut h = Self::new::<P>();
        h.update(&[prefix]);
        h
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hash::S128(h) => {
                let _ = h.update(data);
            }
            Hash::S256(h) => {
                let _ = h.update(data);
            }
        }
    }

    pub fn finalize(self) -> Xof {
        match self {
            Hash::S128(h) => Xof::S128(h.finalize_xof()),
            Hash::S256(h) => Xof::S256(h.finalize_xof()),
        }
    }
}

impl Xof {
    pub fn squeeze(&mut self, len: usize) -> Vec<u8> {
        match self {
            Xof::S128(r) => r.read(len),
            Xof::S256(r) => r.read(len),
        }
    }

    pub fn squeeze_into(&mut self, out: &mut [u8]) {
        let v = self.squeeze(out.len());
        out.copy_from_slice(&v);
    }
}

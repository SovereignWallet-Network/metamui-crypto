//! Simple sampler compatibility facade for Falcon-512.
//!
//! The historical implementation in this module synthesized signatures from
//! placeholder math. Phase 0 keeps the type available but fails closed until a
//! real sampler is wired in.

use crate::error::{Falcon512Error, Result};
use alloc::vec::Vec;
use rand::RngCore;

/// Compatibility wrapper for legacy call sites.
pub struct SimpleSampler;

impl SimpleSampler {
    /// Create a new compatibility wrapper.
    pub fn new() -> Self {
        Self
    }

    /// Refuse to emit a placeholder signature.
    pub fn sample_signature<R: RngCore>(
        &self,
        _target: &[i16],
        _h: &[i16],
        _rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        Err(Falcon512Error::NotImplemented)
    }

    /// Refuse to emit a placeholder signature.
    pub fn sample_direct<R: RngCore>(
        &self,
        _target: &[i16],
        _h: &[i16],
        _rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        Err(Falcon512Error::NotImplemented)
    }
}

impl Default for SimpleSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_simple_sampler_fails_closed() {
        let mut rng = StdRng::seed_from_u64(12345);
        let sampler = SimpleSampler::new();
        let target = vec![100i16; 512];
        let h = vec![1i16; 512];

        assert!(matches!(
            sampler.sample_signature(&target, &h, &mut rng),
            Err(Falcon512Error::NotImplemented)
        ));
        assert!(matches!(
            sampler.sample_direct(&target, &h, &mut rng),
            Err(Falcon512Error::NotImplemented)
        ));
    }
}

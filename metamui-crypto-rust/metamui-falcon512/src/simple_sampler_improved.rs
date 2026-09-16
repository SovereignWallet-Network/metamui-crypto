//! Improved simple sampler compatibility facade for Falcon-512.
//!
//! This module previously exposed heuristic and placeholder signature
//! generation. Phase 0 keeps the public type available but fails closed.

use crate::error::{Falcon512Error, Result};
use alloc::vec::Vec;
use rand::RngCore;

/// Compatibility wrapper for legacy call sites.
pub struct SimpleSamplerImproved;

impl SimpleSamplerImproved {
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
}

impl Default for SimpleSamplerImproved {
    fn default() -> Self {
        Self::new()
    }
}

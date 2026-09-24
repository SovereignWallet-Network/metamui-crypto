//! MPC-in-the-Head protocol implementation for AIMer
//!
//! This implements the zero-knowledge proof system that proves knowledge
//! of a preimage without revealing it.

use crate::{params::AimerParams, error::AimerError};
use metamui_shake::Shake256;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// MPC party in the protocol
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Party {
    /// Party index
    pub index: usize,
    /// Share of the secret
    pub share: Vec<u8>,
    /// Random tape for this party
    pub tape: Vec<u8>,
    /// Commitment to this party's view (length = DIGEST_SIZE for the security level)
    pub commitment: Vec<u8>,
}

/// MPC-in-the-Head execution
pub struct MpcExecution<P: AimerParams> {
    /// Number of parties
    pub n_parties: usize,
    /// Parties in the MPC protocol
    pub parties: Vec<Party>,
    /// Master seed for randomness
    pub master_seed: [u8; 32],
    _phantom: core::marker::PhantomData<P>,
}

impl<P: AimerParams> MpcExecution<P> {
    /// Create a new MPC execution
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            n_parties: P::MPC_PARTIES,
            parties: Vec::with_capacity(P::MPC_PARTIES),
            master_seed: *seed,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Share a secret among parties using XOR-based additive sharing
    pub fn share_secret(&mut self, secret: &[u8]) -> Result<(), AimerError> {
        let share_size = secret.len();
        let mut shares = Vec::with_capacity(self.n_parties);

        // Generate n-1 random shares
        for i in 0..self.n_parties - 1 {
            let mut share = vec![0u8; share_size];
            self.random_bytes(i, &mut share)?;
            shares.push(share);
        }

        // Compute the last share as XOR of secret and all other shares
        let mut last_share = secret.to_vec();
        for share in &shares {
            for (j, byte) in share.iter().enumerate() {
                last_share[j] ^= byte;
            }
        }
        shares.push(last_share);

        // Create parties with their shares and tapes
        for (i, share) in shares.into_iter().enumerate() {
            let mut tape = vec![0u8; P::TAPE_SIZE];
            self.random_tape(i, &mut tape)?;

            let party = Party {
                index: i,
                share,
                tape,
                commitment: Vec::new(),
            };
            self.parties.push(party);
        }

        Ok(())
    }

    /// Commit to all parties' views
    pub fn commit_all_views(&mut self) -> Result<(), AimerError> {
        for i in 0..self.parties.len() {
            let commitment = self.commit_view(&self.parties[i])?;
            self.parties[i].commitment = commitment;
        }
        Ok(())
    }

    /// Open a subset of parties (for verification)
    pub fn open_parties(&self, indices: &[usize]) -> Result<Vec<Party>, AimerError> {
        let mut opened = Vec::new();

        for &idx in indices {
            if idx >= self.n_parties {
                return Err(AimerError::InvalidPartyIndex);
            }
            opened.push(self.parties[idx].clone());
        }

        Ok(opened)
    }

    /// Generate random bytes for a party's share
    fn random_bytes(&self, party_idx: usize, output: &mut [u8]) -> Result<(), AimerError> {
        let mut shake = Shake256::new();
        let _ = shake.update(&self.master_seed);
        let _ = shake.update(&[party_idx as u8]);
        let _ = shake.update(b"share");
        let mut reader = shake.finalize_xof();
        let bytes = reader.read(output.len());
        output.copy_from_slice(&bytes);
        Ok(())
    }

    /// Generate random tape for a party
    fn random_tape(&self, party_idx: usize, output: &mut [u8]) -> Result<(), AimerError> {
        let mut shake = Shake256::new();
        let _ = shake.update(&self.master_seed);
        let _ = shake.update(&[party_idx as u8]);
        let _ = shake.update(b"tape");
        let mut reader = shake.finalize_xof();
        let bytes = reader.read(output.len());
        output.copy_from_slice(&bytes);
        Ok(())
    }

    /// Commit to a party's view (hash of index || share || tape)
    ///
    /// Output length is P::DIGEST_SIZE bytes to match the security level.
    fn commit_view(&self, party: &Party) -> Result<Vec<u8>, AimerError> {
        let mut shake = Shake256::new();
        let _ = shake.update(&[party.index as u8]);
        let _ = shake.update(&party.share);
        let _ = shake.update(&party.tape);

        let mut reader = shake.finalize_xof();
        Ok(reader.read(P::DIGEST_SIZE))
    }
}

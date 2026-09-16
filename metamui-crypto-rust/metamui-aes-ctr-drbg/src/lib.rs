// MetaMUI Crypto Primitives — AES-256-CTR-DRBG
// Copyright (c) 2025 Sovereign Wallet Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// NIST SP 800-90A Rev. 1 compliant deterministic random bit generator.
// Two variants:
//   - Simplified (no DF): `AesCtrDrbg` — for NIST PQC KAT generation
//   - Full DF: `AesCtrDrbgDf` — for general NIST SP 800-90A compliance
//
// Plus `NistKatRng` — thin wrapper matching the NIST PQC KAT RNG interface.

// The modules import `alloc::vec::Vec` when `std` is off; that path needs the
// crate declared here, or every `--no-default-features` build fails at the
// import (found by the release feature matrix, #215).
extern crate alloc;

pub mod error;
pub mod ctr_drbg;
pub mod ctr_drbg_df;
pub mod nist_kat_rng;

// Re-exports for convenience
pub use ctr_drbg::{AesCtrDrbg, SEEDLEN, RESEED_INTERVAL, MAX_REQUEST_SIZE};
pub use ctr_drbg_df::{AesCtrDrbgDf, block_cipher_df, MIN_ENTROPY_DF};
pub use nist_kat_rng::NistKatRng;
pub use error::{AesCtrDrbgError, Result};
